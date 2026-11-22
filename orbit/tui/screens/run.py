"""Run screen: hash gate, per-tool progress/log/elapsed/status, stop controls."""
from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

from rich.markup import escape
from rich.text import Text
from textual import work
from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.screen import Screen
from textual.widgets import Button, Checkbox, Collapsible, Footer, Input, ProgressBar, RichLog, Static

from orbit.core import config_store, emailer, notify
from orbit.core.outputs import make_run_folder
from orbit.core.pipeline import finalize
from orbit.core.runner import Runner, RunError, RunStatus, ToolRun, prepare_run
from orbit.core.secrets import SecretStore
from orbit.core.tools import all_tools
from orbit.core.workspace import Workspace
from orbit.reporting import scorer
from orbit.reporting.context import ReportContext
from orbit.reporting.pdf_report import generate_pdf

STATUS_STYLE = {RunStatus.PENDING: "dim", RunStatus.RUNNING: "cyan", RunStatus.COMPLETE: "green",
                RunStatus.FAILED: "red", RunStatus.SKIPPED: "yellow"}
_IN_PROGRESS = "A run is in progress. No report is available yet."


class RunScreen(Screen):
    BINDINGS = [("escape", "app.pop_screen", "Back")]

    def __init__(self) -> None:
        super().__init__()
        self.runner: Runner | None = None
        self._executing: list | None = None  # tool set of the run in progress
        self._visible_tools: tuple[str, ...] | None = None

    def _tools(self):
        sel = self.app.state.selected
        tools = [t for t in all_tools() if t.name in sel]
        if not tools and self.app.state.dry_run:
            tools = [t for t in all_tools() if t.fixture]
        return tools

    def compose(self) -> ComposeResult:
        mode = "[red](DRY RUN)[/red] " if self.app.state.dry_run else ""
        yield Static(f"[bold cyan]Run[/bold cyan] {mode}")
        yield Static("[dim]Client / engagement name (appears on report cover)[/dim]")
        yield Input(self.app.state.client_name, placeholder="Confidential", id="client-name")
        dry = self.app.state.dry_run
        yield Checkbox("Email results when complete", id="email-run", disabled=dry,
                       value=not dry and config_store.load()["notifications"]["email_notify"])
        with Horizontal():
            yield Button("Start", id="start", variant="success")
            yield Button("Stop all", id="stop-all", variant="error")
        for t in all_tools():  # all of them, shown or hidden to match the current selection
            with Collapsible(title=t.display, collapsed=False, id=f"tool-{t.name}"):
                yield Static("Pending", id=f"status-{t.name}")
                yield ProgressBar(total=100, show_eta=False, id=f"bar-{t.name}")
                yield Button(f"Stop {t.display}", id=f"stop-{t.name}")
                yield RichLog(id=f"log-{t.name}", max_lines=2000, highlight=True, markup=True,
                              wrap=True)
        yield Static("", id="result")
        yield Static("", id="email-status")
        yield Footer()

    def on_mount(self) -> None:
        self._sync_tools()

    def on_screen_resume(self) -> None:
        self._sync_tools()

    def _sync_tools(self) -> None:
        # While a run is in progress the screen shows that run's tools, not the new selection.
        if self._executing is None:
            self._show_tools(self._tools())

    def _show_tools(self, tools: list) -> None:
        names = tuple(t.name for t in tools)
        if names == self._visible_tools:
            return
        self._visible_tools = names
        for t in all_tools():
            self.query_one(f"#tool-{t.name}", Collapsible).display = t.name in names
        self._reset_controls()

    def _reset_controls(self) -> None:
        for t in all_tools():
            self.query_one(f"#status-{t.name}", Static).update("Pending")
            self.query_one(f"#bar-{t.name}", ProgressBar).update(progress=0)
        for log in self.query(RichLog):  # otherwise a second run hides its BLOCKED reason
            log.clear()
            log._shown = 0  # type: ignore[attr-defined]

    def _update(self, run: ToolRun) -> None:
        n = run.tool.name
        self.query_one(f"#status-{n}", Static).update(Text.assemble(
            (run.status.value, STATUS_STYLE[run.status]), f"  {run.elapsed:5.1f}s {run.note}"))
        self.query_one(f"#bar-{n}", ProgressBar).update(progress=run.progress)
        log = self.query_one(f"#log-{n}", RichLog)
        shown = getattr(log, "_shown", 0)
        # Follow output only while the user is at the bottom; scrolling up pauses auto-scroll.
        follow = log.is_vertical_scroll_end
        for line in run.log[shown:]:
            log.write(escape(line), scroll_end=follow)  # tool output is not Rich markup
        log._shown = len(run.log)  # type: ignore[attr-defined]

    def _email(self, findings, written: list[Path], tools) -> bool:
        """Send the summary PDF (generated into a temp dir if PDF output is off). Never raises."""
        st = self.app.state
        if st.dry_run:
            return False
        try:
            settings = emailer.load_settings(config_store.load(), SecretStore(st.passphrase))
            if not settings.configured:
                return False
            ctx = ReportContext(findings, [t.display for t in tools], dry_run=st.dry_run,
                                client=st.client_name.strip() or "Confidential")
            pdf = next((p for p in written if p.suffix == ".pdf" and p.exists()), None)
            if pdf:
                return emailer.send_results(ctx, pdf, settings)
            with tempfile.TemporaryDirectory() as tmp:
                return emailer.send_results(ctx, generate_pdf(ctx, Path(tmp)), settings)
        except Exception:
            return False

    @work(exclusive=True, group="run")
    async def start_run(self) -> None:
        tools = self._tools()  # snapshot: this exact set is displayed, executed and recorded
        if not tools:
            self.notify("Select at least one tool first", severity="warning")
            return
        self._executing = tools
        st = self.app.state
        # nothing from an earlier run may stand in for this one
        st.run_folder, st.findings, st.runs = None, [], {}
        st.run_notice = _IN_PROGRESS
        try:
            self._show_tools(tools)
            await self._run_tools(tools)
        finally:
            if st.run_notice == _IN_PROGRESS:  # cancelled
                st.run_notice = "The last run was stopped. No report is available."
            if self._executing is tools:
                self._executing = None

    async def _run_tools(self, tools: list) -> None:
        st = self.app.state
        self.runner = None  # until it exists, any Stop button cancels this worker
        self._reset_controls()
        hashes, creds, secrets = [], {}, {}
        result = self.query_one("#result", Static)
        result.update("")
        self.query_one("#email-status", Static).update("")
        try:
            with Workspace() as workspace:
                if not st.dry_run:
                    result.update("Verifying tool integrity…")
                    hashes, creds, secrets = await asyncio.to_thread(
                        prepare_run, tools, lambda: SecretStore(st.passphrase), workspace)
                folder = make_run_folder(st.output.base_dir)
                self.runner = Runner(folder, creds, secrets, st.dry_run, hashes,
                                     on_update=self._update)
                st.runs = self.runner.runs
                await self.runner.run_all(tools)
        except Exception as exc:  # shown, never swallowed: no report, history, notification, email
            detail = str(exc) if isinstance(exc, (RunError, PermissionError)) else type(exc).__name__
            st.run_notice = f"The last run FAILED ({detail}). No report is available."
            result.update(Text(f"RUN FAILED — {detail}. No report was written.", style="red"))
            return
        launched = [r.tool for r in st.runs.values() if r.launched]
        not_launched = [r.tool.display for r in st.runs.values() if not r.launched]
        if not launched:  # no report, history record, notification or email
            blocked = all(r.status is RunStatus.SKIPPED for r in st.runs.values())
            word = "BLOCKED" if blocked else "FAILED"
            st.run_notice = (f"The last run {word}: no tools were launched. "
                             "No report is available.")
            result.update(f"[red]{word} — no tools were launched.[/red] See each tool's log.")
            return
        try:
            findings, written = await asyncio.to_thread(
                finalize, folder, [t.display for t in launched], st.output, st.dry_run,
                st.passphrase, st.client_name)
        except Exception as exc:
            st.run_notice = ("The last run FAILED: its report could not be finalised. "
                             "No report is available.")
            result.update(Text(f"RUN FAILED — results could not be packaged ({type(exc).__name__}).",
                               style="red"))
            return
        st.findings, st.run_folder, st.run_notice = findings, folder, ""  # published only here
        result.update(
            f"[green]Done.[/green] {len(findings)} controls. Output: {st.run_folder}\n"
            + (f"[red]Not launched: {', '.join(not_launched)}[/red]\n" if not_launched else "")
            + "\n".join(str(p) for p in written))
        if st.dry_run:  # no desktop notification and no email
            return
        score = round(scorer.summarize(findings).posture)
        await asyncio.to_thread(notify.notify_complete, score)
        if self.query_one("#email-run", Checkbox).value:
            ok = await asyncio.to_thread(self._email, findings, written, launched)
            self.query_one("#email-status", Static).update(
                "[green]Email sent ✓[/green]" if ok else "[red]Email failed ✗[/red]")

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "client-name":
            self.app.state.client_name = event.value.strip()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id or ""
        if bid == "start":
            if self._executing is not None:
                self.notify("A run is already in progress", severity="warning")
            else:
                self.start_run()
        elif bid.startswith("stop-") and not self.runner:
            if self.workers.cancel_group(self, "run"):
                self.query_one("#result", Static).update("Stopped before launch.")
        elif bid == "stop-all" and self.runner:
            self.runner.stop_all()
        elif bid.startswith("stop-") and self.runner:
            self.runner.stop(bid.removeprefix("stop-"))

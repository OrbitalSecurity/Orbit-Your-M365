"""Summary preview + Executive Summary PDF generation."""
from __future__ import annotations

import asyncio
from pathlib import Path

from rich.text import Text
from textual import work
from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import Button, Footer, ProgressBar, Static

from orbit.reporting import scorer


class ReportScreen(Screen):
    BINDINGS = [("escape", "app.pop_screen", "Back")]
    _shown: Path | None = None  # the run folder this screen last described

    DEFAULT_CSS = """
    ReportScreen { padding: 1 3; }
    #summary      { margin-bottom: 1; }
    #exec-section { height: auto; margin-top: 1; border-top: solid #0d2a40; padding-top: 1; }
    #exec-desc    { color: #1a4a5a; margin-bottom: 1; }
    #exec-bar     { height: 1; margin: 1 0; display: none; }
    #exec-bar.active { display: block; }
    #exec-status  { height: 1; color: #2a6070; }
    #exec-btn     { width: auto; min-width: 28; }
    """

    def compose(self) -> ComposeResult:
        yield Static("[bold cyan]Summary preview[/bold cyan]", id="title")
        yield Static("", id="summary")
        yield Static(
            "[bold]Executive Summary PDF[/bold]\n"
            "[dim]A 2-page plain-English report for non-technical stakeholders — "
            "posture score, top findings, remediation priorities, and a written summary. "
            "Generated on demand; does not replace the full technical report.[/dim]",
            id="exec-section"
        )
        yield Button("⬇  Generate Executive Summary PDF", id="exec-btn")
        yield ProgressBar(total=100, show_eta=False, id="exec-bar")
        yield Static("", id="exec-status")
        yield Footer()

    def on_screen_resume(self) -> None:
        # every visit, because the screen is cached and there may have been another run
        st = self.app.state
        box = self.query_one("#summary", Static)
        self.query_one("#exec-btn", Button).disabled = not st.run_folder
        if st.run_folder != self._shown:
            self._shown = st.run_folder
            self.query_one("#exec-status", Static).update("")  # may name an earlier run's file
        if not st.run_folder:
            box.update(Text(st.run_notice, style="red") if st.run_notice
                       else "[dim]No run yet — use Run ▶ first.[/dim]")
            return
        findings = st.findings  # as published, not whatever is in the folder by now
        s = scorer.summarize(findings)
        lines = [
            f"Posture: [bold]{s.posture}%[/bold] ({s.passed_controls}/{s.total_controls})",
            "  ".join(f"{k}: {v}" for k, v in s.counts.items()),
            "",
            "[bold]Top findings[/bold]",
        ]
        for f in scorer.top_n(findings, 3):
            col = "red" if f.severity == "Critical" else "yellow"
            lines.append(f"[{col}]{f.severity}[/{col}] {f.title} ({f.control_id}) - {f.tool}")
        box.update("\n".join(lines))

    @work(exclusive=True)
    async def _generate_exec(self) -> None:
        btn    = self.query_one("#exec-btn", Button)
        bar    = self.query_one("#exec-bar", ProgressBar)
        status = self.query_one("#exec-status", Static)

        btn.disabled = True
        st = self.app.state
        # taken together, before the first await: a new run clears both
        out_dir, findings, client = st.run_folder, st.findings, st.client_name
        if not out_dir:
            return
        bar.add_class("active")
        bar.update(progress=10)
        status.update("[dim]Preparing findings…[/dim]")

        if not findings:
            status.update("[red]No findings available — run an assessment first.[/red]")
            bar.remove_class("active")
            btn.disabled = False
            return

        bar.update(progress=30)
        status.update("[dim]Generating PDF…[/dim]")

        from orbit.reporting.exec_summary import generate_exec_summary
        try:
            out = await asyncio.to_thread(
                generate_exec_summary,
                findings,
                out_dir,
                client,
                st.dry_run,
            )
            bar.update(progress=100)
            if st.run_folder == out_dir:
                status.update(f"[green]✓ Saved:[/green] [dim]{out}[/dim]")
        except Exception as e:
            status.update(f"[red]✗ Failed: {e}[/red]")
        finally:
            bar.remove_class("active")
            btn.disabled = not st.run_folder

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "exec-btn":
            self._generate_exec()

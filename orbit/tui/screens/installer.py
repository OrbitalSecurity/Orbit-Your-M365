"""Installer: compact table, spacer fills gap, bottom bar always in view."""
from __future__ import annotations

import asyncio
import shutil
from pathlib import Path

from textual import work
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Button, Footer, RichLog, Static

from orbit.core.executables import ExecutableError
from orbit.core.hash_checker import launch_binding, verify_tool
from orbit.core.platform_check import check_platform
from orbit.core.process_env import PIP_NO_RECORDS, url_credentials
from orbit.core.runner import stream_process
from orbit.core.tools import Tool, all_tools, get_tool
from orbit.core.workspace import Workspace


def prereq_report() -> list[tuple[str, bool, str]]:
    info = check_platform()
    pw = ".".join(map(str, info.pwsh_version)) if info.pwsh_version else ""
    return [
        ("PowerShell 7", info.pwsh7,              pw or "not found"),
        ("pip",          True,                    "available"),
        ("OPA",          bool(shutil.which("opa")), "found" if shutil.which("opa") else "not on PATH"),
    ]


class InstallerScreen(Screen):
    BINDINGS = [("escape", "app.pop_screen", "Back")]

    DEFAULT_CSS = """
    InstallerScreen { padding: 0; }

    #prereq-strip {
        height: 1; width: 1fr;
        padding: 0 2;
        background: #050c14;
        border-bottom: solid #0d3a55;
    }
    #prereq-strip Static { width: auto; color: #2a5a6a; margin-right: 4; }

    /* tool rows — fixed height, auto-sized to content */
    #tool-table { height: auto; width: 1fr; padding: 0 2; }

    .tool-row {
        height: 3; width: 1fr;
        border-bottom: solid #060e18;
    }
    .tool-row:hover { background: #06101c; }

    .t-name   { width: 14; content-align: left middle; padding: 0 1; color: #00c8ff; }
    .t-status { width: 1fr; content-align: left middle; padding: 0 1; }
    .badge-ok  { color: #00c840; }
    .badge-no  { color: #cc4444; }
    .badge-dim { color: #2a5a6a; }
    .t-ver    { width: 12; content-align: left middle; padding: 0 1; color: #0d3040; }

    .t-btns { width: 42; content-align: left middle; }
    .t-btns Button {
        width: 12; height: 3; min-width: 0;
        margin: 0 1 0 0;
        background: #06101c;
        border: tall #0d2a40;
        color: #2a6070;
    }
    .t-btns Button:hover  { color: #00c8ff; border: tall #00c8ff; background: #0a1a2c; }
    .btn-inst             { color: #00c840 !important; border: tall #004a20 !important; }
    .btn-inst:hover       { color: #00ff60 !important; background: #001a0a !important; }
    .btn-uninst           { color: #883333 !important; border: tall #3a1010 !important; }
    .btn-uninst:hover     { color: #ff6060 !important; background: #1a0808 !important; }

    /* spacer pushes bottom content down */
    #spacer { height: 1fr; width: 1fr; }

    /* log — hidden until output, sits above bottom bar */
    #log-section        { height: 0; width: 1fr; }
    #log-section.active { height: 6; border-top: solid #0d2a40; }
    #log                { height: 1fr; width: 1fr; padding: 0 2; }

    /* bottom bar — always last, always visible */
    #bottom-bar {
        height: 3; width: 1fr;
        padding: 0 2;
        border-top: solid #0d2a40;
        background: #050c14;
    }
    #bottom-bar Button {
        width: 1fr; height: 3;
        margin: 0 1 0 0;
        background: #080e18;
        border: tall #0d3a55;
        color: #2a6070;
    }
    #bottom-bar Button:hover { color: #00c8ff; border: tall #00c8ff; }
    """

    def compose(self) -> ComposeResult:
        dry = self.app.state.dry_run
        with Horizontal(id="prereq-strip"):
            if dry:
                yield Static("DRY RUN: the installer is disabled and nothing is probed")
            for name, ok, detail in [] if dry else prereq_report():
                icon = "[green]✓[/]" if ok else "[red]✗[/]"
                yield Static(f"{icon} [dim]{name}:[/dim] {detail}")

        with Vertical(id="tool-table"):
            for t in all_tools():
                no_install = dry or bool(t.real_run_block)
                with Horizontal(classes="tool-row", id=f"row-{t.name}"):
                    yield Static(t.display, classes="t-name")
                    yield Static("…", classes="t-status badge-dim", id=f"status-{t.name}")
                    yield Static("",  classes="t-ver",              id=f"ver-{t.name}")
                    with Horizontal(classes="t-btns"):
                        yield Button("⬇ Install",  id=f"install-{t.name}",   classes="btn-inst",
                                     disabled=no_install)
                        yield Button("↑ Update",   id=f"update-{t.name}", disabled=no_install)
                        yield Button("✕ Remove",   id=f"uninstall-{t.name}", classes="btn-uninst",
                                     disabled=dry)

        # fills leftover vertical space
        yield Static("", id="spacer")

        with Vertical(id="log-section"):
            yield RichLog(id="log", markup=False, wrap=True, max_lines=300)

        with Horizontal(id="bottom-bar"):
            yield Button("⬇ Install all", id="install-all", disabled=dry)
            yield Button("⬇ Install OPA", id="install-opa", disabled=dry)
            yield Button("↺ Refresh",     id="refresh", disabled=dry)

        yield Footer()

    def on_mount(self) -> None:
        if self.app.state.dry_run:
            for t in all_tools():
                self.query_one(f"#status-{t.name}", Static).update("◌ Not probed (dry run)")
        else:
            self.refresh_versions()

    @work(thread=True)
    def refresh_versions(self) -> None:
        if self.app.state.dry_run:
            return
        plat = check_platform()
        for t in all_tools():
            compat   = t.compatible(plat)
            inst_ver = t.installed_version() if compat else None
            if t.real_run_block:
                st, sc, vt = "⚠ Unsupported: dry-run only", "t-status badge-no", inst_ver or ""
            elif not compat:
                st, sc, vt = "◌ Incompatible OS", "t-status badge-dim", ""
            elif inst_ver:
                st, sc, vt = "● Installed",       "t-status badge-ok",  inst_ver
            else:
                st, sc, vt = "○ Not installed",   "t-status badge-no",  ""

            def _up(name=t.name, s=st, c=sc, v=vt):
                try:
                    w = self.query_one(f"#status-{name}", Static)
                    w.update(s); w.set_classes(c)
                    self.query_one(f"#ver-{name}", Static).update(v)
                except Exception:
                    pass

            self.app.call_from_thread(_up)

    def _log(self, msg: str) -> None:
        self.query_one("#log-section").add_class("active")
        self.query_one("#log", RichLog).write(msg)

    @work(exclusive=True)
    async def _run(self, tool: Tool, action: str) -> None:
        """action is install, update or uninstall."""
        if self.app.state.dry_run:
            self._log(f"BLOCKED: {action} is disabled in dry-run.")
            return
        try:
            # in a thread: resolving the absolute pwsh path starts a process
            if action == "uninstall":
                argv = await asyncio.to_thread(tool.uninstall_command)
            else:
                argv = await asyncio.to_thread(tool.install_command, action == "update")
        except ExecutableError as exc:
            self._log(f"BLOCKED: {exc}")
            return
        except Exception as exc:  # type only: an unhandled error would be shown with its locals
            self._log(f"BLOCKED: {action} could not be prepared ({type(exc).__name__})")
            return
        if not argv:
            self._log(f"No automated uninstall for {tool.display} — remove manually.")
            return
        await self._execute(argv, f"{action.capitalize()} {tool.display}", tool.package_env(),
                            secrets=url_credentials(), pip=tool.route == "pypi")

    async def _execute(self, argv: list[str], label: str, env: dict[str, str],
                       cwd: Path | None = None, secrets: list[str] | None = None,
                       pip: bool = False) -> None:
        """Status only, for every installer child.

        pip and PowerShell can print credentials from configuration that ORBIT never reads
        (pip.conf, registered repositories, credential providers, signed URLs), so redaction
        cannot make their output safe. The output, the command and any error text are withheld,
        and none of it is persisted.
        """
        if self.app.state.dry_run:
            self._log("BLOCKED: processes are not started in dry-run.")
            return
        self._log(f"── {label} ──")
        if pip:
            env = {**env, **PIP_NO_RECORDS}
        self._log("Running… (installer output is hidden: it can contain package-source "
                  "credentials)")
        try:
            rc = await stream_process(argv, env, None, secrets, cwd)
            self._log(f"exit {rc}" + (" ✓" if rc == 0 else " ✗"))
            if rc != 0:
                self._log("For details, run the installer yourself in a private terminal.")
        except Exception as e:  # type only: the text can quote the package source
            self._log(f"✗  Could not complete ({type(e).__name__})")
        self.refresh_versions()

    @work(exclusive=True, group="opa")
    async def _install_opa(self) -> None:
        """Initialize-SCuBA executes ScubaGear code, so it is bound exactly like a run."""
        if self.app.state.dry_run:
            self._log("BLOCKED: Install OPA runs ScubaGear, which is disabled in dry-run.")
            return
        tool = get_tool("scubagear")
        with Workspace() as workspace:  # holds the snapshot until the process has ended
            result = await asyncio.to_thread(verify_tool, tool, workspace)
            binding, msg = launch_binding([result])
            if binding is None:
                self._log("BLOCKED: " + msg)
                return
            try:
                await asyncio.to_thread(binding.verify)
                spec = tool.opa_spec(binding)
            except Exception as exc:
                self._log(f"BLOCKED: re-check before launch failed ({type(exc).__name__})")
                return
            await self._execute(spec.argv, "Install OPA", spec.env, cwd=spec.cwd,
                                secrets=url_credentials())

    def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id or ""
        tools = {t.name: t for t in all_tools()}

        if self.app.state.dry_run:
            self._log("BLOCKED: the installer is disabled in dry-run.")
        elif bid == "refresh":
            self.refresh_versions()
        elif bid == "install-opa":
            self._install_opa()
        elif bid == "install-all":
            for t in tools.values():
                if t.real_run_block:
                    self._log(f"SKIPPED: {t.display}: {t.real_run_block}")
                else:
                    self._run(t, "install")
        else:
            action, _, name = bid.partition("-")
            if action in ("install", "update", "uninstall") and name in tools:
                self._run(tools[name], action)

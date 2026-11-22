"""Pre-flight check screen — local checks only, no network calls."""
from __future__ import annotations

import shutil
from pathlib import Path

from rich.text import Text
from textual import work
from textual.app import ComposeResult
from textual.containers import Vertical
from textual.screen import Screen
from textual.widgets import Button, Footer, Static
from textual.worker import get_current_worker

from orbit.core.admin_check import is_elevated
from orbit.core.hash_checker import HashResult, launch_binding, verify_tool
from orbit.core.platform_check import check_platform
from orbit.core.runner import token_location_error
from orbit.core.secrets import SecretStore
from orbit.core.tools import Tool, all_tools
from orbit.core.workspace import Workspace


_NETWORK_NOTE = (
    "[dim]Network connectivity and tenant credential validity are not tested here.\n"
    "A live check would require contacting Microsoft's servers and could expose\n"
    "credentials to network logging. Verify tenant access manually before running.[/dim]"
)


def _check_output_writable(base_dir: Path) -> tuple[bool, str]:
    try:
        base_dir.mkdir(parents=True, exist_ok=True)
        test = base_dir / ".orbit_write_test"
        test.touch()
        test.unlink()
        return True, str(base_dir)
    except OSError as e:
        return False, str(e)


def _selected_tools(state) -> list:
    tools = [t for t in all_tools() if t.name in (state.selected or set())]
    if not tools and state.dry_run:
        tools = [t for t in all_tools() if t.fixture]
    return tools


def _dry_run_preflight(state) -> list[tuple[bool | None, str, str]]:
    """Fixture-only: no PowerShell, installation, manifest or credential store is looked at."""
    results: list[tuple[bool | None, str, str]] = [
        (True, "Mode", "dry-run — fixture playback; real tools and credentials are not probed"),
    ]
    results += [(True, t.display, "dry-run mode (fixture data)") for t in _selected_tools(state)]
    ok, detail = _check_output_writable(state.output.base_dir)
    results.append((ok, "Output folder writable", detail))
    results.append((None, "Tool integrity", "not checked in dry-run — nothing real is launched"))
    return results


def _launch_problem(tool: Tool, check: HashResult, base_dir: Path) -> str:
    """Why a launch would be blocked now, or ''. The snapshot is released however this ends."""
    problem = ""
    try:
        binding, problem = launch_binding([check])
        if binding:
            if binding.tool != tool.name:
                problem = "the binding is for another tool"
            else:
                binding.verify()  # the same complete re-check as immediately before a launch
                problem = token_location_error(tool, binding, base_dir)
    except Exception as exc:
        problem = f"re-check failed: {exc}"
    finally:
        if check.binding and not check.binding.release():
            problem = problem or "the private snapshot could not be removed"
    return problem


def run_preflight(state) -> list[tuple[bool | None, str, str]]:
    """
    Returns list of (passed, label, detail) tuples.
    All checks are local — no network calls.
    """
    if state.dry_run:
        return _dry_run_preflight(state)

    results: list[tuple[bool | None, str, str]] = []
    plat = check_platform()

    # 1. Elevation
    elevated = is_elevated()
    results.append((
        elevated,
        "Administrator / elevated",
        "OK" if elevated else "Not elevated — ScubaGear and Maester require Global Admin"
    ))

    # 2. PowerShell 7
    pw_ok = plat.pwsh7
    pw_ver = ".".join(map(str, plat.pwsh_version)) if plat.pwsh_version else "not found"
    why = plat.pwsh_error or f"{pw_ver} — install pwsh 7+"
    results.append((pw_ok, "PowerShell 7", pw_ver if pw_ok else why))

    # 3. OPA binary
    opa = bool(shutil.which("opa"))
    results.append((opa, "OPA binary", shutil.which("opa") or "not on PATH — required by ScubaGear"))

    # 4. Each selected tool: installed, and ready to pass the same gate as a run
    tools = _selected_tools(state)
    if not tools:
        results.append((False, "Tools selected", "No tools selected — use Tools screen"))
    with Workspace() as workspace:
        for t in tools:
            if t.real_run_block:
                results.append((False, f"{t.display} real run", f"BLOCKED — {t.real_run_block}"))
                continue
            if not t.compatible(plat):
                why = plat.pwsh_error if t.needs_pwsh and plat.os_name in t.supported_os else ""
                results.append((False, f"{t.display} compatible",
                                why or f"Not compatible with {plat.os_name}"))
                results.append((False, f"{t.display} integrity", "BLOCKED — cannot be verified"))
                continue
            check = verify_tool(t, workspace)
            message = _launch_problem(t, check, Path(state.output.base_dir))
            if check.version:
                results.append((True, t.display, f"v{check.version}"))
            else:
                results.append((False, t.display,
                                f"not usable: {check.reason or 'not installed'}"))
            label = f"{t.display} {check.version or '(unknown version)'} integrity"
            if message:
                results.append((False, label, f"BLOCKED — {message}"))
            else:
                results.append((True, label, "ready — files match the manifest; "
                                             "checked again at launch"))

    # 5. Credentials loaded
    runnable = [t for t in tools if not t.real_run_block]  # never read credentials for the rest
    try:
        store = SecretStore(state.passphrase) if runnable else None
        for t in runnable:
            creds = store.load(t.name)
            has = bool(creds and any(creds.values()))
            results.append((has, f"{t.display} credentials", "loaded" if has else "missing — use Credentials screen"))
    except Exception as e:
        results.append((False, "Credentials", f"Could not read credential store: {e}"))

    # 6. Output folder writable
    ok, detail = _check_output_writable(state.output.base_dir)
    results.append((ok, "Output folder writable", detail))

    return results


class PreflightScreen(Screen):
    BINDINGS = [
        ("escape", "app.pop_screen", "Back"),
        ("r", "recheck", "Re-check"),
    ]

    DEFAULT_CSS = """
    PreflightScreen { padding: 1 3; }

    #title    { margin-bottom: 1; }
    #checks   { height: auto; width: 1fr; margin-bottom: 1; }
    .chk-row  { height: 1; width: 1fr; }
    #note     { margin-top: 1; }
    #actions  { height: 3; margin-top: 1; }
    #actions Button { width: auto; min-width: 16; margin-right: 1; }
    """

    def compose(self) -> ComposeResult:
        yield Static("[bold cyan]Pre-flight checks[/bold cyan]  "
                     "[dim]Local checks only — see note below[/dim]", id="title")
        yield Vertical(id="checks")
        yield Static(_NETWORK_NOTE, id="note")
        from textual.containers import Horizontal
        with Horizontal(id="actions"):
            yield Button("↺ Re-check", id="recheck")
            yield Button("▶ Proceed to Run", id="proceed")
        yield Footer()

    def on_screen_resume(self) -> None:
        # every visit, because the screen is cached and the selection may have changed
        self.query_one("#checks", Vertical).remove_children()
        self._run_checks()

    @work(thread=True, exclusive=True)
    def _run_checks(self) -> None:
        worker = get_current_worker()
        results = run_preflight(self.app.state)
        if worker.is_cancelled:  # superseded by a check of a newer selection
            return

        def _render():
            if worker.is_cancelled:
                return
            container = self.query_one("#checks", Vertical)
            container.remove_children()
            for ok, label, detail in results:
                if ok is True:
                    icon  = ("✓", "green")
                    style = "#2a6070"
                elif ok is None:
                    icon  = ("⚠", "yellow")
                    style = "#b07800"
                else:
                    icon  = ("✗", "red")
                    style = "#cc4444"
                # not markup: details carry file names and paths taken from disk
                row = Static(Text.assemble(icon, "  ", (label, style), "  ", (detail, "dim")),
                             classes="chk-row")
                container.mount(row)

        self.app.call_from_thread(_render)

    def action_recheck(self) -> None:
        self._run_checks()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "recheck":
            self._run_checks()
        elif event.button.id == "proceed":
            self.app.pop_screen()
            self.app.push_screen("run")

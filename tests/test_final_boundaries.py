"""Final hardening items 4-8: installer output, report state, pre-flight, ROADtools, limits.

Every credential is synthetic. Nothing here reaches a network, a tenant or a real tool.
"""
import asyncio
import json
import logging
import re
import subprocess
import sys
import threading
from pathlib import Path

import keyring
import pytest
from click.testing import CliRunner
from textual.widgets import Button, Checkbox

from orbit import cli
from orbit.config import FIXTURES_DIR
from orbit.core import config_store, executables, hash_checker, headless, history, pipeline, runner
from orbit.core.executables import Executable, ExecutableError
from orbit.core.hash_checker import HashResult, HashStatus, hash_tree, verify_tool
from orbit.core.outputs import OutputConfig, make_run_folder
from orbit.core.platform_check import PlatformInfo, compat_flags
from orbit.core.runner import Runner, RunStatus, prepare_run
from orbit.core.tools import base, get_tool
from orbit.core.tools.discovery import DiscoveryError, Installation
from orbit.core.tools.roadtools import REAL_RUN_BLOCK, ROADtools
from orbit.core.workspace import Workspace
from orbit.reporting import exec_summary
from orbit.reporting.parser import Finding
from orbit.tui.app import OrbitApp
from orbit.tui.screens import home, installer, preflight
from orbit.tui.screens import run as run_screen
from orbit.tui.state import SessionState

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture()
def app(tmp_path, monkeypatch):
    monkeypatch.setattr("orbit.tui.screens.onboarding.has_saved_credentials", lambda: True)
    app = OrbitApp(dry_run=False)
    app.state.output.base_dir = tmp_path / "out"
    app.state.output.formats = set()
    return app


async def _until(pilot, condition):
    for _ in range(200):
        await pilot.pause(0.05)
        if condition():
            return
    raise AssertionError("timed out")


def _text(screen, selector):
    return str(screen.query_one(selector).render())


# --- 4. installer output ------------------------------------------------------

CONFIG_SECRET = "SYNTH-config-file-password-71f3"
QUERY_SECRET = "SYNTH-query-signature-9a2c"
SIGNED_SECRET = "SYNTH-signed-url-5e8d"
CERT_SECRET = "SYNTH-client-cert-passphrase-c04b"
DIAG_MARKER = "raw-child-diagnostic"
SECRETS = (CONFIG_SECRET, QUERY_SECRET, SIGNED_SECRET, CERT_SECRET)

NOISY_PIP = """\
import base64, os, sys
config = open(os.environ['PIP_CONFIG_FILE']).read()
found = [config, os.environ['PIP_INDEX_URL'], os.environ['PIP_CLIENT_CERT']]
for text in found:
    print('raw-child-diagnostic', text)
    print('raw-child-diagnostic', base64.b64encode(text.encode()).decode(), file=sys.stderr)
with open(sys.argv[1], 'w') as proof:
    proof.write(f"{len(config)} {os.environ['PIP_LOG']} {os.environ['PIP_NO_CACHE_DIR']}")
sys.exit(int(sys.argv[2]))
"""


@pytest.fixture()
def installer_ui(app, monkeypatch):
    shown = []
    real = installer.InstallerScreen._log

    def record(self, message):
        shown.append(message)
        real(self, message)

    monkeypatch.setattr(installer, "prereq_report", list)
    monkeypatch.setattr(installer.InstallerScreen, "refresh_versions", lambda self: None)
    monkeypatch.setattr(installer.InstallerScreen, "_log", record)
    return shown


@pytest.fixture()
def enterprise(tmp_path, monkeypatch):
    config = tmp_path / "pip.conf"
    config.write_text("[global]\n"
                      f"index-url = https://builder:{CONFIG_SECRET}@pypi.corp.invalid/simple\n"
                      f"find-links = https://wheels.corp.invalid/w?X-Amz-Signature={SIGNED_SECRET}\n")
    monkeypatch.setenv("PIP_CONFIG_FILE", str(config))
    monkeypatch.setenv("PIP_INDEX_URL", f"https://pypi.corp.invalid/simple?sig={QUERY_SECRET}")
    monkeypatch.setenv("PIP_CLIENT_CERT", f"/certs/client.pem#{CERT_SECRET}")
    return config


@pytest.mark.parametrize("rc", [0, 1])
@pytest.mark.parametrize("action", ["uninstall", "install", "update"])
async def test_raw_pip_output_never_reaches_the_ui_or_a_file(
        app, installer_ui, enterprise, tmp_path, tmp_path_factory, monkeypatch, caplog, capfd,
        request, action, rc):
    if action != "uninstall":  # disabled in production; the containment must hold for any pip action
        request.getfixturevalue("roadtools_mechanics")
    caplog.set_level(logging.DEBUG)
    script, proof = tmp_path / "noisy.py", tmp_path / "proof"
    script.write_text(NOISY_PIP)
    argv = [sys.executable, str(script), str(proof), str(rc)]
    method = "uninstall_command" if action == "uninstall" else "install_command"
    monkeypatch.setattr(ROADtools, method, lambda self, *args: argv)
    async with app.run_test(size=(160, 60)) as pilot:
        app.push_screen("installer")
        await pilot.pause()
        app.screen.query_one(f"#{action}-roadtools").press()
        await _until(pilot, lambda: f"exit {rc}" in "".join(installer_ui))
        await pilot.pause()
        rendered = "".join(line.text for line in app.screen.query_one("#log").lines)
        notices = "".join(str(n.message) for n in app._notifications)

    length, log, no_cache = proof.read_text().split()
    assert int(length) == len(enterprise.read_text())  # the child really had the secrets
    assert log == installer.PIP_NO_RECORDS["PIP_LOG"] and no_cache == "1"
    surfaces = "\n".join([*installer_ui, rendered, notices, caplog.text, *capfd.readouterr()])
    for needle in (*SECRETS, DIAG_MARKER, "pypi.corp.invalid", str(script)):
        assert needle not in surfaces
    for path in tmp_path_factory.getbasetemp().rglob("*"):
        # only what this test, or ORBIT during it, wrote
        if path in (enterprise, script) or not path.is_file() or path.is_symlink():
            continue
        if path.is_relative_to(tmp_path) or path.stat().st_mtime >= script.stat().st_mtime:
            content = path.read_bytes()
            assert not any(secret.encode() in content for secret in SECRETS), path


@pytest.mark.parametrize("error", [RuntimeError, FileNotFoundError, OSError, ValueError])
@pytest.mark.parametrize("stage", ["prepare", "execute"])
async def test_installer_exceptions_do_not_carry_secrets_to_the_ui(
        app, installer_ui, monkeypatch, caplog, stage, error):
    message = f"failed for https://pypi.corp.invalid/simple?sig={QUERY_SECRET}"

    def fail(*args, **kwargs):
        raise error(message)

    async def fail_async(*args, **kwargs):
        raise error(message)

    if stage == "prepare":
        monkeypatch.setattr(ROADtools, "uninstall_command", fail)
    else:
        monkeypatch.setattr(ROADtools, "uninstall_command", lambda self: ["never-started"])
        monkeypatch.setattr(installer, "stream_process", fail_async)
    async with app.run_test(size=(160, 60)) as pilot:
        app.push_screen("installer")
        await pilot.pause()
        app.screen.query_one("#uninstall-roadtools").press()
        await _until(pilot, lambda: error.__name__ in "".join(installer_ui))
    assert QUERY_SECRET not in "".join(installer_ui) + caplog.text


async def test_installer_output_is_always_hidden(app, installer_ui):
    async with app.run_test(size=(160, 60)) as pilot:
        app.push_screen("installer")
        await pilot.pause()
        await app.screen._execute([sys.executable, "-c", f"print('{DIAG_MARKER}')"], "generic", {})
    assert DIAG_MARKER not in "".join(installer_ui) and "exit 0 ✓" in installer_ui


async def test_powershell_output_is_withheld_and_gets_no_pip_settings(
        app, installer_ui, enterprise, tmp_path, monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://user:SYNTH-proxy-password@proxy.invalid:8080")
    proof = tmp_path / "proof"
    code = (f"import os; open({str(proof)!r}, 'w').write(str([k for k in os.environ "
            f"if k.startswith('PIP_')])); print({DIAG_MARKER!r}, os.environ['HTTPS_PROXY'])")
    monkeypatch.setattr(base.Tool, "install_command",
                        lambda self, update=False: [sys.executable, "-c", code])
    async with app.run_test(size=(160, 60)) as pilot:
        app.push_screen("installer")
        await pilot.pause()
        app.screen.query_one("#install-maester").press()
        await _until(pilot, lambda: "exit 0 ✓" in installer_ui)
    shown = "".join(installer_ui)
    assert DIAG_MARKER not in shown and proof.read_text() == "[]"
    assert "SYNTH-proxy-password" not in shown and not any(s in shown for s in SECRETS)


async def test_installer_error_text_is_withheld_even_with_known_secrets(
        app, installer_ui, monkeypatch):
    async def fail(*args, **kwargs):
        raise RuntimeError("proxy said SYNTH-known-value and SYNTH-unknown-value")

    monkeypatch.setattr(installer, "stream_process", fail)
    async with app.run_test(size=(160, 60)) as pilot:
        app.push_screen("installer")
        await pilot.pause()
        await app.screen._execute(["pwsh"], "pwsh", {}, secrets=["SYNTH-known-value"])
    shown = "".join(installer_ui)
    assert "RuntimeError" in shown and "SYNTH" not in shown and "proxy said" not in shown


@pytest.fixture()
def pip_python():
    python = executables.base_python().path
    if subprocess.run([python, "-I", "-c", "import pip"], capture_output=True).returncode:
        pytest.skip("pip is not installed in the base interpreter")
    return python


async def test_real_pip_cannot_leak_through_output_or_its_configured_log(
        app, installer_ui, pip_python, tmp_path, monkeypatch, capfd):
    log = tmp_path / "pip.log"
    config = tmp_path / "pip.conf"
    config.write_text(f"[global]\nlog = {log}\n[install]\n"
                      f"find-links = file:///nonexistent/wheels?sig={QUERY_SECRET}\n")
    monkeypatch.setenv("HOME", str(tmp_path / "home"))  # not the developer's pip configuration
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    env = {"PIP_CONFIG_FILE": str(config), "PIP_NO_INDEX": "1",
           "PIP_DISABLE_PIP_VERSION_CHECK": "1"}
    argv = [str(pip_python), "-I", "-m", "pip", "install", "--target", str(tmp_path / "target"),
            "orbit-synthetic-absent-package"]
    async with app.run_test(size=(160, 60)) as pilot:
        app.push_screen("installer")
        await pilot.pause()
        await app.screen._execute(argv, "pip", env, pip=True)
    assert "exit 1 ✗" in installer_ui
    assert QUERY_SECRET not in "".join([*installer_ui, *capfd.readouterr()])
    assert not log.exists()


# --- 5. report state ----------------------------------------------------------

@pytest.fixture()
def outcomes(bound, monkeypatch):
    """outcome(kind) sets how the next real run ends; only fakes are ever started."""
    def outcome(kind):
        async def start(argv, env, on_line, *args, on_start=None, **kwargs):
            if kind == "creation-fails":
                raise PermissionError("cannot execute")
            on_start()
            out = Path(env["ORBIT_OUT_DIR"])
            (out / "maester.json").write_bytes((FIXTURES_DIR / "maester_sample.json").read_bytes())
            return 0

        def prepare(tools, open_store, workspace):
            if kind == "prepare-fails":
                raise PermissionError("store is locked")
            if kind == "blocked":
                return [HashResult(t.name, None, HashStatus.UNVERIFIED) for t in tools], {}, {}
            return [bound(t.name) for t in tools], {}, {}

        def finalize(*args, **kwargs):
            if kind == "finalize-fails":
                raise OSError("disk full")
            return pipeline.finalize(*args, **kwargs)

        monkeypatch.setattr(runner, "stream_process", start)
        monkeypatch.setattr(run_screen, "prepare_run", prepare)
        monkeypatch.setattr(run_screen, "finalize", finalize)
        monkeypatch.setattr(run_screen.notify, "notify_complete", lambda *args: None)

    return outcome


async def test_report_visited_after_a_zero_launch_run_end_to_end(
        app, manifest_file, monkeypatch, tmp_path):
    def absent(self):
        raise DiscoveryError("not installed")

    monkeypatch.setattr(base.Tool, "discover", absent)
    app.state.selected = {"maester"}
    async with app.run_test(size=(120, 60)) as pilot:
        await pilot.pause()
        app.push_screen("run")
        await pilot.pause()
        app.screen.query_one("#start", Button).press()  # a click can miss while layout settles
        await _until(pilot, lambda: "no tools were launched" in _text(app.screen, "#result"))
        await pilot.press("escape")
        await pilot.pause()
        app.screen.query_one("#nav-report", Button).press()
        await _until(pilot, lambda: type(app.screen).__name__ == "ReportScreen")
        await pilot.pause()
        summary = _text(app.screen, "#summary")
        assert "BLOCKED" in summary and "No report" in summary
        assert "Posture" not in summary and "(0/0)" not in summary
        assert app.screen.query_one("#exec-btn", Button).disabled
        assert app.state.run_folder is None and app.state.findings == []
    assert history.read() == []


@pytest.mark.parametrize("kind", ["blocked", "creation-fails", "prepare-fails", "finalize-fails"])
async def test_failed_run_replaces_an_earlier_report_with_a_failure_state(
        app, outcomes, monkeypatch, kind):
    generated = []
    monkeypatch.setattr(exec_summary, "generate_exec_summary", lambda *args: generated.append(args))
    app.state.selected = {"maester"}
    async with app.run_test(size=(120, 60)) as pilot:
        app.push_screen("report")  # visited first, so the cached screen has to follow
        await pilot.pause()
        assert "No run yet" in _text(app.screen, "#summary")
        app.pop_screen()

        outcomes("ok")
        app.push_screen("run")
        await pilot.pause()
        running = app.screen
        running.start_run()
        await _until(pilot, lambda: "Done." in _text(running, "#result") and not running._executing)
        earlier = app.state.run_folder
        assert earlier and app.state.findings
        app.pop_screen()
        app.push_screen("report")
        await pilot.pause()
        assert "Posture" in _text(app.screen, "#summary")
        assert not app.screen.query_one("#exec-btn", Button).disabled
        app.pop_screen()

        outcomes(kind)
        app.push_screen("run")
        await pilot.pause()
        running.start_run()
        await _until(pilot, lambda: not running._executing
                     and ("FAILED" in _text(running, "#result")
                          or "BLOCKED" in _text(running, "#result")))
        app.pop_screen()
        app.push_screen("report")
        await pilot.pause()
        report = app.screen
        summary = _text(report, "#summary")
        assert "No report is available" in summary and "Posture" not in summary
        assert str(earlier) not in summary and report.query_one("#exec-btn", Button).disabled
        report._generate_exec()  # and the handler refuses even if it is reached
        await pilot.pause(0.2)
        assert report.query_one("#exec-btn", Button).disabled
    assert app.state.run_folder is None and app.state.findings == [] and generated == []
    assert len(history.read()) == 1  # the successful run only


async def test_nothing_is_published_until_finalisation_succeeds(app, outcomes, monkeypatch):
    outcomes("ok")
    seen = []

    def observe(*args, **kwargs):
        seen.append((app.state.run_folder, list(app.state.findings), app.state.run_notice))
        return pipeline.finalize(*args, **kwargs)

    monkeypatch.setattr(run_screen, "finalize", observe)
    app.state.selected = {"maester"}
    app.state.run_folder = Path("earlier-run")
    app.state.findings = [Finding("id", "Maester", "High", "old", "d", "c", "r")]
    async with app.run_test(size=(120, 60)) as pilot:
        app.push_screen("run")
        await pilot.pause()
        app.screen.start_run()
        await _until(pilot, lambda: "Done." in _text(app.screen, "#result"))
    assert seen == [(None, [], run_screen._IN_PROGRESS)]
    assert app.state.run_folder.is_dir() and app.state.findings and app.state.run_notice == ""


async def test_report_after_a_run_stopped_before_launch(app, monkeypatch):
    entered, release = threading.Event(), threading.Event()

    def slow(*args):
        entered.set()
        release.wait(5)
        return [], {}, {}

    monkeypatch.setattr(run_screen, "prepare_run", slow)
    app.state.selected = {"maester"}
    app.state.run_folder = Path("earlier-run")
    async with app.run_test(size=(120, 60)) as pilot:
        app.push_screen("run")
        await pilot.pause()
        screen = app.screen
        screen.start_run()
        await _until(pilot, entered.is_set)
        screen.query_one("#stop-all").press()
        await _until(pilot, lambda: screen._executing is None)
        release.set()
        app.push_screen("report")
        await pilot.pause()
        assert "stopped" in _text(app.screen, "#summary")
        assert app.screen.query_one("#exec-btn", Button).disabled
    assert app.state.run_folder is None


def test_history_records_only_a_finalised_report(tmp_path, monkeypatch):
    def fail(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(pipeline, "package", fail)
    with pytest.raises(OSError):
        pipeline.finalize(make_run_folder(tmp_path), ["Maester"],
                          OutputConfig(tmp_path, formats=set()), False)
    assert history.read() == []


# --- 6. pre-flight binding ----------------------------------------------------

class EmptyStore:
    def __init__(self, *args):
        pass

    def load(self, name):
        return {}


@pytest.fixture()
def ready(tmp_path, manifest_file, private_tmp, monkeypatch):
    root = (tmp_path / "install").resolve()
    root.mkdir()
    (root / "Maester.psd1").write_text("verified")
    exe = (tmp_path / "interpreter").resolve()
    exe.write_text("fake")
    exe.chmod(0o755)
    inst = Installation("2.0", root, root / "Maester.psd1", Executable.capture(exe))
    monkeypatch.setattr(base.Tool, "discover", lambda self: inst)
    manifest_file("maester", "2.0", hash_tree(root))
    monkeypatch.setattr(preflight, "SecretStore", EmptyStore)
    monkeypatch.setattr(preflight, "check_platform",
                        lambda: PlatformInfo("macos", None, (7, 4), compat_flags("macos", True)))

    def check():
        state = SessionState(selected={"maester"})
        state.output.base_dir = tmp_path / "out"
        rows = preflight.run_preflight(state)
        return next((ok, detail) for ok, label, detail in rows if label.endswith("integrity"))

    check.root = root
    return check


@pytest.mark.parametrize("mutation", ["sibling-module", "search-path-file", "snapshot-edit",
                                      "executable", "private-dir"])
def test_preflight_blocks_on_whatever_launch_would_block_on(
        ready, private_tmp, monkeypatch, mutation):
    def verify_then_mutate(tool, workspace):
        result = verify_tool(tool, workspace)
        b = result.binding
        for path in [b.search_path, *b.search_path.rglob("*")]:
            path.chmod(0o700)
        if mutation == "sibling-module":
            (b.search_path / "Pester").mkdir()
            (b.search_path / "Pester" / "Pester.psd1").write_text("planted")
        elif mutation == "search-path-file":
            (b.search_path / "planted.psm1").write_text("planted")
        elif mutation == "snapshot-edit":
            b.entry.write_text("edited")
        elif mutation == "executable":
            b.executable.path.write_text("swapped")
        else:
            (b.private_dir / "planted").write_text("planted")
        return result

    monkeypatch.setattr(preflight, "verify_tool", verify_then_mutate)
    ok, detail = ready()
    assert ok is False and "BLOCKED" in detail and "re-check failed" in detail
    assert list(private_tmp.iterdir()) == []


def test_preflight_calls_the_complete_verification(ready, monkeypatch):
    calls, real = [], hash_checker.Binding.verify
    monkeypatch.setattr(hash_checker.Binding, "verify", lambda self: calls.append(1) or real(self))
    assert ready()[0] is True and calls == [1]


@pytest.mark.parametrize("ending", [None, ValueError, KeyboardInterrupt, asyncio.CancelledError])
def test_preflight_releases_the_binding_however_it_ends(ready, monkeypatch, tmp_path, ending):
    def verify(self):
        if ending:
            raise ending("ended")

    monkeypatch.setattr(hash_checker.Binding, "verify", verify)
    tool = get_tool("maester")
    with Workspace() as workspace:
        check = verify_tool(tool, workspace)
        try:
            preflight._launch_problem(tool, check, tmp_path / "out")
        except (KeyboardInterrupt, asyncio.CancelledError):
            assert ending in (KeyboardInterrupt, asyncio.CancelledError)
        assert not check.binding.slot.exists()  # at once, not only when the workspace closes


def test_preflight_release_failure_is_not_ready(ready, monkeypatch):
    monkeypatch.setattr(hash_checker.Binding, "release", lambda self: False)
    ok, detail = ready()
    assert ok is False and "could not be removed" in detail


async def test_cancelled_preflight_still_releases(app, ready, private_tmp, monkeypatch):
    entered, release, real = threading.Event(), threading.Event(), hash_checker.Binding.verify

    def slow(self):
        entered.set()
        release.wait(5)
        real(self)

    monkeypatch.setattr(hash_checker.Binding, "verify", slow)
    app.state.selected = {"maester"}
    async with app.run_test(size=(120, 60)) as pilot:
        app.push_screen("preflight")
        await _until(pilot, entered.is_set)
        app.screen.workers.cancel_all()
        release.set()
        await _until(pilot, lambda: not list(private_tmp.iterdir()))


def test_preflight_is_advisory_and_launch_checks_again(ready, tmp_path):
    assert ready()[0] is True
    (ready.root / "Maester.psd1").write_text("changed since pre-flight")
    with Workspace() as workspace:
        results, _, _ = prepare_run([get_tool("maester")], EmptyStore, workspace)
        runs = asyncio.run(Runner(tmp_path / "run", {}, hash_results=results).run_all(
            [get_tool("maester")]))
    assert runs["maester"].status is RunStatus.SKIPPED and not runs["maester"].launched


# --- 7. ROADtools ---------------------------------------------------------------

@pytest.fixture()
def forbidden(monkeypatch):
    """Everything a blocked real run must not reach. Records, as some callers swallow errors."""
    calls = []

    def wire(owner, name):
        def tripped(*args, **kwargs):
            calls.append(name)
            raise AssertionError(f"reached {name}")
        monkeypatch.setattr(owner, name, tripped)

    for module in (headless, run_screen, preflight):
        wire(module, "SecretStore")
    for name in ("get_keyring", "get_password"):
        wire(keyring, name)
    wire(subprocess, "Popen")
    wire(subprocess, "run")
    wire(asyncio, "create_subprocess_exec")
    wire(base.Tool, "discover")
    return calls


def test_headless_roadtools_blocks_before_credentials_or_processes(forbidden, tmp_path, caplog):
    config_store.update("output", directory=str(tmp_path / "out"))
    payload, code = headless.run_headless(False, ["roadtools"])
    assert code == 1 and payload["blocked_tools"] == {"roadtools": "real run disabled"}
    assert REAL_RUN_BLOCK in caplog.text and "plaintext tokens" in REAL_RUN_BLOCK
    assert forbidden == [] and history.read() == []
    assert "output_dir" not in payload
    (folder,) = (tmp_path / "out").iterdir()
    assert list(folder.iterdir()) == []


async def test_tui_roadtools_blocks_before_credentials_or_processes(app, forbidden, monkeypatch):
    # the home dashboard probes pwsh and the other tools; only the ROADtools run is under test
    monkeypatch.setattr(home, "check_platform",
                        lambda: PlatformInfo("macos", None, None, compat_flags("macos", False)))
    app.state.selected = {"roadtools"}
    async with app.run_test(size=(160, 60)) as pilot:
        await pilot.pause()
        app.push_screen("run")
        await pilot.pause()
        screen = app.screen
        screen.start_run()
        await _until(pilot, lambda: "BLOCKED" in _text(screen, "#result"))
        run = app.state.runs["roadtools"]
        assert run.status is RunStatus.SKIPPED and not run.launched
        assert run.note == "real run disabled" and REAL_RUN_BLOCK in "".join(run.log)
        assert "real run disabled" in _text(screen, "#status-roadtools")
        assert forbidden == []
        app.push_screen("report")
        await pilot.pause()
        assert "No report" in _text(app.screen, "#summary")
        assert app.screen.query_one("#exec-btn", Button).disabled


def test_mixed_run_reads_credentials_only_for_the_other_tool(bound, monkeypatch):
    opened, loaded = [], []

    class Store:
        def load(self, name):
            loaded.append(name)
            return {}

        def secret_values(self, name):
            loaded.append(name)
            return []

    real = runner.verify_tool
    monkeypatch.setattr(runner, "verify_tool",
                        lambda t, ws: bound(t.name) if t.name == "maester" else real(t, ws))
    with Workspace() as workspace:
        results, creds, _ = prepare_run([get_tool("roadtools"), get_tool("maester")],
                                        lambda: opened.append(1) or Store(), workspace)
    assert opened == [1] and set(loaded) == {"maester"} and list(creds) == ["maester"]
    assert results[0].blocks_run and results[0].binding is None


async def test_runner_blocks_even_with_a_verified_binding(tmp_path, bound, forbidden):
    result = bound("roadtools")
    run = await Runner(tmp_path / "run", {}, hash_results=[result]).run_tool(get_tool("roadtools"))
    assert run.status is RunStatus.SKIPPED and run.note == "real run disabled" and not run.launched
    assert forbidden == [] and not result.binding.slot.exists()
    assert not (tmp_path / "run").exists()


def test_a_valid_baseline_does_not_enable_roadtools(tmp_path, manifest_file, monkeypatch):
    root = tmp_path / "install"
    root.mkdir()
    (root / "module").write_text("x")
    monkeypatch.setattr(base.Tool, "discover", lambda self: Installation("1", root))
    manifest_file("roadtools", "1", hash_tree(root))
    assert verify_tool(get_tool("roadtools")).status is HashStatus.OK
    with Workspace() as workspace:
        result = verify_tool(get_tool("roadtools"), workspace)
    assert result.blocks_run and result.binding is None and result.reason == REAL_RUN_BLOCK


def test_adapter_refuses_to_build_a_launch_or_install(tmp_path, bound):
    tool, binding = get_tool("roadtools"), bound("roadtools").binding
    for build in (lambda: tool.launch_spec({}, tmp_path, binding),
                  tool.install_command, lambda: tool.install_command(True)):
        with pytest.raises(ExecutableError, match="plaintext tokens"):
            build()


def test_real_command_line_blocks_roadtools(tmp_path):
    import os
    env = {**os.environ, "ORBIT_HOME": str(tmp_path / "home"), "PATH": str(tmp_path)}
    proc = subprocess.run([sys.executable, str(ROOT / "orbit.py"), "--headless", "--tools", "roadtools"],
                          cwd=tmp_path, env=env, capture_output=True, text=True, timeout=120)
    assert proc.returncode == 1 and "plaintext tokens" in proc.stderr
    assert json.loads(proc.stdout)["blocked_tools"] == {"roadtools": "real run disabled"}


def test_preflight_blocks_roadtools_without_reading_its_credentials(tmp_path, monkeypatch):
    def unread(*args):
        raise AssertionError("credential store or installation was read")

    monkeypatch.setattr(preflight, "SecretStore", unread)
    monkeypatch.setattr(preflight, "verify_tool", unread)
    monkeypatch.setattr(preflight, "check_platform",
                        lambda: PlatformInfo("macos", None, None, compat_flags("macos", False)))
    state = SessionState(selected={"roadtools"})
    state.output.base_dir = tmp_path
    rows = {label: (ok, detail) for ok, label, detail in preflight.run_preflight(state)}
    ok, detail = rows["ROADtools real run"]
    assert ok is False and "plaintext tokens" in detail
    assert not any("credentials" in label.lower() for label in rows)


async def test_installer_marks_and_refuses_roadtools_install_and_update(app, monkeypatch):
    ran, logged = [], []

    async def never(*args, **kwargs):
        ran.append(args)

    monkeypatch.setattr(installer, "prereq_report", list)
    monkeypatch.setattr(installer, "check_platform",
                        lambda: PlatformInfo("macos", None, None, compat_flags("macos", False)))
    monkeypatch.setattr(base.Tool, "installed_version", lambda self: None)
    monkeypatch.setattr(installer, "stream_process", never)
    monkeypatch.setattr(installer.InstallerScreen, "_log", lambda self, msg: logged.append(msg))
    async with app.run_test(size=(160, 60)) as pilot:
        app.push_screen("installer")
        await pilot.pause()
        screen = app.screen
        await _until(pilot, lambda: "Unsupported" in _text(screen, "#status-roadtools"))
        for action in ("install", "update"):
            button = screen.query_one(f"#{action}-roadtools", Button)
            assert button.disabled
            logged.clear()
            screen.on_button_pressed(Button.Pressed(button))  # and the handler refuses as well
            await _until(pilot, lambda: "plaintext tokens" in "".join(logged))
        assert not screen.query_one("#uninstall-roadtools", Button).disabled
    assert ran == []


async def test_install_all_leaves_roadtools_out(app, installer_ui, monkeypatch):
    requested = []
    monkeypatch.setattr(installer.InstallerScreen, "_run",
                        lambda self, tool, action: requested.append(tool.name))
    async with app.run_test(size=(160, 60)) as pilot:
        app.push_screen("installer")
        await pilot.pause()
        app.screen.query_one("#install-all").press()
        await _until(pilot, lambda: requested)
    assert "roadtools" not in requested and "maester" in requested
    assert "SKIPPED: ROADtools" in "".join(installer_ui)


async def test_roadtools_stays_visible_as_dry_run_only(app):
    async with app.run_test(size=(160, 60)) as pilot:
        app.push_screen("tool_select")
        await pilot.pause()
        assert "dry-run only" in str(app.screen.query_one("#sel-roadtools", Checkbox).label)


def test_list_tools_marks_roadtools_dry_run_only(monkeypatch):
    monkeypatch.setattr(base.Tool, "installed_version", lambda self: None)
    monkeypatch.setattr("orbit.core.platform_check.check_platform",
                        lambda: PlatformInfo("macos", None, None, compat_flags("macos", False)))
    result = CliRunner().invoke(cli.main, ["--list-tools"])
    assert result.exit_code == 0 and "Dry-run only" in result.output


def test_headless_roadtools_dry_run_still_works(forbidden, tmp_path):
    config_store.update("output", directory=str(tmp_path / "out"))
    payload, code = headless.run_headless(True, ["roadtools"])
    assert code == 0 and payload["dry_run"] and payload["blocked_tools"] == {}
    assert forbidden == []


async def test_tui_roadtools_dry_run_still_works(forbidden, tmp_path):
    app = OrbitApp(dry_run=True)
    app.state.output.base_dir = tmp_path / "out"
    app.state.output.formats = set()
    app.state.selected = {"roadtools"}
    async with app.run_test(size=(160, 60)) as pilot:
        app.push_screen("run")
        await pilot.pause()
        screen = app.screen
        screen.start_run()
        await _until(pilot, lambda: "Done." in _text(screen, "#result"))
    assert app.state.runs["roadtools"].status is RunStatus.COMPLETE and forbidden == []


# --- 8. documented limits -------------------------------------------------------

@pytest.mark.parametrize("doc", ["README.md", "docs/INSTALL.md", "docs/AUDIT_REPORT.md"])
def test_documents_state_both_limits(doc):
    text = " ".join((ROOT / doc).read_text(encoding="utf-8").replace("**", "").split())
    assert "cannot defend against a malicious process running as the same OS user" in text
    assert "not proof of authenticity or provenance" in text
    assert "ROADtools production execution is disabled" in text
    assert "memory-only or other non-plaintext authentication design" in text


@pytest.mark.parametrize("doc", ["README.md", "docs/INSTALL.md"])
def test_documents_do_not_offer_roadtools_for_real_use(doc):
    text = (ROOT / doc).read_text(encoding="utf-8")
    assert "pip install roadrecon" not in text
    assert "ROADtools, and Hawk all work" not in text


@pytest.mark.parametrize("doc", ["docs/TOOLS.md", "docs/index.html", "docs/PRIVACY.md"])
def test_public_documents_state_that_roadtools_is_dry_run_only(doc):
    text = re.sub(r"<[^>]+>", "", (ROOT / doc).read_text(encoding="utf-8")).replace("**", "")
    text = " ".join(text.split())
    assert ("ROADtools production execution is disabled pending memory-only or other "
            "non-plaintext authentication") in text
    assert "only fixture-based dry-run is supported" in text


@pytest.mark.parametrize("doc, advert", [
    ("docs/TOOLS.md", "pip install roadrecon"),
    ("docs/TOOLS.md", "ORBIT launches it, collects its output"),
    ("docs/TOOLS.md", "Device-code flow supported"),
    ("docs/TOOLS.md", "integrates five independent"),
    ("docs/TOOLS.md", "| ROADtools | Any user with sign-in capability |"),
    ("docs/TOOLS.md", "| ROADtools | Raw output preserved |"),
    ("docs/index.html", "ROADtools, and Hawk in sequence"),
    ("docs/index.html", '<div class="value-number">5</div>'),
    ("docs/index.html", '<span class="tag tag-py">Python</span>'),
    ("docs/PRIVACY.md", "| PyPI downloads |"),
    ("docs/PRIVACY.md", "reads Entra ID directory data and stores it"),
])
def test_public_documents_do_not_advertise_real_roadtools_use(doc, advert):
    assert advert not in (ROOT / doc).read_text(encoding="utf-8")


def test_tools_guide_has_no_roadtools_install_section():
    text = (ROOT / "docs/TOOLS.md").read_text(encoding="utf-8")
    section = text.split("\n## ROADtools", 1)[1].split("\n## ", 1)[0]
    assert "Install via ORBIT" not in section and "pip install" not in section

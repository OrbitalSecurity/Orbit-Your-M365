"""Regression tests for the stop-before-use boundary: no verified OK result, no launch."""
import asyncio
import base64
import importlib.util
import inspect
import json
import os
import subprocess
import sys
import threading
import venv
from pathlib import Path

import pytest
from baseline_helpers import baseline as make_baseline
from baseline_helpers import document, encode
from baseline_helpers import write as write_baseline

from orbit.core import hash_checker, headless, history, runner
from orbit.core.baseline_schema import BaselineError, ErrorCode
from orbit.core.executables import Executable
from orbit.core.hash_checker import HashResult, HashStatus, check_tool, gate_run, hash_tree
from orbit.core.runner import Runner, RunStatus
from orbit.core.tools import all_tools, base, discovery, get_tool
from orbit.core.tools.discovery import DiscoveryError, Installation
from orbit.core.workspace import Workspace

ROOT = Path(__file__).resolve().parent.parent
OK, BAD, UNKNOWN = HashStatus.OK, HashStatus.MISMATCH, HashStatus.UNVERIFIED
posix_only = pytest.mark.skipif(sys.platform == "win32", reason="needs POSIX links / FIFOs")


def _manifest(files, tool="t", version="1"):
    """A validated schema-2 Baseline for this user; check_tool accepts nothing else."""
    return make_baseline({tool: {version: files}})


@pytest.fixture()
def tree(tmp_path):
    root = tmp_path / "install"
    (root / "sub").mkdir(parents=True)
    (root / "m.psd1").write_text("manifest")
    (root / "sub" / "code.psm1").write_text("code")
    return root


class Spawns(list):
    def __init__(self):
        super().__init__()
        self.modules = []  # content of the module at the moment of each launch


@pytest.fixture()
def spawned(monkeypatch):
    """Record launches; nothing is ever really started."""
    calls = Spawns()

    async def fake(argv, env, on_line, *args, on_start=None, **kwargs):
        calls.append((argv, env))
        if env.get("ORBIT_MODULE"):
            calls.modules.append(Path(env["ORBIT_MODULE"]).read_text())
        if on_start:
            on_start()  # the process was created
        return 0

    monkeypatch.setattr(runner, "stream_process", fake)
    return calls


class FakeStore:
    opened: list
    loaded: list

    def __init__(self, *args, **kwargs):
        self.opened.append(1)

    def load(self, name):
        self.loaded.append(name)
        return {"tenant_id": "not-a-tenant"}

    def secret_values(self, name):
        return []


@pytest.fixture()
def store(monkeypatch):
    FakeStore.opened, FakeStore.loaded = [], []
    monkeypatch.setattr(headless, "SecretStore", FakeStore)
    monkeypatch.setattr("orbit.tui.screens.run.SecretStore", FakeStore)
    return FakeStore


@pytest.fixture()
def installed(tmp_path, monkeypatch):
    """Fake installation of every tool plus a manifest; returns a per-tool state setter."""
    manifest_path = tmp_path / "manifest.json"
    manifest: dict = {}
    write_baseline(manifest_path, manifest)
    monkeypatch.setattr(hash_checker, "manifest_path", lambda: manifest_path)
    roots = {}
    exe = tmp_path / "interpreter"
    exe.write_text("not a real interpreter")
    exe.chmod(0o755)
    pinned = Executable.capture(exe.resolve())
    for tool in all_tools():
        roots[tool.name] = root = tmp_path / "installs" / tool.name
        root.mkdir(parents=True)
        (root / "module.psd1").write_text(tool.name)
    monkeypatch.setattr(base.Tool, "discover",
                        lambda self: Installation("1", roots[self.name],
                                                  roots[self.name] / "module.psd1", pinned))

    def set_state(name, state):
        if state == "unverified":
            return
        manifest[name] = {"1": hash_tree(roots[name])}
        write_baseline(manifest_path, manifest)
        if state == "modified":
            (roots[name] / "module.psd1").write_text("evil")
        elif state == "missing":
            (roots[name] / "module.psd1").unlink()
        elif state == "unexpected":
            (roots[name] / "planted.dll").write_text("evil")

    set_state.roots = roots
    return set_state


@pytest.fixture()
def out(tmp_path):
    from orbit.core import config_store
    folder = tmp_path / "out"
    config_store.update("output", directory=str(folder))
    return folder


# --- gate -------------------------------------------------------------------

@pytest.mark.parametrize("statuses, allowed", [
    ([], False), ([OK], True), ([OK, OK], True), ([BAD], False), ([UNKNOWN], False),
    ([OK, BAD], False), ([UNKNOWN, OK], False), ([None], False), (["passed"], False), (["ok"], False),
])
def test_gate_allows_only_explicit_ok(statuses, allowed):
    results = [HashResult("t", "1", s) for s in statuses]
    assert not any(r.blocks_run for r in results if r.status is OK)
    assert all(r.blocks_run for r in results if r.status is not OK)
    if all(isinstance(s, HashStatus) for s in statuses):  # explain() needs a real status
        assert gate_run(results)[0] is allowed


def test_no_override_parameters_remain():
    from orbit.tui.state import SessionState
    for target in (gate_run, Runner, runner.prepare_run, SessionState):
        assert not any("override" in p for p in inspect.signature(target).parameters)


# --- file set ---------------------------------------------------------------

def test_modified_missing_and_unexpected_reported_together(tree):
    good = hash_tree(tree)
    (tree / "m.psd1").write_text("changed")
    (tree / "sub" / "code.psm1").unlink()
    (tree / "sub" / "new.ps1").write_text("planted")
    r = check_tool("t", "1", tree, _manifest(good))
    assert r.status is BAD and r.blocks_run
    assert (r.mismatches, r.missing, r.unexpected) == (
        ["m.psd1"], ["sub/code.psm1"], ["sub/new.ps1"])
    assert "(unexpected)" in r.explain()


@pytest.mark.parametrize("planted", [".hidden", "sub/deep/x.dll", "__pycache__/m.cpython-312.pyc"])
def test_no_path_is_excluded_from_the_file_set(tree, planted):
    good = hash_tree(tree)
    (tree / planted).parent.mkdir(parents=True, exist_ok=True)
    (tree / planted).write_text("x")
    r = check_tool("t", "1", tree, _manifest(good))
    assert r.status is BAD and r.unexpected == [planted]


def test_hash_tree_is_sorted_and_uppercase_digests_are_not_a_valid_baseline(tree):
    files = hash_tree(tree)
    assert list(files) == sorted(files) == ["m.psd1", "sub/code.psm1"]
    upper = {k: v.upper() for k, v in files.items()}
    with pytest.raises(BaselineError) as bad:  # schema 2 digests are lowercase hex, exactly
        _manifest(upper)
    assert bad.value.code is ErrorCode.ENTRY_MALFORMED


@posix_only
@pytest.mark.parametrize("kind", ["dir-link", "file-link", "dangling-link", "fifo"])
def test_unhashable_entries_are_unverified(tree, tmp_path, kind):
    good = hash_tree(tree)
    if kind == "fifo":
        os.mkfifo(tree / "planted")
    else:
        target = tmp_path / "elsewhere"
        if kind == "dir-link":
            target.mkdir()
        elif kind == "file-link":
            target.write_text("x")
        (tree / "planted").symlink_to(target)
    assert check_tool("t", "1", tree, _manifest(good)).status is UNKNOWN


def test_windows_junction_is_unverified(tree, monkeypatch):
    good = hash_tree(tree)
    real = Path.lstat

    class Junction:
        st_reparse_tag = 0xA0000003

        def __init__(self, info):
            self.st_mode = info.st_mode  # junctions report as ordinary directories

    monkeypatch.setattr(Path, "lstat",
                        lambda self: Junction(real(self)) if self.name == "sub" else real(self))
    assert check_tool("t", "1", tree, _manifest(good)).status is UNKNOWN


def test_unreadable_file_is_unverified(tree, monkeypatch):
    good = hash_tree(tree)

    def denied(path):
        raise PermissionError("denied")

    monkeypatch.setattr(hash_checker, "sha256_file", denied)
    assert check_tool("t", "1", tree, _manifest(good)).status is UNKNOWN


def test_manifest_keys_cannot_reach_outside_the_root(tree, tmp_path):
    outside = tmp_path / "outside"
    outside.write_text("x")
    files = {**hash_tree(tree), "../outside": hash_checker.sha256_file(outside)}
    with pytest.raises(BaselineError) as bad:  # such a key cannot be part of a valid baseline
        _manifest(files)
    assert bad.value.code is ErrorCode.ENTRY_MALFORMED


@pytest.mark.parametrize("raw", [
    {}, {"tools": []}, {"tools": {"t": None}}, [], "text", 7,
    {"schema": 2, "tools": {"t": {"versions": {"1": {"files": {"m.psd1": "00" * 32}}}}}},
])
def test_raw_data_is_never_accepted_as_a_baseline(tree, raw):
    with pytest.raises(TypeError):  # no dict or other raw object reaches the authorisation code
        check_tool("t", "1", tree, raw)


@pytest.mark.parametrize("tools", [
    {"t": {"1": {}}}, {"t": {"1": None}}, {"t": {"1": ["m.psd1"]}}, {"t": {"1": {"m.psd1": 7}}},
    {"t": {"1": "text"}}, {"t": {"": {"m.psd1": "00" * 32}}},
])
def test_a_baseline_with_a_bad_entry_cannot_be_built_or_loaded(tree, tmp_path, monkeypatch, tools):
    doc = document()
    doc["tools"] = {t: {"versions": {v: {"files": f} for v, f in versions.items()}}
                    for t, versions in tools.items()}
    path = tmp_path / "manifest.json"
    path.write_bytes(encode(doc))
    path.chmod(0o600)
    monkeypatch.setattr(hash_checker, "manifest_path", lambda: path)
    result = check_tool("t", "1", tree)  # through the real read path
    assert result.status is UNKNOWN and result.blocks_run


@pytest.mark.parametrize("content", [None, "", "{not json", b"\xff\xfe\x00"])
def test_unreadable_manifest_file_is_unverified(tree, tmp_path, monkeypatch, content):
    path = tmp_path / "manifest.json"
    if content is not None:
        path.write_bytes(content if isinstance(content, bytes) else content.encode())
    monkeypatch.setattr(hash_checker, "manifest_path", lambda: path)
    assert check_tool("t", "1", tree).status is UNKNOWN


def test_unknown_version_or_location_is_unverified(tree):
    manifest = _manifest(hash_tree(tree))
    assert check_tool("t", None, tree, manifest).status is UNKNOWN
    with pytest.raises(BaselineError):  # an empty version key is not a valid entry
        _manifest(hash_tree(tree), version="")
    assert check_tool("t", "1", None, manifest).status is UNKNOWN
    assert check_tool("t", "1", tree / "absent", manifest).status is UNKNOWN


def test_explain_escapes_control_characters_from_file_names():
    r = HashResult("t", "1", BAD, unexpected=["\x1b[2Jspoof"])
    assert "\x1b" not in r.explain()


@pytest.mark.parametrize("error", [DiscoveryError("unsupported"), OSError("io"), RuntimeError("bug")])
def test_discovery_failure_is_unverified(monkeypatch, error):
    def fail(self):
        raise error

    monkeypatch.setattr(base.Tool, "discover", fail)
    r = hash_checker.verify_tool(get_tool("maester"))
    assert r.status is UNKNOWN and r.entry is None and r.reason


# --- runner -----------------------------------------------------------------

@pytest.mark.parametrize("results", [
    None, [], [HashResult("hawk", "1", OK)], [HashResult("maester", "1", BAD)],
    [HashResult("maester", None, UNKNOWN)],
    [HashResult("maester", "1", OK), HashResult("maester", "1", UNKNOWN)],
], ids=["none", "empty", "other-tool-ok", "mismatch", "unverified", "conflicting"])
async def test_runner_never_launches_without_ok(tmp_path, spawned, results):
    run = await Runner(tmp_path, {}, hash_results=results).run_tool(get_tool("maester"))
    assert run.status is RunStatus.SKIPPED and run.started is None
    assert spawned == [] and not (tmp_path / "maester").exists()
    assert run.log[0].startswith("BLOCKED: ")


async def test_runner_launches_the_verified_entry(tmp_path, spawned, bound):
    ok = bound("maester")
    entry = ok.entry
    run = await Runner(tmp_path, {}, hash_results=[ok]).run_tool(get_tool("maester"))
    assert run.status is RunStatus.COMPLETE and spawned[0][1]["ORBIT_MODULE"] == str(entry)


async def test_dry_run_cannot_reach_production_execution(tmp_path, monkeypatch, spawned):
    def forbidden(*args, **kwargs):
        raise AssertionError("production path reached from dry-run")

    for tool in all_tools():
        monkeypatch.setattr(type(tool), "launch_spec", forbidden)
        monkeypatch.setattr(type(tool), "discover", forbidden)
    r = Runner(tmp_path, {"maester": {"client_secret": "s"}}, {"maester": ["s"]}, dry_run=True)
    assert r.creds == {} and r.secrets == {}
    runs = await r.run_all(all_tools())
    assert {x.status for x in runs.values()} == {RunStatus.COMPLETE} and spawned == []


def test_headless_dry_run_needs_no_tools_store_or_manifest(monkeypatch, out, spawned):
    def forbidden(*args, **kwargs):
        raise AssertionError("production path reached from dry-run")

    for name in ("prepare_run", "SecretStore"):
        monkeypatch.setattr(headless, name, forbidden)
    payload, code = headless.run_headless(True, ["maester"])
    assert code == 0 and payload["dry_run"] and spawned == []


# --- headless ---------------------------------------------------------------

@pytest.mark.parametrize("name", [t.name for t in all_tools()])
@pytest.mark.parametrize("state", ["unverified", "modified", "missing", "unexpected"])
def test_headless_fails_closed(installed, out, spawned, store, roadtools_mechanics, name, state):
    installed(name, state)
    payload, code = headless.run_headless(False, [name])
    note = "integrity unverified" if state == "unverified" else "hash mismatch"
    assert code == 1 and payload["blocked_tools"] == {name: note}
    assert spawned == [] and store.opened == []  # no launch and no credential read
    assert history.read() == [] and "output_dir" not in payload and "score" not in payload
    (folder,) = out.iterdir()
    assert list(folder.iterdir()) == []


def test_headless_empty_results_do_not_authorise(monkeypatch, out, spawned):
    monkeypatch.setattr(headless, "prepare_run", lambda *args: ([], {}, {}))
    payload, code = headless.run_headless(False, ["maester"])
    assert code == 1 and payload["failed_tools"] == ["maester"] and spawned == []


def test_headless_launches_only_verified_tools(installed, out, spawned, store, monkeypatch):
    reported = []
    monkeypatch.setattr(headless, "finalize",
                        lambda folder, used, *a, **k: (reported.extend(used) or [], []))
    installed("maester", "ok")
    installed("hawk", "modified")
    payload, code = headless.run_headless(False, ["maester", "hawk"])
    assert code == 1 and payload["blocked_tools"] == {"hawk": "hash mismatch"}
    assert len(spawned) == 1 and store.loaded == ["maester"] and reported == ["Maester"]
    launched = Path(spawned[0][1]["ORBIT_MODULE"])
    assert not launched.is_relative_to(installed.roots["maester"].parent)  # the snapshot
    assert spawned.modules == ["maester"] and not launched.exists()  # and it was cleaned up


# --- TUI --------------------------------------------------------------------

@pytest.fixture()
def real_app(tmp_path, monkeypatch):
    from orbit.tui.app import OrbitApp
    monkeypatch.setattr("orbit.tui.screens.onboarding.has_saved_credentials", lambda: True)
    app = OrbitApp(dry_run=False)
    app.state.output.base_dir = tmp_path / "out"
    app.state.selected = {"maester"}
    return app


async def _until(pilot, condition):
    for _ in range(100):
        await pilot.pause(0.05)
        if condition():
            return
    raise AssertionError("timed out")


@pytest.mark.parametrize("state", ["unverified", "modified", "missing", "unexpected", "empty"])
async def test_tui_fails_closed(real_app, installed, spawned, store, monkeypatch, state):
    after_run = []
    for target in ("finalize", "notify.notify_complete", "RunScreen._email"):
        monkeypatch.setattr(f"orbit.tui.screens.run.{target}", lambda *a, **k: after_run.append(1))
    if state == "empty":
        monkeypatch.setattr("orbit.tui.screens.run.prepare_run", lambda *a: ([], {}, {}))
    else:
        installed("maester", state)
    real_app.state.findings = ["stale finding from an earlier run"]
    async with real_app.run_test(size=(120, 60)) as pilot:
        real_app.push_screen("run")
        await pilot.pause()
        screen = real_app.screen
        assert not screen.query("#override")
        screen.query_one("#email-run").value = True
        screen.start_run()
        await _until(pilot, lambda: "BLOCKED" in str(screen.query_one("#result").render()))
        assert real_app.state.runs["maester"].status is RunStatus.SKIPPED
    assert spawned == [] and store.opened == [] and after_run == []
    assert real_app.state.findings == [] and history.read() == []


async def test_tui_shows_block_reason_on_every_attempt(real_app, installed, spawned, store):
    async with real_app.run_test(size=(120, 60)) as pilot:
        real_app.push_screen("run")
        await pilot.pause()
        screen = real_app.screen
        log = screen.query_one("#log-maester")
        for _ in range(2):
            log.clear()
            log._shown = 7  # as left behind by a longer earlier run
            screen.query_one("#result").update("")
            screen.start_run()
            await _until(pilot, lambda: "BLOCKED" in str(screen.query_one("#result").render()))
            assert log._shown == 1
            await _until(pilot, lambda: any("BLOCKED" in line.text for line in log.lines))


async def test_tui_launches_verified_tool(real_app, installed, spawned, store):
    installed("maester", "ok")
    async with real_app.run_test(size=(120, 60)) as pilot:
        real_app.push_screen("run")
        await pilot.pause()
        screen = real_app.screen
        screen.start_run()
        await _until(pilot, lambda: "Done." in str(screen.query_one("#result").render()))
    assert len(spawned) == 1 and store.loaded == ["maester"]


@pytest.mark.parametrize("button", ["stop-all", "stop-maester"])
async def test_stop_during_verification_prevents_launch(real_app, monkeypatch, spawned, button):
    entered, release = threading.Event(), threading.Event()

    def slow_prepare(*args):
        entered.set()
        release.wait(5)
        return [HashResult("maester", "1", OK)], {}, {}

    monkeypatch.setattr("orbit.tui.screens.run.prepare_run", slow_prepare)
    async with real_app.run_test(size=(120, 60)) as pilot:
        real_app.push_screen("run")
        await pilot.pause()
        screen = real_app.screen
        screen.start_run()
        await _until(pilot, entered.is_set)
        screen.query_one(f"#{button}").press()
        await pilot.pause()
        release.set()
        await pilot.pause(0.3)
        assert screen.runner is None and spawned == []


@pytest.mark.parametrize("dry_run, state, launches", [
    (False, "unverified", False), (False, "unexpected", False), (True, "ok", False),
    (False, "ok", True),
])
async def test_install_opa_is_gated(real_app, installed, monkeypatch, dry_run, state, launches):
    from orbit.tui.screens.installer import InstallerScreen
    ran, logged = [], []

    async def execute(self, argv, label, env, cwd=None, secrets=None, pip=False):
        # PowerShell is given no package-source settings
        assert not pip and not any(key.startswith("PIP_") for key in env)
        ran.append((argv, env, Path(env["ORBIT_MODULE"]).read_text()))

    monkeypatch.setattr(InstallerScreen, "_execute", execute)
    monkeypatch.setattr(InstallerScreen, "_log", lambda self, msg: logged.append(msg))
    installed("scubagear", state)
    real_app.state.dry_run = dry_run
    async with real_app.run_test(size=(120, 60)) as pilot:
        real_app.push_screen("installer")
        await pilot.pause()
        button = real_app.screen.query_one("#install-opa")
        assert button.disabled is dry_run
        if dry_run:
            real_app.screen._install_opa()  # and the handler refuses even if it is reached
        else:
            button.press()
        await _until(pilot, lambda: ran or logged)
    assert bool(ran) is launches
    if launches:
        argv, env, content = ran[0]
        assert "Import-Module ScubaGear" not in argv[-1] and content == "scubagear"
        assert not Path(env["ORBIT_MODULE"]).is_relative_to(installed.roots["scubagear"].parent)
        assert Path(argv[0]).is_absolute() and Path(argv[0]).name == "interpreter"


def test_dry_run_preflight_does_not_probe_installations(tmp_path, monkeypatch):
    from orbit.tui.screens import preflight
    from orbit.tui.state import SessionState

    def forbidden(self):
        raise AssertionError("probed a real installation")

    monkeypatch.setattr(base.Tool, "installed_version", forbidden)
    monkeypatch.setattr(base.Tool, "compatible", lambda self, plat: True)
    state = SessionState(dry_run=True, selected={"maester"})
    state.output.base_dir = tmp_path
    assert preflight.run_preflight(state)


# --- PowerShell discovery and launch (pwsh is faked) -------------------------

FAKE_PWSH = Executable(Path("/fake/pwsh").absolute(), "0" * 64)


@pytest.fixture()
def pwsh(monkeypatch):
    calls = []

    def answer(*modules, rc=0, raw=None):
        lines = [f"ORBIT|{v}|{base64.b64encode(str(p).encode()).decode()}" for v, p in modules]
        text = "\n".join(lines) if raw is None else raw

        def fake(argv, **kwargs):
            calls.append((argv, kwargs))
            return subprocess.CompletedProcess(argv, rc, text, "")

        monkeypatch.setattr(discovery.subprocess, "run", fake)
        return calls

    monkeypatch.setattr(discovery, "resolve_pwsh", lambda: FAKE_PWSH)
    return answer


def _module(tmp_path, where, name="Maester.psd1"):
    path = tmp_path / where / name
    path.parent.mkdir(parents=True)
    path.write_text("x")
    return path


def test_ps_discovery_pins_highest_version(tmp_path, pwsh):
    old, new = _module(tmp_path, "a/1.9.0"), _module(tmp_path, "b/1.10.0")
    calls = pwsh(("1.9.0", old), ("1.10.0", new), ("1.10.0", new))
    assert discovery.find_ps_module("Maester") == Installation(
        "1.10.0", new.parent.resolve(), new.resolve(), FAKE_PWSH)
    assert calls[0][0][0] == str(FAKE_PWSH.path)
    script = calls[0][0][-1]
    assert "Import-Module" not in script and "Sort-Object" not in script
    assert "$PSModuleAutoLoadingPreference = 'None'" in script
    assert "{{" not in script and "}}" not in script
    assert "PSMODULEPATH" not in calls[0][1]["env"]


def test_ps_discovery_rejects_ambiguous_install(tmp_path, pwsh):
    pwsh(("1", _module(tmp_path, "a")), ("1", _module(tmp_path, "b")))
    with pytest.raises(DiscoveryError, match="more than one"):
        discovery.find_ps_module("Maester")


@pytest.mark.parametrize("where, name", [("a", "Maester.psm1"), ("a[1]", "Maester.psd1")])
def test_ps_discovery_rejects_unpinnable_paths(tmp_path, pwsh, where, name):
    pwsh(("1", _module(tmp_path, where, name)))
    with pytest.raises(DiscoveryError):
        discovery.find_ps_module("Maester")


@pytest.mark.parametrize("rc, raw", [
    (0, ""), (1, ""), (0, "banner only"), (0, "ORBIT|broken"), (0, "ORBIT|1|%%%"),
    (0, "ORBIT|1|" + base64.b64encode(b"/does/not/exist/Maester.psd1").decode()),
])
def test_ps_discovery_failures(pwsh, rc, raw):
    pwsh(rc=rc, raw=raw)
    with pytest.raises(DiscoveryError):
        discovery.find_ps_module("Maester")


def test_ps_discovery_without_pwsh(monkeypatch, tmp_path):
    monkeypatch.setenv("PATH", str(tmp_path))
    with pytest.raises(DiscoveryError, match="pwsh"):
        discovery.find_ps_module("Maester")


@pytest.mark.parametrize("os_name", ["macos", "linux", "other"])
def test_unsupported_platform_is_unverified(monkeypatch, os_name):
    monkeypatch.setattr(base, "detect_os", lambda: os_name)
    r = hash_checker.verify_tool(get_tool("scubagear"))
    assert r.status is UNKNOWN and "unsupported" in r.reason


@pytest.mark.parametrize("name", ["scubagear", "maester", "monkey365", "hawk"])
def test_ps_launch_imports_only_the_verified_path(tmp_path, bound, name):
    tool = get_tool(name)
    binding = bound(name).binding
    entry = binding.entry
    spec = tool.launch_spec({}, tmp_path, binding)
    assert spec.argv[0] == str(binding.executable.path)
    script = spec.argv[-1]
    assert script.startswith(base.IMPORT_VERIFIED) and script.count("Import-Module") == 1
    assert "exit 1" in base.IMPORT_VERIFIED and spec.env["ORBIT_MODULE"] == str(entry)


# --- ROADtools: real interpreter, fake package --------------------------------

@pytest.fixture()
def fake_roadtools(tmp_path, monkeypatch, roadtools_mechanics):
    env_dir = tmp_path / "venv"
    venv.EnvBuilder(with_pip=False, symlinks=sys.platform != "win32").create(env_dir)
    if sys.platform == "win32":
        python, site = env_dir / "Scripts" / "python.exe", env_dir / "Lib" / "site-packages"
    else:
        python, site = env_dir / "bin" / "python", next(env_dir.glob("lib/python*/site-packages"))
    package = site / "roadtools" / "roadrecon"
    package.mkdir(parents=True)
    executed = tmp_path / "executed"
    (package / "__init__.py").write_text(f"open({str(executed)!r}, 'a').write('x')\n")
    (package / "main.py").write_text("def main():\n    print('fake roadrecon')\n")
    meta = site / "roadrecon-9.9.dist-info"
    meta.mkdir()
    (meta / "METADATA").write_text("Metadata-Version: 2.1\nName: roadrecon\nVersion: 9.9\n")
    (meta / "RECORD").write_text("roadtools/roadrecon/main.py,,\nroadrecon-9.9.dist-info/RECORD,,\n")
    monkeypatch.setattr(sys, "executable", str(python))
    monkeypatch.setattr(discovery, "site_dir", site.resolve)
    manifest = tmp_path / "manifest.json"
    manifest.write_text("{}")
    monkeypatch.setattr(hash_checker, "manifest_path", lambda: manifest)
    return site / "roadtools", executed, manifest


def _roadtools_baseline(manifest):
    inst = get_tool("roadtools").discover()
    files = hash_tree(inst.root, inst.members, inst.strict_member)
    write_baseline(manifest, {"roadtools": {"9.9": files}})


def test_roadtools_discovery_does_not_execute_the_package(fake_roadtools):
    root, executed, _ = fake_roadtools
    (root / "__init__.py").write_text(f"open({str(executed)!r}, 'a').write('x')\n")
    inst = get_tool("roadtools").discover()
    assert (inst.version, inst.root) == ("9.9", root.parent.resolve())
    assert inst.members == ("roadrecon-9.9.dist-info", "roadtools")
    assert not executed.exists()


def test_roadtools_end_to_end_through_headless(fake_roadtools, out, store):
    root, executed, manifest = fake_roadtools
    assert headless.run_headless(False, ["roadtools"])[1] == 1  # no baseline
    assert not executed.exists()

    _roadtools_baseline(manifest)
    assert headless.run_headless(False, ["roadtools"])[1] == 0
    assert executed.exists()
    # the run wrote no bytecode into the install, so it still verifies
    assert hash_checker.verify_tool(get_tool("roadtools")).status is OK

    executed.unlink()
    (root / "roadrecon" / "planted.py").write_text("evil")
    payload, code = headless.run_headless(False, ["roadtools"])
    assert code == 1 and payload["blocked_tools"] == {"roadtools": "hash mismatch"}
    assert not executed.exists()


def test_roadtools_launch_cannot_be_shadowed(fake_roadtools, tmp_path, monkeypatch):
    work = tmp_path / "work"
    work.mkdir()
    planted = tmp_path / "shadowed"
    (work / "roadtools.py").write_text(f"open({str(planted)!r}, 'w').write('x')\n")
    monkeypatch.setenv("PYTHONPATH", str(work))
    _roadtools_baseline(fake_roadtools[2])
    with Workspace() as workspace:
        binding = hash_checker.verify_tool(get_tool("roadtools"), workspace).binding
        spec = get_tool("roadtools").launch_spec({}, work, binding)
        lines = []
        # started from the hostile directory, which is the stronger condition
        rc = asyncio.run(runner.stream_process(spec.argv, spec.env, lines.append, cwd=work))
    assert rc == 0, lines
    assert not planted.exists()


# --- baseline generator -------------------------------------------------------

@pytest.fixture()
def generator(tmp_path, monkeypatch, installed):
    from orbit.core import baseline
    monkeypatch.setattr(hash_checker, "manifest_path", lambda: tmp_path / "manifest.json")
    return baseline


def test_generated_baseline_satisfies_the_gate(generator):
    generator.main()
    assert all(not hash_checker.verify_tool(t).blocks_run for t in all_tools())


def test_generator_cannot_rebless_a_failed_result(generator, installed):
    generator.main()
    (installed.roots["hawk"] / "planted.ps1").write_text("evil")
    with pytest.raises(SystemExit) as stopped:
        generator.main()
    assert stopped.value.code == 1
    assert hash_checker.verify_tool(get_tool("hawk")).status is BAD

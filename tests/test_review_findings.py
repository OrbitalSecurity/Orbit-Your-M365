"""Fourth pass: Windows extraction, installer diagnostics, zero-launch payload, executable checks.

Windows is simulated without links, junctions or races. Every credential is synthetic, and the
only processes started are fakes.
"""
import errno
import importlib.util
import io
import json
import os
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest
from click.testing import CliRunner

from orbit import cli
from orbit.config import FIXTURES_DIR
from orbit.core import config_store, executables, headless, history, process_env, runner, safe_dir
from orbit.core.executables import Executable, ExecutableError
from orbit.core.hash_checker import HashResult, HashStatus, hash_tree, verify_tool
from orbit.core.platform_check import PlatformInfo, compat_flags
from orbit.core.secrets import redact
from orbit.core.tools import base, get_tool
from orbit.core.tools.discovery import Installation
from orbit.security import encryption
from orbit.security.encryption import DecryptionError, decrypt_archive, encrypt_bytes
from orbit.tui.app import OrbitApp
from orbit.tui.screens import installer, preflight
from orbit.tui.state import SessionState

FAST = 1000
posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX modes, sessions or fake pwsh")


# --- 1. Windows extraction boundary -------------------------------------------

@pytest.fixture()
def windows(monkeypatch):
    monkeypatch.setattr(safe_dir.sys, "platform", "win32")
    monkeypatch.setattr(safe_dir, "_FD_RELATIVE", False)


def _tree(root):
    return {p.relative_to(root).as_posix(): p.read_bytes() if p.is_file() else None
            for p in root.rglob("*")}


@pytest.mark.parametrize("members", [["file"], ["dir/file"], ["empty/"], []],
                         ids=["file", "tree", "directory", "no-members"])
@pytest.mark.parametrize("below", ["present", "present/out", "absent/deeper/out"])
def test_windows_extraction_fails_before_any_file_system_operation(
        tmp_path, windows, monkeypatch, members, below):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name in members:
            zf.writestr(name, b"payload")
    archive = tmp_path / "a.orbit.zip"
    archive.write_bytes(encrypt_bytes(buf.getvalue(), "pw", iterations=FAST))
    (tmp_path / "present").mkdir()
    before, reached = _tree(tmp_path), []

    def wire(patch, owner, name):
        real = getattr(owner, name)
        patch.setattr(owner, name, lambda *a, **k: reached.append(name) or real(*a, **k))

    # with no operation at all, there is no check-to-use window for a junction to land in
    with monkeypatch.context() as patch:
        for name in ("lstat", "mkdir", "open", "rename", "replace", "link", "unlink", "rmdir"):
            wire(patch, os, name)
        wire(patch, encryption, "create_file")
        with pytest.raises(DecryptionError, match="not supported on Windows"):
            decrypt_archive(archive, "pw", tmp_path / below, iterations=FAST)
    assert reached == [] and _tree(tmp_path) == before


def test_a_windows_import_of_the_module_selects_the_refusal(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location("safe_dir_as_windows", safe_dir.__file__)
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setattr(sys, "platform", "win32")
    spec.loader.exec_module(module)  # the real platform test, not a patched flag
    with pytest.raises(module.UnsafePathError, match="not supported on Windows"):
        module.open_directory(tmp_path / "out")
    assert not (tmp_path / "out").exists()


@pytest.mark.parametrize("operation", ["at", "lstat", "has", "child", "make", "names"])
def test_an_unpinned_directory_never_falls_back_to_a_path(tmp_path, monkeypatch, operation):
    checked, elsewhere = tmp_path / "checked", tmp_path / "elsewhere"
    for root in (checked, elsewhere):
        (root / "entry").mkdir(parents=True)
    monkeypatch.chdir(elsewhere)  # dir_fd=None would mean this directory
    unpinned = safe_dir.Directory(checked, checked.lstat(), None)
    name = "new" if operation == "make" else "entry"
    with pytest.raises(safe_dir.UnsafePathError, match="not pinned"):
        getattr(unpinned, operation)(*([] if operation == "names" else [name]))
    assert not unpinned.remove("entry", (checked / "entry").lstat())
    for root in (checked, elsewhere):
        assert [p.name for p in root.iterdir()] == ["entry"]


@posix_only
def test_a_closed_directory_cannot_be_used_by_path(tmp_path):
    directory = safe_dir.open_directory(tmp_path)
    directory.close()
    with pytest.raises(safe_dir.UnsafePathError, match="not pinned"):
        directory.make("new")
    assert not (tmp_path / "new").exists()


@pytest.mark.parametrize("publish", ["file", "directory"])
def test_publication_from_an_unpinned_directory_fails_closed(tmp_path, monkeypatch, publish):
    (tmp_path / "entry").write_text("staged")
    unpinned = safe_dir.Directory(tmp_path, tmp_path.lstat(), None)
    for name in ("link", "rename", "replace"):
        monkeypatch.setattr(os, name, lambda *a, **k: pytest.fail("published by pathname"))
    with pytest.raises((safe_dir.UnsafePathError, OSError)) as stopped:
        if publish == "file":
            encryption._publish_file(unpinned, unpinned, "entry", lambda: b"staged")
        else:
            safe_dir.move_new(unpinned, unpinned, "entry")
    if isinstance(stopped.value, OSError):
        assert stopped.value.errno == errno.ENOTSUP


# --- 2. installer diagnostics -------------------------------------------------

REPOSITORY_SECRET = "SYNTH-repository-credential-4d17"


@pytest.fixture()
def installer_log(monkeypatch):
    shown, real = [], installer.InstallerScreen._log

    def record(self, message):
        shown.append(message)
        real(self, message)

    monkeypatch.setattr(installer, "prereq_report", list)
    monkeypatch.setattr(installer.InstallerScreen, "refresh_versions", lambda self: None)
    monkeypatch.setattr(installer.InstallerScreen, "_log", record)
    monkeypatch.setattr("orbit.tui.screens.onboarding.has_saved_credentials", lambda: True)
    return shown


@pytest.fixture()
def repository_pwsh(tmp_path, monkeypatch):
    """A fake pwsh that loads a credential from its own repository file and prints it everywhere."""
    config, proof = tmp_path / "repositories.xml", tmp_path / "proof.json"
    config.write_text(f'<Repository Url="https://feed.invalid/v3?sig={REPOSITORY_SECRET}" />')

    def make(rc=0):
        exe = tmp_path / "bin" / "pwsh"
        exe.parent.mkdir()
        exe.write_text(
            f"#!{executables.base_python().path} -IS\n"
            "import json, os, sys\n"
            "if 'PSVersionTable.PSVersion' in sys.argv[-1]:\n"
            "    print('PWSH|7.4.1')\n"
            "    sys.exit(0)\n"
            f"found = open({str(config)!r}).read()\n"
            "try:\n"
            "    open('/dev/tty', 'w').close()\n"
            "    terminal = True\n"
            "except OSError:\n"
            "    terminal = False\n"
            f"with open({str(proof)!r}, 'w') as out:\n"
            "    json.dump({'argv': sys.argv, 'loaded': len(found), 'terminal': terminal,\n"
            "               'own_session': os.getsid(0) == os.getpid()}, out)\n"
            "print('repository-diagnostic', found)\n"
            "print('Install-Package: exception', found, file=sys.stderr)\n"
            f"sys.exit({rc})\n")
        exe.chmod(0o755)
        monkeypatch.setenv("PATH", str(exe.parent))
        # the premise: nothing that environment-based redaction knows can remove this secret
        assert not any(REPOSITORY_SECRET in value for value in os.environ.values())
        assert REPOSITORY_SECRET in redact(config.read_text(), process_env.url_credentials())
        return exe.resolve()

    make.config, make.proof = config, proof
    return make


@posix_only
@pytest.mark.parametrize("rc", [0, 1])
@pytest.mark.parametrize("action", ["install", "update", "uninstall", "opa"])
async def test_powershell_repository_secret_never_leaves_the_child(
        tmp_path, installer_log, repository_pwsh, manifest_file, private_tmp, monkeypatch,
        caplog, capfd, action, rc):
    caplog.set_level("DEBUG")
    exe = repository_pwsh(rc)
    if action == "opa":
        root = (tmp_path / "ScubaGear").resolve()
        root.mkdir()
        (root / "ScubaGear.psd1").write_text("verified")
        manifest_file("scubagear", "1.0", hash_tree(root))
        inst = Installation("1.0", root, root / "ScubaGear.psd1", Executable.capture(exe))
        monkeypatch.setattr(base.Tool, "discover", lambda self: inst)
    app = OrbitApp(dry_run=False)
    async with app.run_test(size=(160, 60)) as pilot:
        app.push_screen("installer")
        await pilot.pause()
        button = "install-opa" if action == "opa" else f"{action}-maester"
        app.screen.query_one(f"#{button}").press()
        for _ in range(200):
            await pilot.pause(0.05)
            if any(line.startswith(f"exit {rc}") for line in installer_log):
                break
        else:
            raise AssertionError(installer_log)
        await pilot.pause()
        rendered = "".join(line.text for line in app.screen.query_one("#log").lines)
        notices = "".join(str(n.message) for n in app._notifications)

    proof = json.loads(repository_pwsh.proof.read_text())
    assert proof["loaded"] == len(repository_pwsh.config.read_text())  # it really had the secret
    assert proof["own_session"] and not proof["terminal"]  # no way round the withheld streams
    assert "-NonInteractive" in proof["argv"]  # a prompt nobody can see must fail, not wait
    surfaces = "\n".join([*installer_log, rendered, notices, caplog.text, *capfd.readouterr()])
    for needle in (REPOSITORY_SECRET, "feed.invalid", "repository-diagnostic", "Install-Package"):
        assert needle not in surfaces
    for root in (tmp_path, private_tmp, Path(os.environ["ORBIT_HOME"])):
        for path in root.rglob("*"):
            if path.is_file() and path != repository_pwsh.config:
                assert REPOSITORY_SECRET.encode() not in path.read_bytes(), path


@pytest.mark.parametrize("error", [RuntimeError, FileNotFoundError])
@pytest.mark.parametrize("stage", ["prepare", "execute", "opa-recheck"])
async def test_powershell_exception_text_is_withheld(
        installer_log, bound, monkeypatch, stage, error):
    def fail(*args, **kwargs):
        raise error(f"repository said {REPOSITORY_SECRET}")

    async def fail_async(*args, **kwargs):
        fail()

    monkeypatch.setattr(base.Tool, "install_command", lambda self, update=False: ["never-started"])
    monkeypatch.setattr(installer, "stream_process", fail_async)
    if stage == "prepare":
        monkeypatch.setattr(base.Tool, "install_command", fail)
    elif stage == "opa-recheck":
        result = bound("scubagear")
        monkeypatch.setattr(installer, "verify_tool", lambda tool, workspace: result)
        monkeypatch.setattr(type(result.binding), "verify", fail)
    app = OrbitApp(dry_run=False)
    async with app.run_test(size=(160, 60)) as pilot:
        app.push_screen("installer")
        await pilot.pause()
        button = "install-opa" if stage == "opa-recheck" else "install-maester"
        app.screen.query_one(f"#{button}").press()
        for _ in range(100):
            await pilot.pause(0.05)
            if error.__name__ in "".join(installer_log) or REPOSITORY_SECRET in "".join(installer_log):
                break
    shown = "".join(installer_log)
    assert error.__name__ in shown and REPOSITORY_SECRET not in shown


@posix_only
def test_find_module_diagnostics_are_not_returned_as_a_version(repository_pwsh, capfd):
    repository_pwsh()
    assert get_tool("maester").latest_version() is None
    proof = json.loads(repository_pwsh.proof.read_text())
    assert proof["own_session"] and "-NonInteractive" in proof["argv"]
    assert REPOSITORY_SECRET not in "".join(capfd.readouterr())


@pytest.mark.parametrize("output, version", [
    ("1.2.3", "1.2.3"), ("2.0", "2.0"), ("", None), (f"1.2.3\n{REPOSITORY_SECRET}", None),
    (f"WARNING: {REPOSITORY_SECRET}\n1.2.3", None), (f"1.2.3-{REPOSITORY_SECRET}", None),
    ("Maester (1.2.3)", None), ("(1.2.3)", None), ("v1.2.3", None), ("1..2", None), ("1", None),
])
def test_find_module_result_is_only_ever_a_version(monkeypatch, output, version):
    exe = Executable(Path("/fake/pwsh").absolute(), "0" * 64)
    monkeypatch.setattr(base, "resolve_pwsh", lambda: exe)
    monkeypatch.setattr(base, "run_capture", lambda *args, **kwargs: output)
    assert get_tool("maester").latest_version() == version


@pytest.mark.parametrize("output", [
    "roadrecon (1.7.0)", "1.7.0", "roadrecon (not-a-version)", "ERROR: no such package (404)",
    f"WARNING: retrying (https://feed.invalid/simple?sig={REPOSITORY_SECRET})",
], ids=["pip-format", "bare", "malformed", "error", "diagnostic"])
@pytest.mark.parametrize("blocked", [True, False], ids=["blocked", "block-lifted"])
def test_pypi_tools_have_no_version_probe(request, monkeypatch, blocked, output):
    if not blocked:  # the absence of a probe must not depend on the block
        request.getfixturevalue("roadtools_mechanics")
    tool = get_tool("roadtools")
    assert bool(tool.real_run_block) is blocked
    reached = []

    def wire(owner, name, result):
        monkeypatch.setattr(owner, name, lambda *a, **k: reached.append(name) or result)

    wire(base, "_pip", ["never-started"])
    wire(base, "run_capture", output)
    wire(base, "resolve_pwsh", None)
    wire(subprocess, "run", None)
    wire(subprocess, "Popen", None)
    assert tool.latest_version() is None and reached == []


async def test_withheld_windows_child_gets_no_console(monkeypatch):
    seen = {}

    class Process:
        returncode = 0

        async def wait(self):
            return 0

    async def create(*argv, **kwargs):
        seen.update(kwargs)
        return Process()

    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(runner.asyncio, "create_subprocess_exec", create)
    assert await runner.stream_process(["pwsh"], {}, None) == 0
    assert seen["creationflags"] == getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
    assert "start_new_session" not in seen
    for stream in ("stdin", "stdout", "stderr"):
        assert seen[stream] is subprocess.DEVNULL


# --- 3. headless zero-launch payload ------------------------------------------

DIAGNOSTICS = ["orbit_version", "timestamp", "dry_run", "failed_tools", "blocked_tools",
               "launch_failures"]
COMPLETED = ["orbit_version", "timestamp", "score", "total_controls", "passed", "critical", "high",
             "medium", "low", "top_findings", "output_dir", "dry_run", "failed_tools",
             "blocked_tools", "launch_failures"]


@pytest.fixture()
def headless_run(tmp_path, bound, monkeypatch):
    out = tmp_path / "out"
    config_store.update("output", directory=str(out))

    def run(outcomes):
        def prepare(tools, open_store, workspace):
            return [bound(t.name) if outcomes[t.name] != "blocked"
                    else HashResult(t.name, "1", HashStatus.MISMATCH, mismatches=["module.psd1"])
                    for t in tools], {}, {}

        async def create(*argv, **kwargs):
            raise PermissionError("cannot execute")

        monkeypatch.setattr(headless, "prepare_run", prepare)
        monkeypatch.setattr(runner.asyncio, "create_subprocess_exec", create)
        monkeypatch.setattr(cli, "exit_cleanly_on_termination", lambda: None)
        result = CliRunner().invoke(cli.main, ["--headless", "--tools", ",".join(outcomes)])
        return result.exit_code, json.loads(result.stdout)

    run.out = out
    return run


@pytest.mark.parametrize("outcomes, blocked, not_started", [
    ({"maester": "blocked"}, ["maester"], []),
    ({"maester": "creation-fails"}, [], ["maester"]),
    ({"maester": "blocked", "hawk": "creation-fails"}, ["maester"], ["hawk"]),
], ids=["integrity-blocked", "creation-fails", "both"])
def test_zero_launch_payload_has_diagnostics_and_no_assessment(
        headless_run, monkeypatch, caplog, outcomes, blocked, not_started):
    monkeypatch.setattr(headless, "finalize", lambda *a, **k: pytest.fail("finalised"))
    code, payload = headless_run(outcomes)
    assert code == 1
    assert list(payload) == DIAGNOSTICS
    assert str(headless_run.out) not in json.dumps(payload)
    assert sorted(payload["failed_tools"]) == sorted(outcomes)
    assert payload["blocked_tools"] == dict.fromkeys(blocked, "hash mismatch")
    assert list(payload["launch_failures"]) == not_started
    for note in payload["launch_failures"].values():
        assert note == "could not start: PermissionError"  # the exception's text is only logged
    assert ("BLOCKED" in caplog.text) is bool(blocked)
    assert ("Cannot launch" in caplog.text) is bool(not_started)
    assert history.read() == []


def _raises(make_error):
    def fault(path):
        raise make_error(str(path))
    return fault


@pytest.mark.parametrize("fault, reason", [
    (lambda path: path.write_text("in the way"), "FileExistsError (EEXIST)"),  # a real mkdir error
    (_raises(lambda p: PermissionError(errno.EACCES, "Permission denied", p)),
     "PermissionError (EACCES)"),
    (_raises(lambda p: OSError(errno.ENOSPC, "No space left", p)), "OSError (ENOSPC)"),
    (_raises(lambda p: OSError(errno.EXDEV, "Cross-device", "source", None, p)), "OSError (EXDEV)"),
    (_raises(lambda p: OSError(REPOSITORY_SECRET, p)), "OSError"),  # errno is whatever was passed
    (_raises(lambda p: OSError([p, REPOSITORY_SECRET], "unhashable errno")), "OSError"),
    (_raises(lambda p: OSError({"path": p}, REPOSITORY_SECRET)), "OSError"),
    (_raises(lambda p: OSError(float(errno.ENOENT), p)), "OSError"),  # hashes like ENOENT
    (_raises(lambda p: OSError(p.encode(), REPOSITORY_SECRET)), "OSError"),
    (_raises(lambda p: ValueError(f"bad {p} {REPOSITORY_SECRET}")), "ValueError"),
], ids=["occupied", "filename", "no-space", "second-filename", "text-as-errno",
        "list-as-errno", "dict-as-errno", "float-as-errno", "bytes-as-errno", "not-os-error"])
@pytest.mark.parametrize("dry_run", [False, True], ids=["real", "dry-run"])
def test_pre_launch_error_text_is_not_serialised(
        tmp_path, bound, monkeypatch, caplog, dry_run, fault, reason):
    out, real_mkdir = tmp_path / "configured-output", Path.mkdir
    config_store.update("output", directory=str(out))
    prepared = [bound("maester")], {}, {}

    def mkdir(path, *args, **kwargs):
        if path.name == "maester" and path.is_relative_to(out.resolve()):
            fault(path)
        return real_mkdir(path, *args, **kwargs)

    monkeypatch.setattr(Path, "mkdir", mkdir)
    monkeypatch.setattr(headless, "prepare_run", lambda *a: prepared)
    monkeypatch.setattr(headless, "finalize", lambda *a, **k: pytest.fail("finalised"))
    monkeypatch.setattr(runner, "stream_process", lambda *a, **k: pytest.fail("launched"))
    monkeypatch.setattr(cli, "exit_cleanly_on_termination", lambda: None)
    args = ["--headless", "--tools", "maester", *(["--dry-run"] if dry_run else [])]
    result = CliRunner().invoke(cli.main, args)

    payload = json.loads(result.stdout)
    assert result.exit_code == 1 and list(payload) == DIAGNOSTICS
    assert payload["failed_tools"] == ["maester"] and payload["blocked_tools"] == {}
    for serialised in (result.stdout, json.dumps(payload["launch_failures"])):
        # the last component also covers the resolved and JSON-escaped forms of the path
        for private in (str(out), str(out.resolve()), out.name, REPOSITORY_SECRET):
            assert private not in serialised
    assert payload["launch_failures"] == {"maester": f"could not start: {reason}"}
    assert "Cannot launch" in caplog.text and out.name in caplog.text  # detail is still logged
    assert history.read() == []


async def test_a_filename_bearing_error_after_launch_is_still_raised(tmp_path, bound, monkeypatch):
    out = tmp_path / "configured-output"

    async def start(*args, on_start, **kwargs):
        on_start()
        raise OSError(errno.EIO, "Input/output error", str(out))

    monkeypatch.setattr(runner, "stream_process", start)
    r = runner.Runner(out, {}, hash_results=[bound("maester")])
    with pytest.raises(runner.RunError) as stopped:
        await r.run_all([get_tool("maester")])
    assert r.runs["maester"].note == "unexpected error: OSError"
    assert out.name not in str(stopped.value) and stopped.value.__cause__.filename == str(out)


@pytest.mark.parametrize("rc", [0, 1])
def test_a_launched_run_keeps_the_payload_shape(tmp_path, bound, monkeypatch, rc):
    async def start(argv, env, on_line, *args, on_start=None, **kwargs):
        on_start()
        out = Path(env["ORBIT_OUT_DIR"])
        (out / "maester.json").write_bytes((FIXTURES_DIR / "maester_sample.json").read_bytes())
        return rc

    config_store.update("output", directory=str(tmp_path / "out"))
    monkeypatch.setattr(headless, "prepare_run", lambda *a: ([bound("maester")], {}, {}))
    monkeypatch.setattr(runner, "stream_process", start)
    payload, code = headless.run_headless(False, ["maester"])
    assert code == rc and list(payload) == COMPLETED
    assert payload["total_controls"] > 0 and Path(payload["output_dir"]).is_dir()


# --- 4. executable verification -----------------------------------------------

@pytest.fixture()
def pinned(tmp_path):
    path = (tmp_path / "tool").resolve()
    path.write_text("unchanged content")
    path.chmod(0o755)
    return Executable.capture(path)


@posix_only
@pytest.mark.parametrize("mode", [0o644, 0o600, 0o400])
def test_losing_execute_permission_fails_verification(pinned, mode):
    pinned.verify()
    pinned.path.chmod(mode)
    with pytest.raises(ExecutableError, match="not executable"):
        pinned.verify()
    with pytest.raises(ExecutableError, match="not executable"):
        Executable.capture(pinned.path)


@posix_only
@pytest.mark.parametrize("kind", ["link-to-same-content", "directory", "fifo"])
def test_executable_must_still_be_an_ordinary_file(pinned, tmp_path, kind):
    moved = tmp_path / "moved"
    pinned.path.rename(moved)
    if kind == "link-to-same-content":
        pinned.path.symlink_to(moved)
    elif kind == "directory":
        pinned.path.mkdir()
    else:
        os.mkfifo(pinned.path, 0o700)
    with pytest.raises(ExecutableError):
        pinned.verify()


def test_windows_has_no_execute_bit_but_keeps_the_other_checks(pinned, monkeypatch):
    monkeypatch.setattr(executables.sys, "platform", "win32")
    monkeypatch.setattr(executables.os, "access", lambda *a, **k: pytest.fail("no such bit"))
    pinned.verify()
    pinned.path.write_text("changed content")
    with pytest.raises(ExecutableError, match="changed"):
        pinned.verify()


class EmptyStore:
    def __init__(self, *args):
        pass

    def load(self, name):
        return {}


@posix_only
def test_execute_permission_removed_after_discovery_is_not_green(
        tmp_path, manifest_file, private_tmp, fake_pwsh, monkeypatch):
    root = (tmp_path / "modules" / "Maester").resolve()
    root.mkdir(parents=True)
    (root / "Maester.psd1").write_text("verified")
    manifest_file("maester", "1.0", hash_tree(root))
    exe = fake_pwsh(tmp_path / "bin", modules=[("1.0", root / "Maester.psd1")])
    monkeypatch.setenv("PATH", str(exe.parent))
    monkeypatch.setattr(preflight, "SecretStore", EmptyStore)
    state = SessionState(selected={"maester"})
    state.output.base_dir = tmp_path / "out"

    def integrity():
        rows = preflight.run_preflight(state)
        return next((ok, detail) for ok, label, detail in rows if label.endswith("integrity"))

    assert integrity()[0] is True

    def verify_then_chmod(tool, workspace):
        result = verify_tool(tool, workspace)
        exe.chmod(0o644)
        return result

    monkeypatch.setattr(preflight, "verify_tool", verify_then_chmod)
    ok, detail = integrity()
    assert ok is False and "not executable" in detail
    assert list(private_tmp.iterdir()) == []


def test_preflight_still_fails_closed_on_an_unsupported_platform(tmp_path, monkeypatch):
    monkeypatch.setattr(preflight, "check_platform",
                        lambda: PlatformInfo("other", None, (7, 4), compat_flags("other", True)))
    monkeypatch.setattr(preflight, "verify_tool", lambda *a: pytest.fail("verified"))
    monkeypatch.setattr(preflight, "SecretStore", EmptyStore)
    state = SessionState(selected={"maester"})
    state.output.base_dir = tmp_path
    rows = {label: ok for ok, label, _ in preflight.run_preflight(state)}
    assert rows["Maester compatible"] is False and rows["Maester integrity"] is False

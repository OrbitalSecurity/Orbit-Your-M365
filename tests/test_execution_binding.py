"""Findings 1 and 3: what runs is what was verified, on the executable resolved during discovery."""
import asyncio
import os
import shutil
import signal
import stat
import subprocess
import sys
import textwrap
import threading
from pathlib import Path

import pytest

from orbit.core import executables, hash_checker, runner, safe_fs, workspace
from orbit.core.executables import Executable, ExecutableError
from orbit.core.hash_checker import HashResult, HashStatus, hash_tree, launch_binding, verify_tool
from orbit.core.runner import Runner, RunStatus, prepare_run
from orbit.core.tools import base, get_tool
from orbit.core.tools.discovery import Installation
from orbit.core.workspace import Workspace, WorkspaceError

ROOT = Path(__file__).resolve().parent.parent
pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX links, modes and fake pwsh")


class NoSecrets:
    def load(self, name):
        return {}

    def secret_values(self, name):
        return []


@pytest.fixture()
def install(tmp_path, manifest_file, monkeypatch):
    root = (tmp_path / "install").resolve()
    (root / "sub").mkdir(parents=True)
    (root / "Maester.psd1").write_text("verified")
    (root / "sub" / "code.psm1").write_text("verified code")
    exe = (tmp_path / "interpreter").resolve()
    exe.write_text("fake")
    exe.chmod(0o755)
    inst = Installation("1.2.3", root, root / "Maester.psd1", Executable.capture(exe))
    monkeypatch.setattr(base.Tool, "discover", lambda self: inst)
    manifest_file("maester", "1.2.3", hash_tree(root))
    return inst


@pytest.fixture()
def no_spawn(monkeypatch):
    calls = []

    async def spawn(*argv, **kwargs):
        calls.append(argv)
        raise AssertionError("a process was created")

    monkeypatch.setattr(runner.asyncio, "create_subprocess_exec", spawn)
    return calls


# --- snapshot ---------------------------------------------------------------

def test_snapshot_is_exact_private_and_read_only(install, private_tmp):
    with Workspace() as ws:
        b = verify_tool(get_tool("maester"), ws).binding
        assert hash_tree(b.root) == hash_tree(install.root) == dict(b.files)
        assert b.root.is_relative_to(private_tmp) and b.entry.is_relative_to(b.root)
        assert b.root == b.search_path / "Maester" / "1.2.3"  # standard module layout
        assert (b.source, b.version, b.executable) == (install.root, "1.2.3", install.executable)
        assert stat.S_IMODE(b.slot.stat().st_mode) == 0o700
        assert stat.S_IMODE(b.private_dir.stat().st_mode) == 0o700
        for path in [b.search_path, *b.search_path.rglob("*")]:
            assert not path.stat().st_mode & 0o277, path
    assert list(private_tmp.iterdir()) == []


def test_executable_bit_survives_without_write_access(install, manifest_file, private_tmp):
    (install.root / "sub" / "code.psm1").chmod(0o755)
    with Workspace() as ws:
        b = verify_tool(get_tool("maester"), ws).binding
        assert stat.S_IMODE((b.root / "sub" / "code.psm1").stat().st_mode) == 0o500


@pytest.mark.parametrize("change", ["modified", "added", "deleted", "dir-link", "file-link"])
def test_change_while_snapshotting_is_refused_and_nothing_unverified_is_copied(
        install, private_tmp, tmp_path, monkeypatch, change):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "code.psm1").write_text("SECRET outside the installation")
    code = install.root / "sub" / "code.psm1"
    real_read, real_create = hash_checker.read_below, hash_checker.create_file
    copied, done = [], []

    def racing_read(root, rel):
        if not done:
            done.append(1)
            if change == "modified":
                code.write_text("SECRET evil")
            elif change == "added":
                (root / "added.ps1").write_text("SECRET planted")
            elif change == "deleted":
                code.unlink()
            elif change == "dir-link":
                shutil.rmtree(code.parent)
                code.parent.symlink_to(outside)
            else:
                code.unlink()
                code.symlink_to(outside / "code.psm1")
        return real_read(root, rel)

    def recording_create(path, data, *args, **kwargs):
        copied.append(data)
        real_create(path, data, *args, **kwargs)

    monkeypatch.setattr(hash_checker, "read_below", racing_read)
    monkeypatch.setattr(hash_checker, "create_file", recording_create)
    with Workspace() as ws:
        result = verify_tool(get_tool("maester"), ws)
        assert result.status is HashStatus.UNVERIFIED and result.binding is None
        assert not any(b"SECRET" in data for data in copied)
        assert not any(list(slot.iterdir()) for slot in private_tmp.glob("orbit-*"))
    assert list(private_tmp.iterdir()) == []


def test_junction_met_while_snapshotting_is_refused(install, private_tmp, monkeypatch):
    real_read, real_lstat = hash_checker.read_below, Path.lstat

    class Junction:
        st_reparse_tag = 0xA0000003

        def __init__(self, info):
            self.st_mode = info.st_mode

    def becomes_junction(root, rel):
        monkeypatch.setattr(Path, "lstat", lambda self: Junction(real_lstat(self))
                            if self == install.root / "sub" else real_lstat(self))
        return real_read(root, rel)

    monkeypatch.setattr(hash_checker, "read_below", becomes_junction)
    with Workspace() as ws:
        assert verify_tool(get_tool("maester"), ws).status is HashStatus.UNVERIFIED


@pytest.mark.parametrize("tag, link", [(0xA0000003, True), (0xA000000C, True), (0xA000001D, True),
                                       (0x9000001A, False), (0, False)])
def test_reparse_points_that_redirect_count_as_links(tag, link):
    info = type("Info", (), {"st_mode": stat.S_IFDIR, "st_reparse_tag": tag})()
    assert safe_fs.is_link(info) is link


def test_file_swapped_between_stat_and_open_is_refused(tmp_path, monkeypatch):
    target, other = tmp_path / "file", tmp_path / "other"
    target.write_text("good")
    other.write_text("evil")
    real_open = os.open

    def swap(path, *args, **kwargs):
        os.replace(other, target)
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(safe_fs.os, "open", swap)
    with pytest.raises(ValueError, match="replaced"):
        safe_fs.sha256_file(target)


@pytest.mark.parametrize("kind", ["symlink", "fifo"])
def test_root_and_entries_must_be_plain(tmp_path, kind):
    root = tmp_path / "root"
    if kind == "symlink":
        (tmp_path / "real").mkdir()
        root.symlink_to(tmp_path / "real")
    else:
        root.mkdir()
        os.mkfifo(root / "pipe")
    with pytest.raises(ValueError):
        hash_tree(root)


@pytest.mark.parametrize("name", [".env", ".env.local", ".roadtools_auth.json", "app.pfx",
                                  "id_rsa", "secrets.enc", "msal_token_cache.bin"])
def test_secret_files_are_neither_read_nor_copied(install, private_tmp, monkeypatch, name):
    (install.root / name).write_text("SECRET")

    def forbidden(*args):
        raise AssertionError("a file was read or copied")

    for target in ("sha256_file", "read_below", "create_file"):
        monkeypatch.setattr(hash_checker, target, forbidden)
    with Workspace() as ws:
        result = verify_tool(get_tool("maester"), ws)
    assert result.status is HashStatus.UNVERIFIED and "secret-like" in result.reason
    assert list(private_tmp.iterdir()) == []


def test_unexpected_file_is_never_copied(install, private_tmp):
    (install.root / "output.json").write_text("tenant data")
    with Workspace() as ws:
        result = verify_tool(get_tool("maester"), ws)
        assert result.status is HashStatus.MISMATCH and result.binding is None
        assert list(private_tmp.iterdir()) == []


def test_download_mark_blocks_because_a_copy_would_lose_it(install, private_tmp, monkeypatch):
    monkeypatch.setattr(hash_checker, "has_download_mark", lambda path: path.name == "code.psm1")
    with Workspace() as ws:
        result = verify_tool(get_tool("maester"), ws)
    assert result.status is HashStatus.UNVERIFIED and "Mark-of-the-Web" in result.reason
    assert list(private_tmp.iterdir()) == []


def test_download_mark_is_read_from_the_windows_stream(tmp_path, monkeypatch):
    module = tmp_path / "module.psm1"
    module.write_text("x")
    monkeypatch.setattr(safe_fs.sys, "platform", "win32")
    assert not safe_fs.has_download_mark(module)
    (tmp_path / "module.psm1:Zone.Identifier").write_text("[ZoneTransfer]\nZoneId=3\n")
    assert safe_fs.has_download_mark(module)


# --- what may launch --------------------------------------------------------

def test_ok_without_a_snapshot_cannot_launch(install):
    result = verify_tool(get_tool("maester"))
    assert result.status is HashStatus.OK
    assert launch_binding([result])[0] is None


@pytest.mark.parametrize("wrong", ["unbound", "duplicate", "other-version", "other-tool", "released"])
async def test_runner_refuses_inexact_provenance(tmp_path, bound, no_spawn, wrong):
    result = bound("maester")
    results = [result]
    if wrong == "unbound":
        results = [HashResult("maester", "1", HashStatus.OK)]
    elif wrong == "duplicate":
        results = [result, result]
    elif wrong == "other-version":
        result.version = "2"
    elif wrong == "other-tool":
        result.binding = bound("hawk").binding
    else:
        result.binding.release()
    run = await Runner(tmp_path / "o", {}, hash_results=results).run_tool(get_tool("maester"))
    assert run.status is RunStatus.SKIPPED and not run.launched and no_spawn == []


@pytest.mark.parametrize("tamper", ["edit", "add", "delete", "link", "sibling-module",
                                    "private-dir", "executable", "not-executable"])
async def test_change_after_verification_blocks_the_launch(
        install, private_tmp, tmp_path, no_spawn, tamper):
    with Workspace() as ws:
        result = verify_tool(get_tool("maester"), ws)
        b = result.binding
        for path in [b.search_path, *b.search_path.rglob("*")]:
            path.chmod(0o700)
        if tamper == "edit":
            b.entry.write_text("evil")
        elif tamper == "add":
            (b.root / "planted.dll").write_text("evil")
        elif tamper == "delete":
            (b.root / "sub" / "code.psm1").unlink()
        elif tamper == "link":
            b.entry.unlink()
            b.entry.symlink_to(install.entry)  # same content, but a mutable path
        elif tamper == "sibling-module":
            (b.search_path / "Pester").mkdir()
            (b.search_path / "Pester" / "Pester.psd1").write_text("evil")
        elif tamper == "not-executable":
            b.executable.path.chmod(0o644)
        elif tamper == "private-dir":
            (b.private_dir / ".roadtools_auth.json").symlink_to(tmp_path / "elsewhere")
        else:
            b.executable.path.write_text("swapped")
        run = await Runner(tmp_path / "o", {}, hash_results=[result]).run_tool(get_tool("maester"))
    assert run.status is RunStatus.SKIPPED and run.note == "integrity changed"
    assert not run.launched and no_spawn == [] and list(private_tmp.iterdir()) == []


@pytest.mark.parametrize("edit", ["rewrite", "replace-dir", "delete"])
def test_source_change_after_verification_cannot_reach_execution(
        tmp_path, manifest_file, private_tmp, fake_pwsh, monkeypatch, edit):
    root = (tmp_path / "modules" / "Maester").resolve()
    root.mkdir(parents=True)
    (root / "Maester.psd1").write_text("verified")
    manifest_file("maester", "1.2.3", hash_tree(root))
    exe = fake_pwsh(tmp_path / "bin", modules=[("1.2.3", root / "Maester.psd1")])
    monkeypatch.setenv("PATH", str(exe.parent))
    tool = get_tool("maester")
    with Workspace() as ws:
        results, creds, secrets = prepare_run([tool], NoSecrets, ws)
        if edit == "rewrite":
            (root / "Maester.psd1").write_text("evil")
        else:
            shutil.rmtree(root)
            if edit == "replace-dir":
                root.mkdir()
                (root / "Maester.psd1").write_text("evil")
        runs = asyncio.run(Runner(tmp_path / "o", creds, secrets, False, results).run_all([tool]))
    assert runs["maester"].status is RunStatus.COMPLETE, runs["maester"].log
    assert fake_pwsh.calls() == ["approved:verified"] and list(private_tmp.iterdir()) == []


# --- clean-up ---------------------------------------------------------------

@pytest.mark.parametrize("outcome", ["ok", "nonzero", "creation-fails", "cancelled"])
async def test_snapshot_is_removed_however_the_tool_ends(
        install, private_tmp, tmp_path, monkeypatch, outcome):
    entered = asyncio.Event()

    async def fake(argv, env, on_line, *args, on_start=None, **kwargs):
        if outcome == "creation-fails":
            raise PermissionError("cannot execute")
        on_start()
        entered.set()
        if outcome == "cancelled":
            await asyncio.sleep(60)
        return 1 if outcome == "nonzero" else 0

    monkeypatch.setattr(runner, "stream_process", fake)
    with Workspace() as ws:
        result = verify_tool(get_tool("maester"), ws)
        r = Runner(tmp_path / "o", {}, hash_results=[result])
        task = asyncio.create_task(r.run_all([get_tool("maester")]))
        if outcome == "cancelled":
            await asyncio.wait_for(entered.wait(), 10)
            r.stop_all()
        await task
        assert not result.binding.slot.exists()  # per tool, before the run as a whole ends
    assert list(private_tmp.iterdir()) == []


def test_workspace_removes_everything_on_an_exception(install, private_tmp):
    with pytest.raises(RuntimeError), Workspace() as ws:
        assert verify_tool(get_tool("maester"), ws).binding
        raise RuntimeError("failure after snapshot")
    assert list(private_tmp.iterdir()) == []


def test_closing_during_a_copy_defers_removal_to_the_worker(install, private_tmp, monkeypatch):
    entered, release = threading.Event(), threading.Event()
    real_read = hash_checker.read_below

    def slow(root, rel):
        entered.set()
        release.wait(5)
        return real_read(root, rel)

    monkeypatch.setattr(hash_checker, "read_below", slow)
    ws, results = Workspace(), []
    thread = threading.Thread(target=lambda: results.append(verify_tool(get_tool("maester"), ws)))
    thread.start()
    assert entered.wait(5)
    ws.close()  # the user pressed Stop
    release.set()
    thread.join(5)
    assert results[0].binding is None and list(private_tmp.iterdir()) == []


@pytest.mark.parametrize("signame", ["SIGTERM", "SIGHUP"])
def test_termination_signal_removes_private_storage(tmp_path, private_tmp, signame):
    code = textwrap.dedent("""
        import asyncio, sys
        sys.path.insert(0, sys.argv[1])
        from orbit.cli import exit_cleanly_on_termination
        from orbit.core.workspace import Workspace
        exit_cleanly_on_termination()
        async def main():
            print("ready", flush=True)
            await asyncio.sleep(60)
        with Workspace() as ws:
            (ws.new_slot() / "token").write_text("synthetic")
            asyncio.run(main())
    """)
    env = {**os.environ, "TMPDIR": str(private_tmp)}
    proc = subprocess.Popen([sys.executable, "-c", code, str(ROOT)], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, env=env, cwd=tmp_path)
    try:
        assert proc.stdout.readline().strip() == "ready"
        assert list(private_tmp.glob("orbit-*/*/token"))
        number = getattr(signal, signame)
        proc.send_signal(number)
        assert proc.wait(15) == 128 + number
    finally:
        proc.kill()
        proc.communicate()
    assert list(private_tmp.iterdir()) == []


def test_blocked_shutdown_still_removes_private_storage_and_exits(tmp_path, private_tmp):
    code = textwrap.dedent("""
        import sys, time
        sys.path.insert(0, sys.argv[1])
        from orbit import cli
        from orbit.core.workspace import Workspace
        cli.STOP_GRACE = 0.5
        cli.exit_cleanly_on_termination()
        ws = Workspace()
        (ws.new_slot() / "token").write_text("synthetic")
        try:
            print("ready", flush=True)
            time.sleep(60)
        finally:
            time.sleep(60)  # an unwind that never finishes, e.g. the terminal has gone
    """)
    env = {**os.environ, "TMPDIR": str(private_tmp)}
    proc = subprocess.Popen([sys.executable, "-c", code, str(ROOT)], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, env=env, cwd=tmp_path)
    try:
        assert proc.stdout.readline().strip() == "ready"
        proc.send_signal(signal.SIGHUP)
        assert proc.wait(15) == 128 + signal.SIGHUP
    finally:
        proc.kill()
        proc.communicate()
    assert list(private_tmp.iterdir()) == []


@pytest.mark.parametrize("mode", [0o777, 0o770, 0o722])
def test_shared_temp_directory_is_refused(private_tmp, mode):
    private_tmp.chmod(mode)
    try:
        with pytest.raises(WorkspaceError), Workspace() as ws:
            ws.new_slot()
    finally:
        private_tmp.chmod(0o700)
    assert list(private_tmp.iterdir()) == []


def test_temp_directory_of_another_user_is_refused(private_tmp, monkeypatch):
    monkeypatch.setattr(workspace.os, "geteuid", lambda: 987654)
    with pytest.raises(WorkspaceError, match="another user"):
        workspace.check_private_location(private_tmp)


def test_windows_temp_must_be_inside_the_profile(tmp_path, monkeypatch):
    profile = (tmp_path / "profile").resolve()
    monkeypatch.setattr(workspace.sys, "platform", "win32")
    monkeypatch.setattr(workspace.Path, "home", lambda: profile)
    workspace.check_private_location(profile / "Temp")
    with pytest.raises(WorkspaceError):
        workspace.check_private_location(tmp_path.resolve() / "shared")


def test_unusable_private_storage_blocks_as_unverified(install, private_tmp):
    private_tmp.chmod(0o777)
    try:
        with Workspace() as ws:
            result = verify_tool(get_tool("maester"), ws)
    finally:
        private_tmp.chmod(0o700)
    assert result.status is HashStatus.UNVERIFIED and result.binding is None


# --- PowerShell binding -----------------------------------------------------

@pytest.mark.parametrize("swap", ["path", "cwd", "both"])
def test_path_or_cwd_change_cannot_swap_pwsh(
        tmp_path, manifest_file, private_tmp, fake_pwsh, monkeypatch, swap):
    root = (tmp_path / "modules" / "Maester").resolve()
    root.mkdir(parents=True)
    (root / "Maester.psd1").write_text("verified")
    manifest_file("maester", "1.2.3", hash_tree(root))
    good = fake_pwsh(tmp_path / "good", modules=[("1.2.3", root / "Maester.psd1")])
    evil = fake_pwsh(tmp_path / "evil", label="EVIL")
    monkeypatch.setenv("PATH", str(good.parent))
    tool = get_tool("maester")
    with Workspace() as ws:
        results, creds, secrets = prepare_run([tool], NoSecrets, ws)
        assert results[0].binding.executable.path == good.resolve()
        if swap in ("path", "both"):
            monkeypatch.setenv("PATH", str(evil.parent))
        if swap in ("cwd", "both"):
            monkeypatch.chdir(evil.parent)
        runs = asyncio.run(Runner(tmp_path / "o", creds, secrets, False, results).run_all([tool]))
    assert runs["maester"].status is RunStatus.COMPLETE, runs["maester"].log
    assert fake_pwsh.calls() == ["approved:verified"]


async def test_opa_uses_the_pwsh_resolved_during_verification(
        tmp_path, manifest_file, private_tmp, fake_pwsh, monkeypatch):
    from orbit.tui.app import OrbitApp
    from orbit.tui.screens import installer
    root = (tmp_path / "modules" / "ScubaGear").resolve()
    root.mkdir(parents=True)
    (root / "ScubaGear.psd1").write_text("verified")
    manifest_file("scubagear", "1.2.3", hash_tree(root))
    good = fake_pwsh(tmp_path / "good", modules=[("1.2.3", root / "ScubaGear.psd1")])
    evil = fake_pwsh(tmp_path / "evil", label="EVIL")
    monkeypatch.setenv("PATH", str(good.parent))
    monkeypatch.setattr(base, "detect_os", lambda: "windows")
    monkeypatch.setattr(installer, "prereq_report", list)
    monkeypatch.setattr(installer.InstallerScreen, "refresh_versions", lambda self: None)
    monkeypatch.setattr("orbit.tui.screens.onboarding.has_saved_credentials", lambda: True)

    def verify_then_swap(tool, ws):
        result = verify_tool(tool, ws)
        os.environ["PATH"] = str(evil.parent)
        os.chdir(evil.parent)
        return result

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(installer, "verify_tool", verify_then_swap)
    app = OrbitApp(dry_run=False)
    async with app.run_test(size=(120, 60)) as pilot:
        app.push_screen("installer")
        await pilot.pause()
        app.screen.query_one("#install-opa").press()
        for _ in range(200):
            await pilot.pause(0.05)
            if fake_pwsh.calls():
                break
    assert fake_pwsh.calls() == ["approved:verified"]


@pytest.mark.parametrize("entry", ["bin", "./bin", "../cwd/bin", ""])
def test_relative_path_entry_holding_pwsh_is_rejected(tmp_path, fake_pwsh, monkeypatch, entry):
    cwd = tmp_path / "cwd"
    fake_pwsh(cwd / "bin")
    fake_pwsh(cwd)
    absolute = fake_pwsh(tmp_path / "absolute")
    monkeypatch.chdir(cwd)
    monkeypatch.setenv("PATH", os.pathsep.join([entry, str(absolute.parent)]))
    with pytest.raises(ExecutableError, match="relative"):
        executables.find_pwsh()


def test_two_different_pwsh_are_ambiguous(tmp_path, fake_pwsh, monkeypatch):
    a, b = fake_pwsh(tmp_path / "a"), fake_pwsh(tmp_path / "b")
    monkeypatch.setenv("PATH", os.pathsep.join([str(a.parent), str(b.parent)]))
    with pytest.raises(ExecutableError, match="ambiguous"):
        executables.find_pwsh()


def test_links_to_one_pwsh_are_not_ambiguous(tmp_path, fake_pwsh, monkeypatch):
    real = fake_pwsh(tmp_path / "real")
    (tmp_path / "link").mkdir()
    (tmp_path / "link" / "pwsh").symlink_to(real)
    monkeypatch.setenv("PATH", os.pathsep.join([str(tmp_path / "link"), str(real.parent)]))
    assert executables.find_pwsh() == real.resolve()


def test_pwsh_that_is_another_program_is_rejected(tmp_path, monkeypatch):
    other = tmp_path / "launcher"
    other.write_text("#!/bin/sh\n")
    other.chmod(0o755)
    (tmp_path / "pwsh").symlink_to(other)
    monkeypatch.setenv("PATH", str(tmp_path))
    with pytest.raises(ExecutableError, match="not PowerShell"):
        executables.find_pwsh()


def test_world_writable_pwsh_is_rejected(tmp_path, fake_pwsh, monkeypatch):
    exe = fake_pwsh(tmp_path / "bin")
    exe.chmod(0o777)
    monkeypatch.setenv("PATH", str(exe.parent))
    with pytest.raises(ExecutableError, match="writable"):
        executables.find_pwsh()


@pytest.mark.parametrize("version", ["5.1.0", "6.2.7"])
def test_powershell_older_than_7_is_rejected(tmp_path, fake_pwsh, monkeypatch, version):
    monkeypatch.setenv("PATH", str(fake_pwsh(tmp_path / "bin", version=version).parent))
    with pytest.raises(ExecutableError, match="7 or later"):
        executables.resolve_pwsh()


def test_windows_lookup_ignores_shims_and_the_current_directory(tmp_path, monkeypatch):
    real, cwd = tmp_path / "real", tmp_path / "cwd"
    real.mkdir()
    cwd.mkdir()
    for path in (real / "pwsh.exe", real / "pwsh.bat", cwd / "pwsh.exe"):
        path.write_text("x")
        path.chmod(0o755)
    monkeypatch.chdir(cwd)
    monkeypatch.setenv("PATH", str(real))
    monkeypatch.setattr(executables.sys, "platform", "win32")
    assert executables.find_pwsh() == (real / "pwsh.exe").resolve()


def test_resolution_never_uses_shutil_which(tmp_path, fake_pwsh, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("shutil.which")

    exe = fake_pwsh(tmp_path / "bin")
    monkeypatch.setenv("PATH", str(exe.parent))
    monkeypatch.setattr(shutil, "which", forbidden)
    assert executables.resolve_pwsh().path == exe.resolve()


def test_relative_executables_are_rejected():
    with pytest.raises(ExecutableError):
        Executable.capture(Path("pwsh"))
    with pytest.raises(ExecutableError):
        base.ps_command(Path("pwsh"), "exit")


@pytest.mark.parametrize("name", ["scubagear", "maester", "monkey365", "hawk"])
def test_installer_has_no_bare_pwsh_fallback(tmp_path, monkeypatch, name):
    monkeypatch.setenv("PATH", str(tmp_path))
    for build in (get_tool(name).install_command, get_tool(name).uninstall_command):
        with pytest.raises(ExecutableError):
            build()


@pytest.mark.parametrize("name", ["scubagear", "maester", "monkey365", "hawk"])
def test_launch_performs_no_lookup_of_its_own(tmp_path, bound, monkeypatch, name):
    binding = bound(name).binding

    def forbidden(*args, **kwargs):
        raise AssertionError("a second resolution")

    monkeypatch.setattr(shutil, "which", forbidden)
    monkeypatch.setattr(base, "resolve_pwsh", forbidden)
    monkeypatch.setattr(executables, "find_pwsh", forbidden)
    spec = get_tool(name).launch_spec({}, tmp_path, binding)
    assert spec.argv[0] == str(binding.executable.path)
    assert spec.env["ORBIT_MODULE_PATH"] == str(binding.search_path)


def test_child_path_has_no_relative_entries(monkeypatch):
    from orbit.core.process_env import child_env
    monkeypatch.setenv("PATH", os.pathsep.join(["", ".", "bin", "/usr/bin"]))
    assert child_env()["PATH"] == "/usr/bin"

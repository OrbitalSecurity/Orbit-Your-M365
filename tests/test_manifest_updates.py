"""Finding 7: serialised, atomic manifest updates. Only throwaway manifests are written."""
import json
import os
import signal
import stat
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest
from baseline_helpers import write

from orbit.core import hash_checker, manifest
from orbit.core.manifest import ManifestError, update_manifest

ROOT = Path(__file__).resolve().parent.parent
SHIPPED = hash_checker.TEMPLATE_PATH


@pytest.fixture(autouse=True)
def shipped_template_untouched():
    before = SHIPPED.read_bytes()
    yield
    assert SHIPPED.read_bytes() == before


@pytest.fixture()
def path(tmp_path):
    return write(tmp_path / "tool_hashes.json", {"old": {}})  # a schema-2 baseline for this user


def _spawn(tmp_path, code, *args):
    script = "import sys\nsys.path.insert(0, sys.argv[1])\n" + textwrap.dedent(code)
    return subprocess.Popen([sys.executable, "-c", script, str(ROOT), *map(str, args)], cwd=tmp_path,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def test_concurrent_writers_lose_no_entries(path, tmp_path):
    code = """
        import time
        from pathlib import Path
        from orbit.core.manifest import update_manifest
        with update_manifest(Path(sys.argv[2])) as m:
            time.sleep(0.15)
            m['tools'][sys.argv[3]] = {'versions': {}}
    """
    procs = [_spawn(tmp_path, code, path, f"tool{n}") for n in range(8)]
    for proc in procs:
        assert proc.communicate(timeout=60)[1] == "" and proc.returncode == 0
    assert set(json.loads(path.read_text())["tools"]) == {"old", *(f"tool{n}" for n in range(8))}


def test_concurrent_writers_cannot_bless_conflicting_content(path, tmp_path, monkeypatch):
    monkeypatch.setenv("ORBIT_HOME", str(path.parent))  # the generator writes ORBIT_HOME's baseline
    code = """
        import importlib.util, time
        from pathlib import Path
        from orbit.core.tools.discovery import Installation
        from orbit.core import baseline as gen
        root = Path(sys.argv[3])
        class Fake:
            name = 'fake'
            def discover(self):
                time.sleep(0.4)  # inside the read/compare/update window
                return Installation('1', root)
        gen.all_tools = lambda: [Fake()]
        gen.main()
    """
    procs = []
    for label in ("first", "second", "third"):
        install = tmp_path / label
        install.mkdir()
        (install / "module").write_text(label)
        procs.append((label, _spawn(tmp_path, code, path, install)))
    winners = []
    for label, proc in procs:
        out, err = proc.communicate(timeout=60)
        if proc.returncode == 0:
            winners.append(label)
        else:
            assert "NOT recorded" in out, err
    assert len(winners) == 1
    recorded = json.loads(path.read_text())["tools"]["fake"]["versions"]["1"]
    assert recorded["install_dir"] == str(tmp_path / winners[0])


@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt, SystemExit])
def test_interruption_before_write_changes_nothing(path, error):
    before = path.read_bytes()
    with pytest.raises(error), update_manifest(path) as data:
        data["tools"]["partial"] = {"versions": {}}
        raise error
    assert path.read_bytes() == before


@pytest.mark.parametrize("step", ["fsync", "replace", "chmod"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_interruption_during_write_keeps_the_old_manifest(path, monkeypatch, step, error):
    before = path.read_bytes()

    def fail(*args, **kwargs):
        raise error("interrupted")

    if step == "chmod":
        if not hasattr(os, "fchmod"):
            pytest.skip("Windows sets the mode with os.chmod")
        monkeypatch.setattr(manifest.os, "fchmod", fail)
    else:
        monkeypatch.setattr(manifest.os, step, fail)
    with pytest.raises(error), update_manifest(path) as data:
        data["tools"]["new"] = {"versions": {}}
    assert path.read_bytes() == before
    assert sorted(p.name for p in path.parent.iterdir()) == [path.name, path.name + ".lock"]


@pytest.mark.skipif(sys.platform == "win32", reason="needs SIGKILL")
def test_killed_mid_write_keeps_the_old_manifest_and_frees_the_lock(path, tmp_path):
    before = path.read_bytes()
    code = """
        import os, time
        from pathlib import Path
        from orbit.core import manifest
        def stall(fd):
            print('written', flush=True)
            time.sleep(60)
        manifest.os.fsync = stall
        with manifest.update_manifest(Path(sys.argv[2])) as m:
            m['tools']['half'] = {"versions": {}}
    """
    proc = _spawn(tmp_path, code, path)
    try:
        assert proc.stdout.readline().strip() == "written"
        proc.send_signal(signal.SIGKILL)
    finally:
        proc.kill()
        proc.communicate(timeout=10)
    assert path.read_bytes() == before
    started = time.monotonic()
    with update_manifest(path) as data:
        data["tools"]["after"] = {"versions": {}}
    assert time.monotonic() - started < 5 and "after" in path.read_text()


def test_second_writer_waits_for_the_lock(path, monkeypatch):
    monkeypatch.setattr(manifest, "LOCK_TIMEOUT", 0.1)
    with update_manifest(path), pytest.raises(ManifestError, match="lock"), update_manifest(path):
        pass


def test_edit_outside_the_lock_is_not_overwritten(path):
    edited = json.dumps({"tools": {"edited by hand": {}}})
    with pytest.raises(ManifestError, match="edited"), update_manifest(path) as data:
        path.write_text(edited)
        data["tools"]["mine"] = {"versions": {}}
    assert path.read_text() == edited


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX modes")
@pytest.mark.parametrize("before, after", [(0o600, 0o600), (0o640, 0o640), (0o644, 0o644),
                                           (0o755, 0o644)])
def test_permissions_are_retained_and_never_widened(path, before, after):
    path.chmod(before)
    with update_manifest(path) as data:
        data["tools"]["new"] = {"versions": {}}
    assert stat.S_IMODE(path.stat().st_mode) == after


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX modes")
@pytest.mark.parametrize("mode", [0o666, 0o664, 0o620, 0o602])
def test_a_manifest_others_can_write_is_refused_not_reblessed(path, mode):
    """Its content may have been edited by someone else, so the writer must not adopt it."""
    path.chmod(mode)
    before = path.read_bytes()
    with pytest.raises(ManifestError, match="writable by group or others"), update_manifest(path):
        pass
    assert path.read_bytes() == before and stat.S_IMODE(path.stat().st_mode) == mode


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX modes")
def test_new_manifest_is_owner_only(tmp_path):
    with update_manifest(tmp_path / "new.json"):
        pass
    assert stat.S_IMODE((tmp_path / "new.json").stat().st_mode) == 0o600


@pytest.mark.parametrize("content", ["{not json", "[]", '{"tools": []}', ""])
def test_damaged_manifest_is_left_alone(path, content):
    path.write_text(content)
    with pytest.raises(ManifestError), update_manifest(path):
        pass
    assert path.read_text() == content


@pytest.mark.skipif(sys.platform == "win32", reason="needs symlinks")
def test_linked_manifest_is_refused(path, tmp_path):
    link = tmp_path / "link.json"
    os.symlink(path, link)
    with pytest.raises(ManifestError), update_manifest(link):
        pass
    assert link.is_symlink()

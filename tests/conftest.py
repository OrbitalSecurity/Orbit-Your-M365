import os

import pytest

# Never touch the developer's real keychain. Inherited by CLI subprocesses as well.
os.environ["PYTHON_KEYRING_BACKEND"] = "keyring.backends.null.Keyring"


@pytest.fixture(autouse=True)
def _isolated_orbit_home(tmp_path_factory, monkeypatch):
    """Keep tests from reading or writing the real ~/.orbit, or popping real notifications."""
    monkeypatch.setenv("ORBIT_HOME", str(tmp_path_factory.mktemp("orbit_home")))
    from orbit.core import config_store
    config_store.update("notifications", os_notify=False, email_notify=False, update_check=False)
    config_store.update("app", first_run=False)  # onboarding tests opt back in


@pytest.fixture()
def roadtools_mechanics(monkeypatch):
    """Lift the production block to test the mechanics behind it, with fakes only.

    The block itself is tested, without this fixture, in test_final_boundaries.py.
    """
    from orbit.core.tools.roadtools import ROADtools
    monkeypatch.setattr(ROADtools, "real_run_block", "")


@pytest.fixture()
def bound(tmp_path):
    """bound(tool name) -> an OK result bound to a real snapshot of a fake installation."""
    from orbit.core import hash_checker
    from orbit.core.executables import Executable
    from orbit.core.tools import get_tool
    from orbit.core.tools.discovery import Installation
    from orbit.core.workspace import Workspace

    exe = tmp_path / "fake-interpreter"
    exe.write_text("not a real interpreter")
    exe.chmod(0o755)

    def make(name):
        tool = get_tool(name)
        root = tmp_path / "bound" / name
        root.mkdir(parents=True, exist_ok=True)
        entry = root / f"{tool.package}.psd1"
        entry.write_text(name)
        inst = Installation("1", root, entry, Executable.capture(exe.resolve()))
        files = hash_checker.hash_tree(root)
        return hash_checker.HashResult(
            name, "1", hash_checker.HashStatus.OK, files=files,
            binding=hash_checker._snapshot(name, inst, files, workspace))

    with Workspace() as workspace:
        yield make


@pytest.fixture()
def private_tmp(tmp_path_factory, monkeypatch):
    """ORBIT's temp root for this test, separate from tmp_path so leftovers are visible."""
    import tempfile
    root = tmp_path_factory.mktemp("private").resolve()
    root.chmod(0o700)
    monkeypatch.setattr(tempfile, "tempdir", str(root))
    return root


@pytest.fixture()
def manifest_file(tmp_path, monkeypatch):
    """A throwaway schema-2 baseline for this user; record(tool, version, files) adds one."""
    from baseline_helpers import write

    from orbit.core import hash_checker
    path = tmp_path / "test_manifest.json"
    tools: dict = {}
    write(path, tools)
    monkeypatch.setattr(hash_checker, "manifest_path", lambda: path)

    def record(tool, version, files):
        tools.setdefault(tool, {})[version] = files
        write(path, tools)

    record.path = path
    return record


@pytest.fixture()
def fake_pwsh(tmp_path):
    """fake_pwsh(dir, label) -> an executable that imitates only what ORBIT asks of pwsh."""
    import sys

    from orbit.core.executables import base_python
    if sys.platform == "win32":
        pytest.skip("the fake pwsh is a POSIX script")
    python = base_python().path
    marker = tmp_path / "pwsh-calls"

    def make(directory, label="approved", version="7.4.1", modules=()):
        directory.mkdir(parents=True, exist_ok=True)
        exe = directory / "pwsh"
        exe.write_text(
            f"#!{python} -IS\n"
            "import base64, os, sys\n"
            "script = sys.argv[-1]\n"
            "if 'PSVersionTable.PSVersion' in script:\n"
            f"    print('PWSH|{version}')\n"
            "elif 'Get-Module' in script:\n"
            f"    for ver, path in {[(v, str(p)) for v, p in modules]!r}:\n"
            "        print('ORBIT|%s|%s' % (ver, base64.b64encode(path.encode()).decode()))\n"
            "else:\n"
            "    module = open(os.environ['ORBIT_MODULE']).read()\n"
            f"    open({str(marker)!r}, 'a').write({label!r} + ':' + module + '\\n')\n")
        exe.chmod(0o755)
        return exe

    make.calls = lambda: marker.read_text().splitlines() if marker.exists() else []
    return make


@pytest.fixture()
def synthetic(tmp_path, monkeypatch):
    """One fake installed tool; discovery returns it with no pwsh and no process."""
    from types import SimpleNamespace

    from orbit.core import baseline
    from orbit.core.executables import Executable
    from orbit.core.tools import base, get_tool
    from orbit.core.tools.discovery import Installation

    root = tmp_path / "installs" / "Maester"
    root.mkdir(parents=True)
    (root / "Maester.psd1").write_text("synthetic manifest")
    (root / "Maester.psm1").write_text("synthetic body")
    exe = tmp_path / "interpreter"
    exe.write_text("not a real interpreter")
    exe.chmod(0o755)
    inst = Installation("1.2.3", root, root / "Maester.psd1", Executable.capture(exe.resolve()))
    tool = get_tool("maester")
    monkeypatch.setattr(base.Tool, "discover", lambda self: inst)
    monkeypatch.setattr(baseline, "all_tools", lambda: [tool])
    return SimpleNamespace(tool=tool, root=root)


@pytest.fixture()
def home(tmp_path, monkeypatch):
    """A not-yet-existing ORBIT_HOME, so the command has to create it."""
    path = tmp_path / "fresh-orbit-home"
    monkeypatch.setenv("ORBIT_HOME", str(path))
    return path

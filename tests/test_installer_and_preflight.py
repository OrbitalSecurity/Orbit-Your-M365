"""Finding 9 (pip source environment) and finding 10 (preflight accuracy)."""
import sys

import pytest

from orbit.core import process_env
from orbit.core.executables import Executable
from orbit.core.hash_checker import hash_tree
from orbit.core.platform_check import PlatformInfo, compat_flags
from orbit.core.runner import stream_process
from orbit.core.tools import base, get_tool
from orbit.core.tools.discovery import DiscoveryError, Installation
from orbit.tui.app import OrbitApp
from orbit.tui.screens import installer, preflight
from orbit.tui.state import SessionState

INDEX = "https://builder:index-password@pypi.corp.invalid/simple"
PRIVATE = {"PIP_INDEX_URL": INDEX, "PIP_EXTRA_INDEX_URL": "https://mirror.corp.invalid/simple",
           "PIP_TRUSTED_HOST": "pypi.corp.invalid", "PIP_CERT": "/etc/corp/ca.pem",
           "PIP_CLIENT_CERT": "/etc/corp/client.pem", "PIP_PROXY": "http://proxy.corp.invalid:8080",
           "PIP_CONFIG_FILE": "/etc/corp/pip.conf", "XDG_CONFIG_DIRS": "/etc/corp/xdg"}
OFFLINE = {"PIP_NO_INDEX": "1", "PIP_FIND_LINKS": "/srv/wheels"}
UNRELATED = {"AWS_SECRET_ACCESS_KEY": "canary", "GITHUB_TOKEN": "canary", "TWINE_PASSWORD": "canary",
             "AZURE_CLIENT_SECRET": "canary", "PIP_PASSWORD": "canary", "PYTHONPATH": "canary",
             "PIP_TARGET": "canary", "PIP_USER": "canary", "UV_PUBLISH_TOKEN": "canary"}


# --- installer ----------------------------------------------------------------

@pytest.mark.parametrize("settings", [PRIVATE, OFFLINE], ids=["private-index", "offline"])
async def test_pip_child_gets_exactly_the_source_settings(monkeypatch, tmp_path, settings):
    for key in (*PRIVATE, *OFFLINE):
        monkeypatch.delenv(key, raising=False)
    for key, value in {**settings, **UNRELATED}.items():
        monkeypatch.setenv(key, value)
    assert get_tool("roadtools").package_env() == settings
    names = sorted({*PRIVATE, *OFFLINE, *UNRELATED})
    code = f"import os\nfor k in {names!r}:\n    if k in os.environ: print(k + '=' + os.environ[k])"
    lines = []
    rc = await stream_process([sys.executable, "-c", code], get_tool("roadtools").package_env(),
                              lines.append, cwd=tmp_path)
    assert rc == 0 and dict(line.split("=", 1) for line in lines) == settings


@pytest.mark.parametrize("name", ["scubagear", "maester", "monkey365", "hawk"])
def test_pip_settings_never_reach_powershell(monkeypatch, name):
    monkeypatch.setenv("PIP_INDEX_URL", INDEX)
    assert get_tool(name).package_env() == {}


def test_pip_settings_never_reach_tools_or_discovery(monkeypatch):
    for key, value in {**PRIVATE, **OFFLINE}.items():
        monkeypatch.setenv(key, value)
    assert not process_env.child_env().keys() & {*PRIVATE, *OFFLINE}


async def test_index_credentials_are_redacted_from_installer_output(monkeypatch, tmp_path):
    monkeypatch.setenv("PIP_INDEX_URL", INDEX)
    lines = []
    await stream_process([sys.executable, "-c", f"print('Looking in {INDEX}')"], {}, lines.append,
                         process_env.url_credentials(), tmp_path)
    assert "index-password" not in lines[0] and "pypi.corp.invalid" in lines[0]


def test_token_only_index_credential_is_redacted(monkeypatch):
    monkeypatch.setenv("PIP_INDEX_URL", "https://abcdef-token@pypi.corp.invalid/simple")
    assert "abcdef-token" in process_env.url_credentials()


def test_pip_cannot_be_shadowed_from_the_working_directory(roadtools_mechanics):
    for argv in (get_tool("roadtools").install_command(), get_tool("roadtools").uninstall_command()):
        assert argv[:4] == [sys.executable, "-I", "-m", "pip"]


@pytest.mark.parametrize("action", ["install", "update"])
async def test_installer_passes_the_settings_through(monkeypatch, roadtools_mechanics, action):
    calls = []

    async def record(argv, env, on_line, secrets=None, cwd=None, **kwargs):
        calls.append((argv, env, secrets))
        return 0

    for key, value in {**OFFLINE, "PIP_INDEX_URL": INDEX}.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(installer, "stream_process", record)
    monkeypatch.setattr(installer, "prereq_report", list)
    monkeypatch.setattr(installer.InstallerScreen, "refresh_versions", lambda self: None)
    monkeypatch.setattr("orbit.tui.screens.onboarding.has_saved_credentials", lambda: True)
    app = OrbitApp(dry_run=False)
    async with app.run_test(size=(120, 60)) as pilot:
        app.push_screen("installer")
        await pilot.pause()
        app.screen.query_one(f"#{action}-roadtools").press()
        for _ in range(100):
            await pilot.pause(0.05)
            if calls:
                break
    argv, env, secrets = calls[0]
    assert "roadrecon" in argv and "index-password" in secrets
    assert env["PIP_INDEX_URL"] == INDEX and env["PIP_FIND_LINKS"] == OFFLINE["PIP_FIND_LINKS"]


# --- preflight ----------------------------------------------------------------

class EmptyStore:
    def __init__(self, *args):
        pass

    def load(self, name):
        return {}


@pytest.fixture()
def check(tmp_path, manifest_file, private_tmp, monkeypatch):
    exe = (tmp_path / "interpreter").resolve()
    exe.write_text("fake")
    exe.chmod(0o755)
    pinned, installs = Executable.capture(exe), {}

    def install(name, version="2.0"):
        root = (tmp_path / "installs" / name).resolve()
        root.mkdir(parents=True)
        (root / "module.psd1").write_text(name)
        installs[name] = Installation(version, root, root / "module.psd1", pinned)
        return root

    def discover(self):
        if self.name not in installs:
            raise DiscoveryError("not installed")
        return installs[self.name]

    monkeypatch.setattr(base.Tool, "discover", discover)
    monkeypatch.setattr(preflight, "SecretStore", EmptyStore)
    monkeypatch.setattr(preflight, "check_platform",
                        lambda: PlatformInfo("windows", None, (7, 4), compat_flags("windows", True)))

    def run(*names, output=None):
        state = SessionState(selected=set(names))
        state.output.base_dir = output or tmp_path / "out"
        return {label: (ok, detail) for ok, label, detail in preflight.run_preflight(state)}

    run.install, run.record = install, manifest_file
    return run


def _integrity(rows):
    return {label: ok for label, (ok, _) in rows.items() if label.endswith("integrity")}


def test_each_tool_and_version_gets_its_own_answer(check):
    ready = check.install("maester")
    check.record("maester", "2.0", hash_tree(ready))
    other_version = check.install("hawk")
    check.record("hawk", "1.0", hash_tree(other_version))  # a baseline, but not for this version
    changed = check.install("monkey365")
    check.record("monkey365", "2.0", hash_tree(changed))
    (changed / "module.psd1").write_text("changed")
    rows = check("maester", "hawk", "monkey365", "scubagear")
    assert _integrity(rows) == {
        "Maester 2.0 integrity": True, "Hawk 2.0 integrity": False,
        "Monkey365 2.0 integrity": False, "ScubaGear (unknown version) integrity": False,
    }
    assert "no manifest entry" in rows["Hawk 2.0 integrity"][1]
    assert "FAILED" in rows["Monkey365 2.0 integrity"][1]


def test_another_tools_baseline_does_not_make_a_tool_ready(check):
    check.record("maester", "2.0", hash_tree(check.install("maester")))
    check.install("hawk")
    assert _integrity(check("hawk")) == {"Hawk 2.0 integrity": False}


def test_readiness_includes_the_snapshot_step(check, private_tmp):
    check.record("maester", "2.0", hash_tree(check.install("maester")))
    private_tmp.chmod(0o777)
    try:
        assert not any(_integrity(check("maester")).values())
    finally:
        private_tmp.chmod(0o700)


def test_readiness_includes_the_token_location(check, private_tmp, roadtools_mechanics):
    check.record("roadtools", "2.0", hash_tree(check.install("roadtools")))
    rows = _integrity(check("roadtools", output=private_tmp))
    assert rows == {"ROADtools 2.0 integrity": False}


def test_preflight_leaves_no_snapshot(check, private_tmp):
    check.record("maester", "2.0", hash_tree(check.install("maester")))
    assert all(_integrity(check("maester")).values())
    assert list(private_tmp.iterdir()) == []


async def test_preflight_rechecks_after_a_selection_change(tmp_path, monkeypatch):
    seen = []
    monkeypatch.setattr(preflight, "run_preflight",
                        lambda state: seen.append(set(state.selected)) or [])
    monkeypatch.setattr("orbit.tui.screens.onboarding.has_saved_credentials", lambda: True)
    app = OrbitApp(dry_run=False)
    async with app.run_test(size=(120, 60)) as pilot:
        for selection in ({"maester"}, {"hawk"}):
            app.state.selected = selection
            app.push_screen("preflight")
            await pilot.pause(0.2)
            app.pop_screen()
            await pilot.pause()
    assert seen == [{"maester"}, {"hawk"}]


async def test_preflight_renders_names_from_disk_as_plain_text(monkeypatch):
    hostile = "[@click=app.quit]click[/] [/oops]"
    monkeypatch.setattr(preflight, "run_preflight", lambda state: [(False, "integrity", hostile)])
    monkeypatch.setattr("orbit.tui.screens.onboarding.has_saved_credentials", lambda: True)
    app = OrbitApp(dry_run=False)
    async with app.run_test(size=(120, 60)) as pilot:
        app.push_screen("preflight")
        await pilot.pause(0.3)
        assert hostile in str(app.screen.query_one(".chk-row").render())

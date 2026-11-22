"""Finding 6: dry-run reaches no credential store, email, process, installation or network."""
import asyncio
import shutil
import smtplib
import socket
import subprocess
import sys
import urllib.request
from types import ModuleType, SimpleNamespace

import keyring
import pytest
from click.testing import CliRunner
from textual.widgets import Button, Input

from orbit import cli
from orbit.core import config_store, emailer, hash_checker, headless, notify, platform_check, secrets
from orbit.core.tools import all_tools, base
from orbit.tui.app import OrbitApp
from orbit.tui.screens import home, installer, onboarding, preflight
from orbit.tui.state import SessionState


@pytest.fixture()
def touched(monkeypatch):
    """Trip-wires on every boundary. They record, because some callers swallow exceptions."""
    calls = []

    def wire(owner, name):
        def tripped(*args, **kwargs):
            calls.append(f"{getattr(owner, '__name__', owner)}.{name}")
            raise AssertionError(f"dry-run reached {name}")
        monkeypatch.setattr(owner, name, tripped)

    # credentials
    wire(secrets.SecretStore, "__init__")
    for name in ("get_keyring", "get_password", "set_password", "delete_password"):
        wire(keyring, name)
    wire(onboarding, "has_saved_credentials")
    # email and notifications
    for name in ("load_settings", "send_results", "send_test", "_deliver"):
        wire(emailer, name)
    wire(smtplib, "SMTP")
    wire(smtplib, "SMTP_SSL")
    wire(notify, "notify_complete")
    plyer = ModuleType("plyer")
    plyer.notification = SimpleNamespace(notify=lambda **kw: calls.append("plyer.notify"))
    monkeypatch.setitem(sys.modules, "plyer", plyer)
    # processes, installations, PowerShell
    wire(subprocess, "Popen")
    wire(subprocess, "run")
    wire(asyncio, "create_subprocess_exec")
    wire(shutil, "which")
    for name in ("discover", "installed_version", "latest_version", "install_command",
                 "uninstall_command"):
        wire(base.Tool, name)
    for module in (platform_check, home, installer, preflight):
        wire(module, "check_platform")
    for module in (hash_checker, installer, preflight):
        wire(module, "verify_tool")
    wire(hash_checker, "load_manifest")
    # network
    wire(socket, "create_connection")
    wire(urllib.request, "urlopen")
    wire(home, "check_latest")

    # every switch that would cause an external effect in a real run is on
    config_store.update("notifications", os_notify=True, email_notify=True, update_check=True)
    config_store.update("email", enabled=True, smtp_host="smtp.invalid", to_addresses=["to@example.com"])
    return calls


@pytest.fixture()
def app(touched, tmp_path):
    app = OrbitApp(dry_run=True)
    app.state.output.base_dir = tmp_path / "out"
    return app


async def test_startup_and_home_probe_nothing(app, touched):
    async with app.run_test(size=(120, 60)) as pilot:
        await pilot.pause(0.3)
        assert type(app.screen).__name__ == "HomeScreen"
        app.screen.on_screen_resume()
        await pilot.pause(0.2)
    assert touched == []


async def test_onboarding_probes_and_saves_nothing(app, touched):
    config_store.update("app", first_run=True)
    async with app.run_test(size=(120, 60)) as pilot:
        await pilot.pause()
        assert isinstance(app.screen, onboarding.OnboardingScreen)
        await pilot.click("#next-1")
        app.screen.query_one("#wiz-tenant", Input).value = "synthetic-tenant"
        app.screen.query_one("#wiz-app", Input).value = "synthetic-app"
        await pilot.click("#next-2")
        await pilot.pause()
    assert touched == []


async def test_credentials_screen_cannot_save(app, touched):
    async with app.run_test(size=(120, 60)) as pilot:
        app.push_screen("credentials")
        await pilot.pause()
        screen = app.screen
        saves = [b for b in screen.query(Button) if (b.id or "").startswith("save--")]
        assert saves and all(b.disabled for b in saves)
        screen.on_button_pressed(Button.Pressed(saves[0]))  # the handler refuses as well
        await pilot.pause()
    assert touched == []


async def test_email_screen_cannot_read_save_or_send(app, touched):
    async with app.run_test(size=(120, 60)) as pilot:
        app.push_screen("email")
        await pilot.pause()
        for name in ("email-save", "email-test"):
            button = app.screen.query_one(f"#{name}", Button)
            assert button.disabled
            app.screen.on_button_pressed(Button.Pressed(button))
        app.screen._send_test(emailer.EmailSettings())
        await pilot.pause(0.2)
    assert touched == []


async def test_every_installer_action_is_disabled_and_refused(app, touched):
    async with app.run_test(size=(120, 60)) as pilot:
        app.push_screen("installer")
        await pilot.pause()
        screen = app.screen
        buttons = list(screen.query(Button))
        assert len(buttons) == 3 * len(all_tools()) + 3 and all(b.disabled for b in buttons)
        for button in buttons:
            screen.on_button_pressed(Button.Pressed(button))
        for action in ("install", "update", "uninstall"):
            screen._run(all_tools()[0], action)
            await pilot.pause(0.05)
        screen._install_opa()
        await screen._execute(["never-started"], "direct", {})
        await pilot.pause(0.3)
    assert touched == []


async def test_preflight_probes_nothing(app, touched):
    app.state.selected = {t.name for t in all_tools()}
    async with app.run_test(size=(120, 60)) as pilot:
        app.push_screen("preflight")
        await pilot.pause(0.5)
        assert app.screen.query(".chk-row")
    assert touched == []
    assert preflight.run_preflight(SessionState(dry_run=True, output=app.state.output))
    assert touched == []


async def test_completed_run_sends_no_email_or_notification(app, touched):
    app.state.selected = {"scubagear", "maester"}
    async with app.run_test(size=(120, 60)) as pilot:
        app.push_screen("run")
        await pilot.pause()
        screen = app.screen
        checkbox = screen.query_one("#email-run")
        assert checkbox.disabled and not checkbox.value
        checkbox.value = True  # even if it were switched on
        screen.start_run()
        for _ in range(100):
            await pilot.pause(0.05)
            if "Done." in str(screen.query_one("#result").render()) and screen._executing is None:
                break
        else:
            raise AssertionError("run did not finish")
        assert screen._email([], [], []) is False
    assert touched == []


async def test_every_screen_opens_without_probing(app, touched):
    async with app.run_test(size=(120, 60)) as pilot:
        await pilot.pause()
        for name in OrbitApp.SCREENS:
            app.push_screen(name)
            await pilot.pause(0.1)
            app.pop_screen()
    assert touched == []


def test_headless_probes_nothing(touched, tmp_path):
    config_store.update("output", directory=str(tmp_path / "out"))
    payload, code = headless.run_headless(True, [t.name for t in all_tools()])
    assert code == 0 and payload["dry_run"]
    assert touched == []


def test_list_tools_probes_nothing(touched):
    result = CliRunner().invoke(cli.main, ["--dry-run", "--list-tools"])
    assert result.exit_code == 0 and "not probed" in result.output
    assert touched == []


def test_the_tripwires_would_catch_a_real_start(touched):
    with pytest.raises(AssertionError):
        onboarding.should_show(False)
    assert touched
    touched.clear()
    assert onboarding.should_show(True) in (True, False) and touched == []

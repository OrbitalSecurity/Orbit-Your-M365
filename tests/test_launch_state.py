"""Finding 8: launched means created; displayed, executed and recorded tool sets are the same."""
import asyncio
import sys
import threading

import pytest

from orbit.core import config_store, headless, history, runner
from orbit.core.hash_checker import HashResult, HashStatus
from orbit.core.runner import Runner, RunError, RunStatus, stream_process
from orbit.core.tools import all_tools, get_tool
from orbit.tui.app import OrbitApp
from orbit.tui.screens import run as run_screen

CREATION_ERRORS = [FileNotFoundError("no such file"), PermissionError("not executable"),
                   OSError(8, "Exec format error"), ValueError("embedded null byte"),
                   NotImplementedError("no subprocess support")]


@pytest.fixture()
def prepared(bound, monkeypatch):
    """Every requested tool verifies; no store is opened."""
    def prepare(tools, open_store, workspace):
        return [bound(t.name) for t in tools], {}, {}

    monkeypatch.setattr(headless, "prepare_run", prepare)
    monkeypatch.setattr(run_screen, "prepare_run", prepare)


@pytest.fixture()
def after_run(monkeypatch):
    calls = []

    def record(folder, used, *args, **kwargs):
        calls.append(("finalize", list(used)))
        return [], []

    monkeypatch.setattr(headless, "finalize", record)
    monkeypatch.setattr(run_screen, "finalize", record)
    monkeypatch.setattr(run_screen.notify, "notify_complete", lambda *a: calls.append(("notify",)))
    monkeypatch.setattr(run_screen.RunScreen, "_email",
                        lambda self, findings, written, tools: calls.append(
                            ("email", [t.display for t in tools])) or True)
    return calls


@pytest.fixture()
def app(tmp_path, monkeypatch):
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


def _shown(screen):
    return {t.name for t in all_tools() if screen.query_one(f"#tool-{t.name}").display}


def _created(monkeypatch, names=None):
    """Creation succeeds for names (all if None) and fails for the rest."""
    launched = []

    async def fake(argv, env, on_line, *args, on_start=None, **kwargs):
        tool = next(t.name for t in all_tools() if f"{t.package}.psd1" in env.get("ORBIT_MODULE", ""))
        if names is not None and tool not in names:
            raise PermissionError("not executable")
        on_start()
        launched.append(tool)
        return 0

    monkeypatch.setattr(runner, "stream_process", fake)
    return launched


# --- process creation -------------------------------------------------------

@pytest.mark.parametrize("error", CREATION_ERRORS, ids=lambda e: type(e).__name__)
async def test_failed_creation_is_not_a_launch(tmp_path, bound, monkeypatch, error):
    async def fail(*argv, **kwargs):
        raise error

    monkeypatch.setattr(runner.asyncio, "create_subprocess_exec", fail)
    r = Runner(tmp_path / "o", {}, hash_results=[bound("hawk")])
    run = (await r.run_all([get_tool("hawk")]))["hawk"]
    assert run.status is RunStatus.FAILED and not run.launched and run.started is None
    assert run.note.startswith("could not start") and "Cannot launch" in run.log[-1]


async def test_launched_is_set_only_after_creation(tmp_path, bound, monkeypatch):
    r = Runner(tmp_path / "o", {}, hash_results=[bound("hawk")])
    seen = []

    async def create(*argv, **kwargs):
        seen.append((r.runs["hawk"].launched, r.runs["hawk"].status))
        raise OSError("stop here")

    monkeypatch.setattr(runner.asyncio, "create_subprocess_exec", create)
    await r.run_tool(get_tool("hawk"))
    assert seen == [(False, RunStatus.PENDING)]


async def test_launch_spec_failure_is_not_a_launch(tmp_path, bound, monkeypatch):
    def broken(*args):
        raise RuntimeError("cannot build the command")

    tool = get_tool("hawk")
    monkeypatch.setattr(tool, "launch_spec", broken)
    run = await Runner(tmp_path / "o", {}, hash_results=[bound("hawk")]).run_tool(tool)
    assert run.status is RunStatus.FAILED and not run.launched


async def test_failure_message_is_redacted(tmp_path, bound, monkeypatch):
    async def fail(*argv, **kwargs):
        raise OSError("bad value TOP-SECRET-VALUE")

    monkeypatch.setattr(runner.asyncio, "create_subprocess_exec", fail)
    r = Runner(tmp_path / "o", {}, {"hawk": ["TOP-SECRET-VALUE"]}, False, [bound("hawk")])
    run = await r.run_tool(get_tool("hawk"))
    assert "TOP-SECRET-VALUE" not in run.note + "".join(run.log)


def test_headless_failed_creation_has_no_report_or_history(
        tmp_path, prepared, after_run, monkeypatch, caplog):
    _created(monkeypatch, names=())
    config_store.update("output", directory=str(tmp_path / "out"))
    payload, code = headless.run_headless(False, ["hawk"])
    assert code == 1 and payload["failed_tools"] == ["hawk"]
    assert "could not start" in payload["launch_failures"]["hawk"]
    assert "Cannot launch" in caplog.text  # surfaced on stderr
    assert after_run == [] and history.read() == []


def test_headless_reports_only_tools_that_started(tmp_path, prepared, after_run, monkeypatch):
    _created(monkeypatch, names=("maester",))
    config_store.update("output", directory=str(tmp_path / "out"))
    payload, code = headless.run_headless(False, ["maester", "hawk"])
    assert code == 1 and list(payload["launch_failures"]) == ["hawk"]
    assert after_run == [("finalize", ["Maester"])]


async def test_tui_failed_creation_has_no_report_notification_or_email(
        app, prepared, after_run, monkeypatch):
    _created(monkeypatch, names=())
    async with app.run_test(size=(120, 60)) as pilot:
        app.push_screen("run")
        await pilot.pause()
        screen = app.screen
        screen.query_one("#email-run").value = True
        screen.start_run()
        await _until(pilot, lambda: "FAILED" in str(screen.query_one("#result").render()))
        assert "could not start" in str(screen.query_one("#status-maester").render())
    assert after_run == [] and history.read() == []


async def test_tui_email_and_report_name_only_tools_that_started(
        app, prepared, after_run, monkeypatch):
    _created(monkeypatch, names=("maester",))
    app.state.selected = {"maester", "hawk"}
    async with app.run_test(size=(120, 60)) as pilot:
        app.push_screen("run")
        await pilot.pause()
        screen = app.screen
        screen.query_one("#email-run").value = True
        screen.start_run()
        await _until(pilot, lambda: ("email", ["Maester"]) in after_run)
        assert "Not launched: Hawk" in str(screen.query_one("#result").render())
    assert ("finalize", ["Maester"]) in after_run


# --- unexpected exceptions --------------------------------------------------

async def test_unexpected_task_exception_is_raised_after_the_others_finish(tmp_path, monkeypatch):
    finished = []

    async def run_tool(self, tool):
        if tool.name == "maester":
            raise KeyError("bug")
        await asyncio.sleep(0.05)
        finished.append(tool.name)

    monkeypatch.setattr(Runner, "run_tool", run_tool)
    r = Runner(tmp_path, {})
    with pytest.raises(RunError) as info:
        await r.run_all([get_tool("maester"), get_tool("hawk")])
    assert isinstance(info.value.__cause__, KeyError) and finished == ["hawk"]
    assert r.runs["maester"].status is RunStatus.FAILED


async def test_error_after_launch_is_not_swallowed(tmp_path, bound, monkeypatch):
    async def fake(argv, env, on_line, *args, on_start=None, **kwargs):
        on_start()
        raise LookupError("reader broke")

    monkeypatch.setattr(runner, "stream_process", fake)
    r = Runner(tmp_path / "o", {}, hash_results=[bound("hawk")])
    with pytest.raises(RunError):
        await r.run_all([get_tool("hawk")])


def test_headless_unexpected_exception_writes_no_report(tmp_path, prepared, after_run, monkeypatch):
    async def broken(self, tool):
        raise KeyError("bug")

    monkeypatch.setattr(Runner, "run_tool", broken)
    config_store.update("output", directory=str(tmp_path / "out"))
    with pytest.raises(headless.HeadlessError, match="unexpectedly"):
        headless.run_headless(False, ["hawk"])
    assert after_run == []


async def test_tui_unexpected_exception_is_shown_without_a_report(
        app, prepared, after_run, monkeypatch):
    async def broken(self, tool):
        raise KeyError("bug")

    monkeypatch.setattr(Runner, "run_tool", broken)
    async with app.run_test(size=(120, 60)) as pilot:
        app.push_screen("run")
        await pilot.pause()
        screen = app.screen
        screen.start_run()
        await _until(pilot, lambda: "RUN FAILED" in str(screen.query_one("#result").render()))
        assert app.state.run_folder is None
    assert after_run == []


async def test_stop_before_the_task_begins_is_not_an_error(tmp_path):
    r = Runner(tmp_path, {}, hash_results=[HashResult("hawk", "1", HashStatus.UNVERIFIED)])
    task = asyncio.create_task(r.run_all([get_tool("hawk")]))
    await asyncio.sleep(0)
    r.stop_all()
    run = (await task)["hawk"]
    assert run.status in (RunStatus.FAILED, RunStatus.SKIPPED) and not run.launched


async def test_child_is_stopped_when_reading_fails(tmp_path):
    handle = {}

    def fail(line):
        raise RuntimeError("log sink failed")

    with pytest.raises(RuntimeError):
        await stream_process([sys.executable, "-c", "import time;print(1,flush=True);time.sleep(60)"],
                             {}, fail, cwd=tmp_path, handle=handle)
    assert handle["proc"].returncode is not None


async def test_long_output_line_does_not_fail_the_run(tmp_path):
    lines = []
    rc = await stream_process([sys.executable, "-c", "print('x' * 300000)"], {}, lines.append,
                              cwd=tmp_path)
    assert rc == 0 and lines == ["x" * 300000]


# --- selection ----------------------------------------------------------------

@pytest.mark.parametrize("before, after", [
    ({"maester"}, {"hawk"}), ({"maester"}, {"maester", "hawk", "monkey365"}),
    ({"maester", "hawk"}, {"maester"}), (set(), {"hawk"}),
])
async def test_selection_change_syncs_display_execution_and_record(
        app, prepared, after_run, monkeypatch, before, after):
    launched = _created(monkeypatch)
    app.state.selected = set(before)
    async with app.run_test(size=(120, 60)) as pilot:
        app.push_screen("run")
        await pilot.pause()
        screen = app.screen
        assert _shown(screen) == before
        app.pop_screen()
        await pilot.pause()
        app.state.selected = set(after)
        app.push_screen("run")
        await pilot.pause()
        assert app.screen is screen and _shown(screen) == after  # the cached screen followed
        screen.start_run()
        await _until(pilot, lambda: "Done." in str(screen.query_one("#result").render()))
        assert _shown(screen) == after and set(app.state.runs) == after
    assert set(launched) == after
    assert set(after_run[0][1]) == {get_tool(name).display for name in after}


async def test_second_run_records_only_its_own_tools(app, prepared, after_run, monkeypatch):
    launched = _created(monkeypatch)
    async with app.run_test(size=(120, 60)) as pilot:
        app.push_screen("run")
        await pilot.pause()
        screen = app.screen
        for name in ("maester", "hawk"):
            app.pop_screen()
            app.state.selected = {name}
            app.push_screen("run")
            await pilot.pause()
            screen.start_run()
            await _until(pilot, lambda name=name: launched[-1:] == [name] and screen._executing is None)
            assert set(app.state.runs) == _shown(screen) == {name}
    assert [c[1] for c in after_run if c[0] == "finalize"] == [["Maester"], ["Hawk"]]


async def test_selection_changed_during_a_run_does_not_alter_that_run(
        app, bound, after_run, monkeypatch):
    launched = _created(monkeypatch)
    entered, release = threading.Event(), threading.Event()

    def slow(tools, open_store, workspace):
        entered.set()
        release.wait(5)
        return [bound(t.name) for t in tools], {}, {}

    monkeypatch.setattr(run_screen, "prepare_run", slow)
    async with app.run_test(size=(120, 60)) as pilot:
        app.push_screen("run")
        await pilot.pause()
        screen = app.screen
        screen.start_run()
        await _until(pilot, entered.is_set)
        app.pop_screen()
        app.state.selected = {"hawk"}
        app.push_screen("run")
        await pilot.pause()
        assert _shown(screen) == {"maester"}  # still that run's tools
        release.set()
        await _until(pilot, lambda: screen._executing is None)
        assert set(app.state.runs) == {"maester"} and launched == ["maester"]
        app.pop_screen()
        app.push_screen("run")
        await pilot.pause()
        assert _shown(screen) == {"hawk"}

"""Async subprocess runner for PowerShell and Python tools.

Secrets reach child processes only through environment variables (never argv) and every
output line is redacted before it is surfaced.
"""
from __future__ import annotations

import asyncio
import contextlib
import errno
import shutil
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from orbit.config import FIXTURES_DIR
from orbit.core.hash_checker import Binding, HashResult, HashStatus, launch_binding, verify_tool
from orbit.core.process_env import child_env, no_terminal
from orbit.core.secrets import SecretStore, redact
from orbit.core.tools.base import Tool
from orbit.core.workspace import Workspace
from orbit.security.auth_material import purge_auth_material, redact_tokens

LineCb = Callable[[str], None]
_LINE_LIMIT = 16 * 1024 * 1024  # the asyncio default (64 KiB) fails on long JSON lines


def token_location_error(tool: Tool, binding: Binding, output_base: Path) -> str:
    """Why this launch could leave tokens in the output tree, or '' if it cannot."""
    if tool.auth_material and binding.private_dir.resolve().is_relative_to(output_base.resolve()):
        return ("the temporary directory is inside the output directory; "
                "choose another output directory")
    return ""


def _failure_reason(exc: Exception) -> str:
    """Classify without quoting: notes are serialised, and error text can hold paths or secrets."""
    # a hand-built OSError can carry any errno (even an unhashable one), so only look up integers
    code = (errno.errorcode.get(exc.errno)
            if isinstance(exc, OSError) and isinstance(exc.errno, int) else None)
    return f"{type(exc).__name__} ({code})" if code else type(exc).__name__


class RunError(Exception):
    """A task failed unexpectedly, so the run's results must not be reported."""


class RunStatus(str, Enum):
    PENDING = "Pending"
    RUNNING = "Running"
    COMPLETE = "Complete"
    FAILED = "Failed"
    SKIPPED = "Skipped"


@dataclass
class ToolRun:
    tool: Tool
    status: RunStatus = RunStatus.PENDING
    progress: float = 0.0
    started: float | None = None
    finished: float | None = None
    log: list[str] = field(default_factory=list)
    output_dir: Path | None = None
    note: str = ""

    @property
    def launched(self) -> bool:
        """True only once the process exists (or, in dry-run, playback has begun)."""
        return self.started is not None

    @property
    def elapsed(self) -> float:
        if self.started is None:
            return 0.0
        return (self.finished or time.monotonic()) - self.started


async def stream_process(argv: list[str], env: dict[str, str], on_line: LineCb | None,
                         secrets: list[str] | None = None, cwd: Path | None = None,
                         handle: dict | None = None,
                         on_start: Callable[[], None] | None = None) -> int:
    """Run argv with env overlay, stream redacted merged output; terminate on cancellation.

    ``on_start`` is called once, and only after the process has been created.
    With ``on_line`` None the output is discarded by the OS and never enters ORBIT's memory,
    and the child gets no terminal, for children whose diagnostics may contain secrets that
    cannot be recognised.

    The subprocess receives ONLY the variables in ``env`` plus the runtime allowlist in
    ``orbit.core.process_env`` (PATH, HOME, SYSTEMROOT, TEMP, proxy settings …).
    The full parent-process environment is deliberately NOT inherited so that
    tokens, cloud-provider credentials, or LD_PRELOAD values in the calling
    shell cannot leak into child processes.
    """
    secrets = secrets or []
    if on_line is None:
        streams = dict.fromkeys(("stdin", "stdout", "stderr"), asyncio.subprocess.DEVNULL)
        streams.update(no_terminal())
    else:
        streams = {"stdout": asyncio.subprocess.PIPE, "stderr": asyncio.subprocess.STDOUT}
    proc = await asyncio.create_subprocess_exec(
        *argv, **streams, env=child_env(env), cwd=str(cwd) if cwd else None, limit=_LINE_LIMIT,
    )
    try:
        if handle is not None:
            handle["proc"] = proc
        if on_start is not None:
            on_start()
        if on_line is not None:
            assert proc.stdout is not None
            async for raw in proc.stdout:
                on_line(redact_tokens(redact(raw.decode(errors="replace").rstrip(), secrets)))
        return await proc.wait()
    finally:
        if proc.returncode is None:  # cancelled, or reading failed: never leave the child running
            await _terminate(proc)


async def _terminate(proc: asyncio.subprocess.Process) -> None:
    with contextlib.suppress(ProcessLookupError):
        proc.terminate()
    try:
        await asyncio.wait_for(proc.wait(), 5)
    except asyncio.TimeoutError:
        pass
    finally:
        if proc.returncode is None:
            with contextlib.suppress(ProcessLookupError):
                proc.kill()
            with contextlib.suppress(asyncio.TimeoutError):  # a grandchild may hold the pipe open
                await asyncio.wait_for(proc.wait(), 5)


def prepare_run(tools: list[Tool], open_store: Callable[[], SecretStore], workspace: Workspace,
                ) -> tuple[list[HashResult], dict[str, dict], dict[str, list[str]]]:
    """Shared by TUI and headless: verify and snapshot first, then read secrets only for those."""
    results = [verify_tool(t, workspace) for t in tools]
    creds: dict[str, dict] = {}
    secrets: dict[str, list[str]] = {}
    verified = [t for t in tools if launch_binding([r for r in results if r.tool == t.name])[0]]
    if verified and not workspace.closed:
        store = open_store()
        for t in verified:
            creds[t.name] = store.load(t.name)
            secrets[t.name] = store.secret_values(t.name)
    return results, creds, secrets


class Runner:
    def __init__(self, out_dir: Path, creds: dict[str, dict], secrets: dict[str, list[str]] | None = None,
                 dry_run: bool = False, hash_results: list[HashResult] | None = None,
                 fixtures_dir: Path = FIXTURES_DIR,
                 on_update: Callable[[ToolRun], None] | None = None):
        self.out_dir = out_dir
        # Fixture playback never holds credentials.
        self.creds = {} if dry_run else creds
        self.secrets = {} if dry_run else secrets or {}
        self.dry_run = dry_run
        self.hash_results = hash_results or []
        self.fixtures_dir = fixtures_dir
        self.on_update = on_update or (lambda r: None)
        self.runs: dict[str, ToolRun] = {}
        self._tasks: dict[str, asyncio.Task] = {}

    def _emit(self, run: ToolRun, line: str | None = None) -> None:
        if line is not None:
            run.log.append(line)
        self.on_update(run)

    def _started(self, run: ToolRun) -> None:
        run.status, run.started = RunStatus.RUNNING, time.monotonic()
        self._emit(run)

    def _block(self, run: ToolRun, note: str, message: str) -> ToolRun:
        run.status, run.note = RunStatus.SKIPPED, note
        self._emit(run, "BLOCKED: " + message)
        return run

    async def run_tool(self, tool: Tool) -> ToolRun:
        run = self.runs.setdefault(tool.name, ToolRun(tool))
        run.output_dir = self.out_dir / tool.name
        secrets = self.secrets.get(tool.name, [])
        binding: Binding | None = None
        try:
            if self.dry_run:
                run.output_dir.mkdir(parents=True, exist_ok=True)
                self._started(run)
                rc = await self._dry(tool, run)
            else:
                relevant = [r for r in self.hash_results if r.tool == tool.name]
                binding, msg = launch_binding(relevant)
                if tool.real_run_block:
                    return self._block(run, "real run disabled",
                                       f"{tool.display}: {tool.real_run_block}")
                if binding is None:
                    mismatch = any(r.status is HashStatus.MISMATCH for r in relevant)
                    note = "hash mismatch" if mismatch else "integrity unverified"
                    return self._block(run, note, msg)
                if binding.tool != tool.name:
                    return self._block(run, "integrity unverified", "binding is for another tool")
                if problem := token_location_error(tool, binding, self.out_dir.resolve().parent):
                    return self._block(run, "unsafe token location", problem)
                try:
                    await asyncio.to_thread(binding.verify)
                except Exception as exc:
                    return self._block(run, "integrity changed",
                                       f"re-check before launch failed: {exc}")
                run.output_dir.mkdir(parents=True, exist_ok=True)
                spec = tool.launch_spec(self.creds.get(tool.name, {}), run.output_dir, binding)
                if spec.argv[0] != str(binding.executable.path):
                    return self._block(run, "integrity unverified",
                                       "the launch does not use the verified executable")
                rc = await stream_process(spec.argv, spec.env, lambda line: self._emit(run, line),
                                          secrets, spec.cwd, None,
                                          on_start=lambda: self._started(run))
            run.status = RunStatus.COMPLETE if rc == 0 else RunStatus.FAILED
            run.progress = 100.0 if rc == 0 else run.progress
        except asyncio.CancelledError:
            run.status, run.note = RunStatus.FAILED, "stopped by user"
            self._emit(run, "Stopped by user")
        except Exception as exc:
            run.status = RunStatus.FAILED
            if run.launched:  # unexpected: run_all reports it, and no results are published
                run.note = f"unexpected error: {type(exc).__name__}"
                raise
            run.note = f"could not start: {_failure_reason(exc)}"
            detail = redact_tokens(redact(str(exc) or type(exc).__name__, secrets))
            self._emit(run, f"Cannot launch: {detail}")
        finally:
            self._cleanup(tool, run, binding)
            if run.launched:
                run.finished = time.monotonic()
            self._emit(run)
        return run

    def _cleanup(self, tool: Tool, run: ToolRun, binding: Binding | None) -> None:
        """Synchronous, so that cancellation cannot interrupt it."""
        if binding is None:
            return
        released = binding.release()
        if not released:
            run.log.append("WARNING: the private snapshot directory could not be removed")
        if not tool.auth_material:
            return
        try:
            removed = purge_auth_material(self.out_dir, tool.name)
        except (OSError, ValueError):
            removed, released = [], False
        if removed:
            run.log.append(f"Removed {len(removed)} authentication file(s) from the output folder")
        if not released:
            run.status, run.note = RunStatus.FAILED, "authentication cleanup failed"

    async def _dry(self, tool: Tool, run: ToolRun) -> int:
        steps = [f"(DRY RUN) Simulating {tool.display}", "(DRY RUN) Authenticating (skipped)",
                 "(DRY RUN) Collecting configuration (fixture playback)"]
        for i, line in enumerate(steps, 1):
            self._emit(run, line)
            run.progress = i / (len(steps) + 1) * 100
            await asyncio.sleep(0.05)
        if tool.fixture and (self.fixtures_dir / tool.fixture).exists():
            shutil.copy(self.fixtures_dir / tool.fixture, run.output_dir / tool.output_name)
            self._emit(run, f"(DRY RUN) Wrote {tool.output_name}")
        else:
            self._emit(run, "(DRY RUN) No fixture for this tool; nothing to play back")
        return 0

    async def run_all(self, tools: list[Tool]) -> dict[str, ToolRun]:
        for t in tools:
            self.runs.setdefault(t.name, ToolRun(t))
        for t in tools:
            self._tasks[t.name] = asyncio.create_task(self.run_tool(t))
        outcomes = await asyncio.gather(*self._tasks.values(), return_exceptions=True)
        failure: tuple[Tool, BaseException] | None = None
        for tool, outcome in zip(tools, outcomes):
            if not isinstance(outcome, BaseException):
                continue
            run = self.runs[tool.name]
            run.status = RunStatus.FAILED
            if isinstance(outcome, asyncio.CancelledError):  # stopped before it began
                run.note = run.note or "stopped by user"
            else:
                run.note = run.note or f"unexpected error: {type(outcome).__name__}"
                failure = failure or (tool, outcome)
        if failure:
            tool, exc = failure
            raise RunError(
                f"{tool.display} failed unexpectedly ({type(exc).__name__}); no report was written"
            ) from exc
        return self.runs

    def stop(self, name: str) -> None:
        task = self._tasks.get(name)
        if task and not task.done():
            task.cancel()

    def stop_all(self) -> None:
        for name in list(self._tasks):
            self.stop(name)

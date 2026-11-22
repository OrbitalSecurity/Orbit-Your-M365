"""Resolve interpreters once, to an absolute path, and detect a later swap."""
from __future__ import annotations

import functools
import os
import re
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from orbit.core.process_env import child_env
from orbit.core.safe_fs import sha256_file

_VERSION_SCRIPT = "[Console]::Out.WriteLine('PWSH|' + $PSVersionTable.PSVersion.ToString())"


class ExecutableError(Exception):
    """No single trustworthy executable could be resolved, or it changed afterwards."""


@dataclass(frozen=True)
class Executable:
    path: Path
    sha256: str

    @classmethod
    def capture(cls, path: Path) -> Executable:
        if not path.is_absolute():
            raise ExecutableError(f"executable path is not absolute: {str(path)!r}")
        try:
            digest = sha256_file(path)  # refuses a link, or anything but an ordinary file
        except (OSError, ValueError) as exc:
            raise ExecutableError(f"cannot read {str(path)!r}: {type(exc).__name__}") from exc
        # Windows has no execute bit; os.access would report every existing file as executable
        if sys.platform != "win32" and not os.access(path, os.X_OK):
            raise ExecutableError(f"{str(path)!r} is not executable")
        return cls(path, digest)

    def verify(self) -> None:
        """Repeat every check made by capture, and require the same content."""
        if Executable.capture(self.path) != self:
            raise ExecutableError(f"{str(self.path)!r} changed after it was resolved")


def find_pwsh() -> Path:
    """The single pwsh on PATH, as an absolute path with links resolved.

    shutil.which is not used: on Windows it searches the current directory first, and
    everywhere it accepts relative PATH entries.
    """
    name = "pwsh.exe" if sys.platform == "win32" else "pwsh"
    found: set[Path] = set()
    for raw in os.environ.get("PATH", "").split(os.pathsep):
        directory = Path(raw.strip('"'))  # an empty entry means the current directory
        candidate = directory / name
        try:
            present = candidate.is_file() and os.access(candidate, os.X_OK)
        except OSError:
            continue
        if not present:
            continue
        if not directory.is_absolute():
            raise ExecutableError("pwsh is reachable through a relative PATH entry")
        try:
            found.add(candidate.resolve(strict=True))
        except (OSError, RuntimeError) as exc:
            raise ExecutableError(f"cannot resolve {str(candidate)!r}") from exc
    if not found:
        raise ExecutableError("PowerShell 7 (pwsh) not found")
    if len(found) != 1:
        raise ExecutableError("more than one pwsh is on PATH, so the choice is ambiguous")
    path = found.pop()
    if path.name.lower() != name:
        raise ExecutableError(f"pwsh resolves to {path.name!r}, which is not PowerShell itself")
    if sys.platform != "win32":
        try:
            shared = (path.stat().st_mode | path.parent.stat().st_mode) & stat.S_IWOTH
        except OSError as exc:
            raise ExecutableError("cannot inspect pwsh") from exc
        if shared:
            raise ExecutableError("pwsh or its directory is writable by any user")
    return path


@functools.lru_cache(maxsize=16)  # keyed by path and content hash
def pwsh_version(exe: Executable) -> tuple[int, ...]:
    try:
        proc = subprocess.run(
            [str(exe.path), "-NoProfile", "-NonInteractive", "-Command", _VERSION_SCRIPT],
            capture_output=True, text=True, errors="replace", timeout=20, env=child_env(),
            cwd=exe.path.parent, stdin=subprocess.DEVNULL,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ExecutableError(f"pwsh could not run ({type(exc).__name__})") from exc
    match = re.search(r"^PWSH\|(\d+(?:\.\d+)*)", proc.stdout, re.MULTILINE)
    if proc.returncode != 0 or not match:
        raise ExecutableError("pwsh did not report a version")
    return tuple(int(n) for n in match.group(1).split("."))


def resolve_pwsh() -> Executable:
    """The approved PowerShell 7 executable for discovery, launch and OPA initialisation."""
    exe = Executable.capture(find_pwsh())
    if pwsh_version(exe) < (7,):
        raise ExecutableError("PowerShell 7 or later is required")
    exe.verify()
    return exe


def base_python() -> Executable:
    """The base interpreter, so that launch never depends on a venv's pyvenv.cfg or site hooks."""
    try:
        path = Path(getattr(sys, "_base_executable", None) or sys.executable).resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ExecutableError("cannot resolve the Python interpreter") from exc
    return Executable.capture(path)

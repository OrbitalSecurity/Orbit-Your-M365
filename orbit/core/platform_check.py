"""OS detection, PowerShell version check and per-tool compatibility flags."""
from __future__ import annotations

import platform
from dataclasses import dataclass, field

from orbit.core.executables import Executable, ExecutableError, find_pwsh, pwsh_version


@dataclass
class PlatformInfo:
    os_name: str
    pwsh_path: str | None
    pwsh_version: tuple[int, ...] | None
    compat: dict[str, bool] = field(default_factory=dict)
    pwsh_error: str = ""

    @property
    def pwsh7(self) -> bool:
        return bool(self.pwsh_version and self.pwsh_version[0] >= 7)


def detect_os() -> str:
    return {"Windows": "windows", "Darwin": "macos", "Linux": "linux"}.get(
        platform.system(), "other"
    )


def compat_flags(os_name: str, pwsh7: bool) -> dict[str, bool]:
    """ScubaGear is Windows-only; Maester/Monkey365/Hawk need PowerShell 7; ROADtools is Python."""
    return {
        "scubagear": os_name == "windows" and pwsh7,
        "maester": pwsh7,
        "monkey365": pwsh7,
        "hawk": pwsh7,
        "roadtools": True,
    }


def check_platform() -> PlatformInfo:
    os_name = detect_os()
    path, ver, error = None, None, ""
    try:
        exe = Executable.capture(find_pwsh())
        path = str(exe.path)
        ver = pwsh_version(exe)
    except ExecutableError as exc:
        error = str(exc)
    info = PlatformInfo(os_name, path, ver, pwsh_error=error)
    info.compat = compat_flags(os_name, info.pwsh7)
    return info

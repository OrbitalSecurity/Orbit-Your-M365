"""Abstract Tool: install metadata, version detection, launch command, credential env mapping."""
from __future__ import annotations

import re
import subprocess
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING

from orbit.core.executables import ExecutableError, resolve_pwsh
from orbit.core.platform_check import PlatformInfo, detect_os
from orbit.core.process_env import child_env, no_terminal, pip_source_env
from orbit.core.tools.discovery import (
    DiscoveryError,
    Installation,
    find_ps_module,
    find_python_package,
)

if TYPE_CHECKING:
    from orbit.core.hash_checker import Binding

# Import exactly the verified file. Without the catch, a failed import would carry on and
# auto-load whichever copy of the module is first on PSModulePath.
IMPORT_VERIFIED = (
    "$env:PSModulePath = $env:ORBIT_MODULE_PATH + [IO.Path]::PathSeparator + $env:PSModulePath; "
    "try { Import-Module -Name $env:ORBIT_MODULE -ErrorAction Stop } "
    "catch { [Console]::Error.WriteLine('Verified module import failed: ' + $_); exit 1 }; "
)


class ToolStatus(str, Enum):
    INSTALLED = "installed"
    NOT_INSTALLED = "not_installed"
    UPDATE = "update_available"
    INCOMPATIBLE = "incompatible"


STATUS_GLYPH = {
    ToolStatus.INSTALLED: "[green]✓ installed[/green]",
    ToolStatus.NOT_INSTALLED: "[red]✗ not installed[/red]",
    ToolStatus.UPDATE: "[yellow]↑ update available[/yellow]",
    ToolStatus.INCOMPATIBLE: "[yellow]⚠ incompatible OS[/yellow]",
}


@dataclass
class LaunchSpec:
    """argv contains NO secrets; secrets travel only in env."""
    argv: list[str]
    env: dict[str, str]
    cwd: Path | None = None


def ver_tuple(v: str | None) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", v or ""))


def run_capture(argv: list[str], timeout: int = 60, env: dict[str, str] | None = None) -> str:
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                              stdin=subprocess.DEVNULL, env=child_env(env),
                              **no_terminal()).stdout.strip()
    except Exception:
        return ""


class Tool(ABC):
    name: str            # key, e.g. "scubagear"
    display: str
    github: str
    route: str           # "psgallery" | "pypi"
    package: str         # PS module name or pip package
    needs_admin: bool = False
    needs_pwsh: bool = True
    supported_os: tuple[str, ...] = ("windows", "macos", "linux")
    fixture: str = ""    # dry-run fixture filename in orbit/data/fixtures
    output_name: str = ""  # file the tool writes inside its output dir
    import_root: str = ""  # pypi: top-level import directory covered by the hash manifest
    import_package: str = ""  # pypi: package expected inside import_root
    auth_material: bool = False  # writes sign-in tokens, which must stay out of the output tree
    real_run_block: str = ""  # why this tool is dry-run only. Not a setting: there is no override.

    @property
    def label(self) -> str:
        return f"{self.display} (dry-run only)" if self.real_run_block else self.display

    # --- compatibility / version ----------------------------------------
    def compatible(self, platform: PlatformInfo) -> bool:
        return platform.compat.get(self.name, False) and platform.os_name in self.supported_os

    def discover(self) -> Installation:
        """Locate the installation that a launch would use, without executing it."""
        if detect_os() not in self.supported_os:
            raise DiscoveryError("unsupported on this operating system")
        if self.route == "psgallery":
            return find_ps_module(self.package)
        if self.route == "pypi" and self.import_root:
            return find_python_package(self.package, self.import_root, self.import_package)
        raise DiscoveryError("installation discovery is not supported for this tool")

    def installed_version(self) -> str | None:
        try:
            return self.discover().version
        except DiscoveryError:
            return None

    def latest_version(self) -> str | None:
        """Ask PSGallery via pwsh, never ORBIT itself. Other routes have no version probe."""
        if self.route != "psgallery":
            return None
        try:
            pw = resolve_pwsh().path
        except ExecutableError:
            return None
        found = run_capture(ps_command(pw, f"(Find-Module {self.package}).Version.ToString()"))
        # warnings and errors share stdout and can quote repository credentials
        return found if re.fullmatch(r"[0-9]+(\.[0-9]+){1,3}", found) else None

    def status(self, platform: PlatformInfo, installed: str | None = None,
               latest: str | None = None) -> ToolStatus:
        if not self.compatible(platform):
            return ToolStatus.INCOMPATIBLE
        if installed is None:
            return ToolStatus.NOT_INSTALLED
        if latest and ver_tuple(latest) > ver_tuple(installed):
            return ToolStatus.UPDATE
        return ToolStatus.INSTALLED

    # --- install ----------------------------------------------------------
    def package_env(self) -> dict[str, str]:
        return pip_source_env() if self.route == "pypi" else {}

    def install_command(self, update: bool = False) -> list[str]:
        """Raises ExecutableError rather than fall back to a bare command name."""
        if self.real_run_block:  # installing it would imply that a real run works
            raise ExecutableError(f"{self.display}: {self.real_run_block}")
        if self.route == "psgallery":
            verb = "Update-Module" if update else "Install-Module"
            extra = "" if update else " -Scope CurrentUser -Force"
            # non-interactive: installer output is withheld, so nobody could see a prompt
            return ps_command(resolve_pwsh().path, f"{verb} -Name {self.package}{extra}")
        return [*_pip(), "install", "--upgrade", self.package]

    def uninstall_command(self) -> list[str] | None:
        """Return argv to uninstall this tool, or None if manual removal required."""
        if self.route == "psgallery":
            return ps_command(resolve_pwsh().path,
                              f"Uninstall-Module -Name {self.package} -AllVersions -Force")
        return [*_pip(), "uninstall", "-y", self.package]

    # --- run ----------------------------------------------------------------
    @abstractmethod
    def launch_spec(self, creds: dict, out_dir: Path, binding: Binding) -> LaunchSpec:
        """Build argv (secret-free) and env (carries secrets). Uses only what ``binding`` names."""

    def ps_launch(self, script: str, env: dict[str, str], cwd: Path,
                  binding: Binding) -> LaunchSpec:
        if binding.entry is None:
            raise ExecutableError("the verified snapshot has no module to import")
        env = {**env, "ORBIT_MODULE": str(binding.entry),
               "ORBIT_MODULE_PATH": str(binding.search_path)}
        return LaunchSpec(ps_command(binding.executable.path, IMPORT_VERIFIED + script), env, cwd)


def _pip() -> list[str]:
    # -I: a pip.py in the current directory or on PYTHONPATH must not become the installer.
    # It does not affect PIP_* variables or pip's configuration files.
    return [sys.executable, "-I", "-m", "pip"]


def ps_command(pwsh: Path, script: str) -> list[str]:
    if not pwsh.is_absolute():
        raise ExecutableError("PowerShell must be launched by absolute path")
    return [str(pwsh), "-NoProfile", "-NonInteractive", "-Command", script]


def cred_env(prefix: str, creds: dict) -> dict[str, str]:
    """Map credential fields to ORBIT_<PREFIX>_<FIELD> env vars (only non-empty values)."""
    return {f"ORBIT_{prefix}_{k.upper()}": str(v) for k, v in creds.items()
            if v not in (None, "", False)}

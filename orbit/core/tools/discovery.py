"""Locate installed tools without importing or executing their code."""
from __future__ import annotations

import base64
import csv
import re
import subprocess
import sysconfig
from dataclasses import dataclass
from email.parser import HeaderParser
from pathlib import Path

from orbit.core.executables import Executable, ExecutableError, base_python, resolve_pwsh
from orbit.core.process_env import child_env
from orbit.core.safe_fs import read_below

# Auto-loading is off and only Core cmdlets / .NET are used, so no user module runs during discovery.
_PS_FIND = (
    "$PSModuleAutoLoadingPreference = 'None'; "
    "$found = @(Get-Module -ListAvailable -Name '{package}'); "
    "foreach ($m in $found) {{ [Console]::Out.WriteLine('ORBIT|' + $m.Version.ToString() + '|' + "
    "[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($m.Path))) }}"
)
_DIST_INFO = ".dist-info"
_REQUIREMENT = re.compile(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[([^\]]*)\])?")
_EXTRA_MARKER = re.compile(r"""\bextra\s*==\s*['"]([^'"]+)['"]""")


class DiscoveryError(Exception):
    """The installation could not be identified unambiguously."""


@dataclass(frozen=True)
class Installation:
    version: str
    root: Path                  # every covered file is below this directory
    entry: Path | None = None   # exact module manifest to import (PowerShell tools)
    executable: Executable | None = None      # the only interpreter a launch may use
    members: tuple[str, ...] | None = None    # covered entries of a shared root; None = all of it
    strict_member: str = ""                   # member in which even __pycache__ is covered


def _query(pwsh: Executable, script: str) -> str:
    try:
        proc = subprocess.run(
            [str(pwsh.path), "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, errors="replace", timeout=60,
            env=child_env(), cwd=pwsh.path.parent, stdin=subprocess.DEVNULL,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise DiscoveryError(f"discovery could not run ({type(exc).__name__})") from exc
    if proc.returncode != 0:
        raise DiscoveryError("not installed, or discovery failed")
    return proc.stdout


def find_ps_module(package: str) -> Installation:
    """Highest installed version; the same version in two places is ambiguous."""
    try:
        pwsh = resolve_pwsh()
    except ExecutableError as exc:
        raise DiscoveryError(str(exc)) from exc
    out = _query(pwsh, _PS_FIND.format(package=package))
    found: set[Installation] = set()
    try:
        for line in out.splitlines():
            if not line.startswith("ORBIT|"):
                continue
            _, version, encoded = line.split("|")
            path = Path(base64.b64decode(encoded, validate=True).decode("utf-8"))
            if not path.is_absolute():
                raise DiscoveryError(f"{package} was reported at a relative path")
            if path.name.lower() != f"{package}.psd1".lower():
                raise DiscoveryError(f"{package} has no module manifest to pin the import to")
            root = path.parent.resolve(strict=True)
            if any(c in str(root) for c in "[]*?`"):
                # Import-Module expands wildcards and could load a directory we did not hash.
                raise DiscoveryError("install path contains PowerShell wildcard characters")
            found.add(Installation(version, root, root / path.name, pwsh))
    except (OSError, RuntimeError, ValueError) as exc:  # RuntimeError: link loop before 3.13
        raise DiscoveryError("unreadable module discovery result") from exc
    if not found:
        raise DiscoveryError("not installed")

    def key(inst: Installation) -> tuple[int, ...]:
        return tuple(int(n) for n in re.findall(r"\d+", inst.version))

    newest = max(key(i) for i in found)
    candidates = [i for i in found if key(i) == newest]
    if len(candidates) != 1:
        raise DiscoveryError("the same version is installed in more than one location")
    return candidates[0]


def site_dir() -> Path:
    """The one site-packages directory of ORBIT's environment."""
    found = {Path(sysconfig.get_path(k)).resolve(strict=True) for k in ("purelib", "platlib")}
    if len(found) != 1:
        raise DiscoveryError("separate pure and platform site-packages directories are unsupported")
    return found.pop()


def _canonical(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def find_python_package(dist: str, namespace: str, subpackage: str) -> Installation:
    """The package and its installed dependency closure, found by reading metadata files only.

    No interpreter is started, so no .pth, sitecustomize, usercustomize or package code runs.
    Launch uses the base interpreter without site processing, so everything that is imported
    from outside the standard library has to be in this file set.
    """
    try:
        site = site_dir()
        installed: dict[str, list[str]] = {}
        for path in site.iterdir():
            if path.name.endswith(_DIST_INFO):
                name = path.name[:-len(_DIST_INFO)].rpartition("-")[0]
                installed.setdefault(_canonical(name), []).append(path.name)
        if _canonical(dist) not in installed:
            raise DiscoveryError("not installed in ORBIT's Python environment")

        version = ""
        members: set[str] = {namespace}
        done: set[tuple[str, frozenset[str]]] = set()
        pending = [(_canonical(dist), frozenset())]
        while pending:
            item = pending.pop()
            if item in done:
                continue
            done.add(item)
            name, extras = item
            infos = installed[name]
            if len(infos) != 1:
                raise DiscoveryError(f"{name} has more than one installation record")
            info = infos[0]
            meta = HeaderParser().parsestr(read_below(site, f"{info}/METADATA")[0].decode("utf-8"))
            if name == _canonical(dist):
                version = meta.get("Version", "")

            members.add(info)
            record = read_below(site, f"{info}/RECORD")[0].decode("utf-8").splitlines()
            for row in csv.reader(record):
                top = row[0].replace("\\", "/").split("/")[0] if row else ""
                # outside site-packages, cache, or start-up hook: not imported at launch
                # strip(): Windows also reads '.. ' and '...' as the directory above
                if (not top.strip(" .") or top == "__pycache__" or ":" in top
                        or top.endswith(".pth")):
                    continue
                members.add(top)

            for requirement in meta.get_all("Requires-Dist") or []:
                spec, _, marker = requirement.partition(";")
                match = _REQUIREMENT.match(spec)
                if not match:
                    raise DiscoveryError(f"unreadable dependency of {name}")
                wanted = set(_EXTRA_MARKER.findall(marker))
                if wanted and not {_canonical(e) for e in wanted} & extras:
                    continue
                dependency = _canonical(match[1])
                if dependency in installed:
                    pending.append((dependency, frozenset(
                        _canonical(e.strip()) for e in (match[2] or "").split(",") if e.strip())))
                elif not marker.strip():
                    raise DiscoveryError(
                        f"dependency {dependency} is not installed in ORBIT's Python environment")

        if not version:
            raise DiscoveryError(f"{dist} has no version")
        if not (site / namespace / subpackage).is_dir():
            raise DiscoveryError(f"{namespace}.{subpackage} not found")
        python = base_python()
    except ExecutableError as exc:
        raise DiscoveryError(str(exc)) from exc
    except (OSError, RuntimeError, ValueError, csv.Error) as exc:
        raise DiscoveryError("unreadable package installation") from exc
    return Installation(version, site, executable=python, members=tuple(sorted(members)),
                        strict_member=namespace)

"""Minimal environment for child processes (tools, installers, installation discovery)."""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

# os.environ upper-cases names on Windows; on POSIX names are case-sensitive.
# Deliberately absent: tokens, cloud credentials, and code-injection variables such as
# PSMODULEPATH, PYTHONPATH, LD_PRELOAD and DYLD_*.
_PASSTHROUGH = frozenset({
    # common / POSIX
    "PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "LC_CTYPE", "TERM", "TZ", "TMPDIR",
    "XDG_CACHE_HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME",
    # Linux desktop session, needed for browser sign-in and token caches
    "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS", "DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY",
    # Windows: process start-up, .NET, known folders
    "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "COMSPEC", "PATHEXT", "OS", "TEMP", "TMP",
    "USERPROFILE", "USERNAME", "USERDOMAIN", "COMPUTERNAME", "HOMEDRIVE", "HOMEPATH",
    "APPDATA", "LOCALAPPDATA", "PROGRAMDATA", "ALLUSERSPROFILE", "PUBLIC",
    "PROGRAMFILES", "PROGRAMFILES(X86)", "PROGRAMW6432",
    "COMMONPROGRAMFILES", "COMMONPROGRAMFILES(X86)", "COMMONPROGRAMW6432",
    "PROCESSOR_ARCHITECTURE", "NUMBER_OF_PROCESSORS",
    # corporate proxy and CA configuration
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
    "http_proxy", "https_proxy", "all_proxy", "no_proxy",
    "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE",
})

# Given to pip only: where packages come from and how to reach that source. Index URLs may carry
# credentials, so these never reach a tool, PowerShell, or discovery.
_PIP_SOURCE = frozenset({
    "PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "PIP_NO_INDEX", "PIP_FIND_LINKS", "PIP_CONFIG_FILE",
    "PIP_TRUSTED_HOST", "PIP_CERT", "PIP_CLIENT_CERT", "PIP_PROXY",
    "XDG_CONFIG_DIRS",  # where pip looks for a site-wide pip.conf
})
# pip copies what it prints to a configured log, and signed URLs into its cache.
PIP_NO_RECORDS = {"PIP_LOG": os.devnull, "PIP_NO_CACHE_DIR": "1"}
_URL_VARS = ("PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "PIP_FIND_LINKS", "PIP_PROXY",
             "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy")


def child_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    """Allowlisted parent variables plus the caller's explicit overlay."""
    env = {k: v for k, v in os.environ.items() if k in _PASSTHROUGH}
    # A relative or empty PATH entry would let the child's working directory supply a program.
    path = [p for p in env.pop("PATH", "").split(os.pathsep) if p and Path(p).is_absolute()]
    if path:
        env["PATH"] = os.pathsep.join(path)
    if sys.platform == "win32":
        env["NoDefaultCurrentDirectoryInExePath"] = "1"
    return {**env, **(extra or {})}


def no_terminal() -> dict[str, Any]:
    """Spawn options for a child whose output is withheld.

    Redirected streams are not enough: a child can write to /dev/tty or CONOUT$ directly.
    """
    if sys.platform == "win32":
        return {"creationflags": 0x08000000}  # CREATE_NO_WINDOW
    return {"start_new_session": True}


def pip_source_env() -> dict[str, str]:
    """Overlay for pip: deliberate index, mirror and offline settings."""
    return {k: v for k, v in os.environ.items() if k in _PIP_SOURCE}


def url_credentials() -> list[str]:
    """Credentials embedded in package or proxy URLs, for redaction from installer output."""
    found: list[str] = []
    for name in _URL_VARS:
        for url in os.environ.get(name, "").split():
            try:
                parts = urlsplit(url)
                if "@" in parts.netloc:
                    found.append(parts.netloc.rpartition("@")[0])
                    found.append(parts.password or parts.username or "")
            except ValueError:
                found.append(url)
    return [f for f in found if f]

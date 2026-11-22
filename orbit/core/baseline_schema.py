"""Schema v2 of the integrity baseline: the only content that may authorise a run.

``parse_baseline`` is the single place that decides whether bytes are an acceptable baseline. It
looks at *content* only, never at a file name or location, so a baseline written before schema 2
(a copied checkout manifest, an interim build's file, the packaged template) is refused wherever
it sits. A baseline is accepted only when it is a strictly validated schema-2 document that was
generated for the current principal and, on Windows, the current machine.

The schema is closed: an unknown key, a wrong type or an extra field is an error, never ignored.
Forward compatibility is by raising ``schema``.

Binding
    ``binding.principal`` is ``sha256("orbit-baseline-v2|principal|" + P)`` where P is the token user
    SID string on Windows and ``"uid:" + str(os.geteuid())`` on POSIX. ``binding.machine`` is
    ``sha256("orbit-baseline-v2|machine|" + MachineGuid)`` on Windows (64-bit registry view) and
    JSON ``null`` on POSIX. Only hashes are stored, so a baseline attached to a bug report does not
    disclose the SID or machine GUID. The hash is not a secret and not an authenticator: a process
    of the same user can compute it. It stops *accidental* trust of a baseline recorded for
    someone else. It does not change the retained limitation that a same-user process can edit
    the baseline and the tools alike.

The Windows identity readers here only *retrieve identity* (token user SID, MachineGuid). They are
not the secure-state backend and read no file, owner or ACL. They have not been run on Windows; the
logic around them is tested with injected sources and byte buffers only.

Error messages are fixed text. They never contain baseline content, a SID, a machine id or a path.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import struct
import sys
from dataclasses import dataclass
from enum import Enum
from typing import Any

SCHEMA = 2
KIND = "orbit.integrity-baseline"
MAX_BYTES = 16 * 1024 * 1024  # larger input is refused before it is parsed
_MAX_NEWER_SHOWN = 9999       # a newer schema number is printed only when it is this small
_MAX_NAME = 256               # tool name or version key
_MAX_PATH = 32768             # a file key or install_dir
_MAX_GENERATOR = 64

_TOP_KEYS = frozenset({"schema", "kind", "binding", "generator", "tools"})
_BINDING_KEYS = frozenset({"os", "principal", "machine"})
_OS_CLASSES = ("win32", "posix")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_DRIVE = re.compile(r"[A-Za-z]:")
_PRINCIPAL_DOMAIN = "orbit-baseline-v2|principal|"
_MACHINE_DOMAIN = "orbit-baseline-v2|machine|"


class ErrorCode(str, Enum):
    TOO_LARGE = "too_large"
    NOT_JSON = "not_json"
    NOT_OBJECT = "not_object"
    LEGACY = "legacy"
    NEWER = "newer"
    MALFORMED = "malformed"
    BINDING_MISSING = "binding_missing"
    BINDING_MISMATCH = "binding_mismatch"
    ENTRY_MALFORMED = "entry_malformed"
    BINDING_UNAVAILABLE = "binding_unavailable"


_DAMAGED = ("the baseline is damaged or not in the expected format. Move it aside and run "
            "orbit-generate-hashes.")
MESSAGES: dict[ErrorCode, str] = {
    ErrorCode.LEGACY: (
        "the baseline is in the older unbound format (schema 1). ORBIT does not trust or import "
        "it, wherever it came from. Move it aside and run orbit-generate-hashes to record a new "
        "baseline for this user and machine."),
    ErrorCode.NEWER: (
        "the baseline was written by a newer ORBIT. Update ORBIT, or move the file aside and "
        "run orbit-generate-hashes."),
    ErrorCode.BINDING_MISSING: (
        "the baseline carries no user and machine binding, so it cannot be trusted (it may be the "
        "packaged template or an older file). Run orbit-generate-hashes."),
    ErrorCode.BINDING_MISMATCH: (
        "the baseline was recorded for a different user or computer. Run orbit-generate-hashes to "
        "record one for this user and machine; a baseline is never copied between accounts."),
    ErrorCode.BINDING_UNAVAILABLE: (
        "the identity of this user or computer could not be established, so a baseline cannot "
        "be checked or recorded."),
    **{code: _DAMAGED for code in (ErrorCode.MALFORMED, ErrorCode.ENTRY_MALFORMED,
                                   ErrorCode.NOT_JSON, ErrorCode.NOT_OBJECT, ErrorCode.TOO_LARGE)},
}


class BaselineError(Exception):
    """A baseline (or template) was rejected. ``str(exc)`` is fixed text; ``code`` is stable."""

    def __init__(self, code: ErrorCode, newer: int | None = None) -> None:
        self.code = code
        message = MESSAGES[code]
        if code is ErrorCode.NEWER and newer is not None and 0 < newer <= _MAX_NEWER_SHOWN:
            message = message.replace("newer ORBIT.", f"newer ORBIT (schema {newer}).")
        super().__init__(message)


class BindingUnavailable(BaselineError):
    """The current principal or machine identity could not be established (fail closed)."""

    def __init__(self) -> None:
        super().__init__(ErrorCode.BINDING_UNAVAILABLE)


# --- binding ---------------------------------------------------------------------

@dataclass(frozen=True)
class Binding:
    os: str                # "win32" or "posix"
    principal: str         # 64 lowercase hex
    machine: str | None    # 64 lowercase hex on win32, None on posix

    def to_json(self) -> dict[str, Any]:
        return {"os": self.os, "principal": self.principal, "machine": self.machine}


def _sha256(domain: str, value: str) -> str:
    return hashlib.sha256((domain + value).encode("utf-8")).hexdigest()


def binding_for(os_class: str, principal_source: str, machine_source: str | None) -> Binding:
    """The hashed binding for raw identity values. Pure: no platform access."""
    if os_class == "win32":
        if not principal_source or not machine_source:
            raise BindingUnavailable
        return Binding("win32", _sha256(_PRINCIPAL_DOMAIN, principal_source),
                       _sha256(_MACHINE_DOMAIN, machine_source))
    if os_class == "posix":
        if not principal_source or machine_source is not None:
            raise BindingUnavailable
        return Binding("posix", _sha256(_PRINCIPAL_DOMAIN, principal_source), None)
    raise BindingUnavailable


def _platform_class() -> str:
    return "win32" if sys.platform == "win32" else "posix"


def _posix_principal() -> str:
    geteuid = getattr(os, "geteuid", None)
    if geteuid is None:
        raise BindingUnavailable
    return f"uid:{geteuid()}"


def sid_to_string(sid: bytes) -> str:
    """``S-1-5-21-...`` from the binary SID, or ValueError. Pure Python, no Windows API."""
    if len(sid) < 8 or sid[0] != 1:  # header: revision 1, sub-authority count, 6-byte authority
        raise ValueError("unsupported SID")
    count = sid[1]
    if not 1 <= count <= 15 or len(sid) != 8 + 4 * count:
        raise ValueError("unsupported SID")
    authority = int.from_bytes(sid[2:8], "big")
    first = str(authority) if authority < 2**32 else f"0x{authority:012X}"
    subs = struct.unpack_from(f"<{count}I", sid, 8)
    return "S-1-" + "-".join([first, *map(str, subs)])


def token_user_sid(buffer: bytes, base_address: int) -> str:
    """The SID string inside a ``TOKEN_USER`` buffer that ``GetTokenInformation`` filled.

    The structure starts with a pointer to the SID, which lies in the same buffer at
    ``base_address``. The pointer is only followed inside the buffer; anything else is an error.
    """
    width = struct.calcsize("P")
    if len(buffer) < 2 * width:
        raise ValueError("short token buffer")
    (pointer,) = struct.unpack_from("P", buffer, 0)
    offset = pointer - base_address
    if offset < 2 * width or offset >= len(buffer):
        raise ValueError("SID outside the token buffer")
    if len(buffer) - offset < 8:
        raise ValueError("short SID")
    length = 8 + 4 * buffer[offset + 1]
    return sid_to_string(buffer[offset:offset + length])


def _windows_token_sid() -> str:
    """The SID of the user in this process's access token (not ``USERNAME``, not the profile)."""
    import ctypes
    from ctypes import wintypes

    TOKEN_QUERY, TOKEN_USER_CLASS, INSUFFICIENT_BUFFER = 0x8, 1, 122
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)  # type: ignore[attr-defined]
    kernel32.GetCurrentProcess.argtypes = []
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD,
                                          ctypes.POINTER(wintypes.HANDLE)]
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p,
                                             wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    advapi32.GetTokenInformation.restype = wintypes.BOOL

    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), TOKEN_QUERY,
                                     ctypes.byref(token)):
        raise BindingUnavailable
    try:
        needed = wintypes.DWORD(0)
        advapi32.GetTokenInformation(token, TOKEN_USER_CLASS, None, 0, ctypes.byref(needed))
        if ctypes.get_last_error() != INSUFFICIENT_BUFFER or not 0 < needed.value <= 4096:
            raise BindingUnavailable
        buffer = ctypes.create_string_buffer(needed.value)
        if not advapi32.GetTokenInformation(token, TOKEN_USER_CLASS, buffer, needed.value,
                                            ctypes.byref(needed)):
            raise BindingUnavailable
        return token_user_sid(buffer.raw[:needed.value], ctypes.addressof(buffer))
    finally:
        kernel32.CloseHandle(token)


def _windows_machine_guid() -> str:
    """``MachineGuid`` from the 64-bit registry view. Any failure or odd value fails closed."""
    import winreg

    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography", 0,
                            winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
            value, kind = winreg.QueryValueEx(key, "MachineGuid")
    except OSError as exc:
        raise BindingUnavailable from exc
    if kind != winreg.REG_SZ or not isinstance(value, str) or not value.strip() \
            or len(value) > 128 or "\0" in value:
        raise BindingUnavailable
    return value


def current_binding() -> Binding:
    """The binding this process would have generated, or BindingUnavailable (fail closed)."""
    try:
        if _platform_class() == "win32":
            return binding_for("win32", _windows_token_sid(), _windows_machine_guid())
        return binding_for("posix", _posix_principal(), None)
    except BindingUnavailable:
        raise
    except Exception as exc:  # ctypes, registry or struct trouble: never an unbound baseline
        raise BindingUnavailable from exc


# --- the validated baseline ------------------------------------------------------

_TOKEN = object()


class Baseline:
    """A baseline that ``parse_baseline`` validated for this user (and machine). Immutable.

    Authorisation code accepts only this type. It cannot be built from a plain dict; the
    constructor needs a token that only this module holds.
    """

    __slots__ = ("_tools", "binding", "generator")

    def __init__(self, token: object, binding: Binding, generator: str,
                 tools: dict[str, dict[str, dict[str, Any]]]) -> None:
        if token is not _TOKEN:
            raise TypeError("a Baseline can only be produced by parse_baseline")
        object.__setattr__(self, "binding", binding)
        object.__setattr__(self, "generator", generator)
        object.__setattr__(self, "_tools", tools)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("a Baseline is immutable")

    def files_for(self, tool: str, version: str) -> dict[str, str] | None:
        """A copy of the recorded {relative path: sha256} for one tool version, or None."""
        entry = self._tools.get(tool, {}).get(version)
        return dict(entry["files"]) if entry else None

    def to_document(self) -> dict[str, Any]:
        """A fresh, mutable copy of the whole document (for the writer to edit and re-validate)."""
        return {
            "schema": SCHEMA, "kind": KIND, "binding": self.binding.to_json(),
            "generator": {"orbit": self.generator},
            "tools": {t: {"versions": {v: {k: (dict(x) if k == "files" else x)
                                         for k, x in e.items()}
                                       for v, e in versions.items()}}
                      for t, versions in self._tools.items()},
        }

    def __repr__(self) -> str:  # never print entries, hashes or binding values
        return f"<Baseline schema={SCHEMA} tools={len(self._tools)}>"


# --- validation ------------------------------------------------------------------

def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _Duplicate
        result[key] = value
    return result


class _Duplicate(Exception):
    pass


def _reject_constant(_name: str) -> None:
    raise ValueError("non-finite number")


def _load_object(data: bytes) -> dict[str, Any]:
    if not isinstance(data, (bytes, bytearray)):
        raise BaselineError(ErrorCode.NOT_JSON)
    if len(data) > MAX_BYTES:
        raise BaselineError(ErrorCode.TOO_LARGE)
    try:
        doc = json.loads(bytes(data).decode("utf-8"), object_pairs_hook=_no_duplicates,
                         parse_constant=_reject_constant)
    except _Duplicate as exc:
        raise BaselineError(ErrorCode.MALFORMED) from exc
    except (ValueError, RecursionError, MemoryError) as exc:  # includes UnicodeDecodeError
        raise BaselineError(ErrorCode.NOT_JSON) from exc
    if not isinstance(doc, dict):
        raise BaselineError(ErrorCode.NOT_OBJECT)
    return doc


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _bounded_text(value: object, limit: int) -> bool:
    return (isinstance(value, str) and 0 < len(value) <= limit
            and not any(ord(c) < 0x20 or ord(c) == 0x7F for c in value))


def is_safe_relative_name(name: object) -> bool:
    """A recordable file key: relative, ``/``-separated, no traversal, drive, NUL or control."""
    if not isinstance(name, str) or not 0 < len(name) <= _MAX_PATH:
        return False
    if name.startswith("/") or "\\" in name or _DRIVE.match(name):
        return False
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in name):
        return False
    return all(part not in ("", ".", "..") for part in name.split("/"))


def _check_schema(doc: dict[str, Any]) -> None:
    """LEGACY and NEWER are decided here, on content, before anything else is looked at."""
    if "schema" not in doc:
        raise BaselineError(ErrorCode.LEGACY if "tools" in doc else ErrorCode.MALFORMED)
    schema = doc["schema"]
    if not _is_int(schema):  # bool, float, string, null, list ...
        raise BaselineError(ErrorCode.MALFORMED)
    if schema == 1:
        raise BaselineError(ErrorCode.LEGACY)
    if schema > SCHEMA:
        raise BaselineError(ErrorCode.NEWER, newer=schema)
    if schema != SCHEMA:
        raise BaselineError(ErrorCode.MALFORMED)


def _check_common(doc: dict[str, Any], allowed: frozenset[str]) -> None:
    if not set(doc) <= allowed or doc.get("kind") != KIND or not isinstance(doc.get("tools"), dict):
        raise BaselineError(ErrorCode.MALFORMED)
    if "generator" in doc:
        generator = doc["generator"]
        if (not isinstance(generator, dict) or set(generator) != {"orbit"}
                or not _bounded_text(generator["orbit"], _MAX_GENERATOR)):
            raise BaselineError(ErrorCode.MALFORMED)


def _check_binding_shape(binding: dict[str, Any]) -> Binding:
    if set(binding) != _BINDING_KEYS:
        raise BaselineError(ErrorCode.MALFORMED)
    os_class, principal, machine = binding["os"], binding["principal"], binding["machine"]
    if os_class not in _OS_CLASSES or not isinstance(principal, str) \
            or not _HEX64.fullmatch(principal):
        raise BaselineError(ErrorCode.MALFORMED)
    if os_class == "win32":
        if not isinstance(machine, str) or not _HEX64.fullmatch(machine):
            raise BaselineError(ErrorCode.MALFORMED)  # a Windows baseline is always machine-bound
    elif machine is not None:
        raise BaselineError(ErrorCode.MALFORMED)
    return Binding(os_class, principal, machine)


def _check_entries(tools: dict[str, Any]) -> dict[str, dict[str, dict[str, Any]]]:
    """Every tool, version and file key and digest; the first bad one rejects the whole baseline."""
    clean: dict[str, dict[str, dict[str, Any]]] = {}
    for name, entry in tools.items():
        if not _bounded_text(name, _MAX_NAME) or not isinstance(entry, dict) \
                or set(entry) != {"versions"} or not isinstance(entry["versions"], dict):
            raise BaselineError(ErrorCode.ENTRY_MALFORMED)
        versions: dict[str, dict[str, Any]] = {}
        for version, record in entry["versions"].items():
            if not _bounded_text(version, _MAX_NAME) or not isinstance(record, dict) \
                    or not set(record) <= {"install_dir", "files"} or "files" not in record:
                raise BaselineError(ErrorCode.ENTRY_MALFORMED)
            install_dir = record.get("install_dir", "")
            if ("install_dir" in record and not (isinstance(install_dir, str)
                    and len(install_dir) <= _MAX_PATH and "\0" not in install_dir)):
                raise BaselineError(ErrorCode.ENTRY_MALFORMED)
            files = record["files"]
            if not isinstance(files, dict) or not files:
                raise BaselineError(ErrorCode.ENTRY_MALFORMED)
            for rel, digest in files.items():
                if not is_safe_relative_name(rel) or not isinstance(digest, str) \
                        or not _HEX64.fullmatch(digest):
                    raise BaselineError(ErrorCode.ENTRY_MALFORMED)
            versions[version] = dict(record, files=dict(files))
        clean[name] = versions
    return clean


def parse_baseline(data: bytes, expected: Binding) -> Baseline:
    """Validate ``data`` as a schema-2 baseline for ``expected``; raise BaselineError otherwise.

    Order: size, JSON, object, LEGACY, NEWER, structure (kind, closed keys, types), binding
    present, binding matches, entries. Decided on content only, never on where it was found.
    """
    doc = _load_object(data)
    _check_schema(doc)
    _check_common(doc, _TOP_KEYS)
    binding_raw = doc.get("binding")
    if binding_raw is None or binding_raw == {}:
        raise BaselineError(ErrorCode.BINDING_MISSING)
    if not isinstance(binding_raw, dict):
        raise BaselineError(ErrorCode.MALFORMED)
    found = _check_binding_shape(binding_raw)
    if "generator" not in doc:
        raise BaselineError(ErrorCode.MALFORMED)  # an active baseline always names its writer
    if found != expected:
        raise BaselineError(ErrorCode.BINDING_MISMATCH)
    tools = _check_entries(doc["tools"])
    return Baseline(_TOKEN, found, doc["generator"]["orbit"], tools)


def parse_template(data: bytes) -> list[str]:
    """Validate the packaged template: schema 2, exact kind, empty tool version maps, nothing else.

    It carries no binding and no generator, so it can never be an active baseline. Returns the tool
    names. A template with entries, a binding or any other key is rejected.
    """
    doc = _load_object(data)
    _check_schema(doc)
    _check_common(doc, frozenset({"schema", "kind", "tools"}))
    tools = doc["tools"]
    for name, entry in tools.items():
        if not _bounded_text(name, _MAX_NAME) or entry != {"versions": {}}:
            raise BaselineError(ErrorCode.MALFORMED)
    return list(tools)


def baseline_from_template(template: bytes, binding: Binding, generator: str) -> Baseline:
    """The first baseline: the parsed template plus the current binding and generator."""
    names = parse_template(template)
    doc = {"schema": SCHEMA, "kind": KIND, "binding": binding.to_json(),
           "generator": {"orbit": generator},
           "tools": {name: {"versions": {}} for name in names}}
    return parse_baseline(dump_document(doc), binding)


def dump_document(doc: dict[str, Any]) -> bytes:
    """Deterministic bytes: sorted keys, two-space indent, UTF-8, trailing newline."""
    return (json.dumps(doc, indent=2, sort_keys=True) + "\n").encode("utf-8")


def dump_baseline(baseline: Baseline) -> bytes:
    """Deterministic bytes of a validated baseline; they re-parse to the same baseline."""
    return dump_document(baseline.to_document())


def revalidated(doc: dict[str, Any], expected: Binding) -> tuple[Baseline, bytes]:
    """Serialise a document the writer edited and prove it is still a valid baseline.

    The bytes returned are exactly what ``parse_baseline`` accepted, so the writer can never
    publish a file that the reader would refuse (or an unbound one).
    """
    data = dump_document(doc)
    return parse_baseline(data, expected), data

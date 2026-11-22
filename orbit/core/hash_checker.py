"""SHA-256 integrity checks of installed tool files against data/tool_hashes.json.

Fail closed: only an explicit OK result that is bound to a verified snapshot authorises a real
run, and there is no override.

The file set is every file below the discovered installation root, with no exclusions. Where an
installation is a set of members of a shared directory (Python site-packages), it is every file
below those members; only dependency __pycache__ directories are left out, and because they are
never copied into the snapshot they can never run.

Execution is bound to what was verified: the verified bytes are copied into a private read-only
snapshot, and launch uses only that snapshot and the executable resolved during discovery.

Threat model: this detects accidental changes, and unauthorised changes by other OS principals.
It does not resist a malicious process running as the same OS user, which can alter the manifest
and the runtime files alike. A match is neither authenticity nor provenance.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING

from orbit.config import DATA_DIR
from orbit.core.executables import Executable
from orbit.core.safe_fs import (
    create_file,
    has_download_mark,
    is_link,
    is_secret_name,
    read_below,
    sha256_file,
)
from orbit.core.workspace import Workspace

if TYPE_CHECKING:
    from orbit.core.tools.base import Tool
    from orbit.core.tools.discovery import Installation

MANIFEST_PATH = DATA_DIR / "tool_hashes.json"
_MAX_LISTED = 10


class HashStatus(str, Enum):
    OK = "ok"
    MISMATCH = "mismatch"
    UNVERIFIED = "unverified"  # no baseline, no installation found, or it could not be read


@dataclass(frozen=True)
class Binding:
    """Exactly what one verified launch uses. Launch code resolves nothing else."""
    tool: str
    version: str
    source: Path                        # installation that was verified
    root: Path                          # read-only snapshot of it
    search_path: Path                   # directory that name lookups must hit first
    entry: Path | None                  # module manifest inside the snapshot (PowerShell)
    executable: Executable
    files: tuple[tuple[str, str], ...]  # (relative path, sha256) of every snapshot file
    private_dir: Path                   # empty private directory for this launch
    slot: Path
    workspace: Workspace = field(repr=False, compare=False)

    def verify(self) -> None:
        """Called immediately before process creation; raises if anything has changed."""
        if self.workspace.closed:
            raise ValueError("the verified snapshot has been released")
        self.executable.verify()
        prefix = self.root.relative_to(self.search_path)
        expected = {(prefix / rel).as_posix(): digest for rel, digest in self.files}
        # all of the search path: a module planted beside the snapshot would win name lookups
        if hash_tree(self.search_path) != expected:
            raise ValueError("the verified snapshot changed")
        # a planted link here could redirect a token out of private storage
        if is_link(self.private_dir.lstat()) or any(self.private_dir.iterdir()):
            raise ValueError("the private directory is no longer empty")

    def release(self) -> bool:
        return self.workspace.release(self.slot)


@dataclass
class HashResult:
    tool: str
    version: str | None
    status: HashStatus
    mismatches: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    unexpected: list[str] = field(default_factory=list)
    reason: str = ""
    files: dict[str, str] = field(default_factory=dict, repr=False)  # set only when OK
    binding: Binding | None = None  # set only when verified for launch

    @property
    def entry(self) -> Path | None:
        return self.binding.entry if self.binding else None

    @property
    def blocks_run(self) -> bool:
        return self.status is not HashStatus.OK

    def explain(self) -> str:
        name = f"{self.tool} {self.version or '(unknown version)'}"
        if self.status is HashStatus.OK:
            return f"{name}: all file hashes match the manifest."
        if self.status is HashStatus.UNVERIFIED:
            return f"{name}: integrity could not be verified ({self.reason or 'no manifest entry'})."
        # repr() the names: they come from disk and may contain terminal control characters.
        bad = ([repr(m) for m in self.mismatches] + [f"{m!r} (missing)" for m in self.missing]
               + [f"{m!r} (unexpected)" for m in self.unexpected])
        more = f" and {len(bad) - _MAX_LISTED} more" if len(bad) > _MAX_LISTED else ""
        return (f"{name}: integrity check FAILED for: {', '.join(bad[:_MAX_LISTED])}{more}. "
                "The installed files differ from the trusted manifest and may be tampered with "
                "or from an unexpected release.")


def hash_tree(root: Path, members: tuple[str, ...] | None = None,
              strict_member: str = "") -> dict[str, str]:
    """Hash every file below root. Raises on anything that cannot be hashed faithfully.

    With members, only those entries of root are covered (see the module docstring).
    The whole tree is listed and vetted before any file is opened.
    """
    def fail(exc: OSError) -> None:
        raise exc

    def vet(path: Path) -> os.stat_result:
        info = path.lstat()
        rel = path.relative_to(root).as_posix()
        if is_link(info):
            raise ValueError(f"link in installation: {rel!r}")
        if is_secret_name(path.name):
            raise ValueError(f"secret-like file in installation: {rel!r}")
        if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
            raise ValueError(f"special file in installation: {rel!r}")
        return info

    top = root.lstat()
    if is_link(top) or not stat.S_ISDIR(top.st_mode):
        raise ValueError("installation root is a link or not a directory")

    found: list[Path] = []
    starts: list[tuple[Path, bool]] = [(root, False)] if members is None else []
    for member in members or ():
        path = root / member
        if not os.path.lexists(path):
            continue  # its files are then reported missing
        if stat.S_ISDIR(vet(path).st_mode):
            starts.append((path, member != strict_member))
        else:
            found.append(path)
    for start, skip_cache in starts:
        for base, dirs, names in os.walk(start, onerror=fail):
            if skip_cache:
                dirs[:] = [d for d in dirs if d != "__pycache__"]
            for name in dirs + names:
                path = Path(base, name)
                if stat.S_ISREG(vet(path).st_mode):
                    found.append(path)
    return dict(sorted((p.relative_to(root).as_posix(), sha256_file(p)) for p in found))


def load_manifest(path: Path | None = None) -> dict:
    return json.loads(Path(path or MANIFEST_PATH).read_text(encoding="utf-8"))


def check_tool(tool: str, version: str | None, install_dir: Path | None,
               manifest: dict | None = None, members: tuple[str, ...] | None = None,
               strict_member: str = "") -> HashResult:
    def unverified(reason: str) -> HashResult:
        return HashResult(tool, version, HashStatus.UNVERIFIED, reason=reason)

    if not version or install_dir is None:
        return unverified("installation or version unknown")
    try:
        manifest = manifest if manifest is not None else load_manifest()
        expected = (manifest.get("tools", {}).get(tool, {}).get("versions", {})
                    .get(version, {}).get("files"))
    except (OSError, ValueError, AttributeError) as exc:
        return unverified(f"manifest unreadable: {type(exc).__name__}")
    if not expected:
        return unverified("no manifest entry for this version")
    if not isinstance(expected, dict) or not all(isinstance(v, str) for v in expected.values()):
        return unverified("manifest entry is malformed")
    try:
        actual = hash_tree(Path(install_dir), members, strict_member)
    except (OSError, ValueError) as exc:
        return unverified(f"installation unreadable: {exc}")
    # Compare sets of names; never open a path that was built from a manifest key.
    modified = sorted(k for k in expected.keys() & actual.keys()
                      if actual[k] != expected[k].lower())
    missing = sorted(expected.keys() - actual.keys())
    unexpected = sorted(actual.keys() - expected.keys())
    status = HashStatus.MISMATCH if (modified or missing or unexpected) else HashStatus.OK
    return HashResult(tool, version, status, modified, missing, unexpected,
                      files=actual if status is HashStatus.OK else {})


def _snapshot(tool: str, inst: Installation, files: dict[str, str],
              workspace: Workspace) -> Binding:
    """Copy exactly the verified bytes; nothing unlisted or changed ever reaches the snapshot."""
    if inst.executable is None:
        raise ValueError("no approved executable was resolved")
    entry_rel = None
    if inst.entry is not None:
        wanted = inst.entry.relative_to(inst.root).as_posix()
        matches = [rel for rel in files if rel.casefold() == wanted.casefold()]
        if len(matches) != 1:
            raise ValueError("the module manifest is not a verified file")
        entry_rel = matches[0]

    slot = workspace.new_slot()
    try:
        search = root = slot / "m"
        if inst.entry is not None:
            # <name>/<version> layout, so an import by name from inside the tool finds this copy
            root = search / inst.entry.stem
            if re.fullmatch(r"\d+(\.\d+){1,3}", inst.version):
                root = root / inst.version
            if any(c in str(root) for c in "[]*?`" + os.pathsep):
                raise ValueError("the private snapshot path cannot be imported safely")
        root.mkdir(parents=True)
        for rel, digest in files.items():
            if workspace.closed:
                raise ValueError("the run was stopped")
            if has_download_mark(inst.root / rel):
                raise ValueError(f"{rel!r} is marked as downloaded (Mark-of-the-Web); "
                                 "review it and use Unblock-File before it can run")
            data, executable = read_below(inst.root, rel)
            if hashlib.sha256(data).hexdigest() != digest:
                raise ValueError(f"installation changed while snapshotting: {rel!r}")
            target = root / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            create_file(target, data)
            target.chmod(0o500 if executable else 0o400)
        if hash_tree(inst.root, inst.members, inst.strict_member) != files:
            raise ValueError("installation changed while snapshotting")
        for base, _, _ in os.walk(search, topdown=False):
            os.chmod(base, 0o500)
        if hash_tree(root) != files:
            raise ValueError("the snapshot does not match the verified files")
        inst.executable.verify()
        private = slot / "private"
        private.mkdir(mode=0o700)
    except BaseException:
        workspace.release(slot)
        raise
    return Binding(tool=tool, version=inst.version, source=inst.root, root=root,
                   search_path=search, entry=root / entry_rel if entry_rel else None,
                   executable=inst.executable, files=tuple(files.items()), private_dir=private,
                   slot=slot, workspace=workspace)


def verify_tool(tool: Tool, workspace: Workspace | None = None) -> HashResult:
    """Discover and check one tool. Any failure is an explicit UNVERIFIED, never an exception.

    Only a call that passes a workspace yields a result that can be launched.
    """
    if workspace is not None and tool.real_run_block:
        return HashResult(tool.name, None, HashStatus.UNVERIFIED, reason=tool.real_run_block)
    version = None
    try:
        inst = tool.discover()
        version = inst.version
        result = check_tool(tool.name, version, inst.root, members=inst.members,
                            strict_member=inst.strict_member)
        if not result.blocks_run and workspace is not None:
            with workspace.busy():
                result.binding = _snapshot(tool.name, inst, result.files, workspace)
    except Exception as exc:
        return HashResult(tool.name, version, HashStatus.UNVERIFIED,
                          reason=str(exc) or type(exc).__name__)
    return result


def launch_binding(results: list[HashResult]) -> tuple[Binding | None, str]:
    """The binding to launch from, or None and the reason that launch is blocked."""
    ok, message = gate_run(results)
    if not ok:
        return None, message
    if len(results) != 1:
        return None, "More than one integrity result for the tool; the choice is ambiguous."
    result, binding = results[0], results[0].binding
    if binding is None or (binding.tool, binding.version) != (result.tool, result.version):
        return None, f"{result.tool}: the result is not bound to a verified snapshot."
    return binding, ""


def gate_run(results: list[HashResult]) -> tuple[bool, str]:
    """Allow only a non-empty list in which every result is OK."""
    if not results:
        return False, "No integrity result; the tool was not verified."
    blocked = [r for r in results if r.blocks_run]
    return not blocked, "\n".join(r.explain() for r in blocked)

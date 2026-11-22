"""Serialised, atomic updates of the integrity manifest."""
from __future__ import annotations

import contextlib
import json
import os
import stat
import sys
import tempfile
import time
from collections.abc import Iterator
from pathlib import Path

from orbit.core.safe_fs import is_link

LOCK_TIMEOUT = 600.0  # seconds; another writer holds the lock while it hashes every tool


class ManifestError(Exception):
    """The manifest could not be updated safely. It was left as it was."""


def _try_lock(fd: int) -> bool:
    try:
        if sys.platform == "win32":
            import msvcrt

            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        return False
    return True


@contextlib.contextmanager
def _locked(path: Path) -> Iterator[None]:
    # A separate file, because replacing the manifest would detach a lock held on it. The lock
    # file is never deleted: unlinking it would let two writers each hold "the" lock.
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path.with_name(path.name + ".lock"), flags, 0o600)
    try:
        deadline = time.monotonic() + LOCK_TIMEOUT
        while not _try_lock(fd):
            if time.monotonic() >= deadline:
                raise ManifestError("another process holds the manifest lock")
            time.sleep(0.05)
        yield
    finally:
        os.close(fd)  # releases the lock


def _read(path: Path) -> tuple[bytes | None, int]:
    """(content, permission bits); content is None when there is no manifest yet."""
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None, 0o600
    if is_link(info) or not stat.S_ISREG(info.st_mode):
        raise ManifestError("the manifest is a link or not a regular file")
    # keep what was there, minus execute bits and write access for anyone but the owner
    return path.read_bytes(), (stat.S_IMODE(info.st_mode) & 0o644) | 0o600


def atomic_write(path: Path, data: bytes, mode: int) -> None:
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temp = Path(name)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        temp.chmod(mode)
        for attempt in range(10):
            try:
                os.replace(temp, path)
                break
            except PermissionError:  # Windows: a reader has the manifest open for a moment
                if sys.platform != "win32" or attempt == 9:
                    raise
                time.sleep(0.1)
    except BaseException:
        with contextlib.suppress(OSError):
            temp.unlink()
        raise
    if sys.platform != "win32":
        with contextlib.suppress(OSError):  # not every file system can fsync a directory
            dir_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)


@contextlib.contextmanager
def update_manifest(path: Path) -> Iterator[dict]:
    """Yield the manifest under an exclusive lock. It is replaced only if the block completes."""
    path = Path(path)
    with _locked(path):
        before, mode = _read(path)
        try:
            manifest = {"schema": 1, "tools": {}} if before is None else json.loads(before)
        except ValueError as exc:
            raise ManifestError("the existing manifest is not valid JSON") from exc
        if not isinstance(manifest, dict) or not isinstance(manifest.get("tools", {}), dict):
            raise ManifestError("the existing manifest is malformed")
        yield manifest
        if _read(path)[0] != before:
            raise ManifestError("the manifest was edited while it was being updated")
        atomic_write(path, json.dumps(manifest, indent=2).encode("utf-8"), mode)

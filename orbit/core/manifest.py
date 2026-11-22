"""Serialised, atomic updates of the integrity manifest.

Every file operation goes through ``trusted_state``: the directory is vetted once and the lock,
the manifest, the temporary file and the rename are all relative to that vetted directory, so
the reader and the writer apply the same policy and a swapped path cannot redirect a write.

Content is held to the reader's schema (``orbit.core.baseline_schema``): a new baseline is
generated from the packaged template with the current user and machine binding, an existing one
is validated before it is yielded, and anything that is not a valid schema-2 baseline for this
user (schema 1, newer, unbound, another user's, damaged) is refused and left byte-for-byte as it
was. Nothing is imported, reformatted or upgraded.
"""
from __future__ import annotations

import contextlib
import os
import secrets
import stat
import sys
import time
from collections.abc import Iterator
from pathlib import Path

from orbit.config import VERSION
from orbit.core import baseline_schema as schema
from orbit.core.trusted_state import StateDir, UnsafeState, open_state_dir

LOCK_TIMEOUT = 600.0  # seconds; another writer holds the lock while it hashes every tool
_LOCK_FLAGS = (os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
               | getattr(os, "O_BINARY", 0))
_TEMP_FLAGS = (os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
               | getattr(os, "O_BINARY", 0))


class ManifestError(Exception):
    """The manifest could not be updated safely. It was left as it was.

    ``code`` is set when the content was refused (see ``baseline_schema.ErrorCode``).
    """

    def __init__(self, message: str, code: schema.ErrorCode | None = None) -> None:
        super().__init__(message)
        self.code = code


def _refused(exc: schema.BaselineError) -> ManifestError:
    return ManifestError(str(exc), exc.code)


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
def _trusted(path: Path, create: bool) -> Iterator[tuple[StateDir, str]]:
    """The vetted directory of the manifest and its file name; policy failures are ManifestErrors."""
    path = Path(path)
    try:
        with open_state_dir(path.parent, create=create) as state:
            yield state, path.name
    except UnsafeState as exc:
        raise ManifestError(str(exc)) from exc


@contextlib.contextmanager
def _locked(state: StateDir, name: str) -> Iterator[None]:
    # A separate file, because replacing the manifest would detach a lock held on it. The lock
    # file is never deleted: unlinking it would let two writers each hold "the" lock.
    lock = name + ".lock"
    for attempt in range(20):
        try:
            fd = state.open(lock, _LOCK_FLAGS, 0o600)
            break
        except FileNotFoundError:
            # The directory is held open and vetted, so ENOENT from O_CREAT can only be a file
            # system race between processes creating the lock at the same moment (seen on macOS).
            if attempt == 19:
                raise
            time.sleep(0.01 * (attempt + 1))
    try:
        opened = os.fstat(fd)
        state.vet_file(opened)  # a regular file of yours with one name, not a planted link
        if not os.path.samestat(state.lstat(lock), opened):
            raise ManifestError("the manifest lock was replaced while it was being opened")
        deadline = time.monotonic() + LOCK_TIMEOUT
        while not _try_lock(fd):
            if time.monotonic() >= deadline:
                raise ManifestError("another process holds the manifest lock")
            time.sleep(0.05)
        yield
    finally:
        os.close(fd)  # releases the lock


def seed_manifest(path: Path, template: bytes) -> bool:
    """Create the manifest from template if there is none. True if it was created.

    The template is parsed as a template, the current binding and generator are added, and the
    result is what is written; template bytes are never copied verbatim. If the identity cannot be
    established nothing is written. An existing manifest, valid or not, is never read into,
    replaced or reformatted here: a broken one stays broken (and the gate stays closed) until the
    user deals with it.
    """
    try:
        data = schema.dump_baseline(
            schema.baseline_from_template(template, schema.current_binding(), VERSION))
    except schema.BaselineError as exc:
        raise _refused(exc) from exc
    with _trusted(path, create=True) as (state, name), _locked(state, name):
        before = _read(state, name)  # raises for a link, a special file or a foreign owner
        if before[0] is not None:
            return False
        _replace(state, name, data, 0o600)
        return True


def _read(state: StateDir, name: str) -> tuple[bytes | None, int, tuple[int, int] | None]:
    """(content, permission bits, identity); content is None when there is no manifest yet."""
    try:
        data, info = state.read_regular(name)
    except FileNotFoundError:
        return None, 0o600, None
    except UnsafeState as exc:
        raise ManifestError(str(exc)) from exc
    # keep what was there, minus execute bits and write access for anyone but the owner
    return data, (stat.S_IMODE(info.st_mode) & 0o644) | 0o600, (info.st_dev, info.st_ino)


def _replace(state: StateDir, name: str, data: bytes, mode: int) -> None:
    """Write data to a private temporary file beside the manifest and rename it into place."""
    try:
        state.assert_current()  # ORBIT_HOME still leads to the directory that was vetted
    except UnsafeState as exc:
        raise ManifestError(str(exc)) from exc
    temp = f".{name}.{secrets.token_hex(8)}.tmp"
    fd = state.open(temp, _TEMP_FLAGS, 0o600)  # O_EXCL: never an existing name or a link
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
            if hasattr(os, "fchmod"):
                os.fchmod(fh.fileno(), mode)
            else:  # Windows: only the read-only attribute exists
                os.chmod(state.path / temp, mode)
        for attempt in range(10):
            try:
                state.replace(temp, name)
                break
            except PermissionError:  # Windows: a reader has the manifest open for a moment
                if sys.platform != "win32" or attempt == 9:
                    raise
                time.sleep(0.1)
    except BaseException:
        with contextlib.suppress(OSError):
            state.unlink(temp)
        raise
    state.sync()


@contextlib.contextmanager
def update_manifest(path: Path) -> Iterator[dict]:
    """Yield the baseline document under an exclusive lock. It is replaced only if the block completes.

    An existing file must be a valid schema-2 baseline for this user (and machine) or
    ``ManifestError`` is raised before anything is yielded, and the file is not touched. With no
    file the document starts empty, bound to the current identity. Before publishing, the edited
    document is validated again, so only a baseline the reader would accept is ever written.
    """
    try:
        binding = schema.current_binding()
    except schema.BaselineError as exc:
        raise _refused(exc) from exc
    with _trusted(path, create=False) as (state, name), _locked(state, name):
        before, mode, identity = _read(state, name)
        try:
            if before is None:
                document = {"schema": schema.SCHEMA, "kind": schema.KIND,
                            "binding": binding.to_json(), "generator": {"orbit": VERSION},
                            "tools": {}}
            else:
                document = schema.parse_baseline(before, binding).to_document()
        except schema.BaselineError as exc:
            raise _refused(exc) from exc
        yield document
        now = _read(state, name)
        if now[0] != before or now[2] != identity:
            raise ManifestError("the manifest was edited or replaced while it was being updated")
        try:
            _, data = schema.revalidated(document, binding)
        except schema.BaselineError as exc:
            raise _refused(exc) from exc
        _replace(state, name, data, mode)

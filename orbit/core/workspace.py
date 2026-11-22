"""Private, short-lived storage for verified snapshots and authentication material.

One workspace covers one run. Its owner closes it in a ``finally``; an atexit hook is the
backstop. Closing while a worker thread is still copying defers removal to that thread, so a
cancelled run cannot leave a half-written snapshot behind.
"""
from __future__ import annotations

import atexit
import contextlib
import logging
import os
import stat
import sys
import tempfile
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import final

from orbit.core.safe_fs import remove_tree

log = logging.getLogger(__name__)
_in_use: set[Workspace] = set()  # workspaces that have a directory on disk


class WorkspaceError(Exception):
    """Private storage is unavailable or cannot be made private."""


def remove_all() -> None:
    """Last resort at exit: remove the private directories of every workspace."""
    for workspace in list(_in_use):
        workspace._remove()


atexit.register(remove_all)


def check_private_location(base: Path) -> None:
    """Refuse a temp directory in which another local user could swap our directory."""
    if sys.platform == "win32":
        # mkdtemp's mode does not set an ACL on every supported Python, so rely on the profile's.
        if not base.is_relative_to(Path.home().resolve()):
            raise WorkspaceError("the temporary directory is not inside the user profile")
        return
    for directory in (base, *base.parents):
        info = directory.stat()
        if info.st_uid not in (0, os.geteuid()):
            raise WorkspaceError(f"temporary path {str(directory)!r} belongs to another user")
        if info.st_mode & (stat.S_IWGRP | stat.S_IWOTH) and not info.st_mode & stat.S_ISVTX:
            raise WorkspaceError(f"temporary path {str(directory)!r} is writable by other users")


@final
class Workspace:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._base: Path | None = None
        self._users = 0
        self._closed = False

    @property
    def closed(self) -> bool:
        return self._closed

    def __enter__(self) -> Workspace:
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    @contextlib.contextmanager
    def busy(self) -> Iterator[None]:
        with self._lock:
            if self._closed:
                raise WorkspaceError("the run was stopped")
            self._users += 1
        try:
            yield
        finally:
            with self._lock:
                self._users -= 1
                if self._closed and not self._users:
                    self._remove()

    def new_slot(self) -> Path:
        """A new empty directory that only the current user can use."""
        with self._lock:
            if self._closed:
                raise WorkspaceError("the run was stopped")
            try:
                if self._base is None:
                    root = Path(tempfile.gettempdir()).resolve(strict=True)
                    check_private_location(root)
                    self._base = Path(tempfile.mkdtemp(prefix="orbit-", dir=root))
                    _in_use.add(self)
                return Path(tempfile.mkdtemp(dir=self._base))
            except OSError as exc:
                raise WorkspaceError(f"private storage unavailable: {type(exc).__name__}") from exc

    def release(self, slot: Path) -> bool:
        """Remove one tool's slot as soon as that tool is finished."""
        with self._lock:
            if self._base is None or slot.parent != self._base:
                return not os.path.lexists(slot)
        return remove_tree(slot)

    def close(self) -> None:
        with self._lock:
            self._closed = True
            if not self._users:
                self._remove()

    def _remove(self) -> None:
        base = self._base  # read once: the stop watcher may be removing it too
        if base is None:
            return
        if remove_tree(base):
            self._base = None
            _in_use.discard(self)
        else:
            log.error("Could not remove private ORBIT directory %s; delete it by hand", base)

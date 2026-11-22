"""Directories reached without following a link, and publication that never replaces.

Every operation is relative to a descriptor of the checked directory, so changing a path
afterwards cannot redirect it, and there is no pathname fallback. Python has no such calls on
Windows: re-checking a path would leave a window in which an ancestor can become a junction,
so there everything here fails closed.
"""
from __future__ import annotations

import contextlib
import ctypes
import errno
import functools
import os
import stat
import sys
from collections.abc import Callable
from pathlib import Path
from typing import final

from orbit.core.safe_fs import is_link

_FD_RELATIVE = sys.platform != "win32"
_REPARSE_POINT = 0x400  # FILE_ATTRIBUTE_REPARSE_POINT
_LIST_FLAGS = (os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
# search permission is enough to pass through an ancestor
_PIN_FLAGS = _LIST_FLAGS | getattr(os, "O_PATH", getattr(os, "O_SEARCH", 0))


class UnsafePathError(Exception):
    """A directory is linked, special, ambiguous, or not the one that was checked."""


def _is_plain_dir(info: os.stat_result) -> bool:
    # any reparse point, not only those that is_link knows: DFS and filter drivers redirect too
    reparse = (getattr(info, "st_reparse_tag", 0)
               or getattr(info, "st_file_attributes", 0) & _REPARSE_POINT)
    return stat.S_ISDIR(info.st_mode) and not is_link(info) and not reparse


@final
class Directory:
    """One checked directory. Close it, or use it as a context manager."""

    def __init__(self, path: Path, info: os.stat_result, fd: int | None,
                 parents: tuple[tuple[Path, os.stat_result], ...] = ()) -> None:
        self.path, self.info, self.fd = path, info, fd
        self.chain = (*parents, (path, info))

    def __enter__(self) -> Directory:
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def close(self) -> None:
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def check(self) -> None:
        """Raise unless every path from the file system root still names what was checked."""
        for path, info in self.chain:
            try:
                now = os.lstat(path)
            except OSError as exc:
                raise UnsafePathError(f"{str(path)!r} disappeared") from exc
            if not _is_plain_dir(now) or not os.path.samestat(now, info):
                raise UnsafePathError(f"{str(path)!r} was replaced")

    def at(self, name: str) -> tuple[str, int]:
        """(what to pass, dir_fd) for an operation on the entry ``name`` of this directory."""
        if self.fd is None:  # never pass None on: as a dir_fd it means the working directory
            raise UnsafePathError(f"{str(self.path)!r} is not pinned by a descriptor")
        return name, self.fd

    def lstat(self, name: str) -> os.stat_result:
        target, fd = self.at(name)
        return os.lstat(target, dir_fd=fd)

    def has(self, name: str) -> bool:
        try:
            self.lstat(name)
        except FileNotFoundError:
            return False
        return True

    def names(self) -> list[str]:
        here, pin = self.at(".")
        fd = os.open(here, _LIST_FLAGS, dir_fd=pin)  # the pinning descriptor may be search-only
        try:
            return os.listdir(fd)
        finally:
            os.close(fd)

    def child(self, name: str) -> Directory:
        path = self.path / name
        info = self.lstat(name)
        if not _is_plain_dir(info):
            raise UnsafePathError(f"{str(path)!r} is a link or not an ordinary directory")
        target, pin = self.at(name)
        fd = os.open(target, _PIN_FLAGS, dir_fd=pin)
        try:
            if not os.path.samestat(info, os.fstat(fd)):
                raise UnsafePathError(f"{str(path)!r} was replaced while being opened")
        except BaseException:
            os.close(fd)
            raise
        return Directory(path, info, fd, self.chain)

    def make(self, name: str) -> Directory:
        """Create a private child. Fails if anything already has that name."""
        target, fd = self.at(name)
        os.mkdir(target, 0o700, dir_fd=fd)
        made = self.child(name)
        try:
            # another user's directory cannot carry our owner, and what we just made is empty
            foreign = made.info.st_uid != os.geteuid()
            if foreign or made.names():
                raise UnsafePathError(f"{str(made.path)!r} was replaced while being created")
        except BaseException:
            made.close()
            raise
        return made

    def remove(self, name: str, expected: os.stat_result) -> bool:
        """Delete the directory ``name`` if it is still ``expected``. Links are never entered."""
        with contextlib.suppress(OSError, UnsafePathError):
            if not os.path.samestat(self.lstat(name), expected):
                return False
            with self.child(name) as child:
                for entry in child.names():
                    info = child.lstat(entry)
                    if _is_plain_dir(info):
                        if not child.remove(entry, info):
                            return False
                    else:
                        target, fd = child.at(entry)
                        os.unlink(target, dir_fd=fd)
            target, fd = self.at(name)
            os.rmdir(target, dir_fd=fd)
            return True
        return False


def open_directory(path: Path) -> Directory:
    """Walk to path from the file system root, refusing links and creating what is missing.

    Refuses, before touching the file system, where directories cannot be pinned.
    """
    if not _FD_RELATIVE:
        raise UnsafePathError("extraction is not supported on Windows, where the destination "
                              "cannot be pinned against replacement")
    path = Path(path)
    if ".." in path.parts:
        raise UnsafePathError("the path contains '..'")
    if not path.is_absolute():
        path = Path(os.getcwd()) / path
    names = path.parts[1:]

    anchor = Path(path.anchor)
    info = os.lstat(anchor)
    if not _is_plain_dir(info):
        raise UnsafePathError("the file system root is not an ordinary directory")
    here = Directory(anchor, info, os.open(anchor, _PIN_FLAGS))
    try:
        for name in names:
            below = here.child(name) if here.has(name) else here.make(name)
            here.close()
            here = below
        here.check()
    except BaseException:
        here.close()
        raise
    return here


@functools.cache
def _exclusive_rename() -> tuple[Callable, int] | None:
    if sys.platform == "darwin":
        symbol, flag = "renameatx_np", 0x4  # RENAME_EXCL
    elif sys.platform.startswith("linux"):
        symbol, flag = "renameat2", 0x1  # RENAME_NOREPLACE
    else:
        return None
    try:
        call = getattr(ctypes.CDLL(None, use_errno=True), symbol)
    except (OSError, AttributeError):  # for example an older C library
        return None
    call.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
    call.restype = ctypes.c_int
    return call, flag


def move_new(source: Directory, dest: Directory, name: str) -> None:
    """Atomically move source/name to dest/name, only if nothing has that name.

    The kernel reserves the name and publishes the whole tree in one step. mkdir followed by a
    merge could not promise this: the directory could be exchanged before it was entered.
    Raises where the platform or file system has no such operation.
    """
    found = _exclusive_rename() if _FD_RELATIVE else None
    if found is None:
        raise OSError(errno.ENOTSUP, "no atomic non-replacing rename on this platform")
    call, flag = found
    (_, src_fd), (_, dst_fd) = source.at(name), dest.at(name)
    raw = os.fsencode(name)
    if call(src_fd, raw, dst_fd, raw, flag) != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))

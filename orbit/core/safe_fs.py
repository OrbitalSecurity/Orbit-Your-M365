"""File primitives for the integrity boundary: never follow a link, never overwrite."""
from __future__ import annotations

import contextlib
import hashlib
import os
import shutil
import stat
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from typing import BinaryIO

_JUNCTION_TAG = 0xA0000003  # Windows IO_REPARSE_TAG_MOUNT_POINT
_NAME_SURROGATE = 0x20000000  # reparse-tag bit: "this entry stands for another path"

_READ_FLAGS = (os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
               | getattr(os, "O_BINARY", 0))
_CREATE_FLAGS = (os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
                 | getattr(os, "O_BINARY", 0))

# An installation containing one of these is refused before any of its files are read or copied.
_SECRET_NAMES = frozenset({
    ".env", ".netrc", "_netrc", ".pypirc", ".git-credentials", "id_rsa", "id_ed25519",
    "secrets.enc", "secrets.json",
})
_SECRET_PREFIXES = (".env.", ".roadtools_auth", "msal_token_cache")
_SECRET_SUFFIXES = (".pfx", ".p12")


def is_secret_name(name: str) -> bool:
    low = name.lower()
    return (low in _SECRET_NAMES or low.startswith(_SECRET_PREFIXES)
            or low.endswith(_SECRET_SUFFIXES))


def is_link(info: os.stat_result) -> bool:
    """Symlink, junction, or any other reparse point that redirects to another path."""
    tag = getattr(info, "st_reparse_tag", 0)
    return stat.S_ISLNK(info.st_mode) or tag == _JUNCTION_TAG or bool(tag & _NAME_SURROGATE)


def has_download_mark(path: Path) -> bool:
    """Windows Mark-of-the-Web. A copy would lose it, and with it RemoteSigned's protection."""
    return sys.platform == "win32" and os.path.exists(f"{path}:Zone.Identifier")


@contextlib.contextmanager
def open_regular(path: Path) -> Iterator[BinaryIO]:
    """Open exactly the regular file at path, and fail if it changes while it is being read."""
    before = path.lstat()
    if is_link(before) or not stat.S_ISREG(before.st_mode):
        raise ValueError(f"not a regular file: {path.name!r}")
    fd = os.open(path, _READ_FLAGS)
    with os.fdopen(fd, "rb") as fh:
        opened = os.fstat(fh.fileno())
        if not stat.S_ISREG(opened.st_mode) or not os.path.samestat(before, opened):
            raise ValueError(f"file was replaced while being read: {path.name!r}")
        yield fh
        after = os.fstat(fh.fileno())
        if (after.st_size, after.st_mtime_ns) != (opened.st_size, opened.st_mtime_ns):
            raise ValueError(f"file changed while being read: {path.name!r}")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open_regular(Path(path)) as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def read_below(root: Path, rel: str) -> tuple[bytes, bool]:
    """(content, executable bit) of root/rel, refusing a link at every level below root."""
    *parents, name = rel.split("/")
    path = root
    for part in parents:
        path = path / part
        info = path.lstat()
        if is_link(info) or not stat.S_ISDIR(info.st_mode):
            raise ValueError(f"link or non-directory in path: {rel!r}")
    with open_regular(path / name) as fh:
        return fh.read(), bool(os.fstat(fh.fileno()).st_mode & 0o111)


def create_file(path: Path, data: bytes, mode: int = 0o600, sync: bool = False,
                dir_fd: int | None = None) -> None:
    """Create path and write data. Fails if anything, including a link, already has that name.

    With dir_fd, only the final name is used, relative to that directory.
    """
    target = path if dir_fd is None else path.name
    fd = os.open(target, _CREATE_FLAGS, mode, dir_fd=dir_fd)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            if sync:
                fh.flush()
                os.fsync(fh.fileno())
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(target, dir_fd=dir_fd)  # it is ours: O_EXCL created it
        raise


def remove_tree(path: Path) -> bool:
    """Delete a tree, including read-only entries, without following links. True when gone."""
    for attempt in range(5):
        if not os.path.lexists(path):
            return True
        if attempt:
            time.sleep(0.1)  # Windows: a child that just exited can still hold a file open
        with contextlib.suppress(OSError):
            if is_link(path.lstat()):
                return False
            os.chmod(path, 0o700)
            for base, dirs, names in os.walk(path):
                for name in list(dirs):
                    child = Path(base, name)
                    if is_link(child.lstat()):
                        dirs.remove(name)
                    else:
                        os.chmod(child, 0o700)
                if sys.platform == "win32":  # the read-only attribute blocks deletion there
                    for name in names:
                        child = Path(base, name)
                        if not is_link(child.lstat()):
                            os.chmod(child, 0o600)
            shutil.rmtree(path)
    return not os.path.lexists(path)

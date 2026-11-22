"""Trusted access to the directory that holds the integrity baseline (ORBIT_HOME).

The real-run gate trusts ``ORBIT_HOME/tool_hashes.json``, so whoever can replace or edit that file
decides what is allowed to run. The reader (``hash_checker.load_manifest``) and the writer
(``orbit.core.manifest``) therefore share one policy, enforced here:

POSIX
    * The path is walked one component at a time with directory file descriptors and
      ``O_NOFOLLOW``; every later operation (read, lock, temporary file, rename) is relative to
      the directory descriptor that was vetted, so swapping a path component afterwards cannot
      redirect it.
    * Every directory on the way must belong to root or to you and must not be writable by group
      or others (a sticky directory such as /tmp is allowed on the way, never as ORBIT_HOME).
      ORBIT_HOME itself must be yours and closed to group and others.
    * Symbolic links are refused for ORBIT_HOME and for every component in the part of the path
      that you control. Only root-owned links in the system part (``/var`` on macOS) are followed.
    * The manifest and its lock must be regular files of yours, with a single hard link and no
      group or other write bit.

Windows
    The standard library cannot read an owner or an ACL, and POSIX mode bits say nothing about
    one, so this does not claim cross-principal protection by inspecting permissions. The
    conservative rule instead: ORBIT_HOME must be inside your user profile (whose default ACL
    excludes other standard users), and no component below the profile may be a link or junction.
    Folder permissions are not inspected; a profile whose ACL was widened is not detected, and the
    checks are path-based, so they are not race-free. This is a documented limitation.

Both
    ORBIT_HOME may not be, or resolve into, ORBIT's own package tree, ``orbit/data``, the
    repository-level ``data`` directory or any other legacy manifest directory, by name, by
    symbolic link or by identity. A baseline recorded for another install is never imported.

Messages are fixed text: they never include the path being rejected.
"""
from __future__ import annotations

import contextlib
import errno
import os
import stat
import sys
from collections import deque
from collections.abc import Iterator
from pathlib import Path

from orbit.core.safe_fs import is_link

_MAX_LINK_HOPS = 40
_DIR_FLAGS = (os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
_READ_FLAGS = (os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
               | getattr(os, "O_BINARY", 0))

MANIFEST_NAME = "tool_hashes.json"  # also hash_checker.MANIFEST_NAME; the legacy file name

DESTINATION = ("ORBIT_HOME resolves into ORBIT's own installation or a legacy data directory. "
               "Set ORBIT_HOME to a private directory outside the ORBIT install (the default is "
               "~/.orbit); a baseline is never read from or written into the package.")
LINKED = ("the baseline location contains a symbolic link or junction. Use a plain directory "
          "you own for ORBIT_HOME")
WRITABLE = ("a directory on the baseline path is writable by group or others, so another user "
            "could replace the baseline. Run chmod go-w on it, or set ORBIT_HOME elsewhere")
FOREIGN = ("a directory on the baseline path belongs to another user. Set ORBIT_HOME to a "
           "directory you own")
FILE_LINKED = "the baseline or its lock is a symbolic link or junction, not a regular file"
RACE = "the baseline location changed while it was being checked; run the command again"


class UnsafeState(Exception):
    """The baseline location or file cannot be trusted. Nothing was read, trusted or changed."""


# --- code locations that may never hold the baseline ---------------------------

def package_dir() -> Path:
    """The installed (or source) ``orbit`` package directory."""
    import orbit
    return Path(orbit.__file__).resolve().parent


def legacy_dirs(package: Path | None = None) -> list[Path]:
    """Directories where older layouts kept a baseline beside the code."""
    package = package or package_dir()
    return [package.parent / "data", package / "data"]


def forbidden_roots(package: Path | None = None) -> list[Path]:
    """ORBIT_HOME may not be any of these or inside them."""
    package = package or package_dir()
    return [package, *legacy_dirs(package)]


def _fold(path: str) -> str:
    return os.path.normcase(path).casefold() if sys.platform in ("darwin", "win32") else path


def _inside(path: str, root: str) -> bool:
    path, root = _fold(path), _fold(root)
    return path == root or path.startswith(root.rstrip(os.sep) + os.sep)


def _identity(info: os.stat_result) -> tuple[int, int]:
    return info.st_dev, info.st_ino


def _forbidden_identities() -> set[tuple[int, int]]:
    found = set()
    for root in forbidden_roots():
        with contextlib.suppress(OSError):
            found.add(_identity(os.stat(root)))
    return found


def _legacy_file_identities() -> set[tuple[int, int]]:
    found = set()
    for folder in legacy_dirs():
        with contextlib.suppress(OSError):
            found.add(_identity(os.stat(folder / MANIFEST_NAME)))
    return found


def _check_lexical(path: str) -> None:
    """Refuse by name, before anything is opened or created. realpath follows links."""
    resolved = os.path.realpath(path)
    for root in forbidden_roots():
        if _inside(resolved, os.path.realpath(root)):
            raise UnsafeState(DESTINATION)


# --- the vetted directory -------------------------------------------------------

class StateDir:
    """A directory that passed the policy; every operation is relative to it."""

    def __init__(self, path: Path, fd: int | None) -> None:
        self.path = path
        self.fd = fd

    def _target(self, name: str):
        return name if self.fd is not None else str(self.path / name)

    def _kw(self) -> dict:
        return {"dir_fd": self.fd} if self.fd is not None else {}

    def identity(self) -> tuple[int, int]:
        return _identity(os.fstat(self.fd) if self.fd is not None else os.stat(self.path))

    def lstat(self, name: str) -> os.stat_result:
        return os.stat(self._target(name), follow_symlinks=False, **self._kw())

    def open(self, name: str, flags: int, mode: int = 0o600) -> int:
        try:
            return os.open(self._target(name), flags, mode, **self._kw())
        except OSError as exc:
            if exc.errno in (errno.ELOOP, errno.ENOTDIR, errno.EMLINK):
                raise UnsafeState(FILE_LINKED) from exc
            raise

    def replace(self, src: str, dst: str) -> None:
        if self.fd is not None:
            os.replace(src, dst, src_dir_fd=self.fd, dst_dir_fd=self.fd)
        else:
            os.replace(self._target(src), self._target(dst))

    def unlink(self, name: str) -> None:
        os.unlink(self._target(name), **self._kw())

    def sync(self) -> None:
        """fsync the directory so a rename is durable, where the file system supports it."""
        if self.fd is not None:
            with contextlib.suppress(OSError):
                os.fsync(self.fd)

    def assert_current(self) -> None:
        """Raise if ORBIT_HOME no longer leads to this directory (it was swapped or moved)."""
        with open_state_dir(self.path) as again:
            if again.identity() != self.identity():
                raise UnsafeState(RACE)

    def vet_file(self, info: os.stat_result) -> None:
        """The baseline or its lock: a regular file that only you can write, with one name."""
        if is_link(info):
            raise UnsafeState(FILE_LINKED)
        if not stat.S_ISREG(info.st_mode):
            raise UnsafeState("the baseline or its lock is not a regular file")
        if info.st_nlink != 1:
            raise UnsafeState("the baseline or its lock has more than one hard link")
        if _identity(info) in _legacy_file_identities():
            raise UnsafeState(DESTINATION)
        if hasattr(os, "geteuid"):
            if info.st_uid != os.geteuid():
                raise UnsafeState("the baseline or its lock belongs to another user")
            if info.st_mode & 0o022:
                raise UnsafeState("the baseline or its lock is writable by group or others "
                                  "(chmod 600 it after checking its contents)")

    def read_regular(self, name: str) -> tuple[bytes, os.stat_result]:
        """Exactly the vetted file called name; FileNotFoundError if there is none.

        Fails closed if it is replaced or changes while it is being read.
        """
        before = self.lstat(name)
        self.vet_file(before)
        fd = self.open(name, _READ_FLAGS)
        with os.fdopen(fd, "rb") as fh:
            opened = os.fstat(fh.fileno())
            if not os.path.samestat(before, opened):
                raise UnsafeState(RACE)
            self.vet_file(opened)
            data = fh.read()
            after = os.fstat(fh.fileno())
            if (after.st_size, after.st_mtime_ns) != (opened.st_size, opened.st_mtime_ns):
                raise UnsafeState(RACE)
        if not os.path.samestat(self.lstat(name), opened):
            raise UnsafeState(RACE)
        return data, opened


@contextlib.contextmanager
def open_state_dir(path: Path, create: bool = False) -> Iterator[StateDir]:
    """Vet and open the directory that holds the baseline.

    With create, missing directories are made private (0700); an existing one is only checked,
    never loosened or taken over. Without it a missing directory raises FileNotFoundError.
    """
    path = Path(path)
    if not os.path.isabs(path):
        path = Path(os.getcwd()) / path
    if ".." in path.parts:
        raise UnsafeState("ORBIT_HOME must not contain '..' components")
    _check_lexical(str(path))
    if sys.platform == "win32":
        yield _open_windows(path, create)
        return
    fd = _walk_posix(path, create)
    try:
        yield StateDir(path, fd)
    finally:
        os.close(fd)


def _vet_dir(info: os.stat_result, *, final: bool) -> None:
    uid = os.geteuid()
    if not stat.S_ISDIR(info.st_mode):
        raise UnsafeState("a component of the baseline path is not a directory")
    if final:
        if info.st_uid != uid:
            raise UnsafeState("ORBIT_HOME must be owned by you")
        if info.st_mode & 0o022:
            raise UnsafeState(WRITABLE)
        return
    if info.st_uid not in (0, uid):
        raise UnsafeState(FOREIGN)
    if info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX:
        raise UnsafeState(WRITABLE)


def _walk_posix(path: Path, create: bool) -> int:
    needed = (os.open, os.stat, os.mkdir, os.unlink, os.readlink, os.rename)
    if not hasattr(os, "geteuid") or not all(f in os.supports_dir_fd for f in needed):
        raise UnsafeState("this platform lacks the directory-relative file operations "
                          "needed to protect the baseline")
    forbidden = _forbidden_identities()
    pending = deque(c for c in path.as_posix().split("/") if c not in ("", "."))
    chain = [os.open("/", _DIR_FLAGS)]
    user_zone = False  # inside a directory that is not root's: links are refused from here on
    hops = 0
    try:
        _vet_dir(os.fstat(chain[0]), final=False)
        while pending:
            name = pending.popleft()
            last = not pending
            cur = chain[-1]
            if name == "..":  # only reachable through a root-owned link's target
                if len(chain) > 1:
                    os.close(chain.pop())
                continue
            try:
                info = os.stat(name, dir_fd=cur, follow_symlinks=False)
            except FileNotFoundError:
                if not create:
                    raise
                os.mkdir(name, 0o700, dir_fd=cur)
                info = os.stat(name, dir_fd=cur, follow_symlinks=False)
                made = True
            else:
                made = False
            if stat.S_ISLNK(info.st_mode):
                hops += 1
                if last or user_zone or info.st_uid != 0 or hops > _MAX_LINK_HOPS:
                    raise UnsafeState(LINKED)
                target = os.readlink(name, dir_fd=cur)
                if target.startswith("/"):
                    while len(chain) > 1:
                        os.close(chain.pop())
                pending.extendleft(reversed([c for c in target.split("/") if c not in ("", ".")]))
                continue
            try:
                fd = os.open(name, _DIR_FLAGS, dir_fd=cur)
            except OSError as exc:  # ELOOP / ENOTDIR: swapped for a link after the check
                raise UnsafeState(RACE) from exc
            chain.append(fd)
            opened = os.fstat(fd)
            if not os.path.samestat(info, opened):
                raise UnsafeState(RACE)
            if made:
                os.fchmod(fd, 0o700)  # mkdir's mode was masked by the umask
                opened = os.fstat(fd)
            _vet_dir(opened, final=last)
            if _identity(opened) in forbidden:
                raise UnsafeState(DESTINATION)
            if opened.st_uid != 0:
                user_zone = True
        final = chain.pop()
    except BaseException:
        for fd in chain:
            os.close(fd)
        raise
    for fd in chain:
        os.close(fd)
    return final


def _open_windows(path: Path, create: bool) -> StateDir:
    """The conservative Windows rule: inside the user profile, no links below it."""
    return _check_windows(path, Path.home(), create)


def _check_windows(path: Path, profile: Path, create: bool) -> StateDir:
    base = os.path.normcase(os.path.abspath(profile))
    here = os.path.normcase(os.path.abspath(path))
    if not _inside(here, base) or here == base:
        raise UnsafeState("on Windows ORBIT_HOME must be a folder inside your user profile, "
                          "because ORBIT cannot check folder permissions there")
    forbidden = _forbidden_identities()
    current = Path(os.path.abspath(profile))
    for part in Path(os.path.abspath(path)).relative_to(Path(os.path.abspath(profile))).parts:
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError:
            if not create:
                raise
            current.mkdir(mode=0o700)
            info = current.lstat()
        if is_link(info):
            raise UnsafeState(LINKED)
        if not stat.S_ISDIR(info.st_mode):
            raise UnsafeState("a component of the baseline path is not a directory")
        if _identity(info) in forbidden:
            raise UnsafeState(DESTINATION)
    return StateDir(current, None)

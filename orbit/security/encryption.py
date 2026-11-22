"""Fernet (AES) encryption with PBKDF2-HMAC-SHA256 key derivation, plus folder -> ZIP."""
from __future__ import annotations

import base64
import functools
import io
import logging
import os
import re
import stat
import unicodedata
import uuid
import zipfile
from collections import Counter, defaultdict
from collections.abc import Callable
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from orbit.core.safe_dir import Directory, UnsafePathError, move_new, open_directory
from orbit.core.safe_fs import create_file, read_below
from orbit.security.auth_material import is_auth_material, walk_output

log = logging.getLogger(__name__)

ITERATIONS = 600_000
SALT_LEN = 16
MAGIC = b"ORBT1"

_WINDOWS_INVALID = re.compile(r'[<>:"|?*\\/\x00-\x1f]')
_WINDOWS_DEVICE = re.compile(r"(?:CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|(?:COM|LPT)[0-9¹²³])",
                             re.IGNORECASE)
_WINDOWS_SHORT_NAME = re.compile(r"(?=[^.]{3,8}(?:\.|$))[^. ]+~[0-9]+(?:\.[^. ]{1,3})?")
_REPARSE_ATTRIBUTE = 0x400
_RENAMED_DIR = "renamed-by-orbit"
_MAX_DEPTH = 64  # components in a member name


class DecryptionError(Exception):
    pass


def derive_key(passphrase: str, salt: bytes, iterations: int = ITERATIONS) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations)
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode("utf-8")))


def encrypt_bytes(data: bytes, passphrase: str, iterations: int = ITERATIONS) -> bytes:
    """Return MAGIC + salt + Fernet token."""
    salt = os.urandom(SALT_LEN)
    token = Fernet(derive_key(passphrase, salt, iterations)).encrypt(data)
    return MAGIC + salt + token


def decrypt_bytes(blob: bytes, passphrase: str, iterations: int = ITERATIONS) -> bytes:
    if not blob.startswith(MAGIC):
        raise DecryptionError("Not an ORBIT encrypted blob")
    salt = blob[len(MAGIC): len(MAGIC) + SALT_LEN]
    token = blob[len(MAGIC) + SALT_LEN:]
    try:
        return Fernet(derive_key(passphrase, salt, iterations)).decrypt(token)
    except InvalidToken as exc:
        raise DecryptionError("Wrong passphrase or corrupted data") from exc


def _portable_parts(name: str) -> tuple[str, ...] | None:
    """Components of a member name that means the same path on POSIX and Windows, else None."""
    name = name.replace("\\", "/")
    if name.startswith("/"):  # absolute or UNC
        return None
    parts = tuple(p for p in name.split("/") if p not in ("", "."))
    if len(parts) > _MAX_DEPTH:
        return None
    for part in parts:
        try:
            too_long = len(part.encode("utf-8")) > 255
        except UnicodeEncodeError:
            return None
        if (too_long or part != part.rstrip(" .")  # Windows strips these, so '..' is covered too
                or _WINDOWS_INVALID.search(part)
                or _WINDOWS_DEVICE.fullmatch(part.split(".")[0].rstrip(" "))
                or _WINDOWS_SHORT_NAME.fullmatch(part)):
            return None
    return parts or None


def _collision_key(part: str) -> str:
    """Names that Windows or macOS could treat as the same entry share a key."""
    return unicodedata.normalize("NFC", part).rstrip(" .").upper().casefold()


def _colliding(entries: list[tuple[tuple[str, ...], bool]]) -> list[bool]:
    """For each (parts, is_dir): does any level of it collide with another entry?"""
    spellings: defaultdict[tuple[str, ...], set[tuple[str, ...]]] = defaultdict(set)
    files: Counter[tuple[str, ...]] = Counter()
    dirs: set[tuple[str, ...]] = set()
    keys = [tuple(_collision_key(p) for p in parts) for parts, _ in entries]
    for (parts, is_dir), key in zip(entries, keys):
        for depth in range(1, len(parts) + 1):
            spellings[key[:depth]].add(parts[:depth])
            if is_dir or depth < len(parts):
                dirs.add(key[:depth])
            else:
                files[key[:depth]] += 1
    bad = {k for k in spellings if len(spellings[k]) > 1 or files[k] > 1 or (files[k] and k in dirs)}
    return [any(key[:d] in bad for d in range(1, len(key) + 1)) for key in keys]


def _renamed_dir(names: list[tuple[str, ...]]) -> str:
    """A top-level name that no member can share in any spelling, as a file or as a directory.

    Generated members all live below it, each with its own number, so reserving this one name
    reserves them against the whole archive and against each other.
    """
    taken = {_collision_key(parts[0]) for parts in names}
    choice, number = _RENAMED_DIR, 0
    while _collision_key(choice) in taken:
        number += 1
        choice = f"{_RENAMED_DIR}-{number}"
    return choice


def zip_folder_bytes(folder: Path) -> bytes:
    """Zip regular files only: links are never followed and token files are never packaged."""
    chosen: list[tuple[str, tuple[str, ...]]] = []
    for path, link in sorted(walk_output(folder)):
        rel = path.relative_to(folder).parts
        if link or not stat.S_ISREG(path.lstat().st_mode):
            log.warning("Not packaged, not a regular file: %r", "/".join(rel))
        elif is_auth_material(path, rel):
            log.warning("Not packaged, authentication material: %r", "/".join(rel))
        else:
            chosen.append(("/".join(rel), rel))

    # decrypt_archive refuses non-portable and colliding names, so store those under safe ones.
    clash = _colliding([(rel, False) for _, rel in chosen])
    renamed = _renamed_dir([rel for _, rel in chosen])
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for number, ((name, rel), collides) in enumerate(zip(chosen, clash)):
            arcname = name
            if collides or _portable_parts(name) != rel:
                arcname = f"{renamed}/{number}_{re.sub(r'[^A-Za-z0-9]', '_', rel[-1])[:80]}"
                log.warning("Packaged %r as %r", name, arcname)
            info = zipfile.ZipInfo.from_file(folder.joinpath(*rel), arcname, strict_timestamps=False)
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, read_below(folder, name)[0])
    return buf.getvalue()


def encrypt_folder(folder: Path, passphrase: str, dest: Path | None = None,
                   iterations: int = ITERATIONS) -> Path:
    """Zip and Fernet-encrypt a folder into a new .orbit.zip. Never replaces an existing file."""
    blob = encrypt_bytes(zip_folder_bytes(folder), passphrase, iterations)
    if dest is not None:
        create_file(dest, blob, sync=True)
        return dest
    target = folder.with_name(folder.name + ".orbit.zip")
    while True:
        try:
            create_file(target, blob, sync=True)  # exclusive creation is the name reservation
            return target
        except FileExistsError:
            target = folder.with_name(f"{folder.name}-{uuid.uuid4().hex[:8]}.orbit.zip")


def _member_type_ok(member: zipfile.ZipInfo, is_dir: bool) -> bool:
    kind = stat.S_IFMT(member.external_attr >> 16)
    if member.external_attr & _REPARSE_ATTRIBUTE or member.flag_bits & 0x1:
        return False
    return kind in ((0, stat.S_IFDIR) if is_dir else (0, stat.S_IFREG))


def _create(parent: Directory, name: str, data: bytes) -> None:
    _, fd = parent.at(name)
    create_file(parent.path / name, data, dir_fd=fd)


def _staged_dir(staging: Directory, parts: tuple[str, ...]) -> Directory:
    """The directory at parts below staging, created as needed. The caller closes it."""
    here = staging.child(parts[0]) if staging.has(parts[0]) else staging.make(parts[0])
    for part in parts[1:]:
        with here:
            below = here.child(part) if here.has(part) else here.make(part)
        here = below
    return here


def _publish_dir(staging: Directory, root: Directory, name: str) -> bool:
    """False if the name is taken, or if it cannot be published without risk of replacing."""
    try:
        move_new(staging, root, name)
    except FileExistsError:
        return False
    except OSError as exc:
        log.warning("Not published, no safe atomic move for %r: %s", name, exc.strerror)
        return False
    return True


def _publish_file(staging: Directory, root: Directory, name: str,
                  content: Callable[[], bytes]) -> bool:
    """False if something already has that name."""
    source, src_fd = staging.at(name)
    target, dst_fd = root.at(name)
    try:
        try:
            # atomic, and unlike rename it never replaces
            os.link(source, target, src_dir_fd=src_fd, dst_dir_fd=dst_fd, follow_symlinks=False)
        except FileExistsError:
            return False
        except OSError:  # no hard links on this file system
            _create(root, name, content())
    except FileExistsError:
        return False
    return True


def decrypt_archive(archive: Path, passphrase: str, out_dir: Path,
                    iterations: int = ITERATIONS) -> list[str]:
    """Extract into out_dir and return the member names that were refused.

    out_dir and every ancestor of it must be ordinary directories. A link anywhere in that path
    is refused, including system ones such as macOS /tmp: pass the physical path.

    Every file is created inside a new private staging directory. A top-level entry is then
    published only where nothing of that name exists, so nothing already on disk is entered,
    followed or replaced.

    Not supported on Windows, where it raises DecryptionError before writing anything: the
    destination cannot be pinned there (see orbit.core.safe_dir).
    """
    data = decrypt_bytes(Path(archive).read_bytes(), passphrase, iterations)
    refused: list[str] = []
    candidates: list[tuple[zipfile.ZipInfo, tuple[str, ...], bool]] = []
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for member in zf.infolist():
            raw = member.orig_filename  # filename is already rewritten on Windows and cut at NUL
            parts = _portable_parts(raw)
            is_dir = raw.endswith(("/", "\\"))
            if parts is None or not _member_type_ok(member, is_dir):
                refused.append(raw)
            else:
                candidates.append((member, parts, is_dir))
        clash = _colliding([(parts, is_dir) for _, parts, is_dir in candidates])
        wanted = []
        for candidate, collides in zip(candidates, clash):
            if collides:
                refused.append(candidate[0].orig_filename)
            else:
                wanted.append(candidate)

        try:
            root = open_directory(out_dir)
        except (OSError, ValueError, UnsafePathError) as exc:
            raise DecryptionError(f"The destination cannot be used safely: {exc}") from exc
        try:
            with root:
                refused += _extract(zf, root, wanted)
        except UnsafePathError as exc:
            raise DecryptionError(f"The destination changed during extraction: {exc}") from exc
    if refused:
        log.warning("Refused %d archive member(s): %r", len(refused), refused[:10])
    return refused


def _extract(zf: zipfile.ZipFile, root: Directory,
             wanted: list[tuple[zipfile.ZipInfo, tuple[str, ...], bool]]) -> list[str]:
    """Stage, then publish. Returns the members that could not be published."""
    scratch = f".orbit-extract-{uuid.uuid4().hex}"
    with root.make(scratch) as staging:
        try:
            top_files: dict[str, zipfile.ZipInfo] = {}
            for member, parts, is_dir in wanted:
                if is_dir:
                    _staged_dir(staging, parts).close()
                elif len(parts) == 1:
                    _create(staging, parts[0], zf.read(member))
                    top_files[parts[0]] = member
                else:
                    with _staged_dir(staging, parts[:-1]) as parent:
                        _create(parent, parts[-1], zf.read(member))

            existing = {_collision_key(n) for n in root.names() if n != scratch}
            unpublished: set[str] = set()
            for name in sorted({parts[0] for _, parts, _ in wanted}):
                root.check()
                if _collision_key(name) in existing:
                    published = False
                elif name in top_files:
                    published = _publish_file(staging, root, name,
                                              functools.partial(zf.read, top_files[name]))
                else:
                    published = _publish_dir(staging, root, name)
                if not published:
                    unpublished.add(name)
        finally:
            if not root.remove(scratch, staging.info):
                log.warning("Could not remove extraction directory %s", staging.path)
    return [member.orig_filename for member, parts, _ in wanted if parts[0] in unpublished]

"""Recognise sign-in tokens so they are never retained, logged or packaged with results."""
from __future__ import annotations

import os
import re
from collections.abc import Iterator
from pathlib import Path

from orbit.core.safe_fs import is_link, open_regular, remove_tree

_NAME_PREFIXES = (".roadtools_auth", "msal_token_cache")
_TOKEN_TOOL_DIRS = ("roadtools",)  # only these folders are also searched by content
_DATABASE_SUFFIXES = (".db", ".sqlite", ".sqlite3")  # tenant data; never deleted on a pattern
_TOKEN_FIELD = re.compile(
    rb"""["'](?:access_?token|refresh_?token|id_?token)["']\s*:\s*["'][^"']{20}""", re.IGNORECASE)
_TOKEN_VALUE = re.compile(
    r"""(["'](?:access_?token|refresh_?token|id_?token)["']\s*:\s*["'])[^"']+""", re.IGNORECASE)
_JWT = re.compile(r"eyJ[\w-]{10,}\.eyJ[\w-]{10,}\.[\w-]*")
_CHUNK = 1 << 20


def redact_tokens(text: str) -> str:
    return _JWT.sub("***", _TOKEN_VALUE.sub(r"\1***", text))


def _has_token(path: Path) -> bool:
    with open_regular(path) as fh:
        tail = b""
        while chunk := fh.read(_CHUNK):
            if _TOKEN_FIELD.search(tail + chunk):
                return True
            tail = chunk[-256:]
    return False


def is_auth_material(path: Path, rel: tuple[str, ...]) -> bool:
    """rel is the path relative to the run folder, so rel[0] is the tool's folder."""
    if any(part.lower().startswith(_NAME_PREFIXES) for part in rel):
        return True
    return (rel[0].lower() in _TOKEN_TOOL_DIRS
            and path.suffix.lower() not in _DATABASE_SUFFIXES and _has_token(path))


def walk_output(top: Path) -> Iterator[tuple[Path, bool]]:
    """(path, is a link) for each non-directory below top; links are reported, never entered."""
    def fail(exc: OSError) -> None:
        raise exc

    for base, dirs, names in os.walk(top, onerror=fail):
        for name in list(dirs):
            path = Path(base, name)
            if is_link(path.lstat()):
                dirs.remove(name)
                yield path, True
        for name in names:
            path = Path(base, name)
            yield path, is_link(path.lstat())


def purge_auth_material(run_folder: Path, below: str = "") -> list[str]:
    """Delete token files from a run folder. Raises if one cannot be checked or removed."""
    top = run_folder / below
    if not top.is_dir() or is_link(top.lstat()):
        return []
    removed: list[str] = []
    for path, link in list(walk_output(top)):
        rel = path.relative_to(run_folder).parts
        named = any(part.lower().startswith(_NAME_PREFIXES) for part in rel)
        if not named and (link or not path.is_file() or not is_auth_material(path, rel)):
            continue
        path.unlink()
        removed.append("/".join(rel))
    for path in sorted(top.rglob("*"), reverse=True):  # directories that were named as token stores
        if path.name.lower().startswith(_NAME_PREFIXES) and not path.is_symlink():
            if not remove_tree(path):
                raise OSError(f"could not remove {path.name!r}")
    return removed

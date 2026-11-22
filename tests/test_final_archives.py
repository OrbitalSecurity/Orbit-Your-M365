"""Final hardening items 1-3: linked ancestors, non-replacing publication, generated names."""
import errno
import io
import os
import random
import stat
import sys
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from orbit.core import safe_dir
from orbit.security import encryption
from orbit.security.encryption import DecryptionError, decrypt_archive, encrypt_bytes, encrypt_folder

FAST = 1000
posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX links, modes or names")


def _archive(tmp_path, *names):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name in names:
            zf.writestr(name, b"payload")
    path = tmp_path / "a.orbit.zip"
    path.write_bytes(encrypt_bytes(buf.getvalue(), "pw", iterations=FAST))
    return path


def _payloads(root):
    return [p for p in Path(root).rglob("*") if p.is_file() and p.read_bytes() == b"payload"]


def _extract(archive, dest):
    if sys.platform == "win32":
        pytest.skip("extraction fails closed on Windows; see test_review_findings.py")
    return decrypt_archive(archive, "pw", dest, iterations=FAST)


# --- 1. destination ancestors -----------------------------------------------

@posix_only
@pytest.mark.parametrize("below", ["new", "new/deeper/out", "present", "present/new"])
def test_linked_ancestor_is_refused_before_anything_is_written(tmp_path, below):
    outside = tmp_path / "outside"
    (outside / "present").mkdir(parents=True)
    (tmp_path / "linked").symlink_to(outside)
    with pytest.raises(DecryptionError, match="link"):
        _extract(_archive(tmp_path, "x", "d/y"), tmp_path / "linked" / below)
    assert sorted(p.relative_to(outside).as_posix() for p in outside.rglob("*")) == ["present"]


@posix_only
@pytest.mark.parametrize("position", [0, 1, 2, 3])
def test_a_link_at_any_depth_is_refused(tmp_path, position):
    names = ["a", "b", "c", "out"]
    here = tmp_path.joinpath(*names[:position])
    here.mkdir(parents=True, exist_ok=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    (here / names[position]).symlink_to(outside)
    with pytest.raises(DecryptionError):
        _extract(_archive(tmp_path, "x"), tmp_path.joinpath(*names))
    assert list(outside.iterdir()) == []


@posix_only
@pytest.mark.parametrize("kind", ["dangling", "file", "fifo"])
def test_dangling_or_special_ancestor_is_refused(tmp_path, kind):
    ancestor = tmp_path / "ancestor"
    if kind == "dangling":
        ancestor.symlink_to(tmp_path / "absent")
    elif kind == "file":
        ancestor.write_text("a file")
    else:
        os.mkfifo(ancestor)
    with pytest.raises(DecryptionError):
        _extract(_archive(tmp_path, "x"), ancestor / "out")
    assert not (tmp_path / "absent").exists()


@pytest.mark.parametrize("tag, attributes", [
    (0xA0000003, 0x410), (0xA000000C, 0x410), (0x8000000A, 0x410), (0x9000001A, 0x410),
    (0xA0000003, 0), (0, 0x410),
], ids=["junction", "symlink", "dfs", "cloud", "tag-only", "attribute-only"])
def test_simulated_windows_reparse_ancestor_is_refused(
        tmp_path, monkeypatch, tag, attributes):
    junction = tmp_path / "junction"
    junction.mkdir()
    archive = _archive(tmp_path, "x")
    real = os.lstat

    class Reparse:
        """A junction reports as an ordinary directory, apart from these two fields."""

        def __init__(self, info):
            self._info = info
            self.st_reparse_tag, self.st_file_attributes = tag, attributes

        def __getattr__(self, name):
            return getattr(self._info, name)

    def lstat(path, **kwargs):
        info = real(path, **kwargs)
        return Reparse(info) if os.path.basename(os.fspath(path)) == "junction" else info

    monkeypatch.setattr(safe_dir.os, "lstat", lstat)
    with pytest.raises(DecryptionError):
        _extract(archive, junction / "new" / "out")
    monkeypatch.undo()
    assert list(junction.iterdir()) == []


def test_parent_references_are_ambiguous(tmp_path):
    with pytest.raises(DecryptionError, match=r"\.\."):
        _extract(_archive(tmp_path, "x"), tmp_path / "a" / ".." / "out")
    assert not (tmp_path / "a").exists() and not (tmp_path / "out").exists()


@pytest.mark.parametrize("part", ["trailing.", "trailing ", "stream:name"])
def test_names_windows_reads_differently_are_refused_there(tmp_path, monkeypatch, part):
    path = tmp_path / part / "out"
    monkeypatch.setattr(safe_dir.sys, "platform", "win32")
    monkeypatch.setattr(safe_dir, "_FD_RELATIVE", False)
    with pytest.raises(safe_dir.UnsafePathError, match="Windows"):
        safe_dir.open_directory(path)
    monkeypatch.undo()
    assert not (tmp_path / part).exists()


@posix_only
@pytest.mark.parametrize("replacement", ["link", "directory"])
def test_ancestor_replaced_between_check_and_open_is_refused(tmp_path, monkeypatch, replacement):
    ancestor, outside = tmp_path / "ancestor", tmp_path / "outside"
    ancestor.mkdir()
    outside.mkdir()
    archive = _archive(tmp_path, "x")
    real = os.open

    def swap(path, *args, **kwargs):
        if path == "ancestor" and not (tmp_path / "moved").exists():
            ancestor.rename(tmp_path / "moved")
            if replacement == "link":
                ancestor.symlink_to(outside)
            else:
                ancestor.mkdir()
        return real(path, *args, **kwargs)

    monkeypatch.setattr(safe_dir.os, "open", swap)
    with pytest.raises(DecryptionError):
        _extract(archive, ancestor / "out")
    monkeypatch.undo()
    assert (tmp_path / "moved").exists() and list(outside.iterdir()) == []
    assert not list(tmp_path.glob("*/out"))


@posix_only
@pytest.mark.parametrize("when", ["setup", "extraction"])
def test_ancestor_replaced_after_its_check_is_never_followed(tmp_path, monkeypatch, when):
    ancestor, outside = tmp_path / "ancestor", tmp_path / "outside"
    ancestor.mkdir()
    (outside / "out").mkdir(parents=True)
    archive = _archive(tmp_path, "x", "d/y")
    trigger = "out" if when == "setup" else ".orbit-extract-"
    real = safe_dir.Directory.make

    def make_then_swap(self, name):
        made = real(self, name)
        if name.startswith(trigger):
            ancestor.rename(tmp_path / "moved")
            ancestor.symlink_to(outside)
        return made

    monkeypatch.setattr(safe_dir.Directory, "make", make_then_swap)
    with pytest.raises(DecryptionError):
        _extract(archive, ancestor / "out")
    assert list((outside / "out").iterdir()) == []
    assert _payloads(tmp_path / "moved") == []


@posix_only
@pytest.mark.parametrize("entry", ["directory", "link"])
def test_component_appearing_during_setup_is_refused(tmp_path, monkeypatch, entry):
    outside = tmp_path / "outside"
    outside.mkdir()
    archive = _archive(tmp_path, "x")
    real = os.mkdir

    def race(path, *args, **kwargs):
        if os.path.basename(path) == "new":
            if entry == "link":
                (tmp_path / "new").symlink_to(outside)
            else:
                real(tmp_path / "new")
        return real(path, *args, **kwargs)

    monkeypatch.setattr(safe_dir.os, "mkdir", race)
    with pytest.raises(DecryptionError):
        _extract(archive, tmp_path / "new" / "out")
    assert list(outside.iterdir()) == []
    assert entry == "link" or list((tmp_path / "new").iterdir()) == []


@posix_only
def test_created_component_owned_by_someone_else_is_refused(tmp_path, monkeypatch):
    archive = _archive(tmp_path, "x")
    monkeypatch.setattr(safe_dir.os, "geteuid", lambda: 987654)
    with pytest.raises(DecryptionError, match="replaced"):
        _extract(archive, tmp_path / "out")
    assert list((tmp_path / "out").iterdir()) == []


@posix_only
def test_missing_components_are_created_private(tmp_path):
    assert _extract(_archive(tmp_path, "x"), tmp_path / "one" / "two") == []
    for path in (tmp_path / "one", tmp_path / "one" / "two"):
        assert stat.S_IMODE(path.stat().st_mode) == 0o700
    assert [p.name for p in (tmp_path / "one" / "two").iterdir()] == ["x"]


def test_relative_destination_still_works(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert _extract(_archive(tmp_path, "x"), Path("out")) == []
    assert (tmp_path / "out" / "x").read_bytes() == b"payload"


@posix_only
def test_search_only_ancestor_is_enough(tmp_path):
    parent = tmp_path / "search-only"
    (parent / "out").mkdir(parents=True)
    archive = _archive(tmp_path, "x")
    parent.chmod(0o100)
    try:
        assert _extract(archive, parent / "out") == []
    finally:
        parent.chmod(0o700)


# --- 2. publication -----------------------------------------------------------

def test_empty_directory_appearing_after_the_check_is_not_replaced(tmp_path, monkeypatch):
    dest, real, winner = tmp_path / "out", encryption.move_new, []

    def race(source, root, name):
        (dest / name).mkdir()
        winner.append((dest / name).stat())
        return real(source, root, name)

    monkeypatch.setattr(encryption, "move_new", race)
    assert _extract(_archive(tmp_path, "race/inner", "safe.txt"), dest) == ["race/inner"]
    assert os.path.samestat(winner[0], (dest / "race").stat())
    assert list((dest / "race").iterdir()) == []
    assert sorted(p.name for p in dest.iterdir()) == ["race", "safe.txt"]


def test_empty_directory_appearing_after_the_listing_is_not_replaced(tmp_path, monkeypatch):
    dest, real, winner = tmp_path / "out", safe_dir.Directory.names, []

    def list_then_race(self):
        found = real(self)
        if self.path == dest and found and not winner:  # the listing taken just before publishing
            (dest / "race").mkdir()
            winner.append((dest / "race").stat())
        return found

    monkeypatch.setattr(safe_dir.Directory, "names", list_then_race)
    assert _extract(_archive(tmp_path, "race/inner"), dest) == ["race/inner"]
    assert os.path.samestat(winner[0], (dest / "race").stat())
    assert list((dest / "race").iterdir()) == []


@posix_only
@pytest.mark.parametrize("kind", ["full-dir", "file", "link-to-dir", "dangling"])
def test_any_entry_appearing_after_the_check_is_left_untouched(tmp_path, monkeypatch, kind):
    dest, outside, real = tmp_path / "out", tmp_path / "outside", encryption.move_new
    outside.mkdir()

    def race(source, root, name):
        if kind == "full-dir":
            (dest / name).mkdir()
            (dest / name / "theirs").write_text("theirs")
        elif kind == "file":
            (dest / name).write_text("theirs")
        else:
            (dest / name).symlink_to(outside if kind == "link-to-dir" else tmp_path / "absent")
        return real(source, root, name)

    monkeypatch.setattr(encryption, "move_new", race)
    assert _extract(_archive(tmp_path, "race/inner"), dest) == ["race/inner"]
    assert _payloads(tmp_path) == [] and list(outside.iterdir()) == []
    if kind == "full-dir":
        assert (dest / "race" / "theirs").read_text() == "theirs"
    elif kind == "file":
        assert (dest / "race").read_text() == "theirs"
    else:
        assert (dest / "race").is_symlink() and not (tmp_path / "absent").exists()


@posix_only
@pytest.mark.parametrize("support", ["no-symbol", "file-system"])
def test_directory_is_refused_without_an_atomic_safe_move(tmp_path, monkeypatch, support):
    def unsupported(*args):
        raise OSError(errno.ENOTSUP, "not supported")

    if support == "no-symbol":
        monkeypatch.setattr(safe_dir, "_exclusive_rename", lambda: None)
    else:
        monkeypatch.setattr(encryption, "move_new", unsupported)
    refused = _extract(_archive(tmp_path, "dir/inner", "safe.txt"), tmp_path / "out")
    assert refused == ["dir/inner"]
    assert [p.name for p in (tmp_path / "out").iterdir()] == ["safe.txt"]


def test_whole_tree_is_published(tmp_path):
    assert _extract(_archive(tmp_path, "d/a", "d/e/f/g", "empty/"), tmp_path / "out") == []
    found = {p.relative_to(tmp_path / "out").as_posix() for p in (tmp_path / "out").rglob("*")}
    assert found == {"d", "d/a", "d/e", "d/e/f", "d/e/f/g", "empty"}


@pytest.mark.parametrize("platform, symbol, flag",
                         [("linux", "renameat2", 1), ("darwin", "renameatx_np", 4)])
def test_the_non_replacing_kernel_call_is_selected(monkeypatch, platform, symbol, flag):
    call = SimpleNamespace()
    monkeypatch.setattr(safe_dir.sys, "platform", platform)
    monkeypatch.setattr(safe_dir.ctypes, "CDLL", lambda *a, **k: SimpleNamespace(**{symbol: call}))
    assert safe_dir._exclusive_rename.__wrapped__() == (call, flag)


def test_windows_never_publishes_by_pathname(monkeypatch):
    monkeypatch.setattr(safe_dir.sys, "platform", "win32")
    monkeypatch.setattr(safe_dir, "_FD_RELATIVE", False)
    for name in ("rename", "replace"):
        monkeypatch.setattr(safe_dir.os, name, lambda *args: pytest.fail("published by pathname"))
    source, dest = (SimpleNamespace(at=lambda name: pytest.fail("a target was resolved"))
                    for _ in range(2))
    with pytest.raises(OSError) as refused:
        safe_dir.move_new(source, dest, "member")
    assert refused.value.errno == errno.ENOTSUP


# --- 3. generated member names ------------------------------------------------

@posix_only
@pytest.mark.parametrize("present", [
    "renamed-by-orbit/0_a_b", "renamed-by-orbit/1_a_b", "Renamed-By-Orbit/x",
    "RENAMED-BY-ORBIT/0_A_B", "renamed-by-orbit", "Renamed-By-Orbit", "renamed-by-orbit.",
    "renamed-by-orbit /x", "renamed-by-orbit/0_a_b/child", "renamed-by-orbit/bad:name",
])
def test_generated_names_round_trip_beside_user_content(tmp_path, present):
    src, dest = tmp_path / "run", tmp_path / "restored"
    for name in (present, "a:b"):
        path = src / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"content of {name}")
    assert _extract(encrypt_folder(src, "pw", iterations=FAST), dest) == []
    restored = sorted(p.read_text() for p in dest.rglob("*") if p.is_file())
    assert restored == sorted([f"content of {present}", "content of a:b"])


@posix_only
def test_repeated_round_trips_never_collide_with_earlier_generated_names(tmp_path):
    src = tmp_path / "gen0"
    src.mkdir()
    (src / "a:b").write_text("a:b from 0")
    contents = {"a:b from 0"}
    for number in range(1, 5):
        dest = tmp_path / f"gen{number}"
        assert _extract(encrypt_folder(src, "pw", iterations=FAST), dest) == []
        assert {p.read_text() for p in dest.rglob("*") if p.is_file()} == contents
        (dest / "a:b").write_text(f"a:b from {number}")
        contents.add(f"a:b from {number}")
        src = dest


@posix_only
def test_too_deep_for_extraction_is_renamed_when_packaged(tmp_path):
    src = tmp_path / "run"
    deep = src.joinpath(*(["d"] * (encryption._MAX_DEPTH + 1)))
    deep.mkdir(parents=True)
    (deep / "f").write_text("deep")
    assert _extract(encrypt_folder(src, "pw", iterations=FAST), tmp_path / "out") == []
    assert [p.read_text() for p in (tmp_path / "out").rglob("*") if p.is_file()] == ["deep"]


@pytest.mark.parametrize("taken", [
    "renamed-by-orbit", "RENAMED-BY-ORBIT", "renamed-by-orbit. .", "Renamed-By-Orbit ",
    "renamed-by-orbıt",
])
def test_every_equivalent_spelling_reserves_the_generated_directory(taken):
    for names in ([(taken,)], [(taken, "child")]):
        assert encryption._renamed_dir(names) == "renamed-by-orbit-1"
    both = [(taken,), ("Renamed-By-Orbit-1", "child")]
    assert encryption._renamed_dir(both) == "renamed-by-orbit-2"


def test_generated_namespace_is_collision_free_for_hostile_trees(tmp_path, monkeypatch):
    # simulated, because a case-insensitive file system cannot hold most of these trees
    atoms = ["renamed-by-orbit", "Renamed-By-Orbit", "renamed-by-orbit-1", "RENAMED-BY-ORBIT-1",
             "renamed-by-orbit.", "0_a_b", "0_A_B", "1_a_b", "a:b", "café", "café", "CON"]
    rng = random.Random(20261122)
    regular = tmp_path / "regular"
    regular.write_text("x")
    info = regular.lstat()
    monkeypatch.setattr(Path, "lstat", lambda self: info)
    monkeypatch.setattr(encryption, "is_auth_material", lambda *args: False)
    monkeypatch.setattr(encryption, "read_below", lambda root, name: (name.encode(), False))
    monkeypatch.setattr(zipfile.ZipInfo, "from_file",
                        lambda path, arcname, **kwargs: zipfile.ZipInfo(arcname))
    for _ in range(2000):
        tree = set()
        for _ in range(rng.randint(1, 7)):
            new = tuple(rng.choices(atoms, k=rng.randint(1, 3)))
            # a file cannot also be a directory under the very same spelling
            if not any(new[:len(old)] == old or old[:len(new)] == new for old in tree):
                tree.add(new)
        paths = [(tmp_path.joinpath(*parts), False) for parts in sorted(tree)]
        monkeypatch.setattr(encryption, "walk_output", lambda folder, found=paths: found)
        with zipfile.ZipFile(io.BytesIO(encryption.zip_folder_bytes(tmp_path))) as zf:
            members = [encryption._portable_parts(name) for name in zf.namelist()]
            assert all(members) and not any(encryption._colliding([(p, False) for p in members])), tree
            assert sorted(map(zf.read, zf.namelist())) == sorted("/".join(p).encode() for p in tree)

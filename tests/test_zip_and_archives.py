"""Findings 5 and 10: exact-destination extraction and archive-name reservation."""
import io
import os
import stat
import sys
import zipfile
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

import pytest

from orbit.core import outputs, safe_dir
from orbit.core.outputs import OutputConfig, make_run_folder, package
from orbit.security import encryption
from orbit.security.encryption import DecryptionError, decrypt_archive, encrypt_bytes, encrypt_folder

FAST = 1000
posix_only = pytest.mark.skipif(sys.platform == "win32", reason="needs POSIX names or links")


def _archive(tmp_path, *members):
    """members are names, or (ZipInfo, data)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for member in members:
            if isinstance(member, tuple):
                zf.writestr(*member)
            else:
                zf.writestr(member, b"data")
    path = tmp_path / "a.orbit.zip"
    path.write_bytes(encrypt_bytes(buf.getvalue(), "pw", iterations=FAST))
    return path


def _extract(tmp_path, *members, dest=None):
    if sys.platform == "win32":
        pytest.skip("extraction fails closed on Windows; see test_review_findings.py")
    dest = dest or tmp_path / "out"
    refused = decrypt_archive(_archive(tmp_path, *members), "pw", dest, iterations=FAST)
    files = sorted(p.relative_to(dest).as_posix() for p in dest.rglob("*") if p.is_file())
    return refused, files


@pytest.mark.parametrize("name", [
    "CON", "con.txt", "PRN", "AUX.json", "NUL", "nul .txt", "COM1", "com9.log", "LPT1",
    "COM\u00b9", "LPT\u00b3.txt", "CONIN$", "CONOUT$", "a/CON/b",
    "file.txt:stream", "a:b", "x<y", "x>y", 'x"y', "x|y", "x?y", "x*y", "tab\there", "bell\x07",
    "trail.", "trail ", "dir./f", "dir /f", "a/...", "PROGRA~1/x", "REPORT~1.TXT", "a" * 256,
])
def test_windows_hostile_names_are_refused(tmp_path, name):
    refused, files = _extract(tmp_path, name, "safe.txt")
    assert refused == [name] and files == ["safe.txt"]


@pytest.mark.parametrize("name", [
    "console.txt", "COM10", "nullable.json", "a b.txt", "~$draft.docx", "r\u00e9sum\u00e9.pdf",
    "v1..2.txt", ".hidden", "REPORT-2026-11-22.json",
])
def test_similar_but_legitimate_names_extract(tmp_path, name):
    assert _extract(tmp_path, name) == ([], [name])


def test_embedded_nul_is_refused(tmp_path):
    info = zipfile.ZipInfo("placeholder")
    info.filename = "safe.txt\x00.exe"
    refused, files = _extract(tmp_path, (info, b"data"))
    assert refused == ["safe.txt\x00.exe"] and files == []


@pytest.mark.parametrize("first, second", [
    ("Report.json", "report.JSON"), ("Dir/a", "dir/b"), ("caf\u00e9", "cafe\u0301"),
    ("a/b", "a\\b"), ("a/b", "./a/b"), ("a/b", "a//b"), ("node", "node/child"),
    ("node", "NODE/child"), ("x/\u0130", "X/\u0130"), ("same.txt", "same.txt"),
])
@pytest.mark.filterwarnings("ignore:Duplicate name")
def test_colliding_names_are_all_refused(tmp_path, first, second):
    for order in ((first, second), (second, first)):
        dest = tmp_path / f"out{len(list(tmp_path.glob('out*')))}"
        refused, files = _extract(tmp_path, *order, "safe.txt", dest=dest)
        assert sorted(refused) == sorted(order) and files == ["safe.txt"]


@pytest.mark.parametrize("mode", [stat.S_IFLNK | 0o777, stat.S_IFIFO | 0o600, stat.S_IFCHR | 0o600,
                                  stat.S_IFBLK | 0o600, stat.S_IFSOCK | 0o600, stat.S_IFDIR | 0o700],
                         ids=["symlink", "fifo", "char", "block", "socket", "dir-as-file"])
def test_special_and_link_members_are_refused(tmp_path, mode):
    info = zipfile.ZipInfo("member")
    info.external_attr = mode << 16
    refused, files = _extract(tmp_path, (info, b"/etc/passwd"), "safe.txt")
    assert refused == ["member"] and files == ["safe.txt"]
    assert not os.path.lexists(tmp_path / "out" / "member")


def test_windows_reparse_member_is_refused(tmp_path):
    info = zipfile.ZipInfo("junction")
    info.external_attr = 0x400
    assert _extract(tmp_path, (info, b"target"), "safe.txt") == (["junction"], ["safe.txt"])


def test_encrypted_flag_member_is_refused():
    info = zipfile.ZipInfo("member")
    info.flag_bits |= 0x1
    assert not encryption._member_type_ok(info, False)


@pytest.mark.parametrize("member", ["existing/evil", "EXISTING/evil", "existing", "Existing.TXT"])
def test_nothing_already_present_is_entered_or_replaced(tmp_path, member):
    dest = tmp_path / "out"
    (dest / "existing").mkdir(parents=True)
    (dest / "existing.txt").write_text("original")
    refused, files = _extract(tmp_path, member, dest=dest)
    assert refused == [member] and files == ["existing.txt"]
    assert (dest / "existing.txt").read_text() == "original"


@posix_only
@pytest.mark.parametrize("present", ["name.", "name ", "name. ."])
def test_existing_name_that_windows_would_treat_as_equal_blocks_publish(tmp_path, present):
    dest = tmp_path / "out"
    dest.mkdir()
    (dest / present).write_text("original")
    refused, files = _extract(tmp_path, "name", dest=dest)
    assert refused == ["name"] and files == [present]


@posix_only
@pytest.mark.parametrize("target", ["dir", "file", "dangling"])
def test_preexisting_link_is_never_followed(tmp_path, target):
    outside, dest = tmp_path / "outside", tmp_path / "out"
    dest.mkdir()
    if target == "dir":
        outside.mkdir()
    elif target == "file":
        outside.write_text("original")
    (dest / "link").symlink_to(outside)
    member = "link/evil" if target == "dir" else "link"
    refused, _ = _extract(tmp_path, member, dest=dest)
    assert refused == [member] and (dest / "link").is_symlink()
    if target == "dir":
        assert list(outside.iterdir()) == []
    elif target == "file":
        assert outside.read_text() == "original"
    else:
        assert not outside.exists()


def test_preexisting_junction_is_never_entered(tmp_path, monkeypatch):
    # a junction looks like an ordinary directory, so model it as one whose contents are "outside"
    junction = tmp_path / "out" / "junction"
    junction.mkdir(parents=True)
    written = []
    real = encryption.create_file
    monkeypatch.setattr(encryption, "create_file",
                        lambda path, *a, **k: (written.append(Path(path)), real(path, *a, **k)))
    refused, _ = _extract(tmp_path, "junction/evil")
    assert refused == ["junction/evil"] and list(junction.iterdir()) == []
    assert not any(p.is_relative_to(junction) for p in written)


def test_destination_that_is_a_junction_is_refused(tmp_path, monkeypatch):
    dest = tmp_path / "out"
    dest.mkdir()
    real = safe_dir.is_link
    monkeypatch.setattr(safe_dir, "is_link",
                        lambda info: os.path.samestat(info, dest.stat()) or real(info))
    with pytest.raises(DecryptionError):
        decrypt_archive(_archive(tmp_path, "x"), "pw", dest, iterations=FAST)
    assert list(dest.iterdir()) == []


@posix_only
def test_destination_that_is_a_symlink_is_refused(tmp_path):
    (tmp_path / "real").mkdir()
    (tmp_path / "out").symlink_to(tmp_path / "real")
    with pytest.raises(DecryptionError):
        decrypt_archive(_archive(tmp_path, "x"), "pw", tmp_path / "out", iterations=FAST)
    assert list((tmp_path / "real").iterdir()) == []


def test_file_appearing_during_publish_is_not_replaced(tmp_path, monkeypatch):
    real_link = os.link

    def race(source, target, **kwargs):
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600,
                     dir_fd=kwargs.get("dst_dir_fd"))
        os.write(fd, b"winner")
        os.close(fd)
        return real_link(source, target, **kwargs)

    monkeypatch.setattr(encryption.os, "link", race)
    refused, _ = _extract(tmp_path, "member")
    assert refused == ["member"] and (tmp_path / "out" / "member").read_text() == "winner"


def test_publish_without_hard_link_support(tmp_path, monkeypatch):
    def unsupported(*args, **kwargs):
        raise OSError("no hard links")

    monkeypatch.setattr(encryption.os, "link", unsupported)
    assert _extract(tmp_path, "member") == ([], ["member"])


@posix_only  # extraction fails closed on Windows
def test_failed_extraction_publishes_nothing(tmp_path, monkeypatch):
    real, calls = encryption.create_file, []

    def fails_second(path, *args, **kwargs):
        calls.append(path)
        if len(calls) == 2:
            raise OSError("disk full")
        real(path, *args, **kwargs)

    archive = _archive(tmp_path, "one", "two")
    monkeypatch.setattr(encryption, "create_file", fails_second)
    with pytest.raises(OSError):
        decrypt_archive(archive, "pw", tmp_path / "out", iterations=FAST)
    assert list((tmp_path / "out").iterdir()) == []


@posix_only
def test_own_archives_round_trip_nonportable_names_without_loss(tmp_path):
    src = tmp_path / "run"
    src.mkdir()
    names = ["a:b.json", "trail.", "back\\slash", "CON", "plain.txt"]
    for name in names:
        (src / name).write_text(f"content of {name}")
    archive = encrypt_folder(src, "pw", iterations=FAST)
    assert decrypt_archive(archive, "pw", tmp_path / "out", iterations=FAST) == []
    restored = {p.read_text() for p in (tmp_path / "out").rglob("*") if p.is_file()}
    assert restored == {f"content of {name}" for name in names}


@posix_only
def test_packaging_never_follows_links(tmp_path):
    src, outside = tmp_path / "run", tmp_path / "outside"
    src.mkdir()
    outside.mkdir()
    (outside / "secret").write_text("outside the run")
    (src / "file-link").symlink_to(outside / "secret")
    (src / "dir-link").symlink_to(outside)
    (src / "report").write_text("report")
    archive = encrypt_folder(src, "pw", iterations=FAST)
    decrypt_archive(archive, "pw", tmp_path / "out", iterations=FAST)
    assert [p.name for p in (tmp_path / "out").iterdir()] == ["report"]


# --- reservation ------------------------------------------------------------

@posix_only  # reads each archive back, and extraction fails closed on Windows
def test_concurrent_packaging_never_overwrites_an_archive(tmp_path):
    folder = tmp_path / "run"
    folder.mkdir()
    (folder / "report").write_text("report")
    cfg = OutputConfig(tmp_path, encrypt=True)
    with ThreadPoolExecutor(16) as pool:
        archives = list(pool.map(lambda _: package(folder, cfg, "pw", FAST), range(32)))
    assert len(set(archives)) == 32
    for number, archive in enumerate(archives):
        dest = tmp_path / f"out{number}"
        assert decrypt_archive(archive, "pw", dest, iterations=FAST) == []
        assert (dest / "report").read_text() == "report"


def test_existing_archive_is_untouched(tmp_path):
    folder = tmp_path / "run"
    folder.mkdir()
    (tmp_path / "run.orbit.zip").write_bytes(b"earlier")
    assert encrypt_folder(folder, "pw", iterations=FAST).name != "run.orbit.zip"
    with pytest.raises(FileExistsError):
        encrypt_folder(folder, "pw", tmp_path / "run.orbit.zip", iterations=FAST)
    assert (tmp_path / "run.orbit.zip").read_bytes() == b"earlier"


@posix_only
def test_link_at_the_archive_name_is_not_written_through(tmp_path):
    folder, victim = tmp_path / "run", tmp_path / "victim"
    folder.mkdir()
    victim.write_text("original")
    (tmp_path / "run.orbit.zip").symlink_to(victim)
    encrypt_folder(folder, "pw", iterations=FAST)
    assert victim.read_text() == "original"


def test_failed_archive_write_keeps_plaintext_and_leaves_no_partial(tmp_path, monkeypatch):
    folder = tmp_path / "run"
    folder.mkdir()

    def fail(fd):
        raise OSError("disk full")

    monkeypatch.setattr("orbit.core.safe_fs.os.fsync", fail)
    with pytest.raises(OSError):
        package(folder, OutputConfig(tmp_path, encrypt=True, keep_unencrypted=False), "pw", FAST)
    assert [p.name for p in tmp_path.iterdir()] == ["run"]


def test_run_name_is_retried_if_its_archive_appears_during_reservation(tmp_path, monkeypatch):
    ids = iter(["a" * 32, "b" * 32])
    monkeypatch.setattr(outputs.uuid, "uuid4", lambda: type("U", (), {"hex": next(ids)})())
    real = Path.mkdir

    def mkdir(self, *args, **kwargs):
        real(self, *args, **kwargs)
        if self.name.endswith("aaaaaaaa"):
            self.with_name(self.name + ".orbit.zip").write_text("just packaged")

    monkeypatch.setattr(Path, "mkdir", mkdir)
    assert make_run_folder(tmp_path, datetime(2026, 11, 22)).name.endswith("bbbbbbbb")

"""Regression tests for containment, output isolation, SMTP and child-environment invariants."""
import io
import smtplib
import sys
import zipfile
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime
from unittest.mock import patch

import pytest
from docx import Document

from orbit.core import emailer, process_env
from orbit.core.outputs import OutputConfig, make_run_folder, package
from orbit.core.runner import stream_process
from orbit.reporting import exec_summary
from orbit.reporting.context import ReportContext
from orbit.reporting.docx_report import generate_docx
from orbit.reporting.parser import Finding
from orbit.security.encryption import decrypt_archive, encrypt_bytes

FAST = 1000
NOW = datetime(2026, 11, 22, 10, 30, 15)


# --- ZIP --------------------------------------------------------------------

def _extract(tmp_path, names, dest):
    if sys.platform == "win32":
        pytest.skip("extraction fails closed on Windows; see test_review_findings.py")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name in names:
            zf.writestr(name, b"data")
    archive = tmp_path / "a.orbit.zip"
    archive.write_bytes(encrypt_bytes(buf.getvalue(), "pw", iterations=FAST))
    decrypt_archive(archive, "pw", dest, iterations=FAST)


@pytest.mark.parametrize("name", [
    "../evil", "a/../../evil", "a/../evil", "..\\evil", "a\\..\\..\\evil", "a/..\\evil",
    "/abs/evil", "\\abs\\evil", "C:/evil", "C:\\evil", "C:evil",
    "//host/share/evil", "\\\\host\\share\\evil", "\\\\?\\C:\\evil",
    ".. /evil", "..\\ evil\\..", ".../evil", "a/.. ./evil", ".",
])
def test_zip_hostile_names_write_nothing(tmp_path, name):
    dest = tmp_path / "deep" / "out"
    dest.mkdir(parents=True)
    _extract(tmp_path, [name, "safe.txt"], dest)
    written = sorted(p.relative_to(tmp_path).as_posix() for p in tmp_path.rglob("*") if p.is_file())
    assert written == ["a.orbit.zip", "deep/out/safe.txt"]


def test_zip_benign_names_still_extract(tmp_path):
    dest = tmp_path / "out"
    _extract(tmp_path, ["a/b.txt", "win\\c.txt", "dir/", "v1..2.txt", ".hidden", "./d.txt"], dest)
    for rel in ("a/b.txt", "win/c.txt", "v1..2.txt", ".hidden", "d.txt"):
        assert (dest / rel).read_bytes() == b"data"
    assert (dest / "dir").is_dir()


@pytest.mark.skipif(sys.platform == "win32", reason="symlink creation needs privileges")
def test_zip_does_not_write_through_existing_symlink(tmp_path):
    outside, dest = tmp_path / "outside", tmp_path / "out"
    outside.mkdir()
    dest.mkdir()
    (dest / "link").symlink_to(outside, target_is_directory=True)
    _extract(tmp_path, ["link/evil"], dest)
    assert not (outside / "evil").exists()


@pytest.mark.skipif(sys.platform == "win32", reason="zipfile normalises separators on Windows")
def test_zip_shared_metadata_is_not_renamed(tmp_path, monkeypatch):
    real, seen = zipfile.ZipFile.read, []

    def spy(self, member, *args, **kwargs):
        seen.append((member.filename, [m.filename for m in self.filelist]))
        return real(self, member, *args, **kwargs)

    def forbidden(*args, **kwargs):
        raise AssertionError("platform-specific zipfile extraction was used")

    monkeypatch.setattr(zipfile.ZipFile, "read", spy)
    monkeypatch.setattr(zipfile.ZipFile, "extract", forbidden)
    monkeypatch.setattr(zipfile.ZipFile, "extractall", forbidden)
    _extract(tmp_path, ["win\\c.txt"], tmp_path / "out")
    assert (tmp_path / "out" / "win" / "c.txt").read_bytes() == b"data"
    assert seen == [("win\\c.txt", ["win\\c.txt"])]


# --- executive summary ------------------------------------------------------

@pytest.mark.parametrize("client", [
    "../../evil", "..\\..\\evil", "/etc/passwd", "C:\\Windows\\x", "\\\\host\\share",
    "a/b", "Acme: Ltd", "line\nbreak", "..", "///", "\u2044\uff0f..", "A" * 300,
])
@pytest.mark.parametrize("unicode_font", [True, False])
def test_exec_summary_stays_in_out_dir(tmp_path, monkeypatch, client, unicode_font):
    if not unicode_font:
        monkeypatch.setattr(exec_summary, "_find_font", lambda: None)
    dest = tmp_path / "deep" / "out"
    path = exec_summary.generate_exec_summary([], dest, client)
    assert path.parent == dest and [p for p in tmp_path.rglob("*") if p.is_file()] == [path]
    assert not set('/\\:\n') & set(path.name) and ".." not in path.name and len(path.name) < 80


# --- output folders ---------------------------------------------------------

def test_same_instant_runs_get_distinct_empty_folders(tmp_path):
    with ThreadPoolExecutor(16) as pool:
        folders = list(pool.map(lambda _: make_run_folder(tmp_path, NOW), range(100)))
    assert len(set(folders)) == 100 and all(not list(f.iterdir()) for f in folders)


def test_existing_folder_and_archive_names_are_never_reused(tmp_path, monkeypatch):
    ids = iter(["a" * 32, "b" * 32, "c" * 32])
    monkeypatch.setattr("orbit.core.outputs.uuid.uuid4",
                        lambda: type("U", (), {"hex": next(ids)})())
    stale = tmp_path / "2026-11-22_10-30-15_aaaaaaaa"
    stale.mkdir()
    (stale / "old.json").write_text("{}")
    (tmp_path / "2026-11-22_10-30-15_bbbbbbbb.orbit.zip").write_text("earlier archive")
    folder = make_run_folder(tmp_path, NOW)
    assert folder.name.endswith("cccccccc") and not list(folder.iterdir())


def test_encrypted_runs_in_the_same_second_keep_both_archives(tmp_path):
    cfg = OutputConfig(base_dir=tmp_path, encrypt=True, keep_unencrypted=False)
    archives = {package(make_run_folder(tmp_path, NOW), cfg, "pw", FAST) for _ in range(2)}
    assert len(archives) == 2 and all(a.exists() for a in archives)


def test_run_folder_is_absolute_for_relative_base(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert make_run_folder("output", NOW).is_absolute()


# --- SMTP -------------------------------------------------------------------

def _settings(host="smtp.example.com", port=587, tls=True, password="pw"):
    return emailer.EmailSettings(host, port, tls, "orbit@example.com", password, ["to@example.com"])


@pytest.mark.parametrize("port", [25, 465, 587, 2525])
def test_smtp_never_sends_credentials_in_plaintext(port):
    with patch("orbit.core.emailer.smtplib.SMTP") as smtp:
        server = smtp.return_value
        ok, detail = emailer.send_test(_settings(port=port, tls=False))
    assert not ok and "plaintext" in detail
    server.login.assert_not_called()
    server.sendmail.assert_not_called()


def test_smtp_logs_in_only_after_starttls():
    with patch("orbit.core.emailer.smtplib.SMTP") as smtp:
        server = smtp.return_value
        assert emailer.send_test(_settings())[0]
    order = [c[0] for c in server.method_calls]
    assert order.index("starttls") < order.index("login") < order.index("sendmail")


@pytest.mark.parametrize("failure", ["not-offered", "rejected"])
def test_smtp_failed_starttls_never_logs_in(monkeypatch, failure):
    # real smtplib, with only the socket operations replaced
    sent = []
    monkeypatch.setattr(smtplib.SMTP, "connect", lambda self, *a, **k: (220, b"ready"))
    monkeypatch.setattr(smtplib.SMTP, "ehlo_or_helo_if_needed", lambda self: None)
    monkeypatch.setattr(smtplib.SMTP, "has_extn", lambda self, name: failure == "rejected")
    monkeypatch.setattr(smtplib.SMTP, "docmd",
                        lambda self, cmd, args="": sent.append(cmd) or (454, b"no"))
    monkeypatch.setattr(smtplib.SMTP, "login", lambda self, *a, **k: sent.append("LOGIN"))
    assert emailer.send_test(_settings())[0] is False
    assert "LOGIN" not in sent and "AUTH" not in sent


@pytest.mark.parametrize("host", ["10.0.0.25", "192.168.1.9", "127.0.0.1", "::1", "localhost",
                                  "mailrelay", "smtp.corp.internal"])
def test_smtp_private_and_on_prem_hosts_are_supported(host):
    with patch("orbit.core.emailer.smtplib.SMTP") as smtp:
        assert emailer.send_test(_settings(host=host))[0]
        smtp.assert_called_once_with(host, 587, timeout=30)


def test_smtp_unauthenticated_relay_still_works():
    with patch("orbit.core.emailer.smtplib.SMTP") as smtp:
        assert emailer.send_test(_settings("mailrelay", 25, False, ""))[0]
        smtp.return_value.login.assert_not_called()
        msg = smtp.return_value.sendmail.call_args.args[2]
    assert "ORBIT test email" in msg


# --- child environment ------------------------------------------------------

BLOCKED = ("AWS_SECRET_ACCESS_KEY", "AZURE_CLIENT_SECRET", "GITHUB_TOKEN", "LD_PRELOAD",
           "DYLD_INSERT_LIBRARIES", "PYTHONPATH", "PYTHONSTARTUP", "PSMODULEPATH")


async def test_child_gets_runtime_but_not_parent_secrets(monkeypatch, tmp_path):
    for key in BLOCKED:
        monkeypatch.setenv(key, "canary")
    monkeypatch.setenv("TMPDIR", str(tmp_path))
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.invalid:8080")
    code = ("import os, ssl, tempfile; ssl.create_default_context(); tempfile.TemporaryFile().close();"
            f"print([k for k in {BLOCKED!r} if os.environ.get(k) == 'canary']);"
            "print(os.environ['TMPDIR'], os.environ['HTTPS_PROXY'], os.environ['ORBIT_X'])")
    lines = []
    rc = await stream_process([sys.executable, "-c", code], {"ORBIT_X": "1"}, lines.append)
    assert rc == 0 and lines == ["[]", f"{tmp_path} http://proxy.invalid:8080 1"]


def test_windows_runtime_variables_pass_through(monkeypatch):
    needed = {"SYSTEMROOT", "COMSPEC", "PATHEXT", "APPDATA", "LOCALAPPDATA", "PROGRAMDATA",
              "PROGRAMFILES", "PROGRAMFILES(X86)", "USERPROFILE", "TEMP", "PROCESSOR_ARCHITECTURE"}
    for key in needed:
        monkeypatch.setenv(key, "value")
    assert needed <= process_env.child_env().keys()


# --- Jinja (audit C3) -------------------------------------------------------

def test_template_syntax_in_values_is_not_evaluated(tmp_path):
    payload = "{{ 1234*4321 }}{% for x in [1] %}X{% endfor %}"
    finding = Finding("id", payload, "High", payload, "d", payload, payload)
    ctx = ReportContext([finding], [payload], client=payload, report_date=date(2026, 11, 22).isoformat())
    text = "\n".join(p.text for p in Document(str(generate_docx(ctx, tmp_path))).paragraphs)
    assert f"Client: {payload}" in text and f"Tools used: {payload}" in text
    assert "5332114" not in text

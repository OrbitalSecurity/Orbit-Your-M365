"""The integrity baseline is per-user state in ORBIT_HOME, never package data.

Synthetic and offline: only fake installations in tmp_path are discovered or hashed, nothing
reaches a network, a tenant, a credential or a real tool, and no process is started.
"""
import hashlib
import json
import os
import stat
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from baseline_helpers import write

import orbit
from orbit.core import baseline, hash_checker
from orbit.core.hash_checker import HashStatus, manifest_path, verify_tool

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover
    import tomli as tomllib

REPO = Path(__file__).resolve().parent.parent
PACKAGE = Path(orbit.__file__).resolve().parent
posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")


def _package_state() -> dict:
    return {p.relative_to(PACKAGE).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in PACKAGE.rglob("*") if p.is_file() and "__pycache__" not in p.parts}


def _run_command():
    try:
        baseline.main([])
    except SystemExit as exc:
        assert exc.code in (0, None), exc.code


# --- active manifest path -----------------------------------------------------

def test_active_manifest_is_in_orbit_home_not_the_package(home):
    assert manifest_path() == home / "tool_hashes.json"
    assert PACKAGE not in manifest_path().parents and REPO not in manifest_path().parents
    assert not hasattr(hash_checker, "MANIFEST_PATH")  # no path captured at import time


def test_orbit_home_changes_after_import_are_respected(tmp_path, monkeypatch, synthetic):
    first, second = tmp_path / "a", tmp_path / "b"
    monkeypatch.setenv("ORBIT_HOME", str(first))
    assert manifest_path() == first / "tool_hashes.json"
    _run_command()
    assert verify_tool(synthetic.tool).status is HashStatus.OK

    monkeypatch.setenv("ORBIT_HOME", str(second))  # another home has no baseline
    assert manifest_path() == second / "tool_hashes.json"
    assert verify_tool(synthetic.tool).status is HashStatus.UNVERIFIED
    assert not (second / "tool_hashes.json").exists()

    monkeypatch.setenv("ORBIT_HOME", str(first))
    assert verify_tool(synthetic.tool).status is HashStatus.OK


# --- fail closed --------------------------------------------------------------

@pytest.mark.parametrize("content", [None, b"", b"{not json", b"\xff\xfe\x00", b"[]", b"{}",
                                     b'{"tools": {"maester": {"versions": {}}}}'])
def test_absent_empty_or_invalid_user_manifest_fails_closed(home, synthetic, content):
    home.mkdir(mode=0o700)
    if content is not None:
        (home / "tool_hashes.json").write_bytes(content)
    result = verify_tool(synthetic.tool)
    assert result.status is HashStatus.UNVERIFIED and result.blocks_run
    assert not hash_checker.gate_run([result])[0]
    if content is None:
        assert result.reason == hash_checker.NO_BASELINE
        assert not (home / "tool_hashes.json").exists()  # checking never seeds or trusts anything


def test_seeded_template_alone_authorises_nothing(home, synthetic, monkeypatch):
    monkeypatch.setattr(baseline, "all_tools", list)  # nothing found: seeds, then exits 1
    with pytest.raises(SystemExit) as stopped:
        baseline.main([])
    assert stopped.value.code == 1
    seeded = json.loads((home / "tool_hashes.json").read_text())
    template = json.loads(hash_checker.TEMPLATE_PATH.read_text())
    # the template's content, plus the binding and generator the raw template never has
    assert {k: v for k, v in seeded.items() if k not in ("binding", "generator")} == template
    assert set(seeded["binding"]) == {"os", "principal", "machine"} and "generator" in seeded
    assert hash_checker.load_manifest().files_for("maester", "1.2.3") is None  # valid, but empty
    assert verify_tool(synthetic.tool).blocks_run


@posix_only
def test_linked_or_special_user_manifest_fails_closed(home, synthetic, tmp_path):
    home.mkdir(mode=0o700)
    target = tmp_path / "elsewhere.json"
    target.write_text(json.dumps({"tools": {}}))
    (home / "tool_hashes.json").symlink_to(target)
    result = verify_tool(synthetic.tool)
    assert result.status is HashStatus.UNVERIFIED and "not trusted" in result.reason
    with pytest.raises(SystemExit):
        baseline.main([])  # and the writer refuses it too
    assert (home / "tool_hashes.json").is_symlink() and json.loads(target.read_text()) == {"tools": {}}


def test_mismatch_after_generation_still_blocks(home, synthetic):
    _run_command()
    assert verify_tool(synthetic.tool).status is HashStatus.OK
    (synthetic.root / "Maester.psm1").write_text("tampered")
    assert verify_tool(synthetic.tool).status is HashStatus.MISMATCH


# --- generation writes only to ORBIT_HOME, securely ---------------------------

def test_generation_writes_only_under_orbit_home(home, synthetic, tmp_path):
    template_before = hash_checker.TEMPLATE_PATH.read_bytes()
    package_before = _package_state()
    _run_command()
    assert _package_state() == package_before  # not a byte in the installed package changed
    assert hash_checker.TEMPLATE_PATH.read_bytes() == template_before
    assert not (PACKAGE / "data" / "tool_hashes.json").exists()
    assert not (REPO / "data").exists()
    assert sorted(p.name for p in home.iterdir()) == ["tool_hashes.json", "tool_hashes.json.lock"]
    recorded = json.loads((home / "tool_hashes.json").read_text())
    assert set(recorded["tools"]["maester"]["versions"]["1.2.3"]["files"]) == {
        "Maester.psd1", "Maester.psm1"}
    assert "_note" not in recorded
    assert verify_tool(synthetic.tool).status is HashStatus.OK


@posix_only
def test_generation_creates_private_home_and_file(home, synthetic):
    _run_command()
    assert stat.S_IMODE(home.stat().st_mode) == 0o700
    assert stat.S_IMODE((home / "tool_hashes.json").stat().st_mode) == 0o600


@posix_only
def test_generation_refuses_a_home_that_others_can_write(home, synthetic, capsys):
    home.mkdir()
    home.chmod(0o777)
    try:
        with pytest.raises(SystemExit) as stopped:
            baseline.main([])
    finally:
        home.chmod(0o700)
    assert stopped.value.code == 1
    assert "NOT updated" in capsys.readouterr().err
    assert not (home / "tool_hashes.json").exists()


def test_generation_preserves_existing_state_exactly(home, synthetic):
    home.mkdir(mode=0o700)
    existing = {"other": {"9": {"f": "00" * 32}}}
    write(home / "tool_hashes.json", existing)
    _run_command()
    tools = json.loads((home / "tool_hashes.json").read_text())["tools"]
    assert tools["other"] == {"versions": {"9": {"files": {"f": "00" * 32}}}} and "maester" in tools


def test_seeding_never_rewrites_an_existing_manifest(home):
    from orbit.core.manifest import seed_manifest
    home.mkdir(mode=0o700)
    odd = b'{"tools":   {"x": 1},\n "schema": 2}'  # unusual formatting must survive byte for byte
    (home / "tool_hashes.json").write_bytes(odd)
    assert seed_manifest(home / "tool_hashes.json", hash_checker.TEMPLATE_PATH.read_bytes()) is False
    assert (home / "tool_hashes.json").read_bytes() == odd


def test_rerun_does_not_rebless_changed_files(home, synthetic):
    _run_command()
    (synthetic.root / "Maester.psm1").write_text("changed")
    with pytest.raises(SystemExit) as stopped:
        baseline.main([])
    assert stopped.value.code == 1
    assert verify_tool(synthetic.tool).status is HashStatus.MISMATCH


# --- legacy manifests are never trusted silently ------------------------------

def test_legacy_checkout_manifest_is_reported_and_not_imported(
        home, synthetic, tmp_path, monkeypatch, capsys):
    checkout = tmp_path / "old-checkout"
    (checkout / "orbit").mkdir(parents=True)
    (checkout / "data").mkdir()
    legacy = checkout / "data" / "tool_hashes.json"
    files = hash_checker.hash_tree(synthetic.root)
    legacy_bytes = json.dumps(
        {"schema": 1, "tools": {"maester": {"versions": {"1.2.3": {"files": files}}}}}).encode()
    legacy.write_bytes(legacy_bytes)
    monkeypatch.setattr(baseline, "orbit", SimpleNamespace(__file__=str(checkout / "orbit/__init__.py")))
    assert baseline.legacy_manifests() == [legacy.resolve()]

    # even though it matches the installation exactly, it authorises nothing
    assert verify_tool(synthetic.tool).status is HashStatus.UNVERIFIED
    assert not (home / "tool_hashes.json").exists()

    monkeypatch.setattr(baseline, "all_tools", list)  # recording nothing must not import it
    with pytest.raises(SystemExit):
        baseline.main([])
    err = capsys.readouterr().err
    assert str(legacy.resolve()) in err and "not trusted" in err and "not imported" in err
    assert json.loads((home / "tool_hashes.json").read_text())["tools"]["maester"] == {"versions": {}}
    assert legacy.read_bytes() == legacy_bytes  # the old file is left exactly as it was
    assert verify_tool(synthetic.tool).status is HashStatus.UNVERIFIED


# --- installed command --------------------------------------------------------

def test_entry_point_is_declared_and_resolves_to_the_generator():
    meta = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))
    assert meta["project"]["scripts"]["orbit-generate-hashes"] == "orbit.core.baseline:cli"
    assert meta["project"]["scripts"]["orbit"] == "orbit.cli:main"
    patterns = meta["tool"]["setuptools"]["package-data"]["orbit"]
    assert "data/tool_hashes.template.json" in patterns
    assert not any("*" in pattern for pattern in patterns)  # explicit names only
    assert callable(baseline.cli)


def test_cli_passes_the_command_line_to_the_generator(monkeypatch):
    seen = []
    monkeypatch.setattr(baseline, "main", lambda args=None: seen.append(args))
    monkeypatch.setattr(sys, "argv", ["orbit-generate-hashes", "--help"])
    baseline.cli()
    assert seen == [["--help"]]


def test_cli_records_the_baseline_end_to_end(home, synthetic, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["orbit-generate-hashes"])
    baseline.cli()
    assert verify_tool(synthetic.tool).status is HashStatus.OK
    assert (home / "tool_hashes.json").is_file()


def test_source_checkout_script_is_a_shim_for_the_same_command():
    text = (REPO / "scripts" / "generate_hashes.py").read_text(encoding="utf-8")
    assert "from orbit.core.baseline import cli" in text
    assert "MANIFEST" not in text and "tool_hashes.json" in text  # documented, not opened


def test_the_command_rejects_arguments(capsys):
    for args in (["--bogus"], ["a", "b"]):
        with pytest.raises(SystemExit) as stopped:
            baseline.main(args)
        assert stopped.value.code == 2
    with pytest.raises(SystemExit) as stopped:
        baseline.main(["--help"])
    assert stopped.value.code == 0 and "ORBIT_HOME" in capsys.readouterr().out


def test_orbit_home_env_is_isolated_for_tests():
    assert os.environ["ORBIT_HOME"] and Path(os.environ["ORBIT_HOME"]) != Path.home() / ".orbit"

"""The baseline path is trusted only when no other OS principal can replace or edit it.

The real-run gate (read) and ``orbit-generate-hashes`` (write) share one policy, so every scenario
here is run against both. Synthetic and offline: only throwaway directories in tmp_path are used,
nothing reaches a network, a tenant, a credential or a real tool, and no process is started.
Never-write cases against ORBIT's own install use a fake checkout in tmp_path, not the real one.
"""
import json
import os
import stat
import sys
from pathlib import Path

import pytest
from baseline_helpers import write

import orbit
from orbit.core import baseline, baseline_schema, hash_checker, trusted_state
from orbit.core.hash_checker import HashStatus, load_manifest, verify_tool
from orbit.core.manifest import ManifestError, update_manifest
from orbit.core.trusted_state import StateDir, UnsafeState, open_state_dir

PACKAGE = Path(orbit.__file__).resolve().parent
posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX ownership and modes")
NAME = "tool_hashes.json"


def _run_command():
    try:
        baseline.main([])
    except SystemExit as exc:
        return exc.code
    return 0


def _good_home(tmp_path) -> Path:
    home = tmp_path / "good-home"
    home.mkdir(mode=0o700)
    home.chmod(0o700)
    return home


def _assert_closed(synthetic, home: Path, capsys, expect: str):
    """Read gate and write command both refuse, with fixed text and without naming the paths."""
    result = verify_tool(synthetic.tool)
    assert result.status is HashStatus.UNVERIFIED and result.blocks_run
    assert expect in result.reason, result.reason
    assert not hash_checker.gate_run([result])[0]
    capsys.readouterr()
    assert _run_command() == 1
    err = capsys.readouterr().err
    assert "Manifest NOT updated" in err and expect in err, err
    for text in (result.reason, err.split("NOT updated", 1)[1]):
        assert str(home) not in text and str(home.parent) not in text


# --- a secure location is accepted --------------------------------------------

@posix_only
def test_secure_posix_baseline_is_written_and_trusted(home, synthetic):
    assert _run_command() == 0
    assert stat.S_IMODE(home.stat().st_mode) == 0o700
    assert stat.S_IMODE((home / NAME).stat().st_mode) == 0o600
    assert load_manifest().files_for("maester", "1.2.3")
    assert verify_tool(synthetic.tool).status is HashStatus.OK
    assert _run_command() == 0  # an unchanged re-run is still fine, and still no re-bless


@posix_only
def test_a_sticky_ancestor_like_tmp_is_acceptable(tmp_path, monkeypatch, synthetic):
    sticky = tmp_path / "sticky"
    sticky.mkdir()
    sticky.chmod(0o1777)
    monkeypatch.setenv("ORBIT_HOME", str(sticky / "home"))
    assert _run_command() == 0
    assert verify_tool(synthetic.tool).status is HashStatus.OK


# --- insecure ownership and permissions ---------------------------------------

@posix_only
def test_a_directory_of_another_owner_is_refused(tmp_path, monkeypatch):
    home = _good_home(tmp_path)
    (home / NAME).write_text("{}")
    monkeypatch.setattr(os, "geteuid", lambda: os.getuid() + 1)  # as if someone else owned it
    with pytest.raises(UnsafeState, match="another user|owned by you"), open_state_dir(home):
        pass


@posix_only
def test_a_manifest_of_another_owner_is_refused(tmp_path, monkeypatch):
    home = _good_home(tmp_path)
    (home / NAME).write_text("{}")
    monkeypatch.setattr(trusted_state, "_vet_dir", lambda *a, **k: None)
    monkeypatch.setattr(os, "geteuid", lambda: os.getuid() + 1)
    with open_state_dir(home) as state, pytest.raises(UnsafeState, match="another user"):
        state.read_regular(NAME)


@posix_only
@pytest.mark.parametrize("mode", [0o777, 0o775, 0o770, 0o757, 0o722])
def test_a_home_others_can_write_is_refused(home, synthetic, capsys, mode):
    home.mkdir()
    home.chmod(mode)
    _assert_closed(synthetic, home, capsys, "writable by group or others")
    assert not (home / NAME).exists()


@posix_only
@pytest.mark.parametrize("mode", [0o777, 0o775, 0o666, 0o664, 0o620, 0o602])
def test_a_manifest_others_can_write_is_refused(home, synthetic, capsys, mode):
    assert _run_command() == 0
    (home / NAME).chmod(mode)
    before = (home / NAME).read_bytes()
    _assert_closed(synthetic, home, capsys, "writable by group or others")
    assert (home / NAME).read_bytes() == before and stat.S_IMODE((home / NAME).stat().st_mode) == mode


@posix_only
def test_a_writable_parent_could_replace_the_home_and_is_refused(tmp_path, monkeypatch, synthetic,
                                                                 capsys):
    shared = tmp_path / "shared"
    shared.mkdir()
    shared.chmod(0o777)
    home = shared / "orbit-home"
    monkeypatch.setenv("ORBIT_HOME", str(home))
    _assert_closed(synthetic, home, capsys, "writable by group or others")
    assert not home.exists()  # not even created under a directory others can write


@posix_only
@pytest.mark.parametrize("mode", [0o775, 0o757])
def test_a_writable_ancestor_further_up_is_refused(tmp_path, monkeypatch, synthetic, capsys, mode):
    top = tmp_path / "top"
    (top / "mid").mkdir(parents=True)
    top.chmod(mode)
    home = top / "mid" / "home"
    monkeypatch.setenv("ORBIT_HOME", str(home))
    _assert_closed(synthetic, home, capsys, "writable by group or others")


# --- links, special files, hard links -----------------------------------------

@posix_only
def test_a_symlinked_orbit_home_is_refused(tmp_path, monkeypatch, synthetic, capsys):
    real = _good_home(tmp_path)
    alias = tmp_path / "alias"
    alias.symlink_to(real)
    monkeypatch.setenv("ORBIT_HOME", str(alias))
    _assert_closed(synthetic, alias, capsys, "symbolic link")
    assert list(real.iterdir()) == []  # nothing was written through the link


@posix_only
def test_a_symlinked_ancestor_in_the_user_controlled_path_is_refused(tmp_path, monkeypatch,
                                                                     synthetic, capsys):
    real = tmp_path / "real"
    (real / "inner").mkdir(parents=True, mode=0o700)
    real.chmod(0o700)
    (tmp_path / "link").symlink_to(real)
    home = tmp_path / "link" / "inner"
    monkeypatch.setenv("ORBIT_HOME", str(home))
    _assert_closed(synthetic, home, capsys, "symbolic link")
    assert list((real / "inner").iterdir()) == []


@posix_only
def test_a_symlinked_manifest_is_refused_and_its_target_untouched(home, synthetic, tmp_path, capsys):
    home.mkdir(mode=0o700)
    target = tmp_path / "elsewhere.json"
    target.write_text(json.dumps({"tools": {}}))
    target.chmod(0o600)
    (home / NAME).symlink_to(target)
    _assert_closed(synthetic, home, capsys, "symbolic link")
    assert json.loads(target.read_text()) == {"tools": {}} and (home / NAME).is_symlink()


@posix_only
def test_a_symlinked_lock_is_refused_and_its_target_untouched(home, synthetic, tmp_path, capsys):
    home.mkdir(mode=0o700)
    target = tmp_path / "victim"
    target.write_text("keep")
    target.chmod(0o600)
    (home / (NAME + ".lock")).symlink_to(target)
    assert _run_command() == 1
    assert "Manifest NOT updated" in capsys.readouterr().err
    assert target.read_text() == "keep" and not (home / NAME).exists()


@posix_only
def test_a_special_file_in_place_of_the_manifest_is_refused_without_blocking(home, synthetic, capsys):
    home.mkdir(mode=0o700)
    os.mkfifo(home / NAME, 0o600)
    _assert_closed(synthetic, home, capsys, "not a regular file")


@posix_only
def test_a_hard_linked_manifest_is_refused(home, synthetic, tmp_path, capsys):
    assert _run_command() == 0
    os.link(home / NAME, tmp_path / "second-name")
    _assert_closed(synthetic, home, capsys, "hard link")


@posix_only
def test_a_hard_linked_lock_is_refused(home, synthetic, tmp_path, capsys):
    assert _run_command() == 0
    os.link(home / (NAME + ".lock"), tmp_path / "second-name")
    capsys.readouterr()
    assert _run_command() == 1
    assert "hard link" in capsys.readouterr().err


# --- races: a swapped path cannot redirect or be trusted ----------------------

@posix_only
def test_operations_stay_in_the_vetted_directory_when_the_path_is_swapped(tmp_path):
    home = _good_home(tmp_path)
    decoy = tmp_path / "decoy"
    decoy.mkdir(mode=0o700)
    with open_state_dir(home) as state:
        home.rename(tmp_path / "moved")
        home.symlink_to(decoy)  # an attacker's replacement
        os.close(state.open("planted", os.O_WRONLY | os.O_CREAT | os.O_EXCL))
        with pytest.raises(UnsafeState, match="symbolic link"):  # and it is not followed
            state.assert_current()
    assert (tmp_path / "moved" / "planted").exists() and list(decoy.iterdir()) == []


@posix_only
def test_a_home_swapped_during_an_update_is_not_written(home, synthetic):
    assert _run_command() == 0
    path = home / NAME
    before = path.read_bytes()
    decoy = home.parent / "decoy"
    with pytest.raises(ManifestError, match="changed while"), update_manifest(path) as data:
        data["tools"]["new"] = {"versions": {}}
        home.rename(home.parent / "moved")
        decoy.mkdir(mode=0o700)
        decoy.rename(home)  # a different directory now sits at ORBIT_HOME
    assert (home.parent / "moved" / NAME).read_bytes() == before
    assert list(home.iterdir()) == []


@posix_only
def test_a_manifest_replaced_by_an_identical_copy_during_an_update_is_not_overwritten(home, synthetic):
    assert _run_command() == 0
    path = home / NAME
    with pytest.raises(ManifestError, match="edited or replaced"), update_manifest(path) as data:
        data["tools"]["mine"] = {"versions": {}}
        copy = home / "copy"
        copy.write_bytes(path.read_bytes())
        copy.chmod(0o600)
        os.replace(copy, path)  # same bytes, different file
    assert "mine" not in path.read_text()


@posix_only
def test_a_manifest_swapped_between_the_check_and_the_open_is_not_trusted(home, synthetic,
                                                                         monkeypatch):
    assert _run_command() == 0
    real_open = StateDir.open

    def swap_then_open(self, name, flags, mode=0o600):
        if name == NAME:
            fake = home / "fake"
            fake.write_bytes((home / NAME).read_bytes())
            fake.chmod(0o600)
            os.replace(fake, home / NAME)
        return real_open(self, name, flags, mode)

    monkeypatch.setattr(StateDir, "open", swap_then_open)
    result = verify_tool(synthetic.tool)
    assert result.status is HashStatus.UNVERIFIED and "changed while" in result.reason


# --- unsafe destinations: ORBIT's own install and legacy directories ----------

@pytest.fixture()
def checkout(tmp_path, monkeypatch):
    """A fake source checkout, with ORBIT's package location pointed at it; the real one is untouched."""
    root = tmp_path / "checkout"
    (root / "orbit" / "data").mkdir(parents=True)
    (root / "data").mkdir()
    for folder in (root, root / "orbit", root / "orbit" / "data", root / "data"):
        folder.chmod(0o700)
    monkeypatch.setattr(trusted_state, "package_dir", lambda: root / "orbit")
    return root


def _destinations(root: Path):
    return {
        "package": root / "orbit",
        "package-data": root / "orbit" / "data",
        "legacy-data": root / "data",
        "inside-package": root / "orbit" / "reporting" / "private",
        "inside-legacy-not-yet-created": root / "data" / "new" / "deeper",
    }


@pytest.mark.parametrize("label", ["package", "package-data", "legacy-data", "inside-package",
                                   "inside-legacy-not-yet-created"])
def test_orbit_home_inside_the_install_or_a_legacy_directory_is_rejected_first(
        checkout, synthetic, monkeypatch, capsys, label):
    home = _destinations(checkout)[label]
    monkeypatch.setenv("ORBIT_HOME", str(home))
    legacy = checkout / "data" / NAME
    legacy.write_bytes(json.dumps({"schema": 1, "tools": {"maester": {"versions": {
        "1.2.3": {"files": hash_checker.hash_tree(synthetic.root)}}}}}).encode())
    legacy.chmod(0o600)
    legacy_before = legacy.read_bytes()
    listing = sorted(p.relative_to(checkout).as_posix() for p in checkout.rglob("*"))

    _assert_closed(synthetic, home, capsys, "ORBIT's own installation or a legacy data directory")
    # nothing was read, seeded, locked or created, and the matching legacy baseline stayed inert
    assert sorted(p.relative_to(checkout).as_posix() for p in checkout.rglob("*")) == listing
    assert legacy.read_bytes() == legacy_before
    with pytest.raises(UnsafeState):
        load_manifest()


def test_a_symlink_alias_of_a_legacy_directory_is_rejected(checkout, synthetic, tmp_path,
                                                          monkeypatch, capsys):
    alias = tmp_path / "alias-of-legacy"
    alias.symlink_to(checkout / "data")
    monkeypatch.setenv("ORBIT_HOME", str(alias))
    _assert_closed(synthetic, alias, capsys, "ORBIT's own installation or a legacy data directory")
    assert list((checkout / "data").iterdir()) == []


def test_an_alias_that_only_identity_reveals_is_rejected(checkout, synthetic, monkeypatch):
    """No name or link gives it away (a bind mount would look like this): the inode does."""
    monkeypatch.setattr(trusted_state, "_check_lexical", lambda path: None)
    monkeypatch.setenv("ORBIT_HOME", str(checkout / "data"))
    with pytest.raises(UnsafeState, match="own installation"), open_state_dir(checkout / "data"):
        pass
    assert verify_tool(synthetic.tool).status is HashStatus.UNVERIFIED


@posix_only
def test_a_hard_link_to_a_legacy_manifest_never_becomes_active(checkout, home, synthetic, capsys):
    legacy = checkout / "data" / NAME
    legacy.write_text(json.dumps({"schema": 1, "tools": {}}))
    legacy.chmod(0o600)
    home.mkdir(mode=0o700)
    os.link(legacy, home / NAME)
    before = legacy.read_bytes()
    _assert_closed(synthetic, home, capsys, "hard link")
    assert legacy.read_bytes() == before


@pytest.mark.skipif(sys.platform not in ("darwin", "win32"), reason="case-insensitive file systems")
def test_case_variants_of_a_legacy_directory_are_rejected(checkout, monkeypatch):
    monkeypatch.setenv("ORBIT_HOME", str(checkout / "DATA" / "sub"))
    with pytest.raises(UnsafeState, match="own installation"), open_state_dir(checkout / "DATA" / "sub"):
        pass


def test_the_real_install_is_rejected_for_reading_and_nothing_in_it_changes(monkeypatch, synthetic):
    before = {p: p.stat().st_mtime_ns for p in PACKAGE.rglob("*") if p.is_file()
              and "__pycache__" not in p.parts}
    for home in (PACKAGE, PACKAGE / "data", PACKAGE / "data" / "fixtures", PACKAGE.parent / "data"):
        monkeypatch.setenv("ORBIT_HOME", str(home))
        result = verify_tool(synthetic.tool)
        assert result.status is HashStatus.UNVERIFIED and "own installation" in result.reason
    assert before == {p: p.stat().st_mtime_ns for p in PACKAGE.rglob("*") if p.is_file()
                      and "__pycache__" not in p.parts}
    assert not (PACKAGE.parent / "data").exists()


def test_the_active_location_is_still_orbit_home_resolved_per_call(tmp_path, monkeypatch):
    first, second = tmp_path / "a", tmp_path / "b"
    monkeypatch.setenv("ORBIT_HOME", str(first))
    assert hash_checker.manifest_path() == first / NAME
    monkeypatch.setenv("ORBIT_HOME", str(second))
    assert hash_checker.manifest_path() == second / NAME


def test_a_legacy_manifest_is_still_reported_and_never_imported(checkout, home, synthetic, capsys,
                                                               monkeypatch):
    legacy = checkout / "data" / NAME
    legacy.write_text("{}")
    monkeypatch.setattr(baseline, "orbit", type("M", (), {"__file__": str(checkout / "orbit/__init__.py")}))
    assert baseline.legacy_manifests() == [legacy.resolve()]
    monkeypatch.setattr(baseline, "all_tools", list)
    assert _run_command() == 1
    err = capsys.readouterr().err
    assert "ignoring the older baseline" in err and "not imported" in err
    assert legacy.read_text() == "{}"


# --- missing and invalid still block; generation still works ------------------

def test_a_missing_home_is_simply_no_baseline(home, synthetic):
    result = verify_tool(synthetic.tool)
    assert result.reason == hash_checker.NO_BASELINE and not home.exists()


@posix_only
def test_a_changed_file_is_not_reblessed_under_the_hardened_path(home, synthetic):
    assert _run_command() == 0
    (synthetic.root / "Maester.psm1").write_text("changed")
    assert _run_command() == 1
    assert verify_tool(synthetic.tool).status is HashStatus.MISMATCH


# --- Windows: conservative rule, exercised through its path-based implementation

def _profile(tmp_path) -> Path:
    profile = tmp_path / "profile"
    profile.mkdir()
    return profile


def test_windows_rule_accepts_a_folder_inside_the_profile_and_creates_it(tmp_path):
    profile = _profile(tmp_path)
    state = trusted_state._check_windows(profile / ".orbit", profile, create=True)
    assert (profile / ".orbit").is_dir() and state.fd is None


@pytest.mark.parametrize("where", ["outside", "profile-itself", "sibling-prefix"])
def test_windows_rule_refuses_a_folder_outside_the_profile(tmp_path, where):
    profile = _profile(tmp_path)
    (tmp_path / "profile-evil").mkdir()
    target = {"outside": tmp_path / "elsewhere", "profile-itself": profile,
              "sibling-prefix": tmp_path / "profile-evil"}[where]
    with pytest.raises(UnsafeState, match="inside your user profile"):
        trusted_state._check_windows(target, profile, create=True)
    assert not (tmp_path / "elsewhere").exists()


def test_windows_rule_refuses_a_link_below_the_profile(tmp_path):
    profile = _profile(tmp_path)
    (tmp_path / "real").mkdir()
    try:
        (profile / "link").symlink_to(tmp_path / "real", target_is_directory=True)
    except OSError:
        pytest.skip("symlinks not permitted here")
    with pytest.raises(UnsafeState, match="symbolic link"):
        trusted_state._check_windows(profile / "link" / "home", profile, create=True)


def test_windows_rule_refuses_the_install_and_legacy_directories(checkout, tmp_path):
    for target in (checkout / "orbit", checkout / "data", checkout / "orbit" / "data" / "x"):
        with pytest.raises(UnsafeState, match="own installation"):
            trusted_state._check_windows(target, checkout, create=False)


def test_windows_dispatch_applies_the_profile_rule_to_reads_and_writes(tmp_path, monkeypatch):
    profile = _profile(tmp_path)
    monkeypatch.setenv("HOME", str(profile))
    monkeypatch.setenv("USERPROFILE", str(profile))
    inside, outside = profile / ".orbit", tmp_path / "outside"
    inside.mkdir(mode=0o700)
    outside.mkdir(mode=0o700)
    for folder in (inside, outside):
        write(folder / NAME, {})
    monkeypatch.setattr(sys, "platform", "win32")  # take the Windows branch of the policy
    # ...but keep the POSIX identity source: this test is about the location rule, not binding
    monkeypatch.setattr(baseline_schema, "_platform_class", lambda: "posix")
    assert load_manifest(inside / NAME).files_for("t", "1") is None  # a valid, empty baseline
    with pytest.raises(UnsafeState, match="inside your user profile"):
        load_manifest(outside / NAME)
    with pytest.raises(ManifestError, match="inside your user profile"), update_manifest(outside / NAME):
        pass

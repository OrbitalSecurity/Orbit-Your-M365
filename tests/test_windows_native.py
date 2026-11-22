"""Native Windows validation of the current product behaviour (no secure-state backend).

These tests run only on Windows and are skipped, with an explicit reason, everywhere else: a
Linux or macOS run does not validate any of this. The Windows CI job fails if any test here is
skipped or if none ran. Everything is synthetic: no
tenant, credential, network, PowerShell module or real tool is used, and nothing is launched.

ORBIT_HOME must lie inside the real user profile (the conservative Windows policy), so scratch
directories are made under ``Path.home()`` and removed afterwards, not under pytest's tmp_path.
"""
from __future__ import annotations

import json
import re
import shutil
import sys
import uuid
from pathlib import Path

import pytest

pytestmark = [
    pytest.mark.windows_native,
    pytest.mark.skipif(sys.platform != "win32",
                       reason="native Windows only: Linux/macOS runs do not validate this"),
]


@pytest.fixture()
def profile_home(monkeypatch):
    """A fresh ORBIT_HOME-to-be inside the user profile; it does not exist yet."""
    root = Path.home() / f"orbit-pytest-{uuid.uuid4().hex[:12]}"
    root.mkdir()
    home = root / "home"
    monkeypatch.setenv("ORBIT_HOME", str(home))
    yield home
    shutil.rmtree(root, ignore_errors=True)


@pytest.fixture()
def synthetic_tool(profile_home, monkeypatch):
    """One fully synthetic Maester installation; nothing real is discovered or launched."""
    from orbit.core import baseline as command
    from orbit.core.executables import Executable
    from orbit.core.tools import base, get_tool
    from orbit.core.tools.discovery import Installation

    root = profile_home.parent / "synthetic" / "Maester"
    root.mkdir(parents=True)
    (root / "Maester.psd1").write_text("synthetic module manifest")
    (root / "Maester.psm1").write_text("synthetic module body")
    interpreter = profile_home.parent / "synthetic" / "interpreter.exe"
    interpreter.write_text("not a real interpreter")
    install = Installation("1.2.3", root, root / "Maester.psd1",
                           Executable.capture(interpreter.resolve()))
    tool = get_tool("maester")
    monkeypatch.setattr(base.Tool, "discover", lambda self: install)
    monkeypatch.setattr(command, "all_tools", lambda: [tool])
    return tool, root


def test_sid_and_machine_guid_are_retrieved_natively():
    from orbit.core import baseline_schema as schema

    sid = schema._windows_token_sid()
    guid = schema._windows_machine_guid()
    # Fixed-message failures: pytest must never render the raw SID or MachineGuid operands.
    if not re.fullmatch(r"S-1-\d+(-\d+){1,15}", sid):
        pytest.fail("the token SID has an unexpected shape (value withheld)")
    if not re.fullmatch(r"[0-9A-Fa-f]{8}(-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}", guid.strip()):
        pytest.fail("the MachineGuid has an unexpected shape (value withheld)")


def test_current_binding_is_the_hash_of_those_identifiers_and_hides_them():
    from orbit.core import baseline_schema as schema

    sid, guid = schema._windows_token_sid(), schema._windows_machine_guid()
    current = schema.current_binding()
    if current != schema.binding_for("win32", sid, guid):
        pytest.fail("the current binding differs from the hash of the native identifiers")
    assert current.os == "win32" and re.fullmatch(r"[0-9a-f]{64}", current.principal)
    assert current.machine and re.fullmatch(r"[0-9a-f]{64}", current.machine)
    rendered = json.dumps(current.to_json())
    if sid in rendered or guid in rendered:
        pytest.fail("the serialised binding contains a raw identifier (value withheld)")


def test_generated_baseline_is_bound_to_current_binding_and_gates_the_tool(
        profile_home, synthetic_tool):
    from orbit.core import baseline as command
    from orbit.core import baseline_schema as schema
    from orbit.core import hash_checker

    tool, root = synthetic_tool
    active = hash_checker.manifest_path()
    assert active == profile_home / "tool_hashes.json"

    missing = hash_checker.verify_tool(tool)  # missing baseline blocks
    assert missing.status is hash_checker.HashStatus.UNVERIFIED and missing.blocks_run
    assert missing.reason == hash_checker.NO_BASELINE and not active.exists()

    command.main([])  # success returns normally; only refusals and no-tools exit via SystemExit
    document = json.loads(active.read_text(encoding="utf-8"))
    assert document["binding"] == schema.current_binding().to_json()
    assert set(document["tools"]["maester"]["versions"]["1.2.3"]["files"]) == {
        "Maester.psd1", "Maester.psm1"}
    ok = hash_checker.verify_tool(tool)
    assert ok.status is hash_checker.HashStatus.OK and not ok.blocks_run

    (root / "Maester.psm1").write_text("tampered")  # a changed file blocks
    changed = hash_checker.verify_tool(tool)
    assert changed.status is hash_checker.HashStatus.MISMATCH and changed.blocks_run


def _refused_contents():
    from orbit.core import baseline_schema as schema

    here = schema.current_binding()
    other = schema.Binding(here.os, "0" * 64, here.machine)
    tools = {name: {"versions": {}} for name in ("scubagear", "maester", "monkey365",
                                                  "roadtools", "hawk")}
    mismatched = {"schema": 2, "kind": schema.KIND, "binding": other.to_json(),
                  "generator": {"orbit": "test"}, "tools": tools}
    from orbit.core import hash_checker
    return {
        "template": (hash_checker.TEMPLATE_PATH.read_bytes(), schema.ErrorCode.BINDING_MISSING),
        "schema-1": (json.dumps({"schema": 1, "tools": {}}).encode(), schema.ErrorCode.LEGACY),
        "malformed": (b"{ not json", schema.ErrorCode.NOT_JSON),
        "mismatched": (json.dumps(mismatched).encode(), schema.ErrorCode.BINDING_MISMATCH),
    }


@pytest.mark.parametrize("label", ["template", "schema-1", "malformed", "mismatched"])
def test_refused_active_baselines_block_and_are_never_changed(
        label, profile_home, synthetic_tool):
    from orbit.core import baseline as command
    from orbit.core import baseline_schema as schema
    from orbit.core import hash_checker

    tool, _ = synthetic_tool
    content, code = _refused_contents()[label]
    profile_home.mkdir()
    active = profile_home / "tool_hashes.json"
    active.write_bytes(content)

    result = hash_checker.verify_tool(tool)
    assert result.status is hash_checker.HashStatus.UNVERIFIED and result.blocks_run
    assert result.reason == schema.MESSAGES[code]
    with pytest.raises(SystemExit) as stop:
        command.main([])
    assert stop.value.code == 1
    assert active.read_bytes() == content


def test_scratch_home_outside_the_profile_is_refused():
    """Documents the policy the CI layout depends on (checked with a path outside the profile)."""
    from orbit.core import trusted_state

    outside = Path(Path.home().anchor) / f"orbit-outside-{uuid.uuid4().hex[:8]}"
    with pytest.raises(trusted_state.UnsafeState), trusted_state.open_state_dir(outside):
        pass

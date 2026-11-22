"""Schema v2 of the integrity baseline: legacy and unbound content can never authorise a run.

Synthetic and offline. Windows identity logic is exercised through injected sources and hand-built
byte buffers on this host; nothing here is evidence about native Windows behaviour.
"""
import hashlib
import json
import os
import sys
import types
from pathlib import Path

import pytest
from baseline_helpers import baseline as make_baseline
from baseline_helpers import binding, document, encode, legacy_document, write

from orbit.config import VERSION
from orbit.core import baseline, baseline_schema, hash_checker
from orbit.core import baseline_schema as schema
from orbit.core.baseline_schema import ErrorCode, parse_baseline
from orbit.core.hash_checker import HashStatus, check_tool, launch_binding, verify_tool
from orbit.core.manifest import ManifestError, seed_manifest, update_manifest

NAME = "tool_hashes.json"
HEX = "ab" * 32
posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX modes and uids")
TEMPLATE = hash_checker.TEMPLATE_PATH.read_bytes()


def code_of(data, expected=None) -> ErrorCode:
    with pytest.raises(schema.BaselineError) as caught:
        parse_baseline(data if isinstance(data, bytes) else encode(data), expected or binding())
    return caught.value.code


def doc(**changes) -> dict:
    d = document({"maester": {"1.2.3": {"Maester.psd1": HEX}}})
    for key, value in changes.items():
        if value is ...:
            d.pop(key)
        else:
            d[key] = value
    return d


# --- U-SCH-04: the schema field ----------------------------------------------------

def test_a_valid_document_is_accepted_and_round_trips_deterministically():
    good = encode(doc())
    parsed = parse_baseline(good, binding())
    assert parsed.files_for("maester", "1.2.3") == {"Maester.psd1": HEX}
    assert schema.dump_baseline(parsed) == good  # sorted keys, indent 2, trailing newline
    assert schema.dump_baseline(parse_baseline(schema.dump_baseline(parsed), binding())) == good


@pytest.mark.parametrize("value, code", [
    (1, ErrorCode.LEGACY), (3, ErrorCode.NEWER), (2**40, ErrorCode.NEWER),
    (0, ErrorCode.MALFORMED), (-1, ErrorCode.MALFORMED),
    (True, ErrorCode.MALFORMED), (False, ErrorCode.MALFORMED), (2.0, ErrorCode.MALFORMED),
    (1.0, ErrorCode.MALFORMED), ("2", ErrorCode.MALFORMED), (None, ErrorCode.MALFORMED),
    ([2], ErrorCode.MALFORMED),
])
def test_schema_must_be_the_integer_2(value, code):
    assert code_of(doc(schema=value)) is code


def test_absent_schema_is_legacy_when_tools_is_present_and_malformed_otherwise():
    assert code_of(doc(schema=...)) is ErrorCode.LEGACY
    assert code_of({}) is ErrorCode.MALFORMED
    assert code_of({"binding": doc()["binding"]}) is ErrorCode.MALFORMED


def test_legacy_is_decided_before_anything_else_is_looked_at():
    assert code_of({"schema": 1, "_note": "x", "tools": "garbage"}) is ErrorCode.LEGACY
    assert code_of({"schema": 99, "garbage": object.__name__}) is ErrorCode.NEWER


def test_newer_message_names_a_small_integer_only():
    with pytest.raises(schema.BaselineError) as small:
        parse_baseline(encode(doc(schema=7)), binding())
    assert "schema 7" in str(small.value)
    with pytest.raises(schema.BaselineError) as huge:
        parse_baseline(encode(doc(schema=10**30)), binding())
    assert "10" not in str(huge.value).replace("orbit-generate-hashes", "")


# --- input shape and size ----------------------------------------------------------

@pytest.mark.parametrize("data, code", [
    (b"", ErrorCode.NOT_JSON), (b"{not json", ErrorCode.NOT_JSON), (b"\xff\xfe\x00", ErrorCode.NOT_JSON),
    (b"NaN", ErrorCode.NOT_JSON), (b'{"schema": NaN}', ErrorCode.NOT_JSON),
    (b"[]", ErrorCode.NOT_OBJECT), (b'"text"', ErrorCode.NOT_OBJECT), (b"7", ErrorCode.NOT_OBJECT),
    (b"null", ErrorCode.NOT_OBJECT), (b"[" * 100000, ErrorCode.NOT_JSON),
    (b'{"schema": 2, "schema": 2}', ErrorCode.MALFORMED),  # duplicate keys: last-wins is not allowed
])
def test_unparseable_input(data, code):
    assert code_of(data) is code


def test_the_input_size_boundary():
    pad = b" " * (schema.MAX_BYTES - len(encode(doc())))
    exactly = encode(doc()) + pad
    assert len(exactly) == schema.MAX_BYTES
    parse_baseline(exactly, binding())  # at the limit: accepted
    assert code_of(exactly + b" ") is ErrorCode.TOO_LARGE  # one byte over: refused unparsed


def test_non_bytes_input_is_refused():
    with pytest.raises(schema.BaselineError):
        parse_baseline("text", binding())  # type: ignore[arg-type]


# --- U-SCH-07: closed schema -------------------------------------------------------

@pytest.mark.parametrize("mutate", [
    lambda d: d.update(extra=1), lambda d: d["binding"].update(extra=1),
    lambda d: d["generator"].update(extra=1), lambda d: d.update(_note="x"),
    lambda d: d.update(kind="orbit.other"), lambda d: d.pop("kind"), lambda d: d.update(kind=2),
    lambda d: d.pop("tools"), lambda d: d.update(tools=[]), lambda d: d.update(tools=None),
    lambda d: d.update(generator="1.5.1"), lambda d: d.update(generator={}),
    lambda d: d["generator"].update(orbit=5), lambda d: d["generator"].update(orbit=""),
    lambda d: d.pop("generator"),
])
def test_unknown_or_malformed_top_level_content_is_rejected(mutate):
    d = doc()
    mutate(d)
    assert code_of(d) is ErrorCode.MALFORMED


# --- U-SCH-05: binding -------------------------------------------------------------

@pytest.mark.parametrize("binding_value", [..., None, {}])
def test_a_missing_binding_is_binding_missing(binding_value):
    d = doc(generator={"orbit": "1"})
    if binding_value is ...:
        d.pop("binding")
    else:
        d["binding"] = binding_value
    assert code_of(d) is ErrorCode.BINDING_MISSING


@pytest.mark.parametrize("mutate", [
    lambda b: b.pop("principal"), lambda b: b.pop("machine"), lambda b: b.pop("os"),
    lambda b: b.update(principal=b["principal"].upper()), lambda b: b.update(principal=b["principal"][:-1]),
    lambda b: b.update(principal=5), lambda b: b.update(principal=None), lambda b: b.update(os="darwin"),
    lambda b: b.update(os=1), lambda b: b.update(machine="ab" * 32),  # a POSIX binding has no machine
    lambda b: b.update(os="win32", machine=None),  # a Windows binding is always machine-bound
    lambda b: b.update(os="win32", machine="AB" * 32), lambda b: b.update(extra=1),
])
def test_a_malformed_binding_is_rejected(mutate):
    d = doc()
    mutate(d["binding"])
    assert code_of(d) is ErrorCode.MALFORMED


def test_binding_that_is_not_an_object_is_malformed():
    assert code_of(doc(binding="x")) is ErrorCode.MALFORMED
    assert code_of(doc(binding=[1])) is ErrorCode.MALFORMED


def test_the_template_copied_verbatim_is_binding_missing():
    assert code_of(TEMPLATE) is ErrorCode.BINDING_MISSING
    template = json.loads(TEMPLATE)
    assert set(template) == {"schema", "kind", "tools"}  # structurally unbound
    assert schema.parse_template(TEMPLATE) == list(template["tools"])


@posix_only
def test_the_posix_binding_is_accepted_and_uses_the_effective_uid_hash():
    expected = hashlib.sha256(f"orbit-baseline-v2|principal|uid:{os.geteuid()}".encode()).hexdigest()
    assert binding() == schema.Binding("posix", expected, None)
    parse_baseline(encode(doc()), binding())


@posix_only
def test_another_user_platform_or_machine_is_a_mismatch(monkeypatch):
    mine = encode(doc())
    other_uid = schema.binding_for("posix", f"uid:{os.geteuid() + 1}", None)
    assert code_of(mine, other_uid) is ErrorCode.BINDING_MISMATCH
    windows = schema.binding_for("win32", "S-1-5-21-1-2-3-1001", "guid-a")
    assert code_of(mine, windows) is ErrorCode.BINDING_MISMATCH  # platform
    # a Windows baseline read on a Windows machine with another MachineGuid, or another SID
    theirs = encode(doc(binding=windows.to_json()))
    assert parse_baseline(theirs, windows)
    assert code_of(theirs, schema.binding_for("win32", "S-1-5-21-1-2-3-1001", "guid-b")
                   ) is ErrorCode.BINDING_MISMATCH
    assert code_of(theirs, schema.binding_for("win32", "S-1-5-21-1-2-3-1002", "guid-a")
                   ) is ErrorCode.BINDING_MISMATCH
    assert code_of(theirs, binding()) is ErrorCode.BINDING_MISMATCH  # read on POSIX


def test_binding_hashes_follow_the_documented_encoding():
    got = schema.binding_for("win32", "S-1-5-21-9-9-9-500", "0123-guid")
    assert got.principal == hashlib.sha256(b"orbit-baseline-v2|principal|S-1-5-21-9-9-9-500").hexdigest()
    assert got.machine == hashlib.sha256(b"orbit-baseline-v2|machine|0123-guid").hexdigest()
    assert got.principal != got.machine


@pytest.mark.parametrize("args", [("win32", "", "g"), ("win32", "S-1-1-0", None), ("win32", "S-1-1-0", ""),
                                  ("posix", "", None), ("posix", "uid:1", "g"), ("other", "x", None)])
def test_incomplete_identity_cannot_make_a_binding(args):
    with pytest.raises(schema.BindingUnavailable):
        schema.binding_for(*args)


# --- Windows identity logic, injected (not native evidence) ---------------------------

SID_BYTES = (bytes([1, 5]) + (5).to_bytes(6, "big")
             + b"".join(n.to_bytes(4, "little") for n in (21, 1, 2, 3, 1001)))


def test_sid_codec():
    assert schema.sid_to_string(SID_BYTES) == "S-1-5-21-1-2-3-1001"
    assert schema.sid_to_string(bytes([1, 1]) + (5).to_bytes(6, "big") + (18).to_bytes(4, "little")) == "S-1-5-18"
    assert schema.sid_to_string(bytes([1, 1]) + (1).to_bytes(6, "big") + (0).to_bytes(4, "little")) == "S-1-1-0"
    big = schema.sid_to_string(bytes([1, 1]) + (2**40).to_bytes(6, "big") + (1).to_bytes(4, "little"))
    assert big == "S-1-0x010000000000-1"
    for bad in (b"", SID_BYTES[:-1], SID_BYTES + b"\0", bytes([2]) + SID_BYTES[1:],
                bytes([1, 0]) + SID_BYTES[2:8], bytes([1, 16]) + SID_BYTES[2:8] + bytes(64)):
        with pytest.raises(ValueError):
            schema.sid_to_string(bad)


def test_token_user_buffer_is_followed_only_inside_the_buffer():
    import struct
    width = struct.calcsize("P")
    base = 0x1000
    header = struct.pack("P", base + 2 * width) + bytes(width)  # Sid pointer, attributes + padding
    assert schema.token_user_sid(header + SID_BYTES, base) == "S-1-5-21-1-2-3-1001"
    for pointer in (0, base - 8, base + 2 * width - 1, base + 10_000):
        with pytest.raises(ValueError):
            schema.token_user_sid(struct.pack("P", pointer) + bytes(width) + SID_BYTES, base)
    with pytest.raises(ValueError):
        schema.token_user_sid(header + SID_BYTES[:6], base)
    with pytest.raises(ValueError):
        schema.token_user_sid(b"\0" * 4, base)


def _windows(monkeypatch, sid="S-1-5-21-1-2-3-1001", guid="machine-guid-1"):
    monkeypatch.setattr(schema, "_platform_class", lambda: "win32")
    monkeypatch.setattr(schema, "_windows_token_sid", lambda: sid)
    monkeypatch.setattr(schema, "_windows_machine_guid", lambda: guid)


def test_windows_binding_comes_from_the_token_sid_and_machine_guid_not_the_environment(monkeypatch):
    _windows(monkeypatch)
    first = schema.current_binding()
    assert first == schema.binding_for("win32", "S-1-5-21-1-2-3-1001", "machine-guid-1")
    monkeypatch.setenv("USERNAME", "someone-else")
    monkeypatch.setenv("USERPROFILE", "/elsewhere")
    monkeypatch.setenv("HOME", "/elsewhere")
    assert schema.current_binding() == first
    monkeypatch.setattr(schema, "_windows_token_sid", lambda: "S-1-5-21-1-2-3-1002")
    assert schema.current_binding() != first
    monkeypatch.setattr(schema, "_windows_token_sid", lambda: "S-1-5-21-1-2-3-1001")
    monkeypatch.setattr(schema, "_windows_machine_guid", lambda: "machine-guid-2")
    assert schema.current_binding() != first


def test_a_windows_baseline_does_not_disclose_the_sid_or_machine_guid(monkeypatch):
    _windows(monkeypatch)
    data = schema.dump_baseline(schema.baseline_from_template(TEMPLATE, schema.current_binding(), "t"))
    assert b"S-1-5" not in data and b"machine-guid-1" not in data
    assert json.loads(data)["binding"]["os"] == "win32"
    assert parse_baseline(data, schema.current_binding())


@pytest.mark.parametrize("failure", ["sid", "guid", "bad-sid-value", "bad-guid-value"])
def test_unestablished_windows_identity_fails_closed(monkeypatch, failure):
    _windows(monkeypatch)

    def broken():
        raise OSError("denied")

    if failure == "sid":
        monkeypatch.setattr(schema, "_windows_token_sid", broken)
    elif failure == "guid":
        monkeypatch.setattr(schema, "_windows_machine_guid", broken)
    elif failure == "bad-sid-value":
        monkeypatch.setattr(schema, "_windows_token_sid", lambda: "")
    else:
        monkeypatch.setattr(schema, "_windows_machine_guid", lambda: "")
    with pytest.raises(schema.BindingUnavailable) as caught:
        schema.current_binding()
    assert caught.value.code is ErrorCode.BINDING_UNAVAILABLE


def _fake_winreg(value="guid", kind=1, error=None):
    calls = []
    module = types.ModuleType("winreg")
    module.HKEY_LOCAL_MACHINE = "HKLM"
    module.KEY_READ, module.KEY_WOW64_64KEY, module.REG_SZ = 0x20019, 0x100, 1

    class Key:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def open_key(root, subkey, reserved, access):
        calls.append((root, subkey, reserved, access))
        if error:
            raise error
        return Key()

    module.OpenKey = open_key
    module.QueryValueEx = lambda key, name: calls.append(("query", name)) or (value, kind)
    return module, calls


def test_machine_guid_is_read_from_the_64_bit_registry_view(monkeypatch):
    module, calls = _fake_winreg("abc-123")
    monkeypatch.setitem(sys.modules, "winreg", module)
    assert schema._windows_machine_guid() == "abc-123"
    root, subkey, reserved, access = calls[0]
    assert (root, subkey, reserved) == ("HKLM", r"SOFTWARE\Microsoft\Cryptography", 0)
    assert access & module.KEY_WOW64_64KEY and access & module.KEY_READ
    assert calls[1] == ("query", "MachineGuid")


@pytest.mark.parametrize("kwargs", [{"error": FileNotFoundError()}, {"error": PermissionError()},
                                    {"value": "", "kind": 1}, {"value": "  ", "kind": 1},
                                    {"value": "x", "kind": 3}, {"value": b"x", "kind": 1},
                                    {"value": "a\0b", "kind": 1}, {"value": "x" * 129, "kind": 1}])
def test_machine_guid_failures_fail_closed(monkeypatch, kwargs):
    module, _ = _fake_winreg(**kwargs)
    monkeypatch.setitem(sys.modules, "winreg", module)
    with pytest.raises(schema.BindingUnavailable):
        schema._windows_machine_guid()


@pytest.mark.skipif(sys.platform == "win32", reason="the real module imports on Windows too")
def test_the_module_imports_and_runs_on_posix_without_windows_apis():
    assert schema.current_binding().os == "posix"  # no ctypes.WinDLL or winreg was needed


# --- U-SCH-06: entries ---------------------------------------------------------------

@pytest.mark.parametrize("tools", [
    {"": {"versions": {}}}, {"m": None}, {"m": []}, {"m": {}}, {"m": {"versions": []}},
    {"m": {"versions": {}, "extra": 1}}, {"m": {"versions": {"": {"files": {"a": HEX}}}}},
    {"m": {"versions": {"1": None}}}, {"m": {"versions": {"1": {}}}},
    {"m": {"versions": {"1": {"files": {}}}}}, {"m": {"versions": {"1": {"files": []}}}},
    {"m": {"versions": {"1": {"files": {"a": HEX}, "extra": 1}}}},
    {"m": {"versions": {"1": {"files": {"a": HEX}, "install_dir": 5}}}},
    {"m": {"versions": {"1": {"files": {"a": HEX}, "install_dir": "a\0b"}}}},
    {"m": {"versions": {"1": {"files": {"a": HEX[:-1]}}}}}, {"m": {"versions": {"1": {"files": {"a": HEX + "0"}}}}},
    {"m": {"versions": {"1": {"files": {"a": HEX.upper()}}}}}, {"m": {"versions": {"1": {"files": {"a": 7}}}}},
    {"m": {"versions": {"1": {"files": {"a": None}}}}}, {"m": {"versions": {"1": {"files": {"a": HEX + "\n"}}}}},
    {"m": {"versions": {"1": {"files": {"a": "g" * 64}}}}},
    {"m" * 257: {"versions": {}}}, {"m": {"versions": {"v" * 257: {"files": {"a": HEX}}}}},
    {"a\x00b": {"versions": {}}}, {"m": {"versions": {"1\n": {"files": {"a": HEX}}}}},
])
def test_malformed_entries_reject_the_whole_baseline(tools):
    assert code_of(doc(tools=tools)) is ErrorCode.ENTRY_MALFORMED


@pytest.mark.parametrize("name", [
    "", "/abs", "../x", "a/../b", "a/..", "./a", "a/./b", "a//b", "a/", "C:\\x", "C:/x", "c:x",
    "a:b", "a\\b", "a\\..\\b", "a\0b", "a\nb", "a\x7fb", "\\\\server\\share", "x" * 32769,
])
def test_unsafe_file_names_are_rejected(name):
    assert not schema.is_safe_relative_name(name)
    assert code_of(doc(tools={"m": {"versions": {"1": {"files": {name: HEX}}}}})) is ErrorCode.ENTRY_MALFORMED


@pytest.mark.parametrize("name", ["a", "a/b.psm1", "sub/deep/x.dll", ".hidden", "__pycache__/m.pyc",
                                  "with space/ü.psd1", "dots..in/name", "dir/a:b"])
def test_ordinary_file_names_are_accepted(name):
    assert schema.is_safe_relative_name(name)
    parse_baseline(encode(doc(tools={"m": {"versions": {"1": {"files": {name: HEX}}}}})), binding())


def test_an_empty_versions_map_and_optional_install_dir_are_valid():
    d = doc(tools={"m": {"versions": {}}, "n": {"versions": {"1": {"files": {"a": HEX},
                                                                   "install_dir": "/x"}}}})
    parsed = parse_baseline(encode(d), binding())
    assert parsed.files_for("m", "1") is None and parsed.files_for("n", "1") == {"a": HEX}


# --- the Baseline object -------------------------------------------------------------

def test_a_baseline_cannot_be_forged_or_mutated():
    good = make_baseline({"t": {"1": {"a": HEX}}})
    with pytest.raises(TypeError):
        schema.Baseline(object(), binding(), "x", {})
    with pytest.raises(AttributeError):
        good.generator = "x"  # type: ignore[misc]
    with pytest.raises(AttributeError):
        good.extra = 1  # type: ignore[attr-defined]
    got = good.files_for("t", "1")
    got["b"] = HEX  # a copy: the baseline itself is unchanged
    assert good.files_for("t", "1") == {"a": HEX}
    edited = good.to_document()
    edited["tools"]["t"]["versions"]["1"]["files"]["c"] = HEX
    assert good.files_for("t", "1") == {"a": HEX}
    assert HEX not in repr(good) and "principal" not in repr(good)


def test_check_tool_accepts_only_a_validated_baseline(tmp_path):
    (tmp_path / "f").write_text("x")
    for raw in (doc(), {"tools": {}}, encode(doc()), "text", 1, [], object()):
        with pytest.raises(TypeError):
            check_tool("maester", "1.2.3", tmp_path, raw)
    assert check_tool("maester", "1.2.3", tmp_path, make_baseline(
        {"maester": {"1.2.3": {"f": hashlib.sha256(b"x").hexdigest()}}})).status is HashStatus.OK


def test_production_code_never_builds_a_baseline_outside_the_validator():
    root = Path(schema.__file__).resolve().parent.parent
    users = [p.relative_to(root).as_posix() for p in root.rglob("*.py")
             if "Baseline(" in p.read_text(encoding="utf-8").replace("check_tool(", "")
             and p.name != "baseline_schema.py"]
    assert users == []
    assert not any("baseline_helpers" in p.read_text(encoding="utf-8") for p in root.rglob("*.py"))


# --- U-SCH-01/02: legacy content blocks wherever it is, through the full gate ----------

def _legacy_variants():
    return {
        "schema-1": encode(legacy_document()),
        "no-schema": encode(legacy_document(schema_value=None)),
        "interim-candidate": encode({**legacy_document(), "_note": "x"}),
        "empty-tools": b'{"schema": 1, "tools": {}}',
    }


@pytest.mark.parametrize("kind", list(_legacy_variants()))
@pytest.mark.parametrize("where", ["orbit-home", "tmp-dir", "cwd", "named-other", "nested"])
def test_legacy_content_is_legacy_wherever_it_is(tmp_path, monkeypatch, kind, where):
    content = _legacy_variants()[kind]
    folder = {"orbit-home": Path(os.environ["ORBIT_HOME"]), "tmp-dir": tmp_path / "t",
              "cwd": tmp_path / "cwd", "named-other": tmp_path / "o", "nested": tmp_path / "a" / "b"}[where]
    folder.mkdir(parents=True, mode=0o700, exist_ok=True)
    name = "anything.json" if where == "named-other" else NAME
    path = folder / name
    path.write_bytes(content)
    path.chmod(0o600)
    if where == "cwd":
        monkeypatch.chdir(folder)
    with pytest.raises(schema.BaselineError) as caught:
        hash_checker.load_manifest(path)
    assert caught.value.code is ErrorCode.LEGACY
    assert path.read_bytes() == content


def _installation(tmp_path, monkeypatch):
    from orbit.core.executables import Executable
    from orbit.core.tools import base, get_tool
    from orbit.core.tools.discovery import Installation
    root = tmp_path / "installs" / "Maester"
    root.mkdir(parents=True)
    (root / "Maester.psd1").write_text("synthetic manifest")
    exe = tmp_path / "interpreter"
    exe.write_text("not a real interpreter")
    exe.chmod(0o755)
    inst = Installation("1.2.3", root, root / "Maester.psd1", Executable.capture(exe.resolve()))
    monkeypatch.setattr(base.Tool, "discover", lambda self: inst)
    return get_tool("maester"), root


@pytest.mark.parametrize("kind", list(_legacy_variants()))
def test_a_legacy_manifest_copied_into_orbit_home_never_authorises_a_run(tmp_path, monkeypatch, kind):
    tool, root = _installation(tmp_path, monkeypatch)
    # an old checkout whose manifest records exactly the files that are installed now
    checkout = tmp_path / "old-checkout" / "data"
    checkout.mkdir(parents=True)
    files = hash_checker.hash_tree(root)
    old = {"schema": 1, "tools": {"maester": {"versions": {"1.2.3": {
        "install_dir": str(root), "files": files}}}}}
    content = {"schema-1": old, "no-schema": {"tools": old["tools"]},
               "interim-candidate": {**old, "_note": "x"},
               "empty-tools": {"schema": 1, "tools": {}}}[kind]
    (checkout / NAME).write_bytes(json.dumps(content).encode())
    home = Path(os.environ["ORBIT_HOME"])
    (home / NAME).write_bytes((checkout / NAME).read_bytes())  # copied by hand, as-is
    (home / NAME).chmod(0o600)
    before = (home / NAME).read_bytes()

    result = verify_tool(tool)
    assert result.status is HashStatus.UNVERIFIED and result.blocks_run
    assert result.reason == schema.MESSAGES[ErrorCode.LEGACY]
    assert launch_binding([result])[0] is None
    assert not hash_checker.gate_run([result])[0]
    assert (home / NAME).read_bytes() == before


def test_a_template_copy_as_the_active_baseline_never_authorises_a_run(tmp_path, monkeypatch):
    tool, _root = _installation(tmp_path, monkeypatch)
    home = Path(os.environ["ORBIT_HOME"])
    (home / NAME).write_bytes(TEMPLATE)
    (home / NAME).chmod(0o600)
    result = verify_tool(tool)
    assert result.status is HashStatus.UNVERIFIED
    assert result.reason == schema.MESSAGES[ErrorCode.BINDING_MISSING]
    assert launch_binding([result])[0] is None
    assert (home / NAME).read_bytes() == TEMPLATE


@posix_only
def test_a_baseline_for_another_user_never_authorises_a_run(tmp_path, monkeypatch):
    tool, root = _installation(tmp_path, monkeypatch)
    home = Path(os.environ["ORBIT_HOME"])
    theirs = schema.binding_for("posix", f"uid:{os.geteuid() + 1}", None)
    write(home / NAME, {"maester": {"1.2.3": hash_checker.hash_tree(root)}}, bound=theirs)
    result = verify_tool(tool)
    assert result.status is HashStatus.UNVERIFIED and result.blocks_run
    assert result.reason == schema.MESSAGES[ErrorCode.BINDING_MISMATCH]


def test_a_valid_baseline_for_this_user_reaches_ok_and_a_missing_one_keeps_its_classification(
        tmp_path, monkeypatch):
    tool, root = _installation(tmp_path, monkeypatch)
    home = Path(os.environ["ORBIT_HOME"])
    assert verify_tool(tool).reason == hash_checker.NO_BASELINE  # missing: the existing wording
    write(home / NAME, {"maester": {"1.2.3": hash_checker.hash_tree(root)}})
    assert verify_tool(tool).status is HashStatus.OK


def test_unestablished_identity_blocks_the_read_gate(tmp_path, monkeypatch):
    tool, root = _installation(tmp_path, monkeypatch)
    home = Path(os.environ["ORBIT_HOME"])
    write(home / NAME, {"maester": {"1.2.3": hash_checker.hash_tree(root)}})
    monkeypatch.setattr(schema, "_platform_class", lambda: "win32")
    monkeypatch.setattr(schema, "_windows_token_sid", lambda: (_ for _ in ()).throw(OSError("x")))
    result = verify_tool(tool)
    assert result.status is HashStatus.UNVERIFIED
    assert result.reason == schema.MESSAGES[ErrorCode.BINDING_UNAVAILABLE]


# --- U-SCH-08/09: generation ---------------------------------------------------------

def _run():
    try:
        baseline.main([])
    except SystemExit as exc:
        return exc.code or 0
    return 0


def test_first_generation_creates_a_bound_schema_2_baseline(home, synthetic):
    assert _run() == 0
    written = json.loads((home / NAME).read_text())
    assert written["schema"] == 2 and written["kind"] == "orbit.integrity-baseline"
    assert written["binding"] == binding().to_json()
    assert written["generator"] == {"orbit": VERSION}
    assert set(written) == {"schema", "kind", "binding", "generator", "tools"}
    assert set(written["tools"]) == set(json.loads(TEMPLATE)["tools"])
    assert (home / NAME).read_bytes() == schema.dump_baseline(hash_checker.load_manifest())
    assert verify_tool(synthetic.tool).status is HashStatus.OK


def test_a_rerun_preserves_entries_and_same_version_changes_are_not_reblessed(home, synthetic, capsys):
    assert _run() == 0
    first = (home / NAME).read_bytes()
    assert _run() == 0
    assert (home / NAME).read_bytes() == first  # nothing lost, deterministic
    (synthetic.root / "Maester.psm1").write_text("changed")
    assert _run() == 1
    assert "NOT recorded" in capsys.readouterr().out
    assert (home / NAME).read_bytes() == first  # not re-blessed
    assert verify_tool(synthetic.tool).status is HashStatus.MISMATCH


def test_other_entries_survive_an_update(home, synthetic):
    home.mkdir(mode=0o700)
    write(home / NAME, {"other": {"9": {"f": HEX}}})
    assert _run() == 0
    kept = json.loads((home / NAME).read_text())["tools"]
    assert kept["other"] == {"versions": {"9": {"files": {"f": HEX}}}} and "maester" in kept


def test_generation_without_an_established_identity_writes_nothing(home, synthetic, monkeypatch, capsys):
    monkeypatch.setattr(schema, "_platform_class", lambda: "win32")
    monkeypatch.setattr(schema, "_windows_token_sid", lambda: "")
    assert _run() == 1
    err = capsys.readouterr().err
    assert schema.MESSAGES[ErrorCode.BINDING_UNAVAILABLE] in err
    assert "Move-Item" not in err  # nothing was refused, so no move-aside advice
    assert not home.exists()
    with pytest.raises(ManifestError):
        seed_manifest(home / NAME, TEMPLATE)
    assert not home.exists()


def test_a_new_file_without_one_is_still_bound(tmp_path):
    folder = tmp_path / "f"
    folder.mkdir(mode=0o700)
    with update_manifest(folder / NAME) as d:
        d["tools"]["t"] = {"versions": {}}
    assert parse_baseline((folder / NAME).read_bytes(), binding())


def test_the_template_is_not_changed_and_seed_never_copies_it_verbatim(home):
    before = TEMPLATE
    assert seed_manifest(home / NAME, TEMPLATE) is True
    assert hash_checker.TEMPLATE_PATH.read_bytes() == before
    assert (home / NAME).read_bytes() != TEMPLATE
    assert seed_manifest(home / NAME, TEMPLATE) is False


@pytest.mark.parametrize("bad", [b"", b"{", b"[]", encode(legacy_document()), encode(doc()),
                                 json.dumps({**json.loads(TEMPLATE), "binding": doc()["binding"]}).encode(),
                                 json.dumps({**json.loads(TEMPLATE), "_note": "x"}).encode(),
                                 json.dumps({"schema": 2, "kind": "orbit.integrity-baseline",
                                             "tools": {"maester": {"versions": {"1": {}}}}}).encode()])
def test_seed_refuses_anything_that_is_not_the_empty_template(home, bad):
    with pytest.raises(ManifestError):
        seed_manifest(home / NAME, bad)
    assert not home.exists()


# --- every refused existing file stays byte-for-byte unchanged ---------------------------

def _refused_cases():
    other = schema.binding_for("posix", f"uid:{os.geteuid() + 1}" if hasattr(os, "geteuid") else "uid:1", None)
    return {
        "schema-1": (encode(legacy_document()), ErrorCode.LEGACY),
        "no-schema": (encode(legacy_document(schema_value=None)), ErrorCode.LEGACY),
        "newer": (encode(doc(schema=3)), ErrorCode.NEWER),
        "template": (TEMPLATE, ErrorCode.BINDING_MISSING),
        "other-user": (encode(doc(binding=other.to_json())), ErrorCode.BINDING_MISMATCH),
        "other-platform": (encode(doc(binding=schema.binding_for("win32", "S", "G").to_json())),
                           ErrorCode.BINDING_MISMATCH),
        "extra-key": (encode(doc(extra=1)), ErrorCode.MALFORMED),
        "bad-entry": (encode(doc(tools={"m": {"versions": {"1": {"files": {"../x": HEX}}}}})),
                      ErrorCode.ENTRY_MALFORMED),
        "not-json": (b"{broken", ErrorCode.NOT_JSON),
        "not-object": (b"[1]", ErrorCode.NOT_OBJECT),
        "odd-format": (b'{"schema":   1,\n "tools":{ }}', ErrorCode.LEGACY),
    }


@pytest.mark.parametrize("case", list(_refused_cases()))
def test_a_refused_existing_file_is_never_rewritten_reformatted_or_upgraded(home, synthetic, capsys, case):
    content, code = _refused_cases()[case]
    home.mkdir(mode=0o700)
    path = home / NAME
    path.write_bytes(content)
    path.chmod(0o600)
    mtime = path.stat().st_mtime_ns

    assert seed_manifest(path, TEMPLATE) is False  # an existing file is not touched by seeding
    with pytest.raises(ManifestError) as caught, update_manifest(path):
        pytest.fail("the block must not run for a refused baseline")
    assert caught.value.code is code
    expected = schema.MESSAGES[code].replace("newer ORBIT.", "newer ORBIT (schema 3).")
    assert str(caught.value) == expected
    capsys.readouterr()
    assert _run() == 1
    err = capsys.readouterr().err
    assert "Manifest NOT updated" in err and "orbit-generate-hashes" in err
    assert "Move-Item" in err and "mv ~/.orbit/tool_hashes.json" in err  # the exact manual step
    assert str(home) not in err
    assert path.read_bytes() == content and path.stat().st_mtime_ns == mtime
    assert sorted(p.name for p in home.iterdir()) == [NAME, NAME + ".lock"]  # no temp files left
    result = verify_tool(synthetic.tool)
    assert result.status is HashStatus.UNVERIFIED and result.blocks_run


@pytest.mark.parametrize("case", ["schema-1", "newer", "other-user", "template", "bad-entry"])
def test_failure_messages_never_contain_attacker_controlled_content(home, case):
    marker = "MARKER-\x1b[31m-S-1-5-21-0-0-0-500"
    content = {
        "schema-1": {"schema": 1, "tools": {marker: {}}, marker: marker},
        "newer": {"schema": 3, marker: marker, "tools": {}},
        "other-user": doc(binding={"os": marker, "principal": marker, "machine": marker}),
        "template": {**json.loads(TEMPLATE), marker: marker},
        "bad-entry": doc(tools={marker: {"versions": {marker: {"files": {marker: marker}}}}}),
    }[case]
    with pytest.raises(schema.BaselineError) as caught:
        parse_baseline(json.dumps(content).encode(), binding())
    for text in (str(caught.value), repr(caught.value), caught.value.code.value):
        assert "MARKER" not in text and "S-1-5" not in text and "\x1b" not in text
    home.mkdir(mode=0o700)
    (home / NAME).write_text(json.dumps(content))
    (home / NAME).chmod(0o600)
    with pytest.raises(ManifestError) as refused, update_manifest(home / NAME):
        pass
    assert "MARKER" not in str(refused.value) and str(home) not in str(refused.value)


def test_every_error_code_has_a_fixed_message():
    assert set(schema.MESSAGES) == set(ErrorCode)
    for code, message in schema.MESSAGES.items():
        assert message and "{" not in message and "\n" not in message, code


def test_the_documented_messages_are_stable():
    assert schema.MESSAGES[ErrorCode.LEGACY].startswith(
        "the baseline is in the older unbound format (schema 1). ORBIT does not trust or import it")
    assert schema.MESSAGES[ErrorCode.BINDING_MISSING].endswith("Run orbit-generate-hashes.")
    assert "different user or computer" in schema.MESSAGES[ErrorCode.BINDING_MISMATCH]


def test_baseline_schema_is_a_pure_module():
    """No file or process I/O: it decides on bytes it is given."""
    source = Path(baseline_schema.__file__).read_text(encoding="utf-8")
    for forbidden in ("open(", "Path(", "read_bytes", "subprocess", "socket", "os.environ", "getenv",
                      "expanduser", "home("):
        assert forbidden not in source, forbidden

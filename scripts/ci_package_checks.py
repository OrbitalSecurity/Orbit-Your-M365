#!/usr/bin/env python3
"""Checks that the CI ``package`` job runs against the built wheel and sdist.

    python -I scripts/ci_package_checks.py contents DIST_DIR
    <venv>/bin/python -I scripts/ci_package_checks.py smoke WORK_DIR CHECKOUT
    <venv>/bin/python -I scripts/ci_package_checks.py baseline WORK_DIR CHECKOUT
    <venv>/bin/python -I scripts/ci_package_checks.py identity          (native Windows only)
    <venv>/bin/python -I scripts/ci_package_checks.py seeded ORBIT_HOME
    python -I scripts/ci_package_checks.py junit REPORT.xml MINIMUM_TESTS

``contents`` needs only the standard library. ``smoke`` and ``baseline`` run inside the scratch
virtualenv that holds nothing but the installed wheel, with the working directory outside the
checkout and ORBIT_HOME pointing at scratch. Everything is offline and synthetic: no tenant,
credential, network, real tool or process is used, and an attempt to use one is recorded and
fails the check even if ORBIT swallows the exception it raised. The dry-run that ``smoke``
accepts runs under that guard, not before it.
"""
from __future__ import annotations

import configparser
import hashlib
import json
import os
import pathlib
import re
import stat
import sys
import tarfile
import zipfile

VERSION = "1.5.1"
TEMPLATE = "orbit/data/tool_hashes.template.json"
ACTIVE_NAMES = ("tool_hashes.json", "tool_hashes.json.lock")  # the per-user baseline and its lock
SCHEMA = 2                          # orbit.core.baseline_schema.SCHEMA; this check is stdlib-only
KIND = "orbit.integrity-baseline"   # orbit.core.baseline_schema.KIND
ENTRY_POINTS = {"orbit": "orbit.cli:main", "orbit-generate-hashes": "orbit.core.baseline:cli"}
TOOLS = {"scubagear", "maester", "monkey365", "roadtools", "hawk"}
REQUIRED = [
    "orbit/data/cve_mappings.json",
    TEMPLATE,
    "orbit/data/fixtures/maester_sample.json",
    "orbit/data/fixtures/scubagear_sample.json",
    "orbit/reporting/templates/cover.txt.j2",
    "orbit/reporting/templates/posture.txt.j2",
]


def _check_template(label: str, raw: bytes) -> None:
    """The packaged template is exactly the schema-2 empty, unbound seed.

    Schema 2, the exact kind, every tool present with an empty version map, and nothing else. In
    particular no ``binding`` and no ``generator``: a raw copy of it can never be an active
    baseline, because the reader refuses an unbound file (see ``baseline`` for the run-time proof).
    """
    template = json.loads(raw)
    assert isinstance(template, dict), f"{label}: template is not an object"
    schema = template.get("schema")
    assert type(schema) is int and schema == SCHEMA, f"{label}: template schema is {schema!r}"
    assert template.get("kind") == KIND, f"{label}: template kind is {template.get('kind')!r}"
    bound = sorted({"binding", "generator"} & set(template))
    assert not bound, f"{label}: template carries {bound}, so it could pass as an active baseline"
    assert set(template) == {"schema", "kind", "tools"}, (
        f"{label}: template has keys {sorted(template)}")
    tools = template["tools"]
    assert isinstance(tools, dict) and set(tools) == TOOLS, f"{label}: template tools {tools!r}"
    full = {name: entry for name, entry in tools.items() if entry != {"versions": {}}}
    assert not full, f"{label}: template carries recorded versions or extra keys: {sorted(full)}"


def _wheel_entry_points(text: str) -> dict:
    parser = configparser.ConfigParser(delimiters=("=",), interpolation=None)
    parser.optionxform = str
    parser.read_string(text)
    return dict(parser["console_scripts"])


def _sdist_entry_points(pyproject: str) -> dict:
    """[project.scripts] of the sdist's own pyproject.toml, by tomllib or a plain scan."""
    try:
        import tomllib
    except ImportError:  # Python 3.10: the table is simple enough to scan
        block = re.search(r"^\[project\.scripts\]\n(.*?)(?=^\[|\Z)", pyproject, re.DOTALL | re.MULTILINE)
        assert block, "sdist pyproject.toml has no [project.scripts]"
        return dict(re.findall(r'^([\w.-]+)\s*=\s*"([^"]+)"', block.group(1), re.MULTILINE))
    return tomllib.loads(pyproject)["project"]["scripts"]


def _check_archive(label: str, found: set[str], template: bytes, scripts: dict) -> None:
    missing = [r for r in REQUIRED if r not in found]
    assert not missing, f"{label} is missing {missing}"
    stray = [n for n in found if n.startswith(("data/", "tests/fixtures/"))]
    assert not stray, f"{label} carries repository-level data: {stray}"
    # the baseline is per-user state: no active manifest (or its lock) may ship, wherever it is
    baselines = [n for n in found if pathlib.PurePosixPath(n).name in ACTIVE_NAMES
                 or n.endswith(tuple(ACTIVE_NAMES))]
    assert not baselines, f"{label} carries a baseline: {baselines}"
    _check_template(label, template)
    for name, target in ENTRY_POINTS.items():
        assert scripts.get(name) == target, f"{label} declares {name} = {scripts.get(name)!r}"
    print(f"{label}: all {len(REQUIRED)} runtime resources present, schema-{SCHEMA} empty unbound "
          f"template, entry points {sorted(ENTRY_POINTS)}, no baseline shipped")


def contents(dist: pathlib.Path) -> None:
    wheels = sorted(dist.glob(f"orbit_m365-{VERSION}-*.whl"))
    sdists = sorted(dist.glob(f"orbit_m365-{VERSION}.tar.gz"))
    assert len(wheels) == 1 and len(sdists) == 1, (wheels, sdists)
    with zipfile.ZipFile(wheels[0]) as z:
        wheel_names = set(z.namelist())
        wheel_template = z.read(TEMPLATE)
        wheel_scripts = _wheel_entry_points(z.read(next(
            n for n in wheel_names if n.endswith(".dist-info/entry_points.txt"))).decode())
    with tarfile.open(sdists[0]) as t:
        members = {n.split("/", 1)[1]: m for n, m in zip(t.getnames(), t.getmembers(), strict=True)
                   if "/" in n}
        assert all(m.isfile() or m.isdir() for m in members.values()), "sdist has a link or device"
        sdist_names = set(members)
        assert TEMPLATE in members and "pyproject.toml" in members, "sdist lacks the template"
        sdist_template = t.extractfile(members[TEMPLATE]).read()
        sdist_scripts = _sdist_entry_points(t.extractfile(members["pyproject.toml"]).read().decode())
    # each archive is validated on its own: neither stands in for the other
    _check_archive("wheel", wheel_names, wheel_template, wheel_scripts)
    _check_archive("sdist", sdist_names, sdist_template, sdist_scripts)
    assert wheel_template == sdist_template, "wheel and sdist carry different templates"


def guard_targets() -> list:
    """(owner, names) of the standard-library process and network entry points this validation guards.

    Process creation (subprocess, os.exec*/spawn*/posix_spawn*/fork*/system/popen, pty,
    multiprocessing, asyncio subprocesses) and network use (socket connects and sends including
    sendto/sendmsg, binds and listens, name resolution, asyncio connections, smtplib,
    http.client, urllib). A name that this Python lacks is skipped.
    """
    import asyncio
    import asyncio.base_events
    import http.client
    import multiprocessing.process
    import smtplib
    import socket
    import subprocess
    import urllib.request

    targets = [
        (socket.socket, ("connect", "connect_ex", "sendto", "sendmsg", "sendmsg_afalg", "bind",
                         "listen")),
        (socket, ("create_connection", "create_server", "getaddrinfo", "gethostbyname",
                  "gethostbyname_ex", "gethostbyaddr", "getnameinfo")),
        (subprocess, ("Popen", "run", "call", "check_call", "check_output", "getoutput",
                      "getstatusoutput")),
        (os, ("system", "popen", "fork", "forkpty", "posix_spawn", "posix_spawnp",
              "execl", "execle", "execlp", "execlpe", "execv", "execve", "execvp", "execvpe",
              "spawnl", "spawnle", "spawnlp", "spawnlpe", "spawnv", "spawnve", "spawnvp",
              "spawnvpe", "startfile")),
        (multiprocessing.process.BaseProcess, ("start",)),
        (asyncio, ("create_subprocess_exec", "create_subprocess_shell", "open_connection",
                   "start_server", "open_unix_connection", "start_unix_server")),
        (asyncio.subprocess, ("create_subprocess_exec", "create_subprocess_shell")),
        (asyncio.base_events.BaseEventLoop, (
            "subprocess_exec", "subprocess_shell", "create_connection", "create_server",
            "create_datagram_endpoint", "sock_connect", "getaddrinfo", "getnameinfo")),
        (asyncio.SelectorEventLoop, ("create_unix_connection", "create_unix_server")),
        (smtplib.SMTP, ("connect", "_get_socket")),
        (smtplib.SMTP_SSL, ("_get_socket",)),
        (smtplib.LMTP, ("connect",)),
        (http.client.HTTPConnection, ("connect",)),
        (http.client.HTTPSConnection, ("connect",)),
        (urllib.request, ("urlopen",)),
    ]
    try:
        import pty
    except ImportError:  # not available off POSIX
        pass
    else:
        targets.append((pty, ("fork", "spawn")))
    return targets


def _label(owner, name: str) -> str:
    if isinstance(owner, type):
        return f"{owner.__module__}.{owner.__qualname__}.{name}"
    return f"{owner.__name__}.{name}"


def install_guard(allow_socketpair: bool | None = None):
    """Block and record attempts on the guarded process and network entry points (see guard_targets).

    This instruments the covered paths only; it is not a proof that no other path exists. The list
    outlives swallowed errors.

    Each replacement appends to the list first and raises second, so code that catches the
    exception still leaves a trace that the final assertion sees.

    ``socket.socketpair`` is the one exemption, and only on Windows (``allow_socketpair``
    defaults to that): there it is built from a loopback bind, listen and connect, and asyncio
    calls it to create every event loop. It never leaves the process and reaches no network, so it
    runs with the originals restored for its own duration; every other use of those methods stays
    blocked and recorded. POSIX uses a native socketpair and needs no exemption.
    """
    import socket

    if allow_socketpair is None:
        allow_socketpair = sys.platform == "win32"
    attempts: list[str] = []
    originals = {name: getattr(socket.socket, name) for name in ("bind", "listen", "connect")}
    real_socketpair = socket.socketpair

    def deny(name):
        def blocked(*args, **kwargs):
            attempts.append(name)
            raise RuntimeError(f"blocked: {name}")
        return blocked

    for owner, names in guard_targets():
        for name in names:
            if hasattr(owner, name):
                setattr(owner, name, deny(_label(owner, name)))

    if allow_socketpair:
        blocked = {name: getattr(socket.socket, name) for name in originals}

        def socketpair(*args, **kwargs):
            for name, original in originals.items():
                setattr(socket.socket, name, original)
            try:
                return real_socketpair(*args, **kwargs)
            finally:
                for name, deny_it in blocked.items():
                    setattr(socket.socket, name, deny_it)
        socket.socketpair = socketpair

    # Prove the recording works: a swallowed exception must still leave a trace.
    try:
        socket.create_connection(("127.0.0.1", 9))
    except Exception:
        pass
    assert attempts == ["socket.create_connection"], attempts
    attempts.clear()
    return attempts


def _site_of(module) -> pathlib.Path:
    site = pathlib.Path(module.__file__).resolve().parent
    assert "site-packages" in site.parts, f"{module.__name__} not imported from site-packages: {site}"
    return site


def _assert_only_wheel_orbit(site: pathlib.Path, checkout: pathlib.Path) -> None:
    for module in list(sys.modules.values()):
        path = getattr(module, "__file__", None)
        if path and module.__name__.split(".")[0] == "orbit":
            resolved = pathlib.Path(path).resolve()
            assert site in resolved.parents, path
            assert checkout not in resolved.parents, path


def _report(payload: dict, out: pathlib.Path) -> list[pathlib.Path]:
    """The final PDF and DOCX reports that this very run generated, and proof they are real."""
    folder = pathlib.Path(payload["output_dir"]).resolve()
    assert out.resolve() in folder.parents, folder
    reports = []
    for ext in ("pdf", "docx"):
        found = sorted(folder.glob(f"ORBIT_Summary_DRYRUN_*.{ext}"))
        assert len(found) == 1, f"expected one generated {ext} report in {folder}, found {found}"
        data = found[0].read_bytes()
        assert len(data) > 2048, f"{found[0].name} is implausibly small"
        if ext == "pdf":
            assert data.startswith(b"%PDF-") and b"%%EOF" in data[-1024:], "not a complete PDF"
        else:
            with zipfile.ZipFile(found[0]) as z:
                assert z.testzip() is None and "word/document.xml" in z.namelist()
        reports.append(found[0])
    return reports


def smoke(work: pathlib.Path, checkout: pathlib.Path) -> None:
    """The one dry-run that is accepted: the installed ``orbit`` command, under the guard."""
    attempts = install_guard()

    import contextlib
    import io
    from importlib.metadata import entry_points

    # the installed console script's own target, not an import path of this script's choosing
    ep = next(e for e in entry_points(group="console_scripts") if e.name == "orbit")
    assert ep.value == ENTRY_POINTS["orbit"], ep.value
    main = ep.load()

    out = io.StringIO()
    try:
        with contextlib.redirect_stdout(out):
            main(["--dry-run", "--headless", "--json"])
    except SystemExit as exc:
        assert exc.code in (0, None), f"exit code {exc.code}"
    payload = json.loads(out.getvalue())

    import orbit.config as cfg
    assert payload["orbit_version"] == VERSION and payload["dry_run"] is True
    assert payload["failed_tools"] == [] and payload["blocked_tools"] == {}
    assert payload["total_controls"] == 16 and payload["score"] == 50
    assert any(f["cve_ids"] for f in payload["top_findings"]), "no CVE mapping resolved"
    reports = _report(payload, work / "out")
    assert len(list((work / "out").iterdir())) == 1, "exactly one run folder is expected"
    print("guarded dry-run final reports:", ", ".join(p.name for p in reports))

    assert attempts == [], f"network or process attempts during the dry-run: {attempts}"
    print("guard recorded attempts: []")

    site = _site_of(cfg)
    for resource in (cfg.DATA_DIR, cfg.FIXTURES_DIR):
        assert site in resource.resolve().parents, resource
    _assert_only_wheel_orbit(site, checkout)
    assert (work / "home" / "history.json").exists()
    assert not (work / "home" / "tool_hashes.json").exists(), "a dry-run must not create a baseline"
    print("installed wheel: offline headless dry-run produced final reports;", site)


def require_profile_scratch(path: pathlib.Path) -> None:
    """On Windows the scratch ORBIT_HOME must lie inside the real user profile.

    The current conservative Windows policy (``trusted_state._check_windows``) refuses any other
    ORBIT_HOME, and RUNNER_TEMP is outside the profile on hosted runners, so a misplaced scratch
    directory would fail for the wrong reason. Check it first and say so.
    """
    if sys.platform != "win32":
        return
    profile = os.path.normcase(os.path.abspath(pathlib.Path.home()))
    here = os.path.normcase(os.path.abspath(path))
    assert here.startswith(profile + os.sep) and here != profile, (
        "the scratch directory must be inside the user profile on Windows")


def _tree_digest(root: pathlib.Path) -> str:
    h = hashlib.sha256()
    for path in sorted(p for p in root.rglob("*") if p.is_file() and "__pycache__" not in p.parts):
        h.update(path.relative_to(root).as_posix().encode())
        h.update(hashlib.sha256(path.read_bytes()).digest())
    return h.hexdigest()


def baseline(work: pathlib.Path, checkout: pathlib.Path) -> None:
    """Record a baseline for a synthetic installation under a scratch ORBIT_HOME."""
    require_profile_scratch(work)
    home = work / "baseline-home"  # does not exist yet: the command must create it privately
    os.environ["ORBIT_HOME"] = str(home)
    attempts = install_guard()

    import orbit.config as cfg
    from orbit.core import baseline as command
    from orbit.core import hash_checker
    from orbit.core.executables import Executable
    from orbit.core.tools import base, get_tool
    from orbit.core.tools.discovery import Installation

    site = _site_of(cfg)
    package_before = _tree_digest(site / "orbit")
    template = hash_checker.TEMPLATE_PATH
    template_before = template.read_bytes()
    assert site in template.resolve().parents

    # 3. the active baseline is per-user, under ORBIT_HOME, and not in the package
    active = hash_checker.manifest_path()
    assert active == home / "tool_hashes.json", active
    assert site not in active.parents and checkout not in active.parents, active
    assert not active.exists()

    # A synthetic installation of one tool: nothing real is discovered, hashed or run.
    root = work / "synthetic" / "Maester"
    root.mkdir(parents=True)
    (root / "Maester.psd1").write_text("synthetic module manifest")
    (root / "Maester.psm1").write_text("synthetic module body")
    interpreter = work / "synthetic" / "interpreter"
    interpreter.write_text("not a real interpreter")
    interpreter.chmod(0o755)
    install = Installation("1.2.3", root, root / "Maester.psd1",
                           Executable.capture(interpreter.resolve()))
    tool = get_tool("maester")
    base.Tool.discover = lambda self: install
    command.all_tools = lambda: [tool]

    # 4. before generation the real-run gate is shut, and nothing was launched
    before = hash_checker.verify_tool(tool)
    assert before.status is hash_checker.HashStatus.UNVERIFIED and before.blocks_run, before
    assert before.reason == hash_checker.NO_BASELINE, before.reason
    assert not active.exists(), "checking must not create the baseline"
    print("before generation:", before.explain())

    # 4b. the raw packaged template, and a schema-1 file, placed as the active baseline anywhere
    # are refused by content: only a bound schema-2 baseline can reach OK
    from orbit.core import baseline_schema as schema
    raw = template.read_bytes()
    try:
        schema.parse_baseline(raw, schema.current_binding())
    except schema.BaselineError as exc:
        assert exc.code is schema.ErrorCode.BINDING_MISSING, exc.code
    else:
        raise AssertionError("the raw template was accepted as a baseline")
    legacy = json.dumps({"schema": 1, "tools": {"maester": {"versions": {"1.2.3": {
        "files": {"Maester.psd1": "0" * 64, "Maester.psm1": "0" * 64}}}}}}).encode()
    here = schema.current_binding()
    other = schema.Binding(here.os, "0" * 64 if here.principal != "0" * 64 else "1" * 64,
                           here.machine)
    mismatched = json.dumps({"schema": 2, "kind": schema.KIND, "binding": other.to_json(),
                             "generator": {"orbit": VERSION}, "tools": {
                                 name: {"versions": {}} for name in sorted(TOOLS)}}).encode()
    cases = (("template", raw, schema.ErrorCode.BINDING_MISSING),
             ("schema-1", legacy, schema.ErrorCode.LEGACY),
             ("malformed", b"{ this is not json", schema.ErrorCode.NOT_JSON),
             ("mismatched", mismatched, schema.ErrorCode.BINDING_MISMATCH))
    for label, content, code in cases:
        scratch = work / f"refused-{label}"
        scratch.mkdir(mode=0o700)
        scratch.chmod(0o700)
        (scratch / "tool_hashes.json").write_bytes(content)
        (scratch / "tool_hashes.json").chmod(0o600)
        os.environ["ORBIT_HOME"] = str(scratch)
        refused = hash_checker.verify_tool(tool)
        assert refused.status is hash_checker.HashStatus.UNVERIFIED and refused.blocks_run, label
        assert refused.reason == schema.MESSAGES[code], (label, refused.reason)
        assert (scratch / "tool_hashes.json").read_bytes() == content, "a refused file was changed"
        # the generator command refuses it too, exits 1 and leaves the bytes alone
        try:
            command.main([])
        except SystemExit as exc:
            assert exc.code == 1, f"{label}: baseline command exit code {exc.code}"
        else:
            raise AssertionError(f"{label}: the baseline command accepted a refused baseline")
        assert (scratch / "tool_hashes.json").read_bytes() == content, "a refused file was changed"
    os.environ["ORBIT_HOME"] = str(home)
    print("template, schema-1, malformed and binding-mismatched files as the active baseline: "
          "UNVERIFIED, untouched, not regenerated")

    # 5. the installed command records the synthetic installation in ORBIT_HOME only
    try:
        command.main([])
    except SystemExit as exc:
        assert exc.code in (0, None), f"baseline command exit code {exc.code}"
    assert active.is_file(), "no baseline was written to ORBIT_HOME"
    if sys.platform != "win32":
        assert stat.S_IMODE(active.stat().st_mode) == 0o600, oct(active.stat().st_mode)
        assert stat.S_IMODE(home.stat().st_mode) == 0o700, oct(home.stat().st_mode)
    document = json.loads(active.read_text())
    assert document["schema"] == 2 and document["kind"] == "orbit.integrity-baseline", document.keys()
    assert set(document["binding"]) == {"os", "principal", "machine"} and "generator" in document
    assert document["binding"] == schema.current_binding().to_json(), "binding differs from this user"
    if sys.platform == "win32":
        assert document["binding"]["os"] == "win32" and document["binding"]["machine"], document
    else:
        assert document["binding"]["os"] == "posix" and document["binding"]["machine"] is None
    recorded = document["tools"]["maester"]["versions"]["1.2.3"]
    assert set(recorded["files"]) == {"Maester.psd1", "Maester.psm1"}, recorded
    after = hash_checker.verify_tool(tool)
    assert after.status is hash_checker.HashStatus.OK and not after.blocks_run, after
    print("after generation:", after.explain(), "baseline:", active)

    # a changed file closes the gate again
    (root / "Maester.psm1").write_text("tampered")
    tampered = hash_checker.verify_tool(tool)
    assert tampered.status is hash_checker.HashStatus.MISMATCH and tampered.blocks_run, tampered
    print("after tampering:", tampered.status.value)

    # 6. nothing was written into the installed package, and the template is unchanged
    assert template.read_bytes() == template_before, "the packaged template changed"
    assert _tree_digest(site / "orbit") == package_before, "the installed package changed"
    assert not (site / "orbit" / "data" / "tool_hashes.json").exists()

    assert attempts == [], f"network or process attempts: {attempts}"
    print("guard recorded attempts: []")

    # the entry point named in the wheel's metadata resolves to the same function
    from importlib.metadata import entry_points
    ep = next(e for e in entry_points(group="console_scripts") if e.name == "orbit-generate-hashes")
    assert ep.value == "orbit.core.baseline:cli" and ep.load() is command.cli
    _assert_only_wheel_orbit(site, checkout)
    print("installed baseline command ok; entry point", ep.value)


def identity() -> None:
    """Native Windows only: retrieve the token SID and MachineGuid and compare with the binding.

    Raw identifiers are checked for shape and never printed.
    """
    assert sys.platform == "win32", "identity is a native Windows check and cannot run elsewhere"
    from orbit.core import baseline_schema as schema

    sid = schema._windows_token_sid()
    guid = schema._windows_machine_guid()
    assert re.fullmatch(r"S-1-\d+(-\d+){1,15}", sid), "the token user SID has an unexpected shape"
    assert re.fullmatch(r"[0-9A-Fa-f]{8}(-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}", guid.strip()), (
        "MachineGuid has an unexpected shape")
    expected = schema.binding_for("win32", sid, guid)
    current = schema.current_binding()
    assert current == expected and current.os == "win32" and current.machine, "binding mismatch"
    assert current.principal != current.machine and sid not in json.dumps(current.to_json())
    assert guid not in json.dumps(current.to_json())
    print("windows identity: token SID and MachineGuid retrieved natively; "
          "binding equals current_binding() (identifiers not printed)")


def seeded(home: pathlib.Path) -> None:
    """The baseline the no-tools command left: bound schema 2, every tool present and empty."""
    from orbit.core import baseline_schema as schema

    document = json.loads((home / "tool_hashes.json").read_text(encoding="utf-8"))
    assert document["schema"] == SCHEMA and document["kind"] == KIND, document.keys()
    assert document["binding"] == schema.current_binding().to_json(), "not bound to this user"
    assert document["generator"] == {"orbit": VERSION}, document["generator"]
    assert set(document["tools"]) == TOOLS
    assert all(v == {"versions": {}} for v in document["tools"].values()), "versions were recorded"
    print("no-tools baseline: bound schema-2, every tool empty")


def junit(report: pathlib.Path, minimum: int) -> None:
    """A mandatory test run: enough tests ran, and none failed, errored or was skipped."""
    import xml.etree.ElementTree as ET  # the runner's own pytest report

    totals = {"tests": 0, "failures": 0, "errors": 0, "skipped": 0}
    for suite in ET.parse(report).getroot().iter("testsuite"):
        for key in totals:
            totals[key] += int(suite.get(key, 0))
    assert totals["tests"] >= minimum, f"only {totals['tests']} tests ran, expected {minimum}+"
    assert totals["skipped"] == 0, f"mandatory tests were skipped: {totals}"
    assert totals["failures"] == 0 and totals["errors"] == 0, f"failures: {totals}"
    print("mandatory tests:", totals["tests"], "ran, none skipped or failed")


def main(argv: list[str]) -> None:
    command, *args = argv
    if command == "contents":
        contents(pathlib.Path(args[0]))
    elif command == "smoke":
        smoke(pathlib.Path(args[0]), pathlib.Path(args[1]).resolve())
    elif command == "baseline":
        baseline(pathlib.Path(args[0]), pathlib.Path(args[1]).resolve())
    elif command == "identity":
        identity()
    elif command == "junit":
        junit(pathlib.Path(args[0]), int(args[1]))
    elif command == "seeded":
        seeded(pathlib.Path(args[0]))
    else:
        raise SystemExit(f"unknown command {command!r}")


if __name__ == "__main__":
    main(sys.argv[1:])

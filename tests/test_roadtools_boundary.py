"""Findings 2 and 4: ROADtools start-up, import binding and token containment.

The package is fake and every token is synthetic. No real ROADtools is used.
Real runs are disabled in production; the road fixture lifts that to test what is behind it.
"""
import asyncio
import json
import os
import signal
import stat
import subprocess
import sys
import venv
from pathlib import Path

import pytest

from orbit.core import hash_checker, runner
from orbit.core.executables import Executable
from orbit.core.hash_checker import HashStatus, hash_tree, verify_tool
from orbit.core.outputs import OutputConfig, make_run_folder, package
from orbit.core.pipeline import finalize
from orbit.core.process_env import child_env
from orbit.core.runner import Runner, RunStatus, prepare_run
from orbit.core.tools import discovery, get_tool
from orbit.core.workspace import Workspace
from orbit.security.auth_material import purge_auth_material, redact_tokens
from orbit.security.encryption import decrypt_archive

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX modes, links and signals")

FAST = 1000
TOKEN = "SYNTHETIC-TOKEN-0123456789-abcdefghijklmnop"
JWT = "eyJhbGciOiJub25lIn0000.eyJzeW50aGV0aWMiOnRydWV9.c2lnbmF0dXJl"

# Imitates the roadrecon CLI. The behaviour is selected through the client ID argument.
FAKE_MAIN = '''\
import json, os, stat, sys, time
import fakedep

def arg(flag):
    return sys.argv[sys.argv.index(flag) + 1] if flag in sys.argv else ""

def main():
    with open({record!r}, "a") as rec:
        command, tokens = sys.argv[1], arg("-f")
        if command == "auth":
            mode = arg("-c")
            blob = json.dumps({{"accessToken": {token!r}, "refreshToken": {token!r}}})
            for path in (tokens, ".roadtools_auth"):  # the second is the default relative path
                with open(path, "w") as fh:
                    fh.write(blob)
            rec.write(json.dumps({{"tokens": tokens, "cwd": os.getcwd(), "file": __file__,
                                  "dep": fakedep.__file__, "mode": mode,
                                  "perms": stat.S_IMODE(os.stat(tokens).st_mode)}}) + "\\n")
            rec.flush()
            if mode == "leak":
                out = os.environ["ORBIT_OUT_DIR"]
                for name in (".roadtools_auth.json", "session.json", "stray"):
                    with open(os.path.join(out, name), "w") as fh:
                        fh.write(blob)
            if mode == "echo":
                print(blob)
                print("bearer", {jwt!r})
            if mode == "auth-fails":
                raise RuntimeError("auth failed")
            if mode == "hang":
                print("holding token", flush=True)
                time.sleep(60)
        else:
            json.load(open(tokens))
            with open(arg("-d"), "w") as fh:
                fh.write("synthetic tenant data")
            if arg("-d") and os.path.exists(arg("-d") + ".fail"):
                raise RuntimeError("gather failed")
'''


class Creds:
    def __init__(self, mode=""):
        self.mode = mode

    def load(self, name):
        return {"client_id": self.mode} if self.mode else {}

    def secret_values(self, name):
        return []


def _dist(site, name, version, tops, requires=()):
    info = site / f"{name}-{version}.dist-info"
    info.mkdir()
    (info / "METADATA").write_text(
        f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n"
        + "".join(f"Requires-Dist: {r}\n" for r in requires))
    (info / "RECORD").write_text(
        "".join(f"{t},,\n" for t in tops) + f"{info.name}/RECORD,,\n../../../bin/{name},,\n")
    return info


@pytest.fixture()
def road(tmp_path, manifest_file, monkeypatch, private_tmp, roadtools_mechanics):
    site = (tmp_path / "site").resolve()
    (site / "roadtools" / "roadrecon").mkdir(parents=True)
    (site / "fakedep").mkdir()
    record = tmp_path / "record"
    (site / "roadtools" / "roadrecon" / "__init__.py").write_text("")
    (site / "roadtools" / "roadrecon" / "main.py").write_text(
        FAKE_MAIN.format(record=str(record), token=TOKEN, jwt=JWT))
    (site / "fakedep" / "__init__.py").write_text("")
    _dist(site, "roadrecon", "9.9", ["roadtools/roadrecon/main.py"], ["fakedep>=1"])
    _dist(site, "fakedep", "1.0", ["fakedep/__init__.py"])
    monkeypatch.setattr(discovery, "site_dir", lambda: site)

    class Road:
        tool = get_tool("roadtools")

        def baseline(self):
            inst = self.tool.discover()
            manifest_file("roadtools", inst.version,
                          hash_tree(inst.root, inst.members, inst.strict_member))

        def calls(self):
            return [json.loads(line) for line in record.read_text().splitlines()] \
                if record.exists() else []

        def run(self, out, mode="", before_launch=lambda: None):
            with Workspace() as ws:
                results, creds, secrets = prepare_run([self.tool], lambda: Creds(mode), ws)
                before_launch()
                folder = make_run_folder(out)
                runs = asyncio.run(Runner(folder, creds, secrets, False, results).run_all([self.tool]))
            return folder, runs["roadtools"]

    r = Road()
    r.site, r.private = site, private_tmp
    r.baseline()
    return r


def _holding_token(*roots):
    return [p for root in roots for p in root.rglob("*")
            if p.is_file() and TOKEN.encode() in p.read_bytes()]


# --- start-up hooks ---------------------------------------------------------

@pytest.fixture()
def hooked_python(tmp_path, road, monkeypatch):
    """An interpreter whose normal start-up fires harmless .pth, site and user hooks."""
    env = tmp_path / "hooked"
    venv.EnvBuilder(system_site_packages=True, with_pip=False, symlinks=True).create(env)
    site = next(env.glob("lib/python*/site-packages"))
    fired = tmp_path / "fired"
    hook = f"open({str(fired)!r}, 'a').write('{{}} ')"
    (site / "orbit_sentinel.pth").write_text(f"import sys; {hook.format('pth')}\n")
    (site / "sitecustomize.py").write_text(hook.format("sitecustomize") + "\n")
    (site / "usercustomize.py").write_text(hook.format("usercustomize") + "\n")
    python = env / "bin" / "python"
    return python, fired


def test_the_sentinels_really_fire_on_a_normal_start(hooked_python, tmp_path):
    python, fired = hooked_python
    subprocess.run([str(python), "-c", "pass"], check=True, timeout=30,
                   env=child_env({"PYTHONUSERBASE": str(tmp_path / "userbase")}))
    assert set(fired.read_text().split()) == {"pth", "sitecustomize", "usercustomize"}


def test_startup_hooks_never_run_during_discovery_or_launch(
        road, hooked_python, tmp_path, monkeypatch):
    python, fired = hooked_python
    monkeypatch.setattr(sys, "executable", str(python))
    monkeypatch.setenv("PYTHONUSERBASE", str(tmp_path / "userbase"))
    inst = road.tool.discover()
    assert inst.version == "9.9" and not fired.exists()
    # launch with the hooked interpreter itself, so only the launch flags can be protecting it
    monkeypatch.setattr(discovery, "base_python", lambda: Executable(python, "pinned"))
    monkeypatch.setattr(Executable, "verify", lambda self: None)
    _, run = road.run(tmp_path / "out")
    assert run.status is RunStatus.COMPLETE, run.log
    assert len(road.calls()) == 1 and not fired.exists()


def test_hooks_planted_beside_the_package_never_run(road, tmp_path):
    fired = tmp_path / "fired"
    code = f"open({str(fired)!r}, 'a').write('x')"
    (road.site / "evil.pth").write_text(f"import sys; {code}\n")
    for name in ("sitecustomize.py", "usercustomize.py"):
        (road.site / name).write_text(code + "\n")
    _, run = road.run(tmp_path / "out")  # not covered members, so they are simply never loaded
    assert run.status is RunStatus.COMPLETE, run.log
    assert not fired.exists()


def test_discovery_starts_no_process(road, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("discovery started a process")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    assert road.tool.discover().version == "9.9"


def test_unverified_package_code_never_runs(road, tmp_path):
    fired = tmp_path / "fired"
    (road.site / "fakedep" / "__init__.py").write_text(f"open({str(fired)!r}, 'w').write('x')\n")
    _, run = road.run(tmp_path / "out")
    assert run.status is RunStatus.SKIPPED and run.note == "hash mismatch"
    assert not fired.exists() and road.calls() == []


# --- import binding ---------------------------------------------------------

def test_package_and_dependency_are_imported_from_the_snapshot(road, tmp_path):
    _, run = road.run(tmp_path / "out")
    assert run.status is RunStatus.COMPLETE, run.log
    call = road.calls()[0]
    assert Path(call["file"]).is_relative_to(road.private)
    assert Path(call["dep"]).is_relative_to(road.private)


@pytest.mark.parametrize("victim", ["roadtools/roadrecon/main.py", "fakedep/__init__.py"])
def test_change_after_verification_does_not_run(road, tmp_path, victim):
    fired = tmp_path / "fired"

    def swap():
        (road.site / victim).write_text(f"open({str(fired)!r}, 'w').write('x')\n")

    _, run = road.run(tmp_path / "out", before_launch=swap)
    assert run.status is RunStatus.COMPLETE, run.log
    assert not fired.exists() and len(road.calls()) == 1


def test_namespace_is_not_resolved_again_from_sys_path(road, tmp_path):
    fired, evil = tmp_path / "fired", tmp_path / "evil"
    (evil / "roadtools").mkdir(parents=True)
    # a regular package anywhere on sys.path normally beats a namespace package ahead of it
    (evil / "roadtools" / "__init__.py").write_text(f"open({str(fired)!r}, 'w').write('x')\n")
    (tmp_path / "out").mkdir()
    with Workspace() as ws:
        binding = verify_tool(road.tool, ws).binding
        spec = road.tool.launch_spec({}, tmp_path / "out", binding)
        code = f"import sys; sys.path.append({str(evil)!r})\n" + spec.argv[-1]
        proc = subprocess.run([*spec.argv[:-1], code], env=child_env(spec.env), cwd=spec.cwd,
                              capture_output=True, text=True, timeout=30)
    assert proc.returncode == 0, proc.stderr
    assert not fired.exists()


def test_dependency_bytecode_is_neither_covered_nor_copied(road, tmp_path):
    cache = road.site / "fakedep" / "__pycache__"
    cache.mkdir()
    (cache / "__init__.cpython-312.pyc").write_bytes(b"not covered")
    with Workspace() as ws:
        result = verify_tool(road.tool, ws)
        assert result.status is HashStatus.OK
        assert not list(result.binding.root.rglob("__pycache__"))


def test_bytecode_inside_roadtools_itself_is_still_covered(road):
    cache = road.site / "roadtools" / "roadrecon" / "__pycache__"
    cache.mkdir()
    (cache / "main.cpython-312.pyc").write_bytes(b"planted")
    assert verify_tool(road.tool).status is HashStatus.MISMATCH


@pytest.mark.parametrize("problem", [
    "missing-dependency", "duplicate-record", "no-record", "editable", "linked-metadata",
    "split-site", "not-installed",
])
def test_unsupported_environment_blocks_as_unverified(road, tmp_path, monkeypatch, problem):
    info = road.site / "roadrecon-9.9.dist-info"
    if problem == "missing-dependency":
        with open(info / "METADATA", "a") as fh:
            fh.write("Requires-Dist: absentdep>=2\n")
    elif problem == "duplicate-record":
        _dist(road.site, "roadrecon", "9.8", [])
    elif problem == "no-record":
        (info / "RECORD").unlink()
    elif problem == "editable":
        (road.site / "roadtools").rename(tmp_path / "source-checkout")
    elif problem == "linked-metadata":
        (info / "METADATA").rename(tmp_path / "METADATA")
        (info / "METADATA").symlink_to(tmp_path / "METADATA")
    elif problem == "split-site":
        def split():
            raise discovery.DiscoveryError("separate site-packages directories")
        monkeypatch.setattr(discovery, "site_dir", split)
    else:
        info.rename(tmp_path / "gone")
    _, run = road.run(tmp_path / "out")
    assert run.status is RunStatus.SKIPPED and run.note == "integrity unverified"
    assert road.calls() == []


def test_extras_are_followed_only_when_requested(road):
    _dist(road.site, "wanted", "1", ["wanted.py"])
    _dist(road.site, "unwanted", "1", ["unwanted.py"])
    (road.site / "fakedep-1.0.dist-info" / "METADATA").write_text(
        "Metadata-Version: 2.1\nName: fakedep\nVersion: 1.0\n"
        'Requires-Dist: wanted; extra == "fast"\nRequires-Dist: unwanted; extra == "dev"\n')
    (road.site / "roadrecon-9.9.dist-info" / "METADATA").write_text(
        "Metadata-Version: 2.1\nName: roadrecon\nVersion: 9.9\nRequires-Dist: fakedep[fast]>=1\n")
    members = road.tool.discover().members
    assert "wanted.py" in members and "unwanted.py" not in members


@pytest.mark.parametrize("row", ["/etc/passwd", "..", "../x", ".", "...", ".. /x", "C:/x", "x.pth"])
def test_record_rows_cannot_widen_the_file_set(road, row):
    before = road.tool.discover().members
    with open(road.site / "roadrecon-9.9.dist-info" / "RECORD", "a") as fh:
        fh.write(f'"{row}",,\n')
    assert road.tool.discover().members == before


# --- token containment ------------------------------------------------------

@pytest.mark.parametrize("mode", ["", "leak", "auth-fails"])
def test_token_is_not_retained_anywhere(road, tmp_path, mode):
    folder, run = road.run(tmp_path / "out", mode)
    expected = RunStatus.FAILED if mode == "auth-fails" else RunStatus.COMPLETE
    assert run.status is expected, run.log
    call = road.calls()[0]
    assert Path(call["tokens"]).is_relative_to(road.private) and call["perms"] == 0o600
    assert Path(call["cwd"]) == Path(call["tokens"]).parent
    assert _holding_token(folder, road.private) == [] and list(road.private.iterdir()) == []
    if mode != "auth-fails":
        assert (folder / "roadtools" / "roadrecon.db").read_text() == "synthetic tenant data"


@pytest.mark.parametrize("keep", [True, False])
@pytest.mark.parametrize("mode", ["", "leak"])
def test_token_is_not_in_plaintext_output_or_encrypted_archive(road, tmp_path, mode, keep):
    folder, _ = road.run(tmp_path / "out", mode)
    cfg = OutputConfig(tmp_path / "out", {"JSON"}, True, keep)
    _, written = finalize(folder, ["ROADtools"], cfg, False, "pw")
    restored = tmp_path / "restored"
    decrypt_archive(written[-1], "pw", restored)
    assert (restored / "roadtools" / "roadrecon.db").exists()
    assert _holding_token(tmp_path / "out", restored, road.private) == []


@pytest.mark.parametrize("name", [".roadtools_auth.json", ".roadtools_auth", "session.json",
                                  "sub/token.txt", "noext"])
def test_packaging_alone_also_excludes_tokens(tmp_path, name):
    folder = make_run_folder(tmp_path / "out")
    path = folder / "roadtools" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"refreshToken": TOKEN}))
    (folder / "roadtools" / "keep.txt").write_text("report")
    archive = package(folder, OutputConfig(tmp_path / "out", encrypt=True), "pw", FAST)
    decrypt_archive(archive, "pw", tmp_path / "restored", iterations=FAST)
    assert (tmp_path / "restored" / "roadtools" / "keep.txt").exists()
    assert _holding_token(tmp_path / "restored") == []


def test_named_token_files_are_purged_from_any_tool_folder(tmp_path):
    for rel in ("maester/.roadtools_auth", "hawk/msal_token_cache.bin", ".roadtools_auth.json",
                "maester/.roadtools_auth.d/token"):
        (tmp_path / "run" / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / "run" / rel).write_text(TOKEN)
    (tmp_path / "run" / "maester" / "maester.json").write_text("{}")
    assert len(purge_auth_material(tmp_path / "run")) == 4
    assert _holding_token(tmp_path / "run") == []
    assert (tmp_path / "run" / "maester" / "maester.json").exists()


def test_purge_does_not_follow_links(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / ".roadtools_auth").write_text(TOKEN)
    (tmp_path / "run").mkdir()
    (tmp_path / "run" / "linked").symlink_to(outside)
    purge_auth_material(tmp_path / "run")
    assert (outside / ".roadtools_auth").exists()


def test_token_spanning_a_read_boundary_is_found(tmp_path):
    folder = tmp_path / "run" / "roadtools"
    folder.mkdir(parents=True)
    (folder / "big.json").write_text(" " * ((1 << 20) - 8) + f'"accessToken": "{TOKEN}"')
    assert purge_auth_material(tmp_path / "run") == ["roadtools/big.json"]


def test_failed_token_cleanup_fails_the_tool(road, tmp_path, monkeypatch):
    def cannot(*args):
        raise PermissionError("locked")

    monkeypatch.setattr(runner, "purge_auth_material", cannot)
    _, run = road.run(tmp_path / "out")
    assert run.status is RunStatus.FAILED and run.note == "authentication cleanup failed"


def test_tokens_are_redacted_from_tool_output(road, tmp_path):
    _, run = road.run(tmp_path / "out", "echo")
    text = "\n".join(run.log)
    assert "bearer ***" in text and TOKEN not in text and JWT not in text
    assert redact_tokens("accessTokenAcceptedVersion: 2") == "accessTokenAcceptedVersion: 2"


def test_temp_inside_the_output_tree_blocks(road, tmp_path):
    _, run = road.run(road.private)
    assert run.status is RunStatus.SKIPPED and run.note == "unsafe token location"
    assert road.calls() == [] and _holding_token(road.private) == []


async def test_token_is_removed_when_the_run_is_stopped(road, tmp_path):
    holding = asyncio.Event()
    with Workspace() as ws:
        results, creds, secrets = await asyncio.to_thread(
            prepare_run, [road.tool], lambda: Creds("hang"), ws)

        def update(run):
            if "holding token" in run.log:
                holding.set()

        r = Runner(tmp_path / "out" / "run", creds, secrets, False, results, on_update=update)
        task = asyncio.create_task(r.run_all([road.tool]))
        await asyncio.wait_for(holding.wait(), 20)
        assert _holding_token(road.private)
        r.stop_all()
        runs = await asyncio.wait_for(task, 20)
    assert runs["roadtools"].status is RunStatus.FAILED
    assert _holding_token(tmp_path / "out", road.private) == []
    assert list(road.private.iterdir()) == []


@pytest.mark.parametrize("sig", [signal.SIGTERM, signal.SIGHUP, signal.SIGINT])
def test_child_removes_tokens_even_without_its_parent(road, tmp_path, sig):
    (tmp_path / "out").mkdir()
    with Workspace() as ws:
        binding = verify_tool(road.tool, ws).binding
        assert stat.S_IMODE(binding.private_dir.stat().st_mode) == 0o700
        spec = road.tool.launch_spec({"client_id": "hang"}, tmp_path / "out", binding)
        proc = subprocess.Popen(spec.argv, env=child_env(spec.env), cwd=spec.cwd, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        try:
            assert "holding token" in proc.stdout.readline()
            assert _holding_token(binding.private_dir)
            proc.send_signal(sig)
            proc.wait(15)
            assert not binding.private_dir.exists()  # before ORBIT's own clean-up has run
        finally:
            proc.kill()
            proc.communicate()

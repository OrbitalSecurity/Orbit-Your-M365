"""Bundled offline data and dry-run fixtures are package resources, not repository paths.

Synthetic and offline: nothing here reaches a network, a tenant, a credential or a real tool.
"""
import fnmatch
import json
import os
import shutil
import subprocess
import sys
from importlib import resources
from pathlib import Path

import pytest

import orbit
import orbit.config as cfg
from orbit.core import hash_checker, runner
from orbit.core.tools import all_tools
from orbit.reporting import cve_map

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover
    import tomli as tomllib

REPO = Path(__file__).resolve().parent.parent
PACKAGE = Path(orbit.__file__).resolve().parent
DATA_FILES = ("cve_mappings.json", "tool_hashes.template.json")
FIXTURE_FILES = ("maester_sample.json", "scubagear_sample.json")


def test_resources_live_inside_the_package():
    assert cfg.DATA_DIR == PACKAGE / "data"
    assert cfg.FIXTURES_DIR == PACKAGE / "data" / "fixtures"
    assert not hasattr(cfg, "ROOT")  # nothing may anchor on the checkout root


def test_every_resource_is_readable_through_importlib_resources():
    data = resources.files("orbit") / "data"
    for name in DATA_FILES:
        assert json.loads((data / name).read_text(encoding="utf-8"))
    for name in FIXTURE_FILES:
        assert json.loads((data / "fixtures" / name).read_text(encoding="utf-8"))


def test_consumers_resolve_to_the_packaged_files():
    assert cve_map.MAP_PATH == cfg.DATA_DIR / "cve_mappings.json" and cve_map.MAP_PATH.is_file()
    # the mutable baseline is user state in ORBIT_HOME; the package owns only an empty template
    assert hash_checker.TEMPLATE_PATH == cfg.DATA_DIR / "tool_hashes.template.json"
    assert hash_checker.manifest_path() == Path(os.environ["ORBIT_HOME"]) / "tool_hashes.json"
    assert not hasattr(hash_checker, "MANIFEST_PATH")
    assert json.loads(hash_checker.TEMPLATE_PATH.read_text(encoding="utf-8"))["tools"]
    assert cve_map._load(str(cve_map.MAP_PATH))[0], "no controls loaded from the bundled mapping"
    assert cfg.FIXTURES_DIR in (runner.Runner.__init__.__defaults__ or ())


def test_dry_run_fixtures_are_bundled_for_the_tools_that_have_them():
    # monkey365 names a fixture that has never been written; the runner reports "no fixture"
    # for it, so it is not required here.
    bundled = {t.name for t in all_tools() if t.fixture and (cfg.FIXTURES_DIR / t.fixture).is_file()}
    assert {"scubagear", "maester"} <= bundled
    assert {p.name for p in cfg.FIXTURES_DIR.glob("*.json")} == set(FIXTURE_FILES)


def test_repository_level_data_directories_are_gone():
    assert not (REPO / "data").exists()
    assert not (REPO / "tests" / "fixtures").exists()


def test_the_mutable_baseline_is_not_package_owned_state():
    assert not (PACKAGE / "data" / "tool_hashes.json").exists()
    template = json.loads(hash_checker.TEMPLATE_PATH.read_text(encoding="utf-8"))
    assert template["schema"] == 2 and type(template["schema"]) is int
    assert template["kind"] == "orbit.integrity-baseline"
    assert set(template) == {"schema", "kind", "tools"}  # no binding, no generator, no other key
    assert set(template["tools"]) == {t.name for t in all_tools()}
    assert all(entry == {"versions": {}} for entry in template["tools"].values())
    assert hash_checker.manifest_path().parent == Path(os.environ["ORBIT_HOME"])


def test_package_data_declares_every_bundled_file():
    meta = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))
    patterns = meta["tool"]["setuptools"]["package-data"]["orbit"]
    shipped = [p.relative_to(PACKAGE).as_posix() for p in (PACKAGE / "data").rglob("*")
               if p.is_file() and p.suffix == ".json"]
    assert len(shipped) == len(DATA_FILES) + len(FIXTURE_FILES)
    for rel in shipped:
        assert any(fnmatch.fnmatchcase(rel, pattern) for pattern in patterns), rel
    for name in ("cover.txt.j2", "posture.txt.j2"):
        assert (PACKAGE / "reporting" / "templates" / name).is_file()
        assert any(fnmatch.fnmatchcase(f"reporting/templates/{name}", p) for p in patterns)


def test_package_data_is_explicit_and_cannot_ship_an_active_baseline():
    meta = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))
    patterns = meta["tool"]["setuptools"]["package-data"]["orbit"]
    assert not any(any(c in pattern for c in "*?[") for pattern in patterns), patterns
    assert sorted(patterns) == sorted([
        "reporting/templates/cover.txt.j2", "reporting/templates/posture.txt.j2",
        "data/cve_mappings.json", "data/tool_hashes.template.json",
        "data/fixtures/maester_sample.json", "data/fixtures/scubagear_sample.json"])
    for stray in ("data/tool_hashes.json", "data/tool_hashes.json.lock", "data/other.json",
                  "data/fixtures/tool_hashes.json"):
        assert not any(fnmatch.fnmatchcase(stray, pattern) for pattern in patterns), stray


def test_build_backend_floor_supports_the_spdx_license():
    meta = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))
    assert meta["project"]["license"] == "MIT"
    assert "setuptools>=77" in meta["build-system"]["requires"]


def test_resource_dir_refuses_an_archive_import(monkeypatch):
    class ZipLike:
        def __truediv__(self, other):
            return self

    monkeypatch.setattr(cfg.resources, "files", lambda name: ZipLike())
    with pytest.raises(RuntimeError, match="regular filesystem"):
        cfg.resource_dir("data")


def test_dry_run_works_from_a_copy_of_only_the_package(tmp_path):
    """A copy of just ``orbit/`` has no ``data/`` or ``tests/`` beside it, as in a wheel install."""
    site = tmp_path / "site"
    shutil.copytree(PACKAGE, site / "orbit", ignore=shutil.ignore_patterns("__pycache__"))
    assert sorted(p.name for p in site.iterdir()) == ["orbit"]

    def tree():
        return sorted(p.relative_to(site).as_posix() for p in site.rglob("*")
                      if "__pycache__" not in p.parts)

    before = tree()
    home, out, cwd = tmp_path / "home", tmp_path / "out", tmp_path / "cwd"
    for d in (home, out, cwd):
        d.mkdir()
    (home / "config.toml").write_text(f"[output]\ndirectory = '{out}'\nformats = [\"json\"]\n",
                                      encoding="utf-8")
    code = (
        "import json, sys\n"
        f"sys.path.insert(0, {str(site)!r})\n"
        "import orbit.config as c\n"
        "from orbit.core.headless import run_headless\n"
        "payload, code = run_headless(True, [])\n"
        "print(json.dumps({'code': code, 'payload': payload, 'file': c.__file__,\n"
        "                  'data': str(c.DATA_DIR), 'fixtures': str(c.FIXTURES_DIR)}))\n")
    env = {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH", "PYTHONHOME")}
    env["ORBIT_HOME"] = str(home)
    proc = subprocess.run([sys.executable, "-I", "-c", code], cwd=cwd, env=env,
                          capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stderr
    got = json.loads(proc.stdout.strip().splitlines()[-1])
    payload = got["payload"]
    assert got["code"] == 0 and payload["dry_run"] is True
    assert Path(got["file"]).resolve().parent == (site / "orbit").resolve()
    assert got["data"].startswith(str(site)) and got["fixtures"].startswith(str(site))
    assert payload["total_controls"] == 16 and payload["score"] == 50
    assert any(f["cve_ids"] for f in payload["top_findings"])  # packaged CVE mapping resolved
    assert Path(payload["output_dir"]).resolve().is_relative_to(out.resolve())
    assert (home / "history.json").exists()
    assert not (home / "tool_hashes.json").exists()  # a dry-run never creates a baseline
    assert tree() == before  # ORBIT wrote nothing into the installed package


# --- the archive checks that CI runs against the built wheel and sdist ----------------

def _checks():
    import importlib.util
    spec = importlib.util.spec_from_file_location("ci_checks", REPO / "scripts" / "ci_package_checks.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _archives(tmp_path, *, wheel_extra=(), sdist_extra=(), wheel_template=None, sdist_template=None,
              wheel_scripts=None, sdist_scripts=None):
    """A synthetic wheel and sdist with the resources the real ones carry, plus any defects."""
    import io
    import tarfile
    import zipfile

    checks = _checks()
    good = (PACKAGE / "data" / "tool_hashes.template.json").read_bytes()
    scripts = checks.ENTRY_POINTS
    resources_ = {name: (PACKAGE.parent / name).read_bytes() for name in checks.REQUIRED}
    with zipfile.ZipFile(tmp_path / f"orbit_m365-{checks.VERSION}-py3-none-any.whl", "w") as z:
        for name, data in resources_.items():
            z.writestr(name, wheel_template if name == checks.TEMPLATE and wheel_template else data)
        ini = "[console_scripts]\n" + "".join(
            f"{k} = {v}\n" for k, v in (wheel_scripts or scripts).items())
        z.writestr(f"orbit_m365-{checks.VERSION}.dist-info/entry_points.txt", ini)
        for name in wheel_extra:
            z.writestr(name, b"{}")
    pyproject = "[project.scripts]\n" + "".join(
        f'{k} = "{v}"\n' for k, v in (sdist_scripts or scripts).items()) + "\n[tool.other]\nx = 1\n"
    root = f"orbit_m365-{checks.VERSION}"
    with tarfile.open(tmp_path / f"{root}.tar.gz", "w:gz") as t:
        files = {name: (sdist_template if name == checks.TEMPLATE and sdist_template else data)
                 for name, data in resources_.items()}
        files["pyproject.toml"] = pyproject.encode()
        files.update({name: b"{}" for name in sdist_extra})
        for name, data in files.items():
            info = tarfile.TarInfo(f"{root}/{name}")
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))
    return checks, good


def test_archive_checks_accept_a_wheel_and_sdist_with_the_empty_template(tmp_path, capsys):
    checks, _ = _archives(tmp_path)
    checks.contents(tmp_path)
    out = capsys.readouterr().out
    assert "wheel:" in out and "sdist:" in out and "schema-2 empty unbound template" in out


def _nonempty(tools_entry):
    template = json.loads((PACKAGE / "data" / "tool_hashes.template.json").read_text())
    template["tools"]["maester"] = tools_entry
    return json.dumps(template).encode()


@pytest.mark.parametrize("where", ["wheel", "sdist"])
@pytest.mark.parametrize("entry", [{"versions": {"1.2.3": {"files": {"a": "00"}}}},
                                   {"versions": {}, "extra": 1}, {}])
def test_a_non_empty_template_is_caught_in_either_archive_alone(tmp_path, where, entry):
    checks, _ = _archives(tmp_path, **{f"{where}_template": _nonempty(entry)})
    with pytest.raises(AssertionError, match=f"{where}: template"):
        checks.contents(tmp_path)


def _template_with(**changes):
    template = json.loads((PACKAGE / "data" / "tool_hashes.template.json").read_text())
    for key, value in changes.items():
        if value is ...:
            template.pop(key)
        else:
            template[key] = value
    return json.dumps(template).encode()


_BINDING = {"os": "posix", "principal": "a" * 64, "machine": None}


@pytest.mark.parametrize("where", ["wheel", "sdist"])
@pytest.mark.parametrize("changes", [
    {"schema": 1}, {"schema": True}, {"schema": 2.0}, {"schema": "2"}, {"schema": 3}, {"schema": ...},
    {"kind": "orbit.other"}, {"kind": ...}, {"binding": _BINDING}, {"generator": {"orbit": "1"}},
    {"binding": _BINDING, "generator": {"orbit": "1"}}, {"_note": "text"}, {"extra": 1},
])
def test_a_template_that_is_not_the_exact_unbound_schema_2_seed_is_caught_in_either_archive_alone(
        tmp_path, where, changes):
    checks, _ = _archives(tmp_path, **{f"{where}_template": _template_with(**changes)})
    with pytest.raises(AssertionError, match=f"{where}: template"):
        checks.contents(tmp_path)


def test_the_raw_shipped_template_is_unbound_and_is_refused_as_an_active_baseline():
    from orbit.core import baseline_schema as schema
    raw = (PACKAGE / "data" / "tool_hashes.template.json").read_bytes()
    document = json.loads(raw)
    assert "binding" not in document and "generator" not in document
    with pytest.raises(schema.BaselineError) as refused:
        schema.parse_baseline(raw, schema.current_binding())
    assert refused.value.code is schema.ErrorCode.BINDING_MISSING


@pytest.mark.parametrize("name", ["orbit/data/tool_hashes.json", "tool_hashes.json",
                                  "orbit/data/tool_hashes.json.lock", "x/y/tool_hashes.json"])
@pytest.mark.parametrize("where", ["wheel", "sdist"])
def test_an_active_baseline_anywhere_in_either_archive_is_rejected(tmp_path, where, name):
    checks, _ = _archives(tmp_path, **{f"{where}_extra": [name]})
    with pytest.raises(AssertionError, match=f"{where} carries a baseline"):
        checks.contents(tmp_path)


@pytest.mark.parametrize("where", ["wheel", "sdist"])
def test_a_missing_or_wrong_entry_point_is_rejected(tmp_path, where):
    bad = {"orbit": "orbit.cli:main", "orbit-generate-hashes": "scripts.generate_hashes:cli"}
    checks, _ = _archives(tmp_path, **{f"{where}_scripts": bad})
    with pytest.raises(AssertionError, match=f"{where} declares orbit-generate-hashes"):
        checks.contents(tmp_path)
    for old in tmp_path.iterdir():
        old.unlink()
    checks, _ = _archives(tmp_path, **{f"{where}_scripts": {"orbit": "orbit.cli:main"}})
    with pytest.raises(AssertionError, match="orbit-generate-hashes"):
        checks.contents(tmp_path)


def test_the_template_check_accepts_exactly_the_shipped_template():
    checks = _checks()
    checks._check_template("wheel", (PACKAGE / "data" / "tool_hashes.template.json").read_bytes())
    assert checks.TOOLS == {t.name for t in all_tools()}

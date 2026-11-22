"""The CI package job proves what it claims: a generated final report, recorded attempts, and
the per-user baseline. Static checks of the workflow and its script; the guard runs in a child.
"""
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CI = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
CHECKS = (ROOT / "scripts/ci_package_checks.py").read_text(encoding="utf-8")
# the Linux jobs and the separate native Windows job, so each is judged on its own text
LINUX, _WINDOWS_TAIL = CI.split("  # Native Windows validation", 1)
WINDOWS = "  # Native Windows validation" + _WINDOWS_TAIL
WINDOWS_TESTS = (ROOT / "tests/test_windows_native.py").read_text(encoding="utf-8")


def test_dry_run_enables_final_reports_not_only_json():
    assert 'formats = [\\"pdf\\", \\"docx\\"]' in CI
    assert '"json"' not in CI.split("printf", 1)[1].split("\n", 1)[0]


def test_the_job_asserts_the_specific_generated_report_exists():
    assert 'folder.glob(f"ORBIT_Summary_DRYRUN_*.{ext}")' in CHECKS
    assert "len(found) == 1" in CHECKS
    assert 'data.startswith(b"%PDF-")' in CHECKS and "word/document.xml" in CHECKS
    # raw fixture JSON is no evidence of a report
    assert 'rglob("*.json")' not in CHECKS and 'rglob("*.json")' not in CI
    assert "ci_package_checks.py\" smoke" in CI


def _in_child(code: str, *args: str):
    """Run code in a throwaway interpreter that has loaded the CI script as ``checks``."""
    prologue = (
        "import importlib.util, json, sys\n"
        "spec = importlib.util.spec_from_file_location('checks', sys.argv[1])\n"
        "checks = importlib.util.module_from_spec(spec); spec.loader.exec_module(checks)\n")
    proc = subprocess.run([sys.executable, "-I", "-c", prologue + code,
                           str(ROOT / "scripts/ci_package_checks.py"), *args],
                          capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    return proc.stdout.strip()


def test_the_guard_records_attempts_and_the_job_asserts_none():
    assert "attempts.append" in CHECKS
    assert CHECKS.count("assert attempts == []") >= 2  # dry-run and baseline phases
    assert "guard recorded attempts: []" in CHECKS
    # the record is made before the error is raised
    blocked = CHECKS.split("def blocked(", 1)[1].split("return blocked", 1)[0]
    assert blocked.index("attempts.append") < blocked.index("raise RuntimeError")


def test_the_guard_leaves_a_trace_even_when_the_error_is_swallowed():
    code = (
        "attempts = checks.install_guard()\n"
        "assert attempts == []\n"
        "import subprocess, socket\n"
        "try:\n    subprocess.Popen(['true'])\nexcept Exception:\n    pass\n"
        "try:\n    socket.getaddrinfo('example.invalid', 80)\nexcept Exception:\n    pass\n"
        "print(attempts)\n")
    assert _in_child(code) == "['subprocess.Popen', 'socket.getaddrinfo']"


def test_the_guard_records_every_blocked_entry_point_and_runs_none_of_them():
    """Calls the replacements (never the originals) and checks each left exactly one trace."""
    code = (
        "attempts = checks.install_guard()\n"
        "expected = []\n"
        "for owner, names in checks.guard_targets():\n"
        "    for name in names:\n"
        "        if hasattr(owner, name):\n"
        "            expected.append(checks._label(owner, name))\n"
        "            try:\n"
        "                getattr(owner, name)()\n"
        "            except RuntimeError as exc:\n"
        "                assert str(exc) == 'blocked: ' + expected[-1], exc\n"
        "            else:\n"
        "                raise SystemExit('not blocked: ' + expected[-1])\n"
        "assert attempts == expected, (attempts, expected)\n"
        "print(json.dumps(attempts))\n")
    recorded = set(__import__("json").loads(_in_child(code)))
    for must in ("os.spawnve", "os.spawnvp", "os.spawnvpe", "os.spawnl", "os.spawnle", "os.execve",
                 "os.posix_spawn", "os.fork", "os.system", "os.popen", "subprocess.Popen",
                 "subprocess.getoutput", "socket.socket.connect", "socket.socket.sendmsg",
                 "socket.socket.sendto", "socket.socket.connect_ex", "socket.create_connection",
                 "socket.getaddrinfo", "asyncio.create_subprocess_exec", "smtplib.SMTP.connect",
                 "urllib.request.urlopen", "http.client.HTTPConnection.connect",
                 "asyncio.base_events.BaseEventLoop.subprocess_exec"):
        assert must in recorded, must


def test_the_reviewer_examples_are_blocked_through_their_real_signatures():
    code = (
        "attempts = checks.install_guard()\n"
        "import os, socket\n"
        "try:\n    os.spawnve(os.P_NOWAIT, '/nonexistent/program', ['program'], {})\n"
        "except Exception:\n    pass\n"
        "sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
        "try:\n    sock.sendmsg([b'x'], [], 0, ('192.0.2.1', 9))\nexcept Exception:\n    pass\n"
        "sock.close()\n"
        "print(attempts)\n")
    assert _in_child(code) == "['os.spawnve', 'socket.socket.sendmsg']"


def test_the_accepted_dry_run_runs_under_the_guard_through_the_installed_entry_point():
    smoke = CHECKS.split("def smoke(", 1)[1].split("\ndef ", 1)[0]
    assert smoke.index("install_guard()") < smoke.index('main(["--dry-run", "--headless", "--json"])')
    assert 'entry_points(group="console_scripts")' in smoke and 'e.name == "orbit"' in smoke
    assert "from orbit.cli import" not in smoke and "unguarded" not in smoke
    assert "result.json" not in smoke and "result.json" not in CI
    # the workflow itself no longer runs an earlier, unguarded dry-run to rely on
    assert "--dry-run" not in CI and "--headless" not in CI
    assert LINUX.count('ci_package_checks.py" smoke') == 1


def test_the_job_keeps_execution_isolated_and_outside_the_checkout():
    assert 'cd "$work/cwd"   # outside the checkout' in CI
    assert 'export ORBIT_HOME="$work/home"' in CI
    assert "unset PYTHONPATH PYTHONHOME" in CI
    assert "-I" in LINUX and "ubuntu-latest" in LINUX
    assert "windows" not in LINUX.lower() and "macos" not in LINUX


def test_the_job_checks_the_baseline_command_template_and_no_shipped_baseline():
    assert "baseline-home" in CHECKS and "tool_hashes.template.json" in CHECKS
    assert "no baseline shipped" in CHECKS and '"tool_hashes.json"' in CHECKS
    assert '"orbit-generate-hashes": "orbit.core.baseline:cli"' in CHECKS
    assert "NO_BASELINE" in CHECKS and "the packaged template changed" in CHECKS
    assert 'PATH="$work/empty-path"' in CI and "No tools found" in CI
    assert "tool_hashes.json\"," not in CHECKS.split("REQUIRED = [", 1)[1].split("]", 1)[0]


# --- the native Windows job (defined here; not run until a hosted Actions run is approved) ---

def _steps() -> list[str]:
    return WINDOWS.split("      - name: ")[1:]


def test_the_linux_jobs_and_matrix_are_preserved():
    for job in ("  test:", "  lint:", "  package:"):
        assert job in LINUX
    assert 'python-version: ["3.10", "3.11", "3.12", "3.13"]' in LINUX
    assert CI.count("runs-on: windows-latest") == 1 and "ubuntu-latest" in LINUX


def test_the_windows_job_is_separate_native_python_312_with_explicit_pwsh():
    assert "\n  windows-validation:\n" in CI and "runs-on: windows-latest" in WINDOWS
    assert "name: Windows release validation" in WINDOWS
    assert 'python-version: "3.12"' in WINDOWS and "shell: pwsh" in WINDOWS
    assert "needs:" not in WINDOWS and "download-artifact" not in WINDOWS  # builds its own wheel
    assert "python -m build --outdir $dist ." in WINDOWS
    assert "$env:RUNNER_TEMP" in WINDOWS


def test_the_windows_job_has_no_secrets_tenant_tools_or_remote_writes():
    lowered = WINDOWS.lower()
    for forbidden in ("secrets.", "tenant", "client_secret", "smtp", "upload-artifact",
                      "download-artifact", "pypi", "twine", "gh release", "gh pr", "git push",
                      "deploy", "environment:", "id-token", "contents: write", "install-module",
                      "curl", "invoke-webrequest", "invoke-restmethod", "winget", "choco",
                      "monkey365", "--live"):
        assert forbidden not in lowered, forbidden
    assert "contents: read" in WINDOWS
    # the only ORBIT dry-run is the guarded one inside the check script
    assert "--dry-run" not in WINDOWS and WINDOWS.count('ci_package_checks.py" smoke') == 1


def test_the_windows_scratch_is_under_the_user_profile_not_runner_temp():
    assert '$work = Join-Path $env:USERPROFILE "orbit-win-validation' in WINDOWS
    assert "ORBIT_WIN_WORK=$work" in WINDOWS
    assert "$work = Join-Path $env:RUNNER_TEMP" not in WINDOWS
    assert '$env:ORBIT_HOME = Join-Path $work "home"' in WINDOWS
    assert "scratch is outside the user profile" in WINDOWS
    # the checks themselves also refuse a misplaced scratch directory
    assert "def require_profile_scratch" in CHECKS and "require_profile_scratch(work)" in CHECKS


def test_the_windows_job_installs_the_fresh_wheel_alone_outside_the_checkout():
    assert 'python -m venv (Join-Path $work "venv")' in WINDOWS
    assert 'Get-ChildItem -LiteralPath $dist -Filter "orbit_m365-1.5.1-*.whl"' in WINDOWS
    assert "$wheels.Count -ne 1" in WINDOWS and "--no-cache-dir" in WINDOWS
    assert 'Set-Location (Join-Path $work "cwd")' in WINDOWS
    assert "Remove-Item Env:PYTHONPATH, Env:PYTHONHOME" in WINDOWS
    assert "*\\site-packages\\orbit\\config.py" in WINDOWS
    assert "orbit was imported from the checkout" in WINDOWS
    assert '--version' in WINDOWS and 'EndsWith(" 1.5.1")' in WINDOWS
    assert "scripts\\ci_package_checks.py contents $dist" in WINDOWS


def test_every_windows_check_runs_and_a_failed_native_command_fails_the_job():
    for command in ("smoke", "baseline", "identity", "seeded", "junit", "contents"):
        assert re.search(rf'ci_package_checks\.py"? {command}\b', WINDOWS), command
    for step in _steps():
        natives = step.count("& $py") + step.count("python -") + step.count("& (Join-Path")
        assert natives == 0 or "$LASTEXITCODE" in step, step.split("\n", 1)[0]
    assert WINDOWS.count("if: always()") == 1  # only the scratch cleanup


def test_windows_only_tests_are_mandatory_and_not_skippable_in_the_windows_job():
    assert "tests/test_windows_native.py" in WINDOWS and "--junitxml" in WINDOWS
    assert "junit $report 8" in WINDOWS
    assert WINDOWS_TESTS.count("\ndef test_") + 3 >= 8  # the refused-baseline test has 4 cases
    junit = CHECKS.split("def junit(", 1)[1].split("\ndef ", 1)[0]
    assert 'totals["skipped"] == 0' in junit and 'totals["tests"] >= minimum' in junit


def test_windows_native_tests_are_explicitly_skipped_off_windows():
    assert 'sys.platform != "win32"' in WINDOWS_TESTS and "pytest.mark.skipif" in WINDOWS_TESTS
    assert "native Windows only" in WINDOWS_TESTS and "pytest.mark.windows_native" in WINDOWS_TESTS
    assert "windows_native" in (ROOT / "pyproject.toml").read_text(encoding="utf-8")


def test_the_windows_validation_covers_each_required_behaviour():
    # native identity, compared with the binding, without printing raw identifiers
    assert "def identity(" in CHECKS and "_windows_token_sid()" in CHECKS
    assert "_windows_machine_guid()" in CHECKS and "identifiers not printed" in CHECKS
    # refused baselines: template, schema 1, malformed and mismatched; bytes unchanged
    for label in ('"template"', '"schema-1"', '"malformed"', '"mismatched"'):
        assert label in CHECKS and label in WINDOWS_TESTS
    assert "a refused file was changed" in CHECKS
    assert "BINDING_MISMATCH" in CHECKS and "NOT_JSON" in CHECKS
    # generated binding equals current_binding(); no dry-run baseline; no-tools baseline is bound
    assert 'document["binding"] == schema.current_binding().to_json()' in CHECKS
    assert "a dry-run must not create a baseline" in CHECKS
    seeded = CHECKS.split("def seeded(", 1)[1].split("\ndef ", 1)[0]
    assert "current_binding" in seeded and '{"versions": {}}' in seeded
    assert "orbit-generate-hashes.exe" in WINDOWS and "No tools found" in WINDOWS
    assert "$code -ne 1" in WINDOWS
    # PDF and DOCX through the guarded smoke, with a UTF-8 config without a BOM
    assert '`"pdf`", `"docx`"' in WINDOWS and "UTF8Encoding($false)" in WINDOWS


def test_the_guard_exempts_only_the_in_process_socketpair_on_windows():
    assert "allow_socketpair" in CHECKS and 'sys.platform == "win32"' in CHECKS
    code = (
        "import socket\n"
        "attempts = checks.install_guard(allow_socketpair=True)\n"
        "a, b = socket.socketpair(); a.close(); b.close()\n"
        "assert attempts == [], attempts\n"
        "s = socket.socket()\n"
        "for call in (lambda: s.bind(('127.0.0.1', 0)), lambda: s.listen(),\n"
        "             lambda: s.connect(('127.0.0.1', 9))):\n"
        "    try:\n        call()\n    except RuntimeError:\n        pass\n"
        "s.close()\n"
        "print(attempts)\n")
    assert _in_child(code) == ("['socket.socket.bind', 'socket.socket.listen', "
                               "'socket.socket.connect']")


def test_every_windows_installed_python_validation_is_utf8_and_isolated():
    invocations = [line for line in WINDOWS.splitlines()
                   if re.search(r"(python|\$py) .*(-I\b|ci_package_checks)", line)
                   and "-m pip" not in line]
    assert invocations
    for line in invocations:
        assert "-X utf8 -I" in line, line
    baseline = [line for line in WINDOWS.splitlines()
                if re.search(r'ci_package_checks\.py" baseline\b', line)]
    assert len(baseline) == 1 and "-X utf8 -I" in baseline[0]

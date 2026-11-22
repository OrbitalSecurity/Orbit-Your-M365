# ORBIT M365 — Security & Functional Audit Report

**Date:** 2026-11-01  
**Version audited:** v1.4.0 (commit `9c9ae34`)  
**Test baseline:** 77/77 passing  
**Method:** Static code review (two independent auditors) + manual verification  
**Scope:** All Python source, dependency manifest, data files, test suite  

---

## Remediation Status (2026-11-22, working tree on `4c5c0d8`, uncommitted)

This section supersedes the original findings below, which are kept as written for the record.

- **Fixed**: changed, with regression tests.
- **False positive**: the claim was tested and does not hold.
- **Verified, deferred**: reproduced or confirmed in source, and not changed.
- **Unverified, deferred**: not reproduced, and not changed.

"Fixed" means tested on macOS with Python 3.12 and fake tools (through the second pass the suite was also run on 3.11 from cached packages with two import shims; the third and fourth passes ran it on 3.12 only; 3.10 was not run). No real PowerShell, Windows or Linux host, third-party tool, SMTP server or tenant was exercised. Windows-specific rules were tested only through helpers and mocks on macOS.

Four remediation passes were made. R17 to R23, and the rows marked "(second pass)", come from the second, which followed an independent review of the first. R24 to R30 come from the third pass. R31 onward come from the fourth, bounded pass, which followed a further independent review. A later pass supersedes earlier rows where they differ.

| ID | Status | Evidence / note |
|----|--------|-----------------|
| C1 | **False positive as written; related issues fixed** (second pass) | `extractall()` did not escape through `..` or absolute names on Python 3.9, 3.11, 3.12 or 3.15. It did write through a symlink already present in the output directory. Extraction now creates each file itself in a new private directory, refuses hostile Windows and POSIX names, colliding names and link or special entries, and never enters or replaces anything already present (completed by R24 and R25). The suggested `filter="data"` argument belongs to `tarfile`; `zipfile` has no such parameter. |
| C2 | **Fixed** | Only an explicit OK launches. UNVERIFIED, MISMATCH and empty results block in TUI and headless (which previously did no check at all). The override is removed. The manifest still ships empty, so real runs are blocked until a baseline is recorded. |
| C3 | **False positive** | Jinja does not evaluate template syntax inside ordinary string values. The original `finding.txt.j2` from `9c9ae34`, rendered with `{{ 1234*4321 }}` as a value, printed it literally. See `test_ssti_not_evaluated` and `test_template_syntax_in_values_is_not_evaluated`. |
| H1 | Verified, deferred | The script always passes a thumbprint and never the client secret. |
| H2 | Verified, deferred | Malformed JSON raises `JSONDecodeError` out of `parse_folder`. |
| H3 | Verified, deferred | Source confirms a local effective-UID check, not an M365 role check. |
| H4 | **Fixed** | Login is refused without TLS, and a failed STARTTLS never logs in. Unauthenticated plaintext relays and private/on-prem hosts remain supported. |
| M1 | Verified, deferred | An imported profile set the output directory to `/etc/x`. |
| M2 | Partly false positive; rest deferred | `keyring` already requires SecretStorage on Linux and `uv.lock` includes it. The passphrase-less file-store `PermissionError` is real. |
| M3 | Verified, deferred | `roadrecon` is not declared. A missing install, or a missing unconditional dependency of it, blocks as UNVERIFIED. |
| M4 | Partly false positive; rest deferred | `uv.lock` pins packages with hashes. CI installs with pip and does not use it. |
| M5 | Unverified, deferred | Needs a real ROADtools install. The code runs `auth` then `gather`, not `gather` then `dump` as quoted. |
| M6 | **Fixed** | Per-tool discovery replaces the stub. PowerShell discovery is tested only against a fake `pwsh`; ROADtools discovery reads package metadata and starts no process. |
| L1 | Verified, deferred | `history.json` is created `0644` under umask 022. |
| L2 | Verified, deferred | AES-256 is still claimed in README, help, PRIVACY and index.html. |
| L3 | Verified, deferred | `os_notify = "evil"` imports. The quoted `smtp_port` example does not, because the email section is not imported. |
| L4 | Verified, deferred | No Hawk parser. `docs/TOOLS.md` documents this; the UI does not. |
| L5 | Verified, deferred | `run_capture` still swallows errors. Integrity discovery no longer uses it. |
| L6 | Verified, deferred | Dead branch still present. |

### Found during remediation

| ID | Status | Issue |
|----|--------|-------|
| R1 | **Fixed** (second pass) | Launch imported modules by name, and later by a mutable path. It now imports only from a private read-only snapshot of the verified bytes, re-checked immediately before process creation. |
| R2 | **Fixed** (second pass) | ROADtools could be shadowed, and `-I` still ran `.pth` and `sitecustomize` code. It now runs on the base interpreter with `-I -S -B`, importing only a verified snapshot of the package and its dependency closure. |
| R3 | **Fixed** (second pass) | "Install OPA" executed ScubaGear code without the integrity gate. It now uses the same snapshot and pinned PowerShell as a run. |
| R4 | **Fixed** | Unexpected files and linked directories were invisible to the check. |
| R5 | **Fixed** | The baseline script silently re-blessed changed files and looked for ROADtools in the wrong directory. |
| R6 | **Fixed** (second pass) | Runs in the same minute shared a folder and could overwrite an earlier encrypted archive. Archives are now created exclusively, including under concurrent packaging. |
| R7 | **Fixed** | A fully blocked run would have produced a 0-score report, history record and email. |
| R8 | **Fixed** | Executive-summary client names could create path components outside the output directory. |
| R9 | **Fixed** (second pass) | Children inherited the whole parent environment. They now get an allowlist, without relative `PATH` entries. pip alone also gets named index, mirror and offline settings. |
| R10 | **Superseded by R30** (second pass) | ROADtools wrote its token file into the report folder. Real runs are now disabled. In the retained, unreachable launcher, tokens go to a private temporary directory that the child and ORBIT both remove, and are also purged from output, excluded from archives and redacted from logs. Tested with synthetic tokens and a fake roadrecon. |
| R11 | **Fixed** (second pass) | The cached Run screen now follows the selection. The set shown is the set executed and recorded, and only created processes are reported as used. |
| R12 | Verified, deferred (Medium) | Textual markup is not escaped on the Report screen. A probe confirmed that such markup in a `Static` can trigger app actions when clicked, and finding titles come from tool output. |
| R13 | Partly fixed; rest deferred (Medium) | Dry-run no longer makes the update check. A real run still calls GitHub by default, contradicting `AGENTS.md`, the README and SECURITY.md. |
| R14 | Verified, deferred (Low) | "Install all" starts only one of five installs (exclusive worker). |
| R15 | Verified, deferred (Low) | `launch.py:25` uses `shell=True` with constant arguments, so the "no `shell=True` anywhere" statement below is inaccurate. |
| R16 | Verified, deferred (Low) | `tests/test_config_store.py` imports `tomllib`, which does not exist on Python 3.10, a version in the CI matrix. |
| R17 | **Fixed** | PowerShell was looked up again by bare name at launch. One absolute path is now resolved at discovery, carried through launch and OPA set-up, and re-hashed before use. Relative and ambiguous paths block. |
| R18 | **Fixed** | Dry-run probed the keychain, PowerShell and installations, and could send email, notify or install. Each of these boundaries has a trip-wire test. |
| R19 | **Fixed** | The manifest was updated without a lock and written in place. The read, compare and update is now locked and atomically replaced. |
| R20 | **Fixed** | A tool counted as launched before its process existed, and unexpected task exceptions were swallowed. |
| R21 | **Fixed** | Pre-flight showed green if any manifest entry existed. It now runs the launch gate for each selected tool and version. |
| R22 | **Fixed** | Encrypted packaging followed symlinks and could copy files from outside the run folder into the archive. |
| R23 | Unverified, deferred (Medium); unreachable while R30 applies | The ROADtools child has block-buffered stdout on a pipe, so a device-code prompt may not appear until the process exits. This predates both passes and needs a real install to confirm. |
| R24 | **Fixed** (third pass) | A linked ancestor of the extraction destination redirected every write. The path is now walked from the root without following links, junctions or other reparse points, and missing components are created privately. |
| R25 | **Fixed** (third pass) | Publishing a directory could replace an empty one created after the check. It now uses the kernel's non-replacing rename, and refuses the member where there is none. |
| R26 | **Fixed** (third pass) | Renamed archive members could collide with user content, so ORBIT refused members of its own archives. They now get a reserved top-level directory. |
| R27 | **Fixed** (third pass) | pip diagnostics could show credentials from configuration files, query strings and certificate settings. pip output is discarded; only the operation and exit code are shown. |
| R28 | **Fixed** (third pass) | A run in which nothing started was offered to Report as a zero-control result. Results are published, and recorded in history, only after finalisation succeeds. |
| R29 | **Fixed** (third pass) | Pre-flight said ready without the pre-launch re-check. It now runs the same one. It is still advisory: launch checks again. |
| R30 | **Disabled by decision** (third pass) | **ROADtools production execution is disabled** pending a memory-only or other non-plaintext authentication design. Real runs block before credential access or process creation, and install and update are disabled. Fixture-only dry-run still works. |
| R31 | **Fixed by failing closed** (fourth pass) | On Windows, extraction checked the destination chain and then used a pathname, so an ancestor replaced by a junction in between redirected creation or rename. The pathname route is removed. **Extraction is unsupported on Windows** and refuses before any file-system operation on the destination. |
| R32 | **Fixed** (fourth pass) | PowerShell installer output and exception text could show repository credentials that redaction cannot know. All installer and OPA set-up children are now status-only, get no terminal and cannot prompt. `Find-Module` output is accepted only as a bare version. |
| R33 | **Fixed** (fourth pass) | A headless run that launched nothing still printed a zero score, counts and an output path. Those keys are now absent; diagnostics and exit code 1 remain. |
| R34 | **Fixed** (fourth pass) | The executable re-check compared content only, so pre-flight stayed green after execute permission was removed. It now repeats the ordinary-file check and, except on Windows, the execute-permission check. |
| R35 | **Fixed** (fourth pass) | TOOLS, PRIVACY and index.html still advertised ROADtools launch and install. They now state the decision in R30. |

### Threat model of the integrity gate

The gate protects against accidental changes and unauthorised modification by other OS principals, provided they cannot write to ORBIT, its Python environment or the manifest (root and administrators always can). Local, user-owned integrity data cannot defend against a malicious process running as the same OS user: that process can alter the manifest and the runtime files. A match is not proof of authenticity or provenance. Claiming more would need privilege separation or an external signed trust anchor. The final binding re-check is defence in depth, not a boundary against the same user.

### Limits of the integrity gate

- The baseline is trust-on-first-use, and the manifest is writable by the user who runs ORBIT.
- Another process running as the same user can undo the snapshot's read-only modes. The re-check catches changes made before process creation, not after it. By the decision above, this will not be chased further.
- PowerShell dependencies (Pester, Microsoft.Graph, ExchangeOnlineManagement and the like) are still loaded, unverified, from `PSModulePath`. So are OPA and anything else a tool starts for itself.
- `pwsh`, Python and its standard library are trusted as installed. The executable is pinned for one run, not compared with a baseline.
- ORBIT's own process runs normal Python start-up. A hostile `.pth` in ORBIT's environment runs when ORBIT starts, before any check, and ROADtools shares that environment.
- A snapshot copies file content only. ACLs, macOS quarantine attributes and Windows alternate data streams are not carried over. Files with Mark-of-the-Web, which `RemoteSigned` relies on, are therefore blocked (tested with a mock on macOS).
- `SIGKILL`, power loss or a Windows hard kill can leave a private `orbit-*` directory, possibly holding a token, in the temporary directory.
- Token detection by content covers the ROADtools folder only and skips database files. Token caches that tools keep in the user's home directory are outside ORBIT's control.

### Limits of extraction and installer containment

- Extraction does not work on Windows (R31). Python has no descriptor-relative calls there; supporting it needs a native handle-based implementation, validated on Windows. The refusal was tested only by simulation on macOS.
- The Linux non-replacing rename (`renameat2`) was tested only for symbol and flag selection with a mock. It has not been run.
- Extraction refuses any linked or reparse ancestor, including macOS `/tmp` and `/var`, linked home directories and OneDrive folders: pass a physical path.
- On a file system without a non-replacing rename, archived directories are refused and reported. Without hard links, a file is created exclusively and is briefly visible while incomplete.
- Publication is atomic for each top-level entry, not for the whole archive.
- Installer children are status-only (R32), but ORBIT cannot control what PowerShell transcription, script-block logging or a credential provider records for itself. Output from a tool during a run is still streamed with only known secrets redacted. The no-console flag and the non-interactive installers were not run with Windows or real PowerShell.
- A `report` option in the user's own pip configuration can still make pip write a file. ORBIT overrides its `log` and cache options only.
- The `log` override is the null device. pip was run with it on macOS only. If pip on Windows cannot open `nul` as a log, Remove will fail with an exit code rather than log.

### Paths that block because they could not be made safe without real validation

- More than one distinct `pwsh` on `PATH`, a relative `PATH` entry containing one, a launcher that resolves to another program (for example snap), and probably Microsoft Store aliases.
- A temporary directory writable by other users or, on Windows, outside the user profile.
- Every real ROADtools run (R30).
- Every archive extraction on Windows (R31).
- On Windows, any installed file that still carries Mark-of-the-Web.

Not validated with real tools: whether each tool works from a relocated read-only directory, on a `noexec` temporary file system, under AppLocker or WDAC, or with Windows long paths.

---

## Executive Summary

ORBIT is well-structured for a v1.x tool. The secret handling, subprocess architecture, PBKDF2 parameters, and TLS defaults are competently implemented. However, **three security vulnerabilities need fixing before this is used in a professional engagement**, and **one core feature (tool integrity) ships in a permanently non-functional state** that actively misleads users. Several functional bugs mean some advertised capabilities silently do nothing.

---

## Severity Ratings

| ID | Severity | Title | File:Line |
|----|----------|-------|-----------|
| C1 | 🔴 Critical | ZIP Slip in `decrypt_archive` — arbitrary file write | `encryption.py:66` |
| C2 | 🔴 Critical | Hash manifest empty — integrity gate never fires | `data/tool_hashes.json:5-9` |
| C3 | 🔴 Critical | Jinja2 SSTI via tool output in DOCX generation | `docx_report.py:14,56` + `finding.txt.j2` |
| H1 | 🟠 High | ScubaGear `client_secret` auth path silently broken | `scubagear.py:18-23` |
| H2 | 🟠 High | Parser crashes abort entire report on malformed JSON | `parser.py:152-164` |
| H3 | 🟠 High | `is_elevated()` checks local OS privilege, not M365 role | `admin_check.py:11-18` |
| H4 | 🟠 High | SMTP credential sent cleartext when TLS disabled | `emailer.py:112-124` |
| M1 | 🟡 Medium | Profile import can redirect output path to any directory | `profile.py:36-40` |
| M2 | 🟡 Medium | `secretstorage` missing from deps; Linux keyring silently fails | `pyproject.toml` |
| M3 | 🟡 Medium | `roadrecon` not declared as a dependency | `pyproject.toml` |
| M4 | 🟡 Medium | No pinned dependency versions / no lockfile | `pyproject.toml` |
| M5 | 🟡 Medium | ROADtools `sys.argv` manipulation is fragile | `roadtools.py:17-27` |
| M6 | 🟡 Medium | `install_dir()` always returns `None`; hash check has second layer of non-function | `base.py:91-93` |
| L1 | 🔵 Low | `history.json` written without `chmod(0o600)` | `history.py:50` |
| L2 | 🔵 Low | README/docs claim AES-256; Fernet is AES-128-CBC | `encryption.py` |
| L3 | 🔵 Low | Profile import accepts wrong-typed values | `profile.py:38-40` |
| L4 | 🔵 Low | Hawk runs and produces no parsed findings (undocumented) | `hawk.py`, `parser.py` |
| L5 | 🔵 Low | `run_capture` swallows all exceptions silently | `tools/base.py:42-46` |
| L6 | 🔵 Low | Dead code block in PDF generator | `pdf_report.py:145-146` |

---

## Critical Findings

### C1 — ZIP Slip: `decrypt_archive` allows arbitrary file write

> **2026-11-22: false positive as written; related symlink issue fixed. See Remediation Status.**
**`orbit/security/encryption.py:66-67`** — **Confirmed**

```python
with zipfile.ZipFile(io.BytesIO(data)) as zf:
    zf.extractall(out_dir)   # no path sanitisation
```

`zipfile.extractall()` on Python 3.10 and 3.11 (both targeted by `requires-python = ">=3.10"`) does not strip `..` components or absolute paths from ZIP entry names. A crafted `.orbit.zip` archive with entries like `../../../../root/.ssh/authorized_keys` writes outside `out_dir` with the permissions of the running process.

Python 3.12 added a `filter=` parameter but this code doesn't use it and must support 3.10/3.11.

**Fix:** Filter every member before extraction:
```python
import os
for member in zf.infolist():
    name = member.filename.replace("\\", "/")
    if os.path.isabs(name) or ".." in name.split("/"):
        continue
    zf.extract(member, out_dir)
```
Or, targeting Python ≥3.12 only: `zf.extractall(out_dir, filter="data")`.

**Zero test coverage** for this path.

---

### C2 — Hash manifest empty: integrity gate is entirely non-functional
**`data/tool_hashes.json:5-9`**, **`hash_checker.py:30-31, 81`** — **Confirmed**

Every tool entry is `{"versions": {}}`. `check_tool()` returns `HashStatus.UNVERIFIED` for every tool. `UNVERIFIED` does not block execution (`blocks_run` is `False`). `gate_run()` always returns `(True, "")`.

Additionally, `install_dir()` at `base.py:91-93` is unimplemented and always returns `None` — which is a second independent path to `UNVERIFIED` (line 66 of `hash_checker.py`). Even if the manifest were populated, the check would still not run.

The UI presents this as an active security gate. It is not. Any tampered or trojaned PowerShell module passes silently.

**Fix (minimum):** Add a preflight warning when every tool version entry is empty. Display "Integrity: NOT CONFIGURED" in the preflight screen instead of implying a check occurred. Longer-term: populate the manifest and implement `install_dir()` per tool.

---

### C3 — Jinja2 SSTI via tool output in DOCX report

> **2026-11-22: false positive. See Remediation Status.**
**`docx_report.py:14`, `finding.txt.j2`** — **Confirmed**

```python
_env = Environment(loader=..., undefined=StrictUndefined, autoescape=False)
# ...
render("finding.txt.j2", f=f, cve_text=ctx.cve_text(f))
```

`finding.txt.j2`:
```
Source tool: {{ f.tool }}
Control ID: {{ f.control_id }}
```

`f.control_id` is sourced directly from tool output JSON (`parser.py:53: cid = c.get("Control ID", "")`). With `autoescape=False`, if a crafted tool output contains `{{ ''.__class__.__mro__[1].__subclasses__() }}` in a Control ID field, Jinja2 evaluates it as a Python expression in the context of the running ORBIT process. This is standard Jinja2 SSTI and allows arbitrary code execution.

`StrictUndefined` blocks undefined *variable names* — it does not prevent expression evaluation.

**Fix:** Either use `jinja2.sandbox.SandboxedEnvironment` (simplest), or render finding fields as string literals rather than Jinja2 expressions — pass pre-formatted strings to the template and use `{{ value | e }}` with `autoescape=True`. The template is simple enough that the Jinja2 layer could be removed entirely.

---

## High Findings

### H1 — ScubaGear `client_secret` auth is silently broken
**`orbit/core/tools/scubagear.py:18-23`** — **Confirmed**

```python
script = (
    "Import-Module ScubaGear; "
    "Invoke-SCuBA -ProductNames * -OutPath $env:ORBIT_OUT_DIR "
    "-AppID $env:ORBIT_SCUBA_CLIENT_ID -Organization $env:ORBIT_SCUBA_TENANT_ID "
    "-CertificateThumbprint $env:ORBIT_SCUBA_CERT_THUMBPRINT"
)
```

The PowerShell script always passes `-CertificateThumbprint` regardless of `auth_method`. When a user selects `client_secret`, the thumbprint env var is empty and ScubaGear will fail authentication with a cryptic PowerShell error. The `client_secret` field is stored but never used.

Compare `maester.py:19-25` which handles this correctly with a conditional branch.

**Fix:** Add an `auth_method` conditional matching Maester's pattern.

**No test coverage** for this path.

---

### H2 — Parser crash aborts entire report
**`orbit/reporting/parser.py:152-164`** — **Confirmed**

```python
for tool, parser in PARSERS.items():
    ...
    raw.extend(parser(hit[0]))  # uncaught exception propagates
```

An unexpected JSON structure (missing keys, wrong types, or a malformed file in the output directory) raises `AttributeError`, `TypeError`, or `json.JSONDecodeError` which propagates out of `parse_folder()`, crashing the pipeline. No partial results are saved. The user gets no report.

**Fix:** Wrap each `parser(hit[0])` call in `try/except Exception as e: log.warning(...)` and continue.

---

### H3 — Admin check measures the wrong thing
**`orbit/core/admin_check.py:11-18`** — **Confirmed**

```python
def is_elevated() -> bool:
    if sys.platform == "win32":
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    return os.geteuid() == 0   # root check on Linux/macOS
```

The preflight warning message says tools require "Global Administrator rights in your M365 tenant." The check detects local OS privilege. These are orthogonal. On Linux/macOS a non-root user with M365 GA rights sees a red "Not elevated" warning. A local admin with no M365 access sees green and proceeds to fail at authentication.

**Fix:** On non-Windows, remove the OS privilege check entirely or re-label it. Add a separate note that M365 GA credentials must be configured via the Credentials screen — which is the actual prerequisite.

---

### H4 — SMTP credentials sent in cleartext
**`orbit/core/emailer.py:112-124`** — **Confirmed**

```python
if settings.smtp_port == 465 and settings.smtp_tls:
    server = smtplib.SMTP_SSL(...)
else:
    server = smtplib.SMTP(...)          # plaintext TCP connection
with server:
    if settings.smtp_tls and settings.smtp_port != 465:
        server.starttls(...)            # skipped if smtp_tls=False
    if settings.password:
        server.login(...)               # sends credentials regardless
```

If `smtp_tls=False` and port ≠ 465, `server.login()` is called over a plaintext SMTP connection. The SMTP password, from address, and report PDF are all transmitted unencrypted.

**Fix:** Refuse to call `server.login()` unless TLS is active. Raise an error or warn the user before sending.

---

## Medium Findings

### M1 — Profile import can redirect output to an arbitrary path
**`orbit/core/profile.py:36-40`** — **Confirmed**

```python
for section in ("output", "tools", "notifications", "app"):
    cfg[section].update({k: v for k, v in data[section].items() if k in cfg[section]})
```

`cfg["output"]` contains `"directory": ""`. A malicious profile JSON with `{"output": {"directory": "/etc"}}` will redirect all report output (PDFs, DOCX, raw tool JSON with tenant findings) to `/etc`. No path validation occurs.

**Fix:** Strip `"directory"` from the import allowlist in `profile.py:19` (like the export already does) or validate it is a safe relative/user path before merging.

---

### M2 — Linux keyring silently fails; `secretstorage` not declared
**`pyproject.toml`** — Confirmed

`keyring>=24` is declared but `secretstorage` (required for `keyring` to use `libsecret` on Linux) is not. Without it, `keyring` falls back to `fail.Keyring` and `SecretStore` falls back to the encrypted file store — but in several call sites (e.g. `credentials.py:21`) `SecretStore()` is constructed with `passphrase=None`, which causes `PermissionError` when writing. Users on minimal Linux will get an unexplained permission error saving credentials.

**Fix:** Add `"secretstorage>=3.0; sys_platform=='linux'"` to deps, or document the fallback and handle `PermissionError` with a user-facing message.

---

### M3 — `roadrecon` not listed as a dependency
**`orbit/core/tools/roadtools.py:30`** — Confirmed

ROADtools is invoked as `sys.executable -c <inline_code>` which imports `roadrecon`. `roadtools` is not in `pyproject.toml`. The tool will fail at runtime with a subprocess error containing `ModuleNotFoundError`. No preflight check catches this.

**Fix:** Add `roadtools` as an optional dependency or add an explicit preflight check that tests `import roadrecon` before offering the tool.

---

### M4 — No pinned dependencies or lockfile
**`pyproject.toml`** — Confirmed

All dependencies use `>=` lower-bound only. No `requirements.lock`, no `pip-compile`, no hash pinning. For a security auditing tool, this is ironic — a supply chain compromise of `cryptography` or `keyring` on PyPI installs silently.

**Fix:** Commit a `uv.lock` (already present but not reviewed) and verify it is kept current in CI.

> Note: `uv.lock` exists in the repo root. Verify it pins all transitive deps with hashes.

---

### M5 — ROADtools `sys.argv` manipulation is fragile
**`orbit/core/tools/roadtools.py:17-27`** — Confirmed

The subprocess runs `sys.executable -c "import sys; sys.argv = [...]; from roadrecon.gather import main; main(); sys.argv = [...]; from roadrecon.dump import main; main()"`. This is fragile: it depends on both `main()` functions being fully re-entrant with no shared global state, which is not guaranteed across ROADtools versions.

**Fix:** Use two separate subprocess calls, one for gather and one for dump, matching how the CLI would be invoked directly.

---

### M6 — `install_dir()` always returns `None`
**`orbit/core/tools/base.py:91-93`** — Confirmed

```python
def install_dir(self) -> Path | None:
    return None   # stub — no subclass overrides this
```

`check_tool()` at `hash_checker.py:66` returns `UNVERIFIED` when `install_dir is None`. Even if `tool_hashes.json` were populated, the integrity check would still never run because the base `install_dir()` is always `None` and no tool subclass overrides it. This is a second independent reason C2 never fires.

---

## Low Findings

| ID | Issue | Fix |
|----|-------|-----|
| L1 | `history.json` written without `chmod(0o600)` — world-readable under default umask on Linux (`history.py:50`) | Add `path.chmod(0o600)` after write |
| L2 | README and `encryption.py` docstring claim "AES-256"; Fernet uses AES-128-CBC with HMAC-SHA256 (key derivation produces 32 bytes but Fernet splits it 16+16) | Correct documentation to "Fernet (AES-128-CBC + HMAC-SHA256)" |
| L3 | Profile import merges values with no type checking — `smtp_port = "evil"` becomes a string and crashes downstream (`profile.py:38-40`) | Type-validate imported values against DEFAULTS types |
| L4 | Hawk runs successfully and logs output, but produces zero parsed findings — no parser exists and this is undocumented in the UI (`hawk.py`, `parser.py`) | Either add a Hawk CSV parser or label it "forensics only — no findings generated" in the Run screen |
| L5 | `run_capture()` silently returns `""` on any exception including broken binaries — version detection is indistinguishable from "not installed" (`base.py:42-46`) | Log at DEBUG level on failure |
| L6 | Dead code: `if pdf.get_y() < row_y: pass` (`pdf_report.py:145-146`) | Remove |

---

## Will It Actually Work?

### What works correctly
- All 77 tests pass on Python 3.11
- Secret storage and redaction architecture is solid — no argv leakage confirmed
- PDF and DOCX generation both function (confirmed via tests)
- Dry-run mode avoids real M365 calls (confirmed: fixture data only)
- PBKDF2 parameters (600,000 iterations, SHA-256, random 16-byte salt) are correct
- No `shell=True` anywhere — zero shell injection surface
- PowerShell scripts use `-NonInteractive -NoProfile` correctly
- Email HTML body properly escapes user data with `html.escape()`

### What will not work as advertised

| Claim | Reality |
|-------|---------|
| ScubaGear works with client_secret auth | Silent failure — PS script only passes `-CertificateThumbprint` |
| Tool integrity is verified before each run | Manifest is empty; `install_dir()` unimplemented — always UNVERIFIED, never blocked |
| Hawk findings appear in reports | Hawk has no parser; runs but contributes zero findings |
| Works on Linux out of the box | `secretstorage` missing dep; `is_elevated()` checks root not M365 role; both confuse users |
| ROADtools device-code flow is smooth | User must alt-tab to browser mid-run with no in-app guidance |

---

## Test Coverage Gaps

The test suite is well-structured and tests happy paths thoroughly. Critical gaps:

| Missing test | Risk |
|---|---|
| `decrypt_archive` with `../` member paths | C1 ZIP Slip entirely untested |
| `import_profile` with `output.directory` override | M1 path redirect untested |
| ScubaGear `client_secret` launch_spec | H1 broken path never caught |
| `parse_folder` with malformed/missing JSON keys | H2 crash untested |
| `gate_run` called with `UNVERIFIED` results (documents non-blocking behaviour) | C2 design intent undocumented |
| `_deliver` with `smtp_tls=False` and non-465 port | H4 cleartext login untested |
| `is_elevated()` on Linux as non-root | H3 misleading semantic untested |

---

## Dependency Audit

| Package | Declared | Notes |
|---------|----------|-------|
| `cryptography>=42` | OK | No unfixed critical CVEs in ≥42 |
| `keyring>=24` | Missing `secretstorage` on Linux | See M2 |
| `textual>=0.60` | OK | No critical CVEs |
| `jinja2>=3.1` | OK for this usage (not web) | SSTI risk is from own template design (C3), not a CVE |
| `plyer>=2.1` | Low maintenance on Linux | `notify2`/`dbus` can fail silently |
| `roadtools` | **Not declared** | See M3 |
| All deps | `>=` lower-bound only | See M4 |

---

## Summary

**Stop-before-use blockers (Critical):**
1. **C1 ZIP Slip** — file write outside designated directory
2. **C3 Jinja2 SSTI** — code execution via crafted tool output
3. **C2 Empty hash manifest** — the integrity feature is security theatre

**Fix-before-client blockers (High):**
4. **H1** — ScubaGear client_secret auth doesn't work
5. **H2** — Malformed tool output crashes the whole report
6. **H4** — SMTP can transmit credentials in cleartext

The architecture is sound. The credential and subprocess handling design is good. Fixing the six blockers above turns this into a professional-grade tool. The medium and low findings are improvement work, not showstoppers.

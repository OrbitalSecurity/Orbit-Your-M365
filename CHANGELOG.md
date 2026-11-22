# Changelog

## [1.5.1] — 2026-11-22

Hardening and release-polish release. No tool-execution, SMTP, encryption or ROADtools behavior changes. The integrity baseline's location is now held to a stricter policy (below); fail-closed behavior is otherwise unchanged.

### Fixed
- **Wheel installs now work offline** — a built wheel did not contain the CVE mappings, the tool-hash manifest or the dry-run fixtures, which were read from repository-level `data/` and `tests/fixtures/` directories that exist only in a source checkout. They now live in the package (`orbit/data/` and `orbit/data/fixtures/`), are declared as package data, ship in both the wheel and the sdist, and are resolved through `importlib.resources` (`orbit.config.DATA_DIR` / `FIXTURES_DIR`). A normal `pip install` of the wheel runs `orbit --dry-run` and reports CVE references without a source tree. ORBIT only reads this data; it never writes into the installed package.
- **Integrity baseline is per-user state, not package data** — the tool-hash manifest is mutable trust state, so it no longer lives in (or beside) the installed code, where a wheel install could not durably record it and an upgrade could overwrite it. The active baseline is `ORBIT_HOME/tool_hashes.json` (normally `~/.orbit/tool_hashes.json`), resolved on every call by `hash_checker.manifest_path()` (the `MANIFEST_PATH` constant is gone), so a source checkout, an editable install and a wheel share one baseline. The package ships only an empty `orbit/data/tool_hashes.template.json` that seeds it and is never read as a baseline. Fail-closed behaviour is unchanged: an absent, empty, invalid, unreadable, linked or mismatching baseline never authorises a real run (an absent one now reports "no integrity baseline has been recorded; run orbit-generate-hashes").
- **New `orbit-generate-hashes` command** — installed with the wheel (`orbit.core.baseline:cli`), it uses the production discovery, hashing and locked atomic-update code and writes only the ORBIT_HOME baseline. The first run creates ORBIT_HOME (mode 0700) and the file (mode 0600) from the template; an existing ORBIT_HOME that is not yours or is writable by group or others is refused. `scripts/generate_hashes.py` remains as a shim for source checkouts. Re-running preserves existing entries and never replaces a differing baseline.
- **Older baselines are never imported** — a `data/tool_hashes.json` from a 1.5.0-or-earlier checkout (or an interim `orbit/data/tool_hashes.json`) is not trusted silently: real runs stay blocked until you run `orbit-generate-hashes` against installations you trust, which prints a note naming the ignored file and leaves it untouched. There is no automatic migration.
- **Integrity baseline is schema 2, bound to your account** — `ORBIT_HOME/tool_hashes.json` is accepted only if it is a strictly validated schema-2 document (`"schema": 2`, `"kind": "orbit.integrity-baseline"`, closed keys, validated entries) generated for the current user (and, on Windows, the current machine). The binding stores only hashes (never the raw uid, SID or MachineGuid). Anything else is refused **by content, wherever the file sits**, so a schema-1 or unmarked baseline (a copied `data/tool_hashes.json` from a 1.5.0-or-earlier checkout, an interim build's file, the packaged template) can never authorise a run, and `orbit-generate-hashes` never imports, rewrites or upgrades it: it leaves the file byte-for-byte unchanged, says why, and exits 1 until you move it aside and record a new baseline. Schema-1, unbound, template and malformed content is rejected unconditionally; a validly bound schema-2 baseline copied from another account or computer is rejected only when the identifiers differ (see below). The packaged template is now schema 2 with no binding, so a raw copy of it is never an active baseline. If the account or machine identity cannot be established, nothing is generated or accepted. The binding is to the effective user ID on macOS and Linux (not to the machine), and on Windows to the current token SID plus the MachineGuid. A baseline copied to another account or computer is normally rejected because those identifiers differ, but a cloned environment that keeps them (a copied VM or image, or the same UID on another POSIX host) may still match. It is a guard against accidental cross-use, not authentication, and not a defence against malware running as the same user, which can compute the binding itself. Windows identity retrieval (token SID, MachineGuid) is unverified until the native Windows CI job has run. This is schema and binding validation only: it adds no new Windows folder-permission protection, and the same-user limitation is unchanged.
- **Version consistency** — package metadata (`pyproject.toml` was still `1.0.0`), `orbit.config.VERSION`, README badge/banner, README report-footer sample, `docs/PRIVACY.md`, the website badge and the issue templates now all report 1.5.1.

### Security
- **Baseline trust path** — the real-run gate no longer trusts `ORBIT_HOME/tool_hashes.json` merely because it exists. Reads (`hash_checker.load_manifest`) and writes (`orbit-generate-hashes`) now share one policy, `orbit/core/trusted_state.py`. On POSIX the path is walked with directory file descriptors and `O_NOFOLLOW`, and the read, lock, temporary file and rename are all relative to the vetted directory, so a swapped path cannot redirect them. `ORBIT_HOME` and every directory above it must be owned by you (or root) and closed to group and others (a root-owned sticky directory such as `/tmp` is accepted above it); the manifest and lock must be regular files of yours, with no group/other write bit and a single hard link. Symbolic links are refused for `ORBIT_HOME`, for ancestors in the part of the path you control, and for the manifest, lock and replacement file (only root-owned links in the system part, such as `/var` on macOS, are followed). A manifest that is replaced, or an `ORBIT_HOME` that is swapped, while it is read or updated fails closed. Locking, atomic replacement, fsync, `0700`/`0600` creation modes, mismatch blocking and the same-version no-rebless rule are unchanged. A manifest that others can write (`0666`, for example) used to be tightened and adopted; it is now refused.
- **Windows** — the standard library cannot read an owner or an ACL and POSIX bits do not describe one, so ORBIT does not claim to. The conservative rule: `ORBIT_HOME` must be inside your user profile and no component below it may be a link or junction. A widened profile ACL is not detected and the checks are path-based, not race-free. This limitation is documented, not hidden.
- **Unsafe `ORBIT_HOME` destinations** — an `ORBIT_HOME` that is, or resolves into (by name, symbolic link, case variant or inode identity), the installed or source package, `orbit/data`, the repository's legacy `data/` directory or another legacy manifest directory is refused before anything is read, seeded, locked or written; a legacy baseline can no longer become active through an alias. Error text is fixed and does not echo the rejected path.

### Changed
- **Package data is explicit** — `[tool.setuptools.package-data]` names each shipped file instead of `data/*.json`, so a stray `orbit/data/tool_hashes.json` can no longer be included by accident. Stale generated `dist/` artifacts that carried one were rebuilt.
- **Packaging metadata** — `[project].license` uses the SPDX string `MIT`, and the build backend floor is raised to `setuptools>=77`, the first release that accepts it.
- **Report footer** — the footer no longer says "No data transmitted". It now reads "No telemetry. Report data is sent by ORBIT only if you enable SMTP email."
- **CI** — the Linux pytest matrix now includes Python 3.13, and a new `package` job builds the wheel and sdist, checks that both contain the runtime resources, installs only the wheel into a clean virtualenv, and from outside the checkout runs the installed `orbit` command's entry point, noninteractive (`--dry-run --headless --json`), with network and process creation blocked, an isolated `ORBIT_HOME` and a scratch output directory, then checks the JSON and that every module and resource came from the installed wheel. That guarded run is the only dry-run the job accepts; no earlier unguarded run is used as evidence. It writes PDF and DOCX final reports and the job validates those exact files. A recording guard (rather than only a raising stub) appends each attempt before it raises, so a swallowed exception cannot hide one, and the job asserts the log is empty. It guards and instruments the covered paths used by this validation, not every conceivable network path: the socket connect/send family (`connect`, `connect_ex`, `sendto`, `sendmsg`, `bind`, `listen`), name resolution, `subprocess`, `os.system`/`popen`/`fork*`/`exec*`/`spawn*`/`posix_spawn*`, `pty`, `multiprocessing`, asyncio subprocess and connection APIs, `smtplib`, `http.client` and `urllib`. The job also checks that the wheel and sdist each ship the immutable resources, an empty template (validated independently in both archives) and the declared `orbit-generate-hashes` entry point, and no active `tool_hashes.json` or lock anywhere, that the installed baseline command writes only to the scratch ORBIT_HOME (against a synthetic installation), and that the real-run gate stays closed before and opens only after that baseline.

### Documentation
- **Privacy and network model corrected** — earlier text, including the first 1.5.1 draft, described the GitHub release check as ORBIT's only outbound request and said findings never leave the machine. That was incomplete. ORBIT's own network requests are (1) the optional, automatic GitHub release check (`api.github.com`, real non-dry-run sessions, disabled by `update_check = false` under `[notifications]` in `~/.orbit/config.toml`; no in-app toggle), which sends no tenant, credential, finding or user data; and (2) SMTP email that you configure and explicitly enable: a test message from the Email screen and, after a real run with *Email results when complete* ticked, a summary containing assessment details (client name, score, counts, top findings and remediation) with the PDF report attached, sent to the SMTP server you configure (which may be a hosted provider) and on to the recipients you choose. The tools ORBIT launches and the installer make their own connections. ORBIT does not automatically submit anything to the author, and there is still no telemetry or analytics. README, SECURITY, LEGAL, PRIVACY, CONTRIBUTING, AGENTS, VALUE, the help screen, the report footer, the website (including the former "0 bytes sent externally" counter) and the issue templates were corrected. Dry-run and `--headless` never send email. No SMTP or update-check code changed.
- **Fernet terminology corrected** — Fernet is AES-128-CBC with HMAC-SHA256 (PBKDF2 for passphrase-derived keys), not AES-256, in README, help screen, PRIVACY, website and historical changelog entries.
- **ROADtools** — production execution remains disabled; only fixture-based dry-run is supported pending a safe non-plaintext authentication design.
- **Windows limitation surfaced** — README and `docs/INSTALL.md` Windows guidance now states that encrypted archives cannot be restored on Windows (extraction fails closed); keep the unencrypted copy or restore on macOS/Linux.
- **Test counts** — stale fixed counts (36/77, then 781) replaced with "the full suite should pass", which does not go stale.
- **SMTP configuration** — `docs/PRIVACY.md` no longer says the Email screen is a prerequisite: SMTP can also come from supported config and secret-store state. The disclosure is otherwise unchanged (no telemetry, no automatic submission to the author, optional GitHub release check, user-configured SMTP may send assessment data through a hosted provider to chosen recipients).

### Validation notes
- Validated locally on macOS only. Python 3.13 and the packaging job are added to CI but have not yet run on GitHub Actions; Windows (including the profile rule above) and real-tool behavior remain unvalidated. A CI runner whose temp directory has group-writable ancestors would be refused by the new path policy rather than trusted.

---

## [1.5.0] — 2026-11-01

### Security fixes (Critical)
- **ZIP Slip patched** — `decrypt_archive` now filters every ZIP member path before extraction; entries containing `..` or absolute paths are silently skipped. Previously a crafted `.orbit.zip` could write files outside the target directory. (`orbit/security/encryption.py`)
- **Jinja2 SSTI eliminated** — DOCX finding fields are no longer rendered through Jinja2 templates. `finding.txt.j2` has been replaced with a plain Python function. Previously a crafted tool output containing a Jinja2 expression in a control ID field could execute arbitrary Python in the ORBIT process. (`orbit/reporting/docx_report.py`)
- **Tool integrity gate now enforced** — `HashStatus.UNVERIFIED` (empty manifest entry) now blocks a real run, the same as `MISMATCH`. Previously all tools passed the hash gate unconditionally because the manifest was empty. Users must populate `data/tool_hashes.json` before running against a real tenant — see the new **[Tool integrity setup](#tool-integrity-setup)** section in README and `docs/INSTALL.md`.

### Added
- **`scripts/generate_hashes.py`** — helper script to populate `data/tool_hashes.json` from your installed tools. Run once after installing each tool; re-run after any update. See [Tool integrity setup](#tool-integrity-setup).
- **Pre-flight integrity warning** — preflight screen now includes a ⚠ amber check for the hash manifest. Shows "NOT CONFIGURED" when the manifest is unpopulated so users see this *before* hitting a blocked run.
- **Amber warning state in preflight** — preflight rows now have three states: ✓ green (pass), ⚠ amber (warning / action required), ✗ red (hard fail).

### Tests
- 80 passing (up from 77)
- `test_zip_slip_is_blocked` — verifies traversal entries are skipped by `decrypt_archive`
- `test_ssti_not_evaluated` — verifies Jinja2 expressions in finding fields are rendered literally
- `test_unverified_blocks_run` — verifies `UNVERIFIED` hash status blocks execution

---

## [1.4.0] — 2026-11-01

### Added
- **Pre-flight check screen** — shown before every run; verifies elevation, PowerShell 7, OPA binary, tool installs, credentials, and output folder writability; all local checks, no network calls; explains why live credential validation is intentionally omitted; Re-check and Proceed buttons
- **Executive Summary PDF** — on-demand 2-page report for non-technical stakeholders: dark cover with posture score bar and risk label (LOW/MEDIUM/HIGH/CRITICAL RISK), priority findings with plain-English remediation, auto-generated summary paragraph; generated async with progress bar, never blocks UI
- **Posture sparkline** — ASCII bar trend (`▁▃▅▇█ 74/100`) on home screen showing last 8 real run scores; dry-run records excluded
- **Remediation action plan** — press `r` or click button in Findings screen; prioritised modal table with control ID, finding, first 80 chars of remediation, CVEs; capped at top 20
- **Keyboard filter in Findings** — press `/` to jump focus to the filter input; live search across all columns
- **Client name on Run screen** — prominent text field at top of Run screen; syncs with Output screen; stamped on all reports
- **Config profile export/import** — `--export-profile FILE` and `--import-profile FILE` CLI flags; portable JSON snapshot of all non-sensitive settings; safe for sharing between machines or team members; never exports secrets
- **Auto-resize launcher** — `launch.py` resizes terminal to 140×43 on macOS (AppleScript + ANSI escape), Windows (`mode con`), and Linux (ANSI) before starting the TUI
- **Slogan** — banner tagline updated to "Orbiting your M365. Nothing escapes."
- **Onboarding re-prompt** — wizard re-shown on every launch until credentials are actually saved; skipping no longer suppresses it permanently

### Improved
- Banner animation reduced from 10fps to 4fps — 60% less CPU, buttons and screen transitions feel instant
- Installer screen redesigned: compact one-row-per-tool layout with status badge, version, Install/Update/Remove per tool; fits on one screen with no scroll; log expands on use
- Quotes panel uses `1fr` height — fills all available space between fixed sections rather than fixed 6 rows
- `#last-run` now shows "Pending first run — no score determined yet." when no real runs recorded; dry-run records excluded from history display and sparkline
- Terminal size warning threshold updated to 120×40

### Tests
- 77 passing (unchanged — new features are UI/async, covered by existing integration tests)

---

## [1.3.0] — 2026-11-01

### Added
- Help screen (`?` key) — full-screen reference overlay: shortcuts, tool list, requirements, privacy note
- Onboarding wizard — shown on first launch only, skippable at any step; guides through credentials and tool selection
- Findings viewer screen — sortable/filterable DataTable with severity colour coding; row detail modal with CVEs and remediation
- Run comparison / delta — compare any two history entries; shows score delta, severity deltas, issues resolved
- Auto-update checker — silent background check against GitHub releases API; dim notice in home screen if newer version available
- Terminal size warning — shown if terminal is under 100×32; "Continue anyway" option
- `--list-tools` CLI flag — prints tool status table to stdout and exits, no TUI needed
- GitHub Pages landing page (`docs/index.html`) — dark-themed, ASCII logo, feature cards, tools table, install block, privacy strip
- vhs demo recording script (`demo.tape`) — record animated GIF of the TUI

### Improved
- Run screen now uses `RichLog` with 2000-line buffer and user-scrollable history
- Report filenames now include client name slug and date: `ORBIT_Summary_Acme_Ltd_2026-11-01.pdf`
- `pyproject.toml` entry point added — `orbit` works as a CLI command after `pip install -e .`

### Tests
- 58 → 77 passing

---

## [1.2.0] — 2026-11-01

### Added
- Logged-in username and permission level (Administrator / Standard User) displayed in banner — green when elevated, amber when not
- Rotating quotes panel filling empty space on home screen — 38 quotes across cybersecurity, open source, hacking, and privacy; fades in/out with attribution

### Improved
- Banner tick rate reduced to 100ms (10fps) — smoother on lower-end hardware
- Quotes widget tick rate reduced to 150ms (6fps) — lower CPU, visually identical
- Nav buttons now fill full terminal width with `min-width: 0` and `overflow: hidden hidden` — no clipping at any terminal size
- Info panel columns use fractional widths — dashboard scales with terminal width
- Quotes widget given fixed 6-row height to guarantee visibility at all terminal sizes

### Fixed
- Worker thread context error (`LookupError: active_app`) — reverted to synchronous dashboard refresh which is stable across Textual versions

---

## [1.1.0] — 2026-11-01

### Added
- Client name field on Output screen — stamped on PDF/DOCX report cover (blank defaults to "Confidential")
- Run history tracking (`~/.orbit/history.json`) — Home screen shows last run date, score, and delta (↑/↓)
- Config file (`~/.orbit/config.toml`) — persists output directory, format selection, tool selection, email settings across sessions
- OS completion notification via `plyer` — fires when run finishes, respects `os_notify` config flag
- `--headless --json` mode — run without TUI, outputs machine-readable JSON to stdout; exit 1 on failure
- `--tools` flag for headless mode — e.g. `--tools scubagear,maester`
- Email on completion — SMTP config screen (host, port, TLS, From, To, CC), HTML body with score and top findings, PDF attached, sends automatically after run if enabled
- "Email results when complete" toggle on Run screen
- GitHub Actions CI — runs 58 tests across Python 3.10, 3.11, 3.12 on every push/PR
- `SECURITY.md` — responsible disclosure policy
- `CONTRIBUTING.md` — contribution guide and code standards
- GitHub issue templates — bug report and feature request

### Improved
- CVE/NIST mappings expanded from 8 → 31 controls covering full CISA SCuBA baseline:
  - Entra ID: legacy auth, admin MFA, user MFA, phishing-resistant MFA, Conditional Access, PIM, guest invite, SSPR, Identity Protection, app consent, OAuth apps, break-glass accounts, cloud-only admins, GA count
  - Exchange Online: external forwarding, Safe Links, Safe Attachments, anti-phishing, DMARC, DKIM, SPF
  - SharePoint: external sharing, guest expiry
  - Teams: external access, meeting security
  - Power Platform: DLP policies, tenant isolation
  - Intune: device compliance

### Tests
- 36 → 58 passing

---

## [1.0.0] — 2026-11-01

### Added
- Animated Textual TUI: home/banner (spinning Earth, satellite, stars), credentials, tool selection, installer, output config, run, report screens
- Animated banner: large ORBIT block logo, photo-style spinning Earth with clouds/atmosphere/city lights, orbiting satellite with trail, twinkling stars, shooting stars, live UTC clock
- Secrets management: OS keychain (Windows Credential Manager / macOS Keychain / libsecret) with Fernet (AES-128-CBC with HMAC-SHA256, PBKDF2) fallback; secrets only via child process env vars, masked `***` in all logs
- SHA-256 integrity gate against bundled manifest before any tool launch
- Async subprocess runner for ScubaGear, Maester, Monkey365, ROADtools, Hawk with live streaming logs
- `--dry-run` mode — full TUI and reports from fixture data, no tenant needed
- Parsers: ScubaGear JSON, Maester JSON, Monkey365 JSON/CSV → unified Finding model with cross-tool deduplication
- Scoring matrix: Critical×10 / High×7 / Medium×4 / Low×1, posture score 0–100
- CVE/NIST mapping (8 controls) with bundled offline JSON
- PDF and DOCX executive summary reports with cover, posture score bar, top findings with CVE + remediation, full findings table
- Optional Fernet-encrypted output folder (AES-128-CBC with HMAC-SHA256, PBKDF2 passphrase)
- Installer screen: ScubaGear/Maester/Monkey365/Hawk via PSGallery, ROADtools via PyPI
- Platform detection: ScubaGear flagged incompatible on non-Windows
- Admin/elevation check with warning banner
- Full documentation: README, TOOLS, PRIVACY, SCORING, INSTALL, VALUE, LEGAL

# ORBIT — Office 365 Risk & Baseline Intelligence Toolkit

<p align="center">
  <img src="https://img.shields.io/badge/python-3.10%2B-blue?style=flat-square" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey?style=flat-square" alt="Platform">
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="MIT License">
  <img src="https://img.shields.io/badge/version-1.5.1-purple?style=flat-square" alt="Version 1.5.1">
  <img src="https://img.shields.io/badge/telemetry-none-brightgreen?style=flat-square" alt="No telemetry">
  <img src="https://img.shields.io/badge/runs-locally-brightgreen?style=flat-square" alt="Runs locally">
</p>

```
 ██████╗ ██████╗ ██████╗ ██╗████████╗
██╔═══██╗██╔══██╗██╔══██╗██║╚══██╔══╝
██║   ██║██████╔╝██████╔╝██║   ██║
██║   ██║██╔══██╗██╔══██╗██║   ██║
╚██████╔╝██║  ██║████████╗██║   ██║
 ╚═════╝ ╚═╝  ╚═╝╚═══════╝╚═╝   ╚═╝

  Office 365 Risk & Baseline Intelligence Toolkit
  Author  : Reece Gabriel Dickson
  Role    : Independent Cybersecurity Research Analyst
  Version : v1.5.1
```

ORBIT is a **terminal application** with an animated TUI that orchestrates leading M365 security auditing tools, manages their credentials securely, runs them, normalises and scores every finding, and writes a **PDF / DOCX executive summary report** — with no telemetry and no ORBIT-operated server. Your tenant data, credentials and findings stay on your machine unless you configure and enable SMTP email delivery of the report (see [Security and Privacy](#security-and-privacy)).

What normally takes a skilled analyst **4–8 hours** of manual portal work and report-writing, ORBIT compresses to **10–15 minutes** of hands-on time.

---

## Contents

- [What ORBIT Does](#what-orbit-does)
- [Tools Integrated](#tools-integrated)
- [Quickstart](#quickstart)
- [Installation](#installation)
- [Tool Integrity Setup](#tool-integrity-setup)
- [How to Test Without a Work Tenant](#how-to-test-without-a-work-tenant)
- [Usage Walkthrough](#usage-walkthrough)
- [Output and Reports](#output-and-reports)
- [Scoring Methodology](#scoring-methodology)
- [Architecture](#architecture)
- [Security and Privacy](#security-and-privacy)
- [Credits and Acknowledgements](#credits-and-acknowledgements)
- [Legal Notices](#legal-notices)
- [Contributing](#contributing)

---

## What ORBIT Does

1. **Pre-flight checks** — before any run, verifies admin rights, PowerShell version, OPA binary, tool installs, credentials, and output folder writability. Local only — no network calls from the pre-flight checks.
2. **Stores credentials securely** — Tenant ID, App ID, and client secrets go into your OS keychain (Windows Credential Manager / macOS Keychain / libsecret). Never written in plaintext. Never in process arguments visible to `ps`.
3. **Checks tool integrity** — SHA-256 hash check against a local manifest that you record, before any tool is launched. It detects change; it is not proof of authenticity (see [what it protects against](#what-the-check-protects-against)). A mismatch or unverified tool is a hard stop. **You must record a baseline in `~/.orbit/tool_hashes.json` (`ORBIT_HOME`) with `orbit-generate-hashes` after installing tools** — see [Tool integrity setup](#tool-integrity-setup).
4. **Installs / updates tools** — one screen to install ScubaGear, Maester, Monkey365, and Hawk with per-tool status, version, Install/Update/Remove buttons. ROADtools install and update are disabled.
5. **Runs selected tools** — async subprocess launcher with live streaming logs and per-tool progress. Tools are stopped cleanly on cancel.
6. **Parses and normalises output** — JSON and CSV from ScubaGear, Maester, and Monkey365 unified into a single `Finding` model with severity, control ID, CVE references, and remediation text.
7. **Scores findings** — a weighted risk matrix (Critical ×10 / High ×7 / Medium ×4 / Low ×1) produces an overall posture score and ranked top findings.
8. **Findings viewer** — sortable/filterable DataTable with severity colour coding; detail modal per finding; `r` for prioritised remediation action plan; `/` to search; run comparison delta.
9. **Generates reports** — PDF or DOCX technical report with cover, posture bar, top findings with CVE + remediation, full findings table. Plus a separate **Executive Summary PDF** (on demand) for non-technical stakeholders: 2-page plain-English report with risk gauge, top findings, and a written summary paragraph.
10. **Optionally encrypts output** — Fernet (AES-128-CBC with HMAC-SHA256) with a PBKDF2 passphrase. An unencrypted copy can be saved as well.
11. **History and trend** — run history stored locally; home screen shows last run date, score delta (↑/↓), and ASCII sparkline trend across last 8 real runs.
12. **Config profiles** — export/import settings as a portable JSON file (`--export-profile`, `--import-profile`) for moving between machines or sharing with a team.

---

## Tools Integrated

ORBIT integrates the following independent, open-source security tools. ORBIT does not modify, fork, or redistribute any of them — it calls them through their published interfaces.

| Tool | Coverage | Language | Official Source |
|------|----------|----------|-----------------|
| **ScubaGear** | CISA SCuBA baselines: Entra ID, Defender, Exchange Online, SharePoint/OneDrive, Teams, Power Platform | PowerShell | [github.com/cisagov/ScubaGear](https://github.com/cisagov/ScubaGear) |
| **Maester** | Pester test framework: CISA SCuBA, CIS M365, ORCA, EIDSCA (280+ tests) | PowerShell | [maester.dev](https://maester.dev) · [github.com/maester365/maester](https://github.com/maester365/maester) |
| **Monkey365** | M365, Azure, Entra ID config review against CIS benchmarks (160+ checks) | PowerShell | [github.com/silverhack/monkey365](https://github.com/silverhack/monkey365) |
| **ROADtools** (dry-run only) | Entra ID enumeration and offline analysis (users, roles, apps, policies) | Python | [github.com/dirkjanm/ROADtools](https://github.com/dirkjanm/ROADtools) |
| **Hawk** | Exchange Online / Entra ID forensic collection for IR and investigation | PowerShell | [github.com/T0pCyber/hawk](https://github.com/T0pCyber/hawk) |

**ROADtools production execution is disabled** pending a memory-only or other non-plaintext authentication design. Its sign-in writes tokens to disk in plaintext, so a real run is blocked before credentials are read or a process starts, and recording a baseline does not change that. `--dry-run` still works.

Further reading and reference tools:
- [CISA SCuBA Project](https://www.cisa.gov/resources-tools/services/secure-cloud-business-applications-scuba-project) — the authoritative source for Microsoft 365 secure configuration baselines
- [Open Policy Agent (OPA)](https://www.openpolicyagent.org/) — policy engine used internally by ScubaGear
- [ORCA](https://github.com/cammurray/orca) — Office 365 Recommended Configuration Analyser (integrated via Maester)
- [EIDSCA](https://github.com/Cloud-Architekt/AzureAD-Attack-Defense/blob/main/AADSecurityConfigAnalyzer.md) — Entra ID Security Config Analyser (integrated via Maester)
- [Pester](https://pester.dev/) — PowerShell test framework that Maester is built on

---

## Quickstart

```bash
# Clone
git clone https://github.com/OrbitalSecurity/Orbit-Your-M365.git
cd orbit-m365

# Create venv and install
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[dev]"

# Run tests (no tenant needed)
pytest tests/ -v

# Launch in dry-run mode (auto-resizes terminal to 140×43, full TUI, no M365 tenant needed)
python launch.py --dry-run

# Real run — requires tool integrity setup first (see below)
python launch.py
```

> **Before your first real run:** you must install tools via the Installer screen, then run `orbit-generate-hashes` to record their SHA-256 hashes in `~/.orbit/tool_hashes.json`. ORBIT will block any unverified tool. See [Tool integrity setup](#tool-integrity-setup).

---

## Installation

### Windows 10/11 (Primary Platform)

> **ScubaGear requires Windows.** All other tools work cross-platform.
>
> **Encrypted archives cannot be restored on Windows.** ORBIT can create an encrypted `.orbit.zip` there, but its extraction fails closed on Windows. If you need to read results on Windows, keep the unencrypted copy; otherwise restore the archive on macOS or Linux.

1. Install **Python 3.10+** from [python.org](https://www.python.org/downloads/) — tick "Add to PATH".
2. Install **PowerShell 7**: `winget install Microsoft.PowerShell`
3. In the project folder:
   ```powershell
   python -m venv .venv
   .venv\Scripts\activate
   pip install -e ".[dev]"
   ```
4. Open **PowerShell 7 as Administrator** (required for ScubaGear/Maester).
5. Run `python orbit.py` and use the **Installer** screen to install each tool.
6. Enter your credentials in the **Credentials** screen, select tools, configure output, then **Run**.

### macOS

```bash
brew install python@3.12
brew install powershell          # optional — needed for PS-based tools
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
python orbit.py --dry-run
```

ScubaGear shows as "incompatible OS" on macOS — this is expected. Maester, Monkey365 and Hawk are intended to work on macOS with PowerShell 7, but have not been validated with the real tools. ROADtools is dry-run only.

### Linux

```bash
# Install PowerShell 7 (Microsoft's package repo)
# https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-linux
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
python orbit.py --dry-run
```

### Verify

```bash
pytest tests/ -v          # the full suite should pass
python orbit.py --help
```

See [docs/INSTALL.md](docs/INSTALL.md) for detailed step-by-step instructions.

---

## Tool Integrity Setup

> **Required before any real run.** Dry-run mode is unaffected.

ORBIT compares the SHA-256 hashes of every installed tool's files with your recorded baseline before launching them. The manifest ships empty — you populate it from your own trusted install.

### What the check protects against

It detects accidental changes, and unauthorised changes made by other OS principals (other users or service accounts without your rights). That holds only while they cannot write to ORBIT, its Python environment or the manifest; root and administrators always can.

The manifest and the runtime files belong to your account, so the check **cannot defend against a malicious process running as the same OS user**: that process can change the files and the manifest together. A match is not proof of authenticity or provenance; that would need privilege separation or an external signed trust anchor, and ORBIT has neither.

### Why you need to do this

The hash manifest (`~/.orbit/tool_hashes.json`, or `tool_hashes.json` in `ORBIT_HOME` if you set it) is your own trust state, kept outside the installed package so that upgrades and reinstalls cannot overwrite it and pip never owns it. It records the expected file hashes for each tool at each version. Until it contains an entry for your installed version, ORBIT treats the tool as **unverified** and blocks the run. The pre-flight screen will show that tool and version as ✗ BLOCKED and the Run screen will skip the tool with "BLOCKED: integrity unverified".

This is intentional: running an unverified tool against a production tenant is a security risk.

### Step-by-step

**1. Install your tools** (via ORBIT's Installer screen or manually — see [Installation](#installation))

**2. Run the hash generator** (installed with ORBIT, from the same environment as `orbit`):

```bash
orbit-generate-hashes
```

From a source checkout, `python scripts/generate_hashes.py` is the same command. This scans your installed PowerShell modules (and ROADtools if present, which stays dry-run only), computes SHA-256 hashes for every file, and writes them into `~/.orbit/tool_hashes.json`. The first run creates that file (and a private `~/.orbit`) from the package's empty template; nothing is ever written into the installed package. Output looks like:

```
Scanning ScubaGear v1.4.0 ...  ✓ 312 files hashed
Scanning Maester v0.4.3 ...    ✓ 89 files hashed
Scanning Monkey365 v1.0.9 ...  ✓ 204 files hashed
Scanning Hawk v3.2.1 ...       ✓ 57 files hashed
Manifest written to /home/you/.orbit/tool_hashes.json
```

**3. Re-run after any tool update**

If you update a tool (via the Installer screen or manually), re-run `orbit-generate-hashes`. ORBIT will block the updated tool until the manifest is refreshed — this is by design.

**4. Verify in pre-flight**

Launch ORBIT and open the **Pre-flight** screen. Each selected tool has its own "<tool> <version> integrity" row, which is ✓ green only if that tool would pass the gate used at launch.

### Upgrading from an older layout

Releases up to 1.5.0 kept the baseline in `data/tool_hashes.json` inside the source checkout. ORBIT **never imports it**: hashes recorded for a different install are not trusted just because they are on disk. Until you run `orbit-generate-hashes`, a real run is blocked with "no integrity baseline has been recorded", and the command prints a note naming any older file it ignored. Record a fresh baseline against installations you trust; your older file is left exactly as it was.

The baseline file is schema 2 and is recorded for your account (and, on Windows, your computer). A file in the older format (schema 1, or no schema), unmarked or malformed content, or the packaged template copied by hand is **always refused wherever it is stored**. A valid, bound schema-2 baseline recorded for another user or computer is normally refused too, because its identifiers differ (see below). All of these are refused even when copied straight into `ORBIT_HOME/tool_hashes.json`; a real run is blocked with a message that says which case it is. `orbit-generate-hashes` never converts or overwrites such a file. Move it aside yourself (`mv ~/.orbit/tool_hashes.json ~/.orbit/tool_hashes.json.v1`, or on Windows `Move-Item "$env:USERPROFILE\.orbit\tool_hashes.json" "$env:USERPROFILE\.orbit\tool_hashes.json.v1"`) and run `orbit-generate-hashes` again to record a new baseline against installations you trust.

If you set `ORBIT_HOME`, the baseline is `$ORBIT_HOME/tool_hashes.json`. The same location rules apply when ORBIT **reads** the baseline for the real-run gate and when `orbit-generate-hashes` **writes** it, so a location that is refused for one is refused for both (a real run is then blocked as "baseline is not trusted"):

- On macOS and Linux, `ORBIT_HOME` must be owned by you and not writable by group or others, and so must every directory above it (a root-owned sticky directory such as `/tmp` is fine above it). `tool_hashes.json` and its `.lock` must be regular files of yours with no group/other write bit and no extra hard links. Symbolic links are refused for `ORBIT_HOME`, for any directory you control above it, and for the manifest and lock. If the check fails, run `chmod go-w` on the directory it names, or point `ORBIT_HOME` somewhere private.
- `ORBIT_HOME` may not be, or resolve into (by name, symbolic link or identity), ORBIT's installed or source package, `orbit/data`, the repository's legacy `data/` directory or another directory where an older layout kept a baseline. Nothing is read from, seeded into or written to such a place, and an older baseline is never trusted through an alias.
- **Windows:** ORBIT cannot read folder owners or ACLs with the standard library, and POSIX permission bits do not describe them, so it does not claim to check them. The conservative rule is that `ORBIT_HOME` must be a folder inside your user profile (whose default ACL excludes other standard users) with no link or junction below the profile; anything else is refused. A profile whose permissions were widened is not detected, and these checks are path-based rather than race-free, so treat the Windows protection against other principals as the profile's default ACL and nothing more.

### Sharing across machines

The manifest is plain JSON, but it is a per-user statement, not something to share. The binding is to the effective user ID on macOS and Linux (not to the machine), and on Windows to the current token SID plus the MachineGuid. A baseline copied to another account or computer is normally rejected because those identifiers differ, but a cloned environment that keeps them (a copied VM or image, or the same UID on another POSIX host) may still match. It is a guard against accidental cross-use, not authentication, and not a defence against malware running as the same user, which can compute the binding itself. Windows identity retrieval (token SID, MachineGuid) is unverified until the native Windows CI job has run. On another account or computer, install and review the tools there and run `orbit-generate-hashes`; never copy a baseline in. A manifest received from an untrusted source defeats the point.

### No override

There is no way to run a tool that failed verification, in the TUI or with `--headless`. For evaluation without installed tools, use `--dry-run`.

`orbit-generate-hashes` will not replace an existing baseline whose files differ for the same version. Find out why the files changed, then delete that version's entry by hand.

### What the check covers

Every file under the tool's install directory: changed, missing and added files all block the run, as do links and credential-like files inside that directory. A ROADtools baseline also covers its installed dependencies, but does not enable a real ROADtools run.

ORBIT runs a private read-only copy of the verified files, not the installation, and deletes it afterwards. It does **not** cover PowerShell, Python, OPA, or PowerShell modules the tool depends on, and a baseline only shows that files are unchanged since you recorded it, not that they were genuine then.

A tool is also blocked when it cannot be bound safely:

- exactly one absolute PowerShell 7 `pwsh` must be reachable on `PATH`;
- the temporary directory must be private to you (on Windows, inside your user profile).

These rules have been tested with fake tools on macOS, not with the real tools or on Windows. See [the audit report](docs/AUDIT_REPORT.md) for the remaining limits.

---

## How to Test Without a Work Tenant

You don't need a production M365 tenant to use or test ORBIT.

### Option 1 — Dry-run mode (no tenant at all)

```bash
python orbit.py --dry-run
```

Plays back fixture JSON instead of running real tools. It does not read or save credentials, probe PowerShell or installed tools, install anything, send email or notifications, or check for updates. The TUI, scoring engine, and report generation all work. Reports are labelled `(DRY RUN)`. Use this to explore the UI, demo to a client, or run in CI.

### Option 2 — Microsoft 365 E5 30-day free trial

Sign up at [microsoft.com/microsoft-365/enterprise/e5](https://www.microsoft.com/en-gb/microsoft-365/enterprise/e5) using a **throwaway Outlook/Hotmail account**. No credit card required for the trial. You get:
- 25 user licences, full E5 feature set (Entra ID P2, Defender, Purview, Exchange, Teams)
- 30 days — enough for a full build-and-test cycle

Deliberately misconfigure the sandbox (disable MFA for some users, enable legacy auth, weaken Conditional Access) to create real findings and verify ORBIT catches them.

### Option 3 — Microsoft 365 Developer Program sandbox (E5, 90-day auto-renew)

Sign up at [developer.microsoft.com/en-us/microsoft-365/dev-program](https://developer.microsoft.com/en-us/microsoft-365/dev-program). Gets you a full E5 sandbox with 25 pre-populated users that auto-renews every 90 days as long as you actively use it.

> **Note:** As of 2023, Microsoft requires a Visual Studio Professional/Enterprise subscription or partner programme membership to qualify.

### Option 4 — Unit tests (no tenant, no tool install)

```bash
pytest tests/ -v
```

~80% of the codebase — secrets, scoring, parsers, report generation, hash checks — is tested entirely with golden fixture JSON. No network connection needed.

---

## Usage Walkthrough

### Screen 1 — Home

On launch, ORBIT shows:
- An animated banner with a spinning ASCII Earth, satellite, and star field
- Tool status dashboard: installed ✓ / not installed ✗ / update available ↑ / incompatible OS ⚠
- Admin / elevation status with a warning if not running as Administrator
- System info: OS, PowerShell version

### Screen 2 — Credentials

Enter connection details for each tool you want to use. Values are stored in your OS keychain immediately on save — never on disk in plaintext.

| Tool | Required credentials |
|------|---------------------|
| ScubaGear / Maester | Tenant ID, App (Client) ID, Certificate thumbprint or Client Secret |
| Monkey365 | Tenant ID, App ID, Client Secret, Subscription ID (for Azure scope) |
| ROADtools | Not used: real runs are disabled |
| Hawk | Global Admin UPN |

### Screen 3 — Tools

Checkbox list to select which tools to run. Incompatible tools (wrong OS) and tools with missing credentials are flagged inline.

### Screen 4 — Output

- Choose an output directory (a unique subfolder is created automatically: `output/2026-11-01_14-32-07_3f9a1c2e/`)
- Select report formats: HTML, JSON, CSV (native tool formats), PDF, DOCX (ORBIT summary)
- Optionally encrypt the output folder to a Fernet-encrypted ZIP with a passphrase
- Option to save an unencrypted copy alongside the encrypted one
- ORBIT cannot extract its encrypted archives on Windows (extraction fails closed there): keep the unencrypted copy, or restore with ORBIT's Python API on macOS or Linux

### Screen 5 — Installer

Install or update any tool from its official source:
- ScubaGear, Maester, Monkey365, Hawk → PowerShell Gallery (`Install-Module`)
- ROADtools → install and update are disabled, as it is dry-run only; Remove is still available
- OPA binary → fetched by ScubaGear's own `Initialize-SCuBA`

pip honours `PIP_INDEX_URL`, `PIP_EXTRA_INDEX_URL`, `PIP_NO_INDEX`, `PIP_FIND_LINKS`, `PIP_CONFIG_FILE`, `PIP_TRUSTED_HOST`, `PIP_CERT`, `PIP_CLIENT_CERT` and `PIP_PROXY` for private-index and offline installs; other environment secrets are not passed on. pip's output is never shown or saved by ORBIT, because it can contain credentials from that configuration: you see the operation and its exit code. All installer actions are disabled in dry-run.

Shows the installed version and operation status. PowerShell installer and OPA set-up output and error text are withheld in the same way, because they can quote repository credentials. PowerShell installers run non-interactively, so an operation that needs a prompt (for example to trust a repository) must be run by you in a private terminal.

### Screen 6 — Run

- Each tool runs as an async subprocess with live streaming log output
- Per-tool status: Pending → Running → Complete ✓ / Failed ✗ / Skipped
- Stop individual tools or cancel all
- Credentials injected as environment variables only — never in process arguments

### Screen 7 — Report

View the generated summary and open the output folder. The ORBIT summary report contains:
1. Cover page: client name placeholder, date, assessor, tools used
2. Overall posture score (0–100) with severity breakdown
3. Top 2–3 critical/high findings with CVE references and remediation steps
4. Full findings table: ID, severity, title, source tool, control reference
5. Footer: "Generated by ORBIT v1.5.1 — No telemetry. Report data is sent by ORBIT only if you enable SMTP email."

---

## Output and Reports

```
output/
└── 2026-11-01_14-32-07_3f9a1c2e/
    ├── ORBIT_Summary.pdf          ← ORBIT executive summary
    ├── ORBIT_Summary.docx         ← same content as Word document
    ├── ScubaGear/
    │   ├── ScubaResults.html
    │   ├── ScubaResults.json
    │   └── ScubaResults.csv
    ├── Maester/
    │   └── MaesterReport.json
    └── Monkey365/
        └── Monkey365Report.json
```

The raw tool reports are preserved exactly as the tool produces them. ORBIT's summary is additive — it never modifies tool output.

---

## Scoring Methodology

See [docs/SCORING.md](docs/SCORING.md) for full details.

| Severity | Weight | Colour |
|----------|--------|--------|
| Critical | 10 | 🔴 Red |
| High | 7 | 🟠 Orange |
| Medium | 4 | 🟡 Yellow |
| Low | 1 | 🟢 Green |
| Pass | 0 | — |

**Posture score** = `(passed_controls / total_controls) × 100`

CVE references are looked up from a bundled static JSON (`orbit/data/cve_mappings.json`) keyed on M365 control IDs. No network calls are made for CVE data.

---

## Architecture

```
orbit-m365/
├── orbit.py                  ← entry point
├── orbit/
│   ├── config.py             ← AUTHOR, VERSION, YEAR constants, bundled-data paths
│   ├── tui/                  ← Textual screens and widgets
│   ├── core/
│   │   ├── secrets.py        ← keyring + Fernet fallback
│   │   ├── hash_checker.py   ← SHA-256 integrity gate
│   │   ├── baseline.py       ← orbit-generate-hashes (records ~/.orbit/tool_hashes.json)
│   │   ├── runner.py         ← async subprocess launcher
│   │   └── tools/            ← one adapter per tool
│   ├── reporting/            ← parser, scorer, PDF, DOCX
│   └── security/             ← folder encryption
├── orbit/data/
│   ├── cve_mappings.json     ← bundled CVE reference (offline)
│   ├── tool_hashes.template.json ← empty template that seeds ~/.orbit/tool_hashes.json (never a baseline)
│   └── fixtures/             ← anonymised sample tool output for --dry-run
├── tests/
└── docs/
```

**Stack:** Python 3.10+, [Textual](https://textual.textualize.io/), [Rich](https://github.com/Textualize/rich), [keyring](https://github.com/jaraco/keyring), [cryptography](https://cryptography.io/), [fpdf2](https://py-pdf.github.io/fpdf2/), [python-docx](https://python-docx.readthedocs.io/), [Jinja2](https://jinja.palletsprojects.com/), [click](https://click.palletsprojects.com/).

---

## Security and Privacy

See [docs/PRIVACY.md](docs/PRIVACY.md) for the full statement.

**Short version:**
- ORBIT sends nothing on its own except in two cases, and has **no telemetry or analytics**:
  - **Optional GitHub release check** — a single HTTPS request to `api.github.com` when the home screen opens in a real (non-dry-run) session. It sends no tenant, credential, finding or user data; GitHub sees your IP address. Set `update_check = false` under `[notifications]` in `~/.orbit/config.toml` to turn it off (there is no in-app toggle yet).
  - **SMTP email you configure and enable** — a test message from the Email screen, and, only when you tick *Email results when complete* on a real run, an email, sent to the SMTP server you configure (which may be a hosted provider) and on to the recipients you choose, containing assessment details (client name, posture score, severity counts, top findings with control IDs and remediation steps) and the PDF summary report as an attachment. Nothing is emailed unless SMTP is configured and enabled; dry-run never sends email. Keep *Use TLS* on.
- The tools ORBIT launches (Microsoft 365 API calls) and the installer (PowerShell Gallery, OPA download) make their own network connections.
- Secrets are stored in your **OS keychain** (Windows Credential Manager / macOS Keychain / libsecret). The Fernet-encrypted fallback (`~/.orbit/secrets.enc`) is used only if no keychain is available.
- Secrets are **never** written to plaintext files, logs, or process arguments.
- All CVE lookups use a **bundled offline JSON file** shipped inside the package.
- Output can be **Fernet-encrypted** (AES-128-CBC with HMAC-SHA256; PBKDF2 passphrase derivation) at rest.

---

## Credits and Acknowledgements

ORBIT is a launcher and orchestration layer. All security assessment capability comes from the independent tools listed below. Their authors deserve full credit.

| Tool | Author / Maintainer | Licence |
|------|---------------------|---------|
| [ScubaGear](https://github.com/cisagov/ScubaGear) | [CISA](https://www.cisa.gov/) | CC0 1.0 Universal |
| [Maester](https://github.com/maester365/maester) | [Merill Fernando](https://github.com/merill) and community contributors | MIT |
| [Monkey365](https://github.com/silverhack/monkey365) | [Juan Garrido (silverhack)](https://github.com/silverhack) | Apache 2.0 |
| [ROADtools](https://github.com/dirkjanm/ROADtools) | [Dirk-jan Mollema](https://github.com/dirkjanm) | MIT |
| [Hawk](https://github.com/T0pCyber/hawk) | [T0pCyber](https://github.com/T0pCyber) and community | MIT |
| [ORCA](https://github.com/cammurray/orca) | [Cam Murray](https://github.com/cammurray) | MIT (integrated via Maester) |
| [EIDSCA](https://github.com/Cloud-Architekt/AzureAD-Attack-Defense) | [Thomas Naunheim](https://github.com/Cloud-Architekt) and contributors | MIT (integrated via Maester) |
| [Open Policy Agent](https://www.openpolicyagent.org/) | [CNCF / OPA Community](https://github.com/open-policy-agent/opa) | Apache 2.0 (used by ScubaGear) |
| [Pester](https://pester.dev/) | [Jakub Jareš](https://github.com/nohwnd) and contributors | Apache 2.0 (used by Maester) |

**Python libraries:**

| Library | Author | Licence |
|---------|--------|---------|
| [Textual](https://github.com/Textualize/rich) | Textualize | MIT |
| [Rich](https://github.com/Textualize/rich) | Will McGugan / Textualize | MIT |
| [keyring](https://github.com/jaraco/keyring) | Jason R. Coombs | MIT |
| [cryptography](https://cryptography.io/) | PyCA | Apache 2.0 / BSD |
| [fpdf2](https://py-pdf.github.io/fpdf2/) | PyFPDF contributors | LGPL 3.0 |
| [python-docx](https://python-docx.readthedocs.io/) | Steve Canny | MIT |
| [Jinja2](https://jinja.palletsprojects.com/) | Armin Ronacher / Pallets | BSD |
| [click](https://click.palletsprojects.com/) | Pallets | BSD |

Reference documentation and standards:
- [CISA Secure Cloud Business Applications (SCuBA) Project](https://www.cisa.gov/resources-tools/services/secure-cloud-business-applications-scuba-project)
- [CISA SCuBA M365 Secure Configuration Baselines](https://github.com/cisagov/ScubaGear/tree/main/baselines)
- [CIS Microsoft 365 Foundations Benchmark](https://www.cisecurity.org/benchmark/microsoft_365)
- [NIST SP 800-53 Security Controls](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [MITRE ATT&CK for Cloud](https://attack.mitre.org/matrices/enterprise/cloud/)

---

## Legal Notices

See [LEGAL.md](LEGAL.md) for the complete legal notice including fair use, disclaimer of liability, and privacy statement.

**Summary:**

> ORBIT is provided as a personal, research, and educational tool under the MIT licence. Use it only against Microsoft 365 tenants you own or have written authorisation to assess. The author accepts no liability for misuse, data loss, or security incidents arising from use of this software or the tools it launches. All integrated tool names, trademarks, and logos belong to their respective owners.

---

## Contributing

Issues and pull requests are welcome. Please:
- Open an issue before starting significant work
- Keep PRs focused on a single change
- Run `pytest tests/ -v` and `ruff check .` before submitting
- Do not add telemetry, remote calls from ORBIT itself, or hardcoded credentials of any kind

---

## Author

**Reece Gabriel Dickson**  
Independent Cybersecurity Research Analyst  
[github.com/OrbitalSecurity](https://github.com/OrbitalSecurity)

---

*Only run ORBIT and the tools it launches against Microsoft 365 tenants you own or have explicit written authorisation to assess.*

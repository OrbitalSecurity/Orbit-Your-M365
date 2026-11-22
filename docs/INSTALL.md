# Installation Guide — ORBIT

## Before you start

ORBIT is a Python application that **launches** other security tools. Prerequisites depend on which tools you want to run.

| Prerequisite | Required for |
|-------------|-------------|
| Python 3.10+ | ORBIT itself |
| PowerShell 7 | ScubaGear, Maester, Monkey365, Hawk |
| Windows 10/11 | ScubaGear (Windows only) |
| M365 App Registration | Non-interactive tool runs |
| Global Administrator or delegated read roles | Most tools |

**ROADtools production execution is disabled** pending a memory-only or other non-plaintext authentication design. Do not install it for ORBIT: real runs are blocked, and `--dry-run` does not need it.

---

## Windows 10/11 (Primary)

> **Limitation: encrypted archives cannot be restored on Windows.** ORBIT can create an encrypted `.orbit.zip` there, but extraction fails closed on Windows ("extraction is not supported on Windows"). Keep the unencrypted copy of any run you need to read on Windows, or restore the archive on macOS or Linux.

### 1. Install Python 3.10+

Download from [python.org](https://www.python.org/downloads/). During install, tick **"Add Python to PATH"**.

Verify: `python --version`

### 2. Install PowerShell 7

```powershell
winget install Microsoft.PowerShell
```

Or download from [github.com/PowerShell/PowerShell/releases](https://github.com/PowerShell/PowerShell/releases).

Verify: `pwsh --version`

### 3. Clone and install ORBIT

```powershell
git clone https://github.com/OrbitalSecurity/Orbit-Your-M365.git
cd orbit-m365
python -m venv .venv
.venv\Scripts\activate
pip install -e ".[dev]"
```

### 4. Verify

```powershell
pytest tests/ -v       # the full suite should pass
python orbit.py --help
python orbit.py --dry-run   # launches TUI in dry-run mode, no tenant needed
```

### 5. Run ORBIT for real

Open **PowerShell 7 as Administrator** (right-click → Run as Administrator). ScubaGear and Maester need elevated rights for some operations.

```powershell
python orbit.py
```

Use the **Installer** screen to install each tool, then **Credentials** to enter your M365 connection details.

### PowerShell execution policy

If you see execution policy errors:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

---

## macOS

```bash
# Python 3.10+ (or use pyenv / brew)
brew install python@3.12

# PowerShell 7 (optional — needed for Maester, Monkey365, Hawk)
brew install powershell

# Clone and install
git clone https://github.com/OrbitalSecurity/Orbit-Your-M365.git
cd orbit-m365
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Verify
pytest tests/ -v
python orbit.py --dry-run
```

**Note:** ScubaGear is Windows-only. ORBIT shows it as "incompatible OS" on macOS. Maester, Monkey365 and Hawk are intended to work on macOS with PowerShell 7, but have not been validated with the real tools. ROADtools is dry-run only.

---

## Linux

```bash
# Python 3.10+ (apt example)
sudo apt install python3.12 python3.12-venv

# PowerShell 7 — see Microsoft's package repo:
# https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-linux

git clone https://github.com/OrbitalSecurity/Orbit-Your-M365.git
cd orbit-m365
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

pytest tests/ -v
python orbit.py --dry-run
```

**Keychain on Linux:** ORBIT uses `libsecret` via the `keyring` library (GNOME Keyring / KWallet). If neither is available, ORBIT falls back to a Fernet-encrypted file (AES-128-CBC with HMAC-SHA256, key derived from your passphrase with PBKDF2) at `~/.orbit/secrets.enc` and prompts for a passphrase.

---

## Setting up an M365 App Registration

For non-interactive / automated runs (recommended), create an App Registration in Entra ID:

1. Go to [portal.azure.com](https://portal.azure.com) → **Entra ID** → **App registrations** → **New registration**.
2. Name it (e.g., `ORBIT-Assessment`), choose **Accounts in this organisational directory only**, no redirect URI.
3. Note the **Application (client) ID** and **Directory (tenant) ID**.
4. Under **Certificates & secrets** → create a **Client secret** (or upload a certificate).
5. Under **API permissions**, add the permissions required by each tool you want to run. Refer to [docs/TOOLS.md](TOOLS.md) and each tool's official documentation for current permission lists.
6. Grant admin consent for the permissions.

Enter the Tenant ID, App ID, and client secret (or certificate thumbprint) in ORBIT's **Credentials** screen.

---

## Installing the security tools

Use ORBIT's **Installer** screen, or install manually:

```powershell
# ScubaGear
Install-Module -Name ScubaGear -Scope CurrentUser
Initialize-SCuBA        # downloads OPA binary

# Maester
Install-Module -Name Maester -Scope CurrentUser

# Monkey365
Install-Module -Name monkey365 -Scope CurrentUser

# Hawk
Install-Module -Name Hawk -Scope CurrentUser
```

---

## Tool integrity setup (required before first real run)

After installing tools you must record their SHA-256 hashes so ORBIT can check them for changes before each run. **Without this step, ORBIT will block every tool with "BLOCKED: integrity unverified".**

With your venv active (any directory):

```bash
orbit-generate-hashes
```

The command is installed with ORBIT. From a source checkout, `python scripts/generate_hashes.py` does the same. It finds each installed tool's directory, hashes every file, and writes the results into `~/.orbit/tool_hashes.json` (`$ORBIT_HOME/tool_hashes.json` if you set `ORBIT_HOME`). That file is yours: it lives outside the installed package, so upgrades and reinstalls do not touch it, and ORBIT never writes into the package. The first run creates `~/.orbit` (private) and the file from the package's empty template. Run it again any time you update a tool. It will not replace a differing baseline for a version it has already recorded: investigate the change, then delete that entry by hand.

A baseline from an older release (`data/tool_hashes.json` in a source checkout) is **not imported**; the command prints a note if it finds one, and you record a fresh baseline against installations you trust. The old file is left unchanged.

The baseline is a schema-2 file recorded for your account (and, on Windows, your computer). ORBIT refuses any other content by what is in it, not where it is: a schema-1 or unmarked file (such as an older `tool_hashes.json` copied into `~/.orbit`), the packaged template copied by hand, a file recorded for another user or computer (normally; see below), or a damaged file all block real runs. `orbit-generate-hashes` then exits with an error, leaves the file exactly as it was, and does not convert it. To start again, move the file aside and re-run the command:

```bash
mv ~/.orbit/tool_hashes.json ~/.orbit/tool_hashes.json.v1          # macOS / Linux
```

```powershell
Move-Item "$env:USERPROFILE\.orbit\tool_hashes.json" "$env:USERPROFILE\.orbit\tool_hashes.json.v1"   # Windows
```

(Adjust the folder if you set `ORBIT_HOME`.) You then record a new baseline against installations you trust; a baseline should not be copied between accounts or computers.

The binding is to the effective user ID on macOS and Linux (not to the machine), and on Windows to the current token SID plus the MachineGuid. A baseline copied to another account or computer is normally rejected because those identifiers differ, but a cloned environment that keeps them (a copied VM or image, or the same UID on another POSIX host) may still match. It is a guard against accidental cross-use, not authentication, and not a defence against malware running as the same user, which can compute the binding itself. Windows identity retrieval (token SID, MachineGuid) is unverified until the native Windows CI job has run.

The command locks the manifest while it works and replaces it in one step, so it is safe to interrupt or to start twice.

The location is vetted the same way when ORBIT reads the baseline before a real run and when this command writes it; a location that fails is refused for both. On macOS and Linux, `ORBIT_HOME` (default `~/.orbit`) and every directory above it must be owned by you (or root) and not writable by group or others, the manifest and its lock must be your own regular files without group/other write access or extra hard links, and symbolic links are refused for `ORBIT_HOME`, the directories you control above it, the manifest and the lock. `ORBIT_HOME` also may not be or lead into ORBIT's installed or source package, `orbit/data`, the checkout's legacy `data/` directory or another directory that held an older baseline. Errors name the problem, not the path: fix permissions with `chmod go-w`, or set `ORBIT_HOME` to a private directory you own.

On Windows ORBIT cannot verify folder owners or ACLs without extra dependencies, so it uses a conservative rule instead: `ORBIT_HOME` must be inside your user profile and contain no link or junction below it. It does not detect a widened profile ACL, and the checks are not race-free; do not rely on more than your profile's default permissions.

The baseline detects accidental changes and changes by other OS principals. It **cannot defend against a malicious process running as the same OS user**, which can alter the manifest as well as the files. A match is not proof of authenticity or provenance. A ROADtools baseline does not enable real ROADtools runs.

Confirm it worked by opening ORBIT's **Pre-flight** screen — each selected tool's "<tool> <version> integrity" row should show ✓ green.

> **Dry-run mode** (`--dry-run`) does not require this step — it uses fixture data only.

---

## Testing without a tenant

See the [Testing section in README.md](../README.md#how-to-test-without-a-work-tenant) for options including dry-run mode, the M365 E5 30-day trial, and the Microsoft 365 Developer Program sandbox.

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `pwsh: command not found` | Install PowerShell 7 and ensure it's on PATH |
| ScubaGear shows "incompatible OS" | Expected on macOS/Linux — ScubaGear is Windows-only |
| "more than one pwsh is on PATH" or "relative PATH entry" | Leave exactly one PowerShell 7 reachable, through an absolute `PATH` entry |
| "temporary path … is writable by other users" or "not inside the user profile" | Point `TMPDIR` (Windows: `TEMP`) at a directory only you can write to |
| ROADtools "real run disabled" | Expected: use `--dry-run` |
| An installer shows only an exit code | pip and PowerShell installer output is withheld because it can contain credentials, and prompts fail; run the installer yourself in a private terminal |
| "extraction is not supported on Windows" | Expected: the destination cannot be pinned there. Extract on macOS or Linux |
| Private package index or offline install | Set the `PIP_*` variables listed in the README before starting ORBIT |
| Keychain not available | ORBIT will use the encrypted file fallback; set a strong passphrase |
| `ModuleNotFoundError: No module named 'textual'` | Activate the venv: `source .venv/bin/activate` (Linux/macOS) or `.venv\Scripts\activate` (Windows) |
| Banner looks garbled | Use a modern terminal: Windows Terminal, iTerm2, or a terminal with full Unicode support |
| Tests fail with import errors | Ensure you installed with `pip install -e ".[dev]"` not `pip install -e .` |

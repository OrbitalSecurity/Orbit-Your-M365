# Privacy Statement — ORBIT

**ORBIT works on your machine and has no telemetry. By default your tenant data, credentials and findings stay on it.** ORBIT's own code makes two kinds of network request, both described under [Network activity](#network-activity): an optional GitHub release check, and SMTP email that you configure and explicitly enable.

---

## What ORBIT does NOT do

- Does not transmit findings, credentials, or configuration data to any server by default. The only exception is SMTP email that you configure and enable (see [Network activity](#network-activity)); it goes to the SMTP server you configure and the recipients you choose. That server may be a hosted mail provider and the recipients may be external; you select those destinations, and ORBIT never sends anything to the author automatically.
- Does not collect telemetry, usage statistics, or analytics.
- Does not send any tenant, credential, finding or user data in its GitHub release check (see [Network activity](#network-activity)).
- Does not use third-party crash reporting, logging services, or cloud storage of its own.
- Does not embed tracking pixels, beacons, or identifiers.

---

## Network activity

ORBIT's own code makes outbound requests in exactly two cases. Neither is telemetry or analytics.

### 1. Optional GitHub release check (automatic, can be turned off)

- **What:** a single HTTPS GET to `https://api.github.com/repos/OrbitalSecurity/Orbit-Your-M365/releases/latest` with a 3-second timeout. Only the published release tag is read. ORBIT sends no tenant, credential, finding or user data, and the request is not telemetry. GitHub, as the server, can see your IP address and the default Python HTTP client headers.
- **When:** when the home screen opens in a real (non-`--dry-run`) session.
- **Turning it off:** set `update_check = false` under `[notifications]` in `~/.orbit/config.toml`. This is a hand-edited setting; there is no in-app toggle yet. Failures are ignored silently.

### 2. SMTP email (only if you configure and enable it)

ORBIT never sends email unless SMTP is configured and enabled. The settings can be entered on the Email screen, or already be present in supported configuration: the `[email]` section of `~/.orbit/config.toml` and the stored SMTP credentials (OS keychain or the encrypted fallback file). However they got there, once SMTP is configured and enabled, two things can send mail, always to the SMTP server and recipients you chose. **User-configured SMTP sends the selected report data to that SMTP server and onward to those recipients.** A hosted provider's server can read the message and attachment, and external recipients receive them:

- **Test message** — when you press *Send test email* on the Email screen (not available in dry-run). It contains only a short fixed sentence. It does carry your From, To and Cc addresses to your SMTP server, as any email does.
- **Results email** — after a real (non-dry-run) run, only when *Email results when complete* is ticked on the Run screen (its default comes from `email_notify` under `[notifications]` in `~/.orbit/config.toml`, which is off by default). The message contains **assessment details**: the client name, report date, posture score, severity counts, the top findings (control ID, tool, title and remediation steps), plus the **PDF summary report** as an attachment. Dry-run and `--headless` runs never send email.
- **Protection in transit:** with *Use TLS* on (the default), the connection uses STARTTLS or SSL on port 465, and ORBIT refuses to send an SMTP password over a plaintext connection. If you turn TLS off, the message and attachment travel unencrypted. Once the email reaches your mail server, its handling is governed by that server and the recipients' mail systems, not by ORBIT.
- **Stored settings:** host, port, TLS and recipients are in `~/.orbit/config.toml` (the Email screen writes them there, and so can an edit by hand or a restored configuration); the From address and password are in the OS keychain (or the encrypted fallback file). Check those stores if you did not expect email to be possible.

### Network activity by launched tools and installers

Other network activity that occurs when using ORBIT:

| Activity | Who initiates it | When |
|----------|-----------------|------|
| Microsoft 365 API calls | The tool ORBIT launches (ScubaGear, Maester, etc.) | During a run |
| PowerShell Gallery downloads | `pwsh` / `Install-Module` | Only when you press Install/Update in the Installer screen |
| OPA binary download | ScubaGear's `Initialize-SCuBA` | Only during ScubaGear first-time setup |

There are no PyPI downloads: ROADtools install and update are disabled.

The rows above are standard, expected operations of the underlying tools, not initiated by ORBIT's own code. Apart from these, the only requests ORBIT's own code makes are the GitHub release check and the SMTP email described above.

### What ORBIT does not do on the network

There is no telemetry, analytics, crash reporting or usage statistics, and no automatic submission of anything to the author. CVE and remediation data are bundled in the package and looked up offline. Desktop notifications are local.

---

## What is stored on your machine

| Data | Location | Format | Encrypted? |
|------|----------|--------|-----------|
| Credentials (Tenant ID, App ID, secrets) | OS keychain (`orbit-m365` service) | Keychain-protected | Yes — by OS |
| Credentials (fallback if no keychain) | `~/.orbit/secrets.enc` | Fernet (AES-128-CBC with HMAC-SHA256), key from PBKDF2-HMAC-SHA256 (600,000 iterations), file mode 0600 | Yes |
| Tool output (raw) | `output/YYYY-MM-DD_HH-MM/<tool>/` or your chosen directory | As produced by each tool (HTML, JSON, CSV) | Optional |
| ORBIT summary report | `output/YYYY-MM-DD_HH-MM/ORBIT_Summary.pdf` and `.docx` | Plain PDF / DOCX | Optional |
| Integrity baseline | `~/.orbit/tool_hashes.json` (`$ORBIT_HOME/tool_hashes.json`), recorded by `orbit-generate-hashes`; never inside the installed package | JSON: file names and SHA-256 hashes of tool files, plus install paths | No (not secret) |
| SMTP settings | host, port, TLS and recipients in `~/.orbit/config.toml`; From address and password in the OS keychain (`orbit-m365/smtp`) | TOML / keychain | Keychain items: yes — by OS |
| Encrypted output bundle (opt-in) | `<run folder>.orbit.zip` | ZIP then Fernet-encrypted (AES-128-CBC with HMAC-SHA256) with a PBKDF2 key from your passphrase | Yes |

**Not stored anywhere:**
- Passphrases (held in memory for the session only; not recoverable if forgotten)
- Plaintext credentials in any file
- Credentials in process arguments (secrets are passed via environment variables of child processes only — never in `argv`, which `ps`/`top` can reveal)
- Log files containing secrets (masked with `***` in all log output)

---

## Credential storage detail

ORBIT uses the `keyring` library, which delegates to:

| OS | Backend |
|----|---------|
| Windows | Windows Credential Manager |
| macOS | macOS Keychain |
| Linux (GNOME) | libsecret / GNOME Keyring |
| Linux (KDE) | KWallet |
| Linux (no keyring) | Fernet-encrypted fallback file |

The service name stored in the keychain is `orbit-m365`. The username key is the tool name (e.g., `scubagear`, `maester`). The secret value is a JSON blob containing the tool's credentials, encrypted by the OS keychain before writing to disk.

The Fernet fallback (AES-128-CBC with HMAC-SHA256) uses a key derived from your passphrase via PBKDF2-HMAC-SHA256 with a random 16-byte salt and 600,000 iterations. The salt is stored alongside the encrypted blob. The passphrase itself is never stored.

---

## Tool output sensitivity

The output of ScubaGear, Maester, Monkey365, and other tools contains **detailed information about your Microsoft 365 tenant configuration**. This data may include:

- Names and states of Conditional Access policies
- User and admin account details (display names, UPNs)
- Application and service principal names
- Licence and feature states
- Security and compliance policy configurations

**Treat tool output as sensitive data.** Store it in a location appropriate to your organisation's data classification policies. Use ORBIT's optional output encryption if the assessment data should be protected at rest.

---

## Third-party tool privacy

Each tool ORBIT launches has its own privacy and data handling characteristics:

- **ScubaGear and Maester** connect to Microsoft 365 APIs. Microsoft's data handling is governed by your Microsoft service agreement and applicable data processing agreements.
- **ROADtools production execution is disabled** pending memory-only or other non-plaintext authentication; only fixture-based dry-run is supported. ORBIT does not launch it, so it signs in to nothing and collects no tenant data through ORBIT.
- **Hawk** reads Exchange and Entra audit logs and writes them to local files. ORBIT does not send Hawk's raw output anywhere; only the summary email described above, if you enable it, carries ORBIT's findings.
- **Monkey365** reads Microsoft API data and writes reports locally. ORBIT does not send Monkey365's raw output anywhere; only the summary email described above, if you enable it, carries ORBIT's findings.

Review each tool's documentation for current information on their data handling.

---

## Open source and auditability

ORBIT's source code is fully open. You can review exactly what it does at:

https://github.com/OrbitalSecurity/Orbit-Your-M365

There are no compiled binaries, obfuscated code, or pre-built executables in ORBIT itself. You run it from source or from the Python package.

---

*This privacy statement describes ORBIT v1.5.1 as of November 2026. It will be updated if the software's data handling changes.*

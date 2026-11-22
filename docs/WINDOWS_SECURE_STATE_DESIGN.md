# ORBIT v1.5.1 — Windows secure-state architecture and validation design

| | |
|---|---|
| Status | Design spike output. **Specification only; nothing in it is implemented.** |
| Baseline inspected | `main` at `d365a9e` plus the uncommitted release-candidate working tree (47 changed or untracked paths at spike start) |
| Release status | **v1.5.1 is not releasable with any Windows cross-user protection claim.** See §9.4. |
| Audience | The implementer (a future Claude session), the independent Codex reviewer, and the user who approves the build |

Conventions used below:

- **[D]** a behaviour or constant I believe is documented by Microsoft but which the implementer must re-confirm against the current Microsoft documentation or SDK header before relying on it.
- **[N]** a behaviour that is **not established** and must be proven by a native Windows test before the design may depend on it. Where a design choice rests on a **[N]** item, the choice has a named fallback or a stop condition.
- **[V]** verified during this spike, on the macOS host, by reading the code or running a local probe. Nothing is **[V]** for Windows.

No Windows security claim in this document is established. The Windows design is a hypothesis with a test plan.

---

## 0. Evidence gathered in this spike

### 0.1 Code reading (what the current candidate really does) [V]

| Finding | Where | Consequence |
|---|---|---|
| The reader never looks at `schema`. `load_manifest` returns `json.loads(...)`; `check_tool` reads `manifest["tools"][tool]["versions"][version]["files"]` and nothing else. | `orbit/core/hash_checker.py:185-194`, `:206-208` | **A schema-1 manifest copied from any old checkout into `ORBIT_HOME/tool_hashes.json` is accepted today.** `legacy_manifests()` only *prints a note* about two known paths (`orbit/core/baseline.py:39-48`). This is the independent reviewer's first finding, confirmed. |
| The packaged template and the writer both emit `"schema": 1`. | `orbit/data/tool_hashes.template.json`, `orbit/core/manifest.py:152`, `scripts/ci_package_checks.py:46` | The v2 change touches all three. |
| On Windows the policy is path-based only: no owner, no DACL, `Path.home()` (which reads `USERPROFILE`), `lstat`-based link checks, then ordinary `os.open`/`os.replace` by path. | `orbit/core/trusted_state.py:323-351`, `orbit/core/manifest.py:22-25,121-138` | Confirms the reviewer's third finding: `os.open(..., O_CREAT)` on the lock does not pass `FILE_FLAG_OPEN_REPARSE_POINT`, so a reparse point at the lock path is followed before `vet_file` can reject it. |
| `manifest.py` works on raw file descriptors (`state.open` returns an fd, then `os.fstat`, `os.fdopen`, `fchmod`, `msvcrt.locking`). | `orbit/core/manifest.py:58-85,114-143` | A Windows backend cannot slot in under this interface. The interface must move up one level (§5). |
| `ORBIT_HOME` is an environment variable. | `orbit/core/config_store.py:26-28` | The location is attacker-influenceable only by the same user; that is inside the retained limitation. |
| Existing Windows "tests" run the path-based function on the macOS/Linux host. | `tests/test_baseline_trust_path.py:405-460` | They test our logic, not Windows. They must not be cited as Windows evidence. |
| `KICKOFF.md`, referenced by `CLAUDE.md` and `AGENTS.md`, is not present in the repository. | `ls KICKOFF.md` | Scope rules were taken from `AGENTS.md` and `CLAUDE.md` only. |

### 0.2 macOS ACL probes [V] (scratch files under `/tmp/spike`, removed afterwards)

Run with `ctypes` against the system libc on Darwin 25.6 (arm64):

| Probe | Result |
|---|---|
| `acl_get_fd_np(fd, ACL_TYPE_EXTENDED = 0x100)` on a file with **no** ACL | returns `NULL`, `errno == ENOENT` |
| same call on a file/directory **with** an ACL entry | returns a non-`NULL` `acl_t` with that entry |
| `acl_get_entry(acl, ACL_FIRST_ENTRY = 0, &e)` then `ACL_NEXT_ENTRY = -1` | `0` per entry; at the end returns `-1` with `errno == EINVAL` (macOS semantics, not the POSIX 0/1 convention) |
| `acl_get_tag_type` values | `ACL_EXTENDED_ALLOW = 1`, `ACL_EXTENDED_DENY = 2` (from `sys/acl.h`) |
| `acl_get_file` on a symlink | **follows** the link and returns the target's ACL |
| `acl_get_link_np` on a symlink | looks at the link itself (`ENOENT`: links carry no ACL) |
| `acl_get_fd_np` on a directory fd opened `O_DIRECTORY` | works |
| **The default macOS home directory** (`/Users/<name>`, `drwxr-x---+`) | carries `0: group:everyone deny delete` |
| `/Users` | no ACL |
| Entry order from `chmod +a` | a file with `deny delete` then `allow write` returned tags `[2, 1]` |

The home-directory result is decisive for §4: a rule of "refuse any ACL on any component" would reject every default macOS install, because the parent of `~/.orbit` has one.

### 0.3 What was not and could not be verified

- Every Win32 behaviour in §3. There is no Windows host, no VM application installed (`/Applications` has no UTM, Parallels or VMware) and this spike must not install software.
- Linux POSIX-ACL behaviour (§4.4) was not executed here; it follows from POSIX ACL semantics and needs one Linux CI run.
- `uname -m` reports `arm64`. Any local Windows VM would be Windows 11 ARM64, which is not the x64 target (§7.2).

---

## 1. Scope and non-goals

### 1.1 The security property

Define the property precisely, because every later choice is judged against it.

> **P1 (baseline integrity).** A real-run authorisation derived from the integrity baseline is granted only if the bytes that were compared against the installed tool files were read, by one open handle or descriptor, from a regular file at `ORBIT_HOME/tool_hashes.json` such that, at the time of that read and again immediately before the bytes were used:
>
> 1. every directory from the volume root down to `ORBIT_HOME`, and the file itself, was reached without following any symbolic link, junction, mount point or other reparse point;
> 2. each of those objects is owned by the current user or by a principal that already controls the whole machine (administrators, the system), and its access-control list grants no write, delete, change-permissions or take-ownership right (and, for directories, no create/delete-child right) to any other principal;
> 3. the file has exactly one hard link, is not pending deletion, and is on a local NTFS volume (Windows) or a local volume whose ACLs can be read (macOS/Linux);
> 4. its content is a **schema-v2 baseline bound to this user and this machine** (§2), and no schema-v1 or otherwise unbound content can satisfy that check at any location;
> 5. `ORBIT_HOME` lies inside the profile directory of the current user, and that profile is identified by the account's token, not by an environment variable alone.
>
> If any condition cannot be established, the result is `UNVERIFIED` and the gate stays shut. There is no override.

**P2 (write safety).** `orbit-generate-hashes` modifies the baseline only while holding an exclusive writer lock that it created or opened without following a link, and publishes the new content by an atomic replacement whose result is re-verified, so that after a crash or concurrent writers the baseline is either entirely the old content or entirely the new content, never a mix, and no entry is lost.

### 1.2 Threat model

In scope (these are the attackers the design must stop):

| # | Attacker capability | Where it is addressed |
|---|---|---|
| T1 | Another standard local user, with ordinary rights on shared locations | §3.4 DACL policy, §3.3 walk, §3.5 volume rules |
| T2 | A principal with a writable ACE on `ORBIT_HOME`, its file, its lock or a parent (explicit, inherited, via a broad group such as `Users`, `Authenticated Users`, `Everyone`) | §3.4 |
| T3 | Symlinks, junctions, mount points, other reparse points at **any** component, including the final file and the lock | §3.3, §3.6 |
| T4 | Hard links to the baseline or lock | §3.4 (`NumberOfLinks`) |
| T5 | Concurrent writers, including a second `orbit-generate-hashes` and a reader during replacement | §3.7 |
| T6 | Rename or replacement races between check and use (TOCTOU) on any component | §3.3 handle pinning, §3.8 re-checks |
| T7 | Crashes and kill at any step; stale temporary files; stale lock | §3.7, §6 |
| T8 | Package upgrade/downgrade, and a leftover or copied baseline from an older checkout or release | §2, §6 |
| T9 | Unsupported or look-alike storage: FAT/exFAT, SMB/UNC, `subst`, removable media, cloud placeholders | §3.5 |

**Retained limitation (must remain stated in user documentation).** A malicious process running as the *same* Windows user, or as an administrator or SYSTEM, can alter the baseline and the installed tool files alike. The baseline detects accidental change and tampering by other principals; it is neither authenticity nor provenance. Nothing here tries to close that gap (no secret store, no HMAC, no code signing).

### 1.3 Non-goals

- Tenant, credential, tool-execution and snapshot behaviour (`hash_checker._snapshot`, `hash_tree`, `Binding`) are unchanged.
- General `ORBIT_HOME` state (`config.toml`, `history.json`, reports, secrets) is not placed under this backend. Only the baseline directory policy and the baseline/lock/temp files use it.
- No unrelated refactors. The POSIX walk is kept as it is, moved only as far as §5 requires.
- **No new runtime dependency.** `ctypes`, `struct`, `winreg`, `msvcrt` and `hashlib` from the standard library suffice (justification in §9.1, D3). `pywin32` is rejected.
- No change to file-set discovery, hash algorithm, report formats, TUI or email behaviour.
- No claim about the Windows `%TEMP%`, archive extraction or installation directories.
- Authenticode, WDAC, AppLocker, Defender exclusions and Group Policy interactions are out of scope; where they might disturb the backend (§3.9) the failure mode is fail-closed.

---

## 2. Baseline format migration (schema v2)

### 2.1 Why a content marker, and why it removes the checkout search

The current defence against old manifests is location-based: forbid the package directory, `orbit/data`, the repository `data/` directory, and match their file identity (`trusted_state.py:72-126`). That can only recognise checkouts ORBIT can find. It cannot recognise `D:\old\orbit\data\tool_hashes.json` that the user copied into `ORBIT_HOME`, because that file is then in a perfectly good directory.

Schema v2 changes the question from *"where did this come from?"* to *"can this content have been produced by the v2 writer for this user and machine?"*. No file written before v2 contains the v2 marker or a binding that matches, so the reader rejects it **wherever it sits**. The existing location checks stay as defence in depth but are no longer load-bearing for legacy rejection.

### 2.2 Schema-v2 structure

```json
{
  "schema": 2,
  "kind": "orbit.integrity-baseline",
  "binding": {
    "os": "win32",
    "principal": "3f2c…64 lowercase hex…",
    "machine": "9a71…64 lowercase hex…"
  },
  "generator": {"orbit": "1.5.1"},
  "tools": {
    "scubagear": {"versions": {
      "1.4.0": {"install_dir": "C:\\…", "files": {"relative/path.psm1": "ab12…64 hex…"}}
    }}
  }
}
```

Rules (a *closed* schema; anything else is rejected, not ignored):

| Field | Rule |
|---|---|
| `schema` | JSON integer exactly `2`. `true`, `2.0`, `"2"`, `null`, absent → rejected. `1` → **LEGACY**. Any integer `> 2` → **NEWER**. |
| `kind` | exact string `orbit.integrity-baseline`. |
| `binding.os` | `"win32"` or `"posix"`; must equal the running platform class. |
| `binding.principal` | `sha256("orbit-baseline-v2|principal|" + P)` hex, where `P` is the token user SID string on Windows (`S-1-5-21-…`) or `"uid:" + str(os.geteuid())` on POSIX. Must equal the value computed now. |
| `binding.machine` | Windows: `sha256("orbit-baseline-v2|machine|" + MachineGuid)` hex, with `MachineGuid` read through `winreg` from `HKLM\SOFTWARE\Microsoft\Cryptography` (64-bit view). POSIX: the JSON value `null` (no portable stdlib machine id; the principal binding and the directory policy carry the weight there). Must match; on Windows `null` is rejected. |
| `generator.orbit` | informational string; never used for a decision. |
| `tools` | object; each tool → `{"versions": {version → {"install_dir": str, "files": {rel → 64 lowercase hex}}}}`. File keys must be non-empty relative `/`-separated paths with no `..`, no leading `/`, no drive letter, no NUL. Digests must match `^[0-9a-f]{64}$`. |
| any other key at top level, in `binding`, or `generator` | rejected (`MALFORMED`). Forward compatibility is by raising `schema`, never by tolerating unknown keys. |

The user and machine identifiers are **hashed** so that a baseline attached to a bug report does not disclose the account SID or machine GUID (`docs/PRIVACY.md` spirit). The hash is not a secret and not an authenticator: a same-user process can compute it. It exists to stop *accidental* trust of a baseline recorded for someone else (§2.5). On POSIX the binding is to the effective UID, not the machine; on Windows to the current token SID plus MachineGuid. Windows identity retrieval is unverified until native CI has run.

`install_dir` is kept because the existing writer records it; it is informational.

A self-checksum or HMAC of the body is deliberately **not** included (D2, §9.1): a checksum would break the documented "delete one entry by hand" workflow, and an HMAC key readable by the same user adds no cross-principal protection.

### 2.3 Generation

1. The packaged template becomes `{"schema": 2, "kind": "orbit.integrity-baseline", "tools": {…empty versions…}}` **without** `binding` or `generator`. A raw copy of the template therefore fails read validation (`binding` missing). "The template is never a baseline" becomes structural instead of a convention.
2. `seed_manifest` (first run) loads the template bytes, parses them as a template, inserts `binding` and `generator`, and writes the result through the secure-state backend (§5). It never copies template bytes verbatim.
3. `update_manifest` validates the existing file with exactly the reader's validator (`parse_baseline`) **before** yielding it. A schema-1 file raises `ManifestError(LEGACY)`; the file is left byte-for-byte untouched.
4. `record()` is unchanged except that it operates on the validated structure.
5. `json.dumps(..., indent=2, sort_keys=True)`; UTF-8; trailing newline.

### 2.4 Read validation

`parse_baseline(data: bytes, expected: Binding) -> Baseline` is a pure function in a new module (§5.1). It applies §2.2 in this order and returns a typed error code at the first failure:

`TOO_LARGE` (> 16 MiB) → `NOT_JSON` / `NOT_OBJECT` → `LEGACY` → `NEWER` → `MALFORMED` (kind, closed keys, types) → `BINDING_MISSING` → `BINDING_MISMATCH` → `ENTRY_MALFORMED`.

`LEGACY` is decided on the **content** (`schema` is `1`, or `schema` is absent while `tools` is present) — never on the file name or path. `hash_checker.check_tool` accepts only a `Baseline` object produced by this function over bytes returned by the secure-state backend (§5.4).

### 2.5 Sharing and copying a baseline

A schema-v2 file copied to another user or machine is **normally rejected** (`BINDING_MISMATCH`) because the identifiers differ; a cloned environment that keeps them may match, and the check is an accidental-cross-use guard, not authentication. This is the intended behaviour:

- The baseline is a per-user statement (and, on Windows only, per-machine; on POSIX the binding is to the effective UID, not the machine): "these are the tool files *I* approved on *this* computer". File hashes depend on installed versions and paths that differ between machines.
- The secure-state check authenticates *where the file lives and who can change it*, not *who wrote it*. If a copied file were accepted, the only thing vouching for its content would be whoever put it there.
- Deliberate sharing remains possible and compatible with the trust model **by recomputation, never by trust**: the recipient installs the tools, reviews them, and runs `orbit-generate-hashes`, which hashes the local files. A future `--compare-with FILE` option may *report differences* against a shared file but must never import it (out of scope for 1.5.1).
- A re-imaged machine or a VM given a new `MachineGuid` fails closed, which is the right outcome: the installed tools may differ. A clone that retains its `MachineGuid` and SID (and a POSIX copy that keeps the same UID) is not detected. A renamed Windows account keeps its SID and keeps working; a deleted-and-recreated account has a new SID and must regenerate.

### 2.6 Upgrade UX and the no-auto-import rule

There is **no** code path that reads a schema-1 file as data other than to detect that it is schema 1 and refuse it. `legacy_manifests()` is retained only to *name* known legacy locations in help text.

Fixed message texts (no paths, no SIDs; tests assert on a stable code, then on text):

| Code | Message |
|---|---|
| `LEGACY` | `the baseline is in the older unbound format (schema 1). ORBIT does not trust or import it, wherever it came from. Move it aside and run orbit-generate-hashes to record a new baseline for this user and machine.` |
| `NEWER` | `the baseline was written by a newer ORBIT (schema N). Update ORBIT, or move the file aside and run orbit-generate-hashes.` (`N` is the integer, validated to be an int ≤ 9999 before it is printed.) |
| `BINDING_MISSING` | `the baseline carries no user and machine binding, so it cannot be trusted (it may be the packaged template or an older file). Run orbit-generate-hashes.` |
| `BINDING_MISMATCH` | `the baseline was recorded for a different user or computer. Run orbit-generate-hashes to record one for this user and machine; a baseline is never copied between accounts.` |
| `MALFORMED` / `ENTRY_MALFORMED` / `NOT_JSON` / `NOT_OBJECT` / `TOO_LARGE` | `the baseline is damaged or not in the expected format. Move it aside and run orbit-generate-hashes.` |

Upgrade flows:

- **Fresh install:** no file → `UNVERIFIED (no baseline)` as today; `orbit-generate-hashes` seeds v2.
- **Candidate or interim build with a schema-1 `ORBIT_HOME/tool_hashes.json`:** the reader reports `LEGACY`; `orbit-generate-hashes` exits 1 with the `LEGACY` message and the exact manual step (`Move-Item "$env:USERPROFILE\.orbit\tool_hashes.json" "$env:USERPROFILE\.orbit\tool_hashes.json.v1"`; `mv ~/.orbit/tool_hashes.json ~/.orbit/tool_hashes.json.v1`). There is **no** `--replace-legacy` flag in 1.5.1: the only population of schema-1 files in `ORBIT_HOME` is unreleased candidate builds, so one deliberate manual step is cheaper than a new destructive option. (Reconsider if telemetry-free field reports show otherwise.)
- **Checkout manifest from ≤ 1.5.0 (`data/tool_hashes.json`):** never read by ORBIT ≥ 1.5.1. The existing "ignoring the older baseline" note is kept.

Rollback and downgrade:

- ORBIT ≤ 1.5.0 never reads `ORBIT_HOME/tool_hashes.json`; after a downgrade it finds no baseline at its own location. Fail closed.
- The unreleased schema-1 candidate does not validate `schema` and would read a v2 file's `tools` as before, since the `tools` shape is unchanged. That candidate is not a supported downgrade target; this is documented rather than engineered around.
- A future reader meeting schema 3 reports `NEWER`.
- The Windows backend adds no on-disk format. File names (`tool_hashes.json`, `tool_hashes.json.lock`) are unchanged, so a mixed-version moment is safe: the old `msvcrt.locking` writer and the new exclusive-share writer exclude each other, because the old writer holds a read/write handle and the new open requests share mode 0 (§3.7, **[N]** N-CONC-05).

---

## 3. Windows native backend

Everything in this section is a **design hypothesis**. The implementer must re-confirm each **[D]** item against Microsoft documentation and may not rely on any **[N]** item until the named native test has passed.

### 3.1 Technology and structure

- `ctypes` with `ctypes.WinDLL("kernel32", use_last_error=True)`, `advapi32`, `userenv`; stdlib `winreg`, `struct`, `hashlib`.
- Every foreign function gets explicit `argtypes` and `restype`. Handles are `ctypes.c_void_p` (never the default `int` restype: 64-bit handle truncation is a known ctypes defect). `INVALID_HANDLE_VALUE` is `ctypes.c_void_p(-1).value`.
- **Parsing is pure Python.** Security descriptors, ACLs and SIDs are copied out of native memory with `ctypes.string_at` once and parsed with `struct` (§3.4). This keeps `GetAce`, `EqualSid`, `ConvertSidToStringSidW` out of the trust path and lets the parser and the policy evaluator be unit-tested on macOS/Linux with hand-built binary ACLs. The native layer is limited to *obtaining bytes*.
- A thin `Win32Api` object holds every native call. Production wires `ctypes`; tests inject a fake (§6.1). No policy code touches `ctypes` directly.
- The module must import cleanly on POSIX (`ctypes.WinDLL` is resolved lazily inside `Win32Api.__init__`), so the unit tests run everywhere.

### 3.2 Principal, profile and machine identity

| Need | Call sequence | Notes |
|---|---|---|
| Current user SID | `OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY \| TOKEN_DUPLICATE \| TOKEN_IMPERSONATE, &tok)`; `GetTokenInformation(tok, TokenUser = 1, buf, n, &need)` twice (first call returns `ERROR_INSUFFICIENT_BUFFER`); the SID bytes follow the `TOKEN_USER` header. | The SID is the same in a UAC-filtered and an elevated token of the same account. **[D]** |
| SID → string | pure Python from bytes (`S-1-<authority>-<sub>…`) | Not `ConvertSidToStringSidW`. |
| Profile directory | `GetUserProfileDirectoryW(tok, buf, &chars)` (userenv.dll), sized by the first call | Reads the profile path registered for the account SID, not `USERPROFILE`. **[D]** the exact access the token needs (Microsoft documents `TOKEN_QUERY`, `TOKEN_IMPERSONATE`, `TOKEN_DUPLICATE`; confirm). If the call fails the backend fails closed. `Path.home()`/`USERPROFILE` is **not** used for trust (it is attacker-influenceable by the same user and by tests). **[N]** N-ID-01 compares the two on a pristine profile. |
| Machine id | `winreg.OpenKey(HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography", 0, KEY_READ \| KEY_WOW64_64KEY)` → `MachineGuid` | Unreadable → fail closed. |

**Trusted principal sets** (SIDs as strings; compared as strings after pure-Python decoding):

- `U` = current user SID.
- `ADMIN` = `S-1-5-32-544` (BUILTIN\Administrators). Accepted as *owner* and as an ACE holder because administrators are inside the retained limitation, and because an elevated process commonly creates objects owned by this group. **[N]** N-ACL-07 confirms the owner an elevated token produces.
- `SYSTEM` = `S-1-5-18`.
- `TI` = `S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464` (NT SERVICE\TrustedInstaller). **[N]** confirm the value with `sc.exe showsid TrustedInstaller` on the runner; used only for system-owned ancestors.

Policy sets: **file/profile-and-below** trusted = `{U, ADMIN, SYSTEM}`; **ancestor** trusted = `{ADMIN, SYSTEM, TI}` (plus `U` is *not* needed above the profile).

### 3.3 Opening and walking the path

#### 3.3.1 Normalisation (before any API call)

`ORBIT_HOME` is made absolute with `os.path.abspath` (which uses `GetFullPathNameW`), converted to the `\\?\` extended-length form, and checked as text. Reject with a fixed code and **zero native calls** if:

- it starts with `\\` but not `\\?\<drive>:\` (UNC, `\\.\` device, `\\?\UNC\`, `\\?\Volume{…}`, `\\?\GLOBALROOT`);
- it has no drive letter;
- any component is `.` or `..`, ends with `.` or space, contains `:` (alternate data stream), `<>"|?*`, a control character, or is a reserved device name (`CON`, `PRN`, `AUX`, `NUL`, `COM1-9`, `LPT1-9`, with or without extension);
- the extended path is longer than 32 000 UTF-16 code units (leaves room for the lock and temporary names under the 32 767 hard limit).

Long paths work because the `\\?\` prefix switches off the 260-character `MAX_PATH` normalisation; the manual normalisation above replaces what Win32 would have done. **[D]** `\\?\` paths are not re-normalised by `CreateFileW`; **[N]** N-VOL-05 proves a 300-character `ORBIT_HOME` opens.

#### 3.3.2 Handle semantics table

| Handle | `CreateFileW` desired access | Share | Disposition | Flags |
|---|---|---|---|---|
| Directory in the chain | `FILE_LIST_DIRECTORY (0x1) \| FILE_READ_ATTRIBUTES (0x80) \| READ_CONTROL (0x20000)` | `FILE_SHARE_READ \| FILE_SHARE_WRITE` — **no `FILE_SHARE_DELETE`** | `OPEN_EXISTING` | `FILE_FLAG_BACKUP_SEMANTICS (0x02000000) \| FILE_FLAG_OPEN_REPARSE_POINT (0x00200000)` |
| Baseline, reading | `FILE_READ_DATA (0x1) \| FILE_READ_ATTRIBUTES \| READ_CONTROL` | `FILE_SHARE_READ` | `OPEN_EXISTING` | `FILE_ATTRIBUTE_NORMAL (0x80) \| FILE_FLAG_OPEN_REPARSE_POINT \| FILE_FLAG_OPEN_NO_RECALL (0x00100000)` |
| Lock (writer) | `GENERIC_READ \| GENERIC_WRITE \| READ_CONTROL` | **`0` (exclusive)** | `OPEN_ALWAYS` | `FILE_ATTRIBUTE_NORMAL \| FILE_FLAG_OPEN_REPARSE_POINT \| FILE_FLAG_OPEN_NO_RECALL`, with `SECURITY_ATTRIBUTES` carrying the protected DACL of §3.4.4 and `bInheritHandle = FALSE` |
| Lock probe (reader, §5.5) | `FILE_READ_ATTRIBUTES \| READ_CONTROL` | `FILE_SHARE_READ \| FILE_SHARE_WRITE` | `OPEN_EXISTING` | `FILE_FLAG_OPEN_REPARSE_POINT \| FILE_FLAG_OPEN_NO_RECALL` |
| Temporary file | `GENERIC_WRITE \| READ_CONTROL \| DELETE` | `0` | `CREATE_NEW` | `FILE_ATTRIBUTE_NORMAL \| FILE_FLAG_OPEN_REPARSE_POINT`, protected-DACL `SECURITY_ATTRIBUTES`, `bInheritHandle = FALSE` |
| Post-replace verification | `FILE_READ_DATA \| FILE_READ_ATTRIBUTES \| READ_CONTROL` | `FILE_SHARE_READ` | `OPEN_EXISTING` | as "Baseline, reading" |

Rules shared by all handles:

- **`FILE_FLAG_OPEN_REPARSE_POINT` on every open**, including `OPEN_ALWAYS`/`CREATE_NEW`. **[D]** For the *final* path component it makes `CreateFileW` open the reparse point itself instead of its target; **[N]** N-LNK-04 proves that with `OPEN_ALWAYS` on a symlink or junction (and on a dangling symlink) the target is neither followed nor created. This is the direct fix for the lock-redirection finding.
- **`FILE_FLAG_OPEN_REPARSE_POINT` does not apply to intermediate components** **[D]**; those are protected by the walk, the pins and the final-path comparison below.
- `bInheritHandle` is always `FALSE`, and no handle is duplicated into a child. `baseline.record()` calls `tool.discover()`, which can start PowerShell while the writer lock is held. If a handle were inheritable the lock could outlive the parent. **[N]** N-CONC-04.
- `FILE_FLAG_BACKUP_SEMANTICS` is only for directories (it is required to open one). Backup *privilege* is never requested; the flag is used for its open-directory meaning only.
- `FILE_FLAG_OPEN_NO_RECALL` is a defence so that probing a cloud placeholder cannot trigger a download. **[N]** N-LNK-10.

#### 3.3.3 Walk algorithm

```
def open_state_dir_win32(path, create, api = Win32Api(), profile = None):
    p = normalise(path)                                   # §3.3.1; pure; no API calls
    tok  = api.token();  user = api.token_user_sid(tok)  # §3.2
    prof = profile or api.profile_dir(tok)               # injectable for native tests only
    prof_h = api.open_dir(normalise(prof))               # independent handle on the profile
    prof_id = api.file_id(prof_h); prof_final = api.final_path(prof_h)
    require is_strict_prefix(fold(prof_final), fold(p.final_expected))   # ORBIT_HOME strictly inside profile

    chain = [];  expected = volume_root(p)
    try:
        root_h = api.open_dir(expected)
        check_volume(root_h)                              # §3.5
        check_dir(root_h, policy=ANCESTOR)                # owner + DACL, §3.4
        for i, comp in enumerate(p.components):
            expected = expected + "\\" + comp
            try:    h = api.open_dir(expected, share=R|W)           # pin: no FILE_SHARE_DELETE
            except NotFound:
                if not (create and i >= depth(profile)): raise
                api.create_dir(expected, sa=protected_inheritable_sd(user))
                h = api.open_dir(expected, share=R|W)
            tag = api.attribute_tag(h)                    # FileAttributeTagInfo
            if tag.attrs & FILE_ATTRIBUTE_REPARSE_POINT: raise Unsafe(LINKED)   # ANY reparse point
            if not tag.attrs & FILE_ATTRIBUTE_DIRECTORY: raise Unsafe(NOT_DIR)
            require api.volume_serial(h) == api.volume_serial(root_h)           # no volume crossing
            require fold(api.final_path(h)) == fold(expected)                   # no redirected traversal
            check_dir(h, policy = FULL if i >= depth(profile) - 1 else ANCESTOR)
            chain.append(h)
        require api.file_id(chain[depth(profile) - 1]) == prof_id               # profile identity by ID, not text
        require api.file_id(chain[-1]) not in forbidden_identities()            # package / legacy dirs (kept)
        return WindowsStateDir(chain, api, user)
    except BaseException:
        close_all(chain + [root_h, prof_h]); raise
```

Key points:

- **Reject reparse points at every user-controlled component.** The test is `FILE_ATTRIBUTE_REPARSE_POINT` from `GetFileInformationByHandleEx(h, FileAttributeTagInfo = 9, …)` on the handle just opened with `FILE_FLAG_OPEN_REPARSE_POINT`. This refuses name surrogates *and* every other reparse tag (OneDrive/cloud placeholders, dedup, WSL, App Execution aliases). The current `is_link` allows non-surrogate tags; the native backend is stricter by design (D15). Consequence: a profile directory that is itself a junction, a redirected `C:\Users`, or a mounted-volume profile is **unsupported** in 1.5.1 and fails closed with an explanatory message.
- **Pinning.** Each directory handle stays open for the whole `StateDir` lifetime without `FILE_SHARE_DELETE`. **[N]** The design depends on this: that an open handle lacking `FILE_SHARE_DELETE` makes a rename or delete of that directory — and of an ancestor that contains it — fail with a sharing/access error, so no component can be swapped for a junction after it has been checked. Documented sharing semantics support this for the directory itself; the behaviour for *ancestors* is the part to prove (N-RACE-01, N-RACE-02). **If it does not hold, stop** (§8.5): the fallback is relative opens through `NtCreateFile(RootDirectory = …, OBJ_DONT_REPARSE)` in `ntdll`, which is a materially riskier ctypes surface and needs a fresh approval.
- **Final-path comparison** (`GetFinalPathNameByHandleW(h, buf, n, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS)`) catches any redirected traversal that slipped past the pin, including `subst` and 8.3 short names. Because `expected` is built from the (already extended) user text, a path written with a short name or an unusual case fails the comparison and is refused, never "fixed up". The case-insensitive fold uses Python `casefold`; exotic Unicode that NTFS folds differently only causes a refusal (fail closed). **[N]** N-VOL-04.
- **Profile identity by object ID.** The profile is opened independently from the token-derived path and compared to the chain element at the same depth by `FILE_ID_INFO` (volume serial + 128-bit file ID), not just by string. The string prefix test is only the cheap first gate.
- **Creation.** Missing directories are created only at or below the profile depth, with the protected DACL of §3.4.4. An existing directory is vetted, never "fixed". `ERROR_ALREADY_EXISTS` from a race re-enters the open path.
- **Count of handles.** Typically 5–8 (`C:\`, `Users`, profile, `.orbit`). They are held only for the duration of one `StateDir` use (a read: milliseconds; a write: until the manifest update ends, which may be minutes while tools are hashed).

### 3.4 Ownership, DACL and identity checks

#### 3.4.1 Obtaining the descriptor

`GetSecurityInfo(handle, SE_FILE_OBJECT = 1, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner, NULL, &dacl, NULL, &psd)` — handle-based, so there is no path to race. It returns a Win32 error code (not via `GetLastError`). Copy the descriptor to Python with `GetSecurityDescriptorLength(psd)` and `ctypes.string_at`, `LocalFree(psd)` in a `finally`, then parse the bytes.

- `GetNamedSecurityInfoW` (path-based) is **not used**: it would re-resolve a path after the check.
- The parser requires `SE_SELF_RELATIVE (0x8000)` in the control field. **[N]** N-ACL-05 confirms `GetSecurityInfo` returns a self-relative descriptor for file handles; if it does not, use `GetKernelObjectSecurity` (self-relative into a caller buffer, no `LocalFree`) or stop. A non-self-relative descriptor is a refusal.
- Errors (`ERROR_ACCESS_DENIED`, `ERROR_NOT_SUPPORTED`, `ERROR_INVALID_FUNCTION`, anything else) → refuse with `ACL_UNREADABLE`. A `NULL` owner, a missing DACL (`SE_DACL_PRESENT` clear or `NULL` DACL = full access to everyone) → refuse with `ACL_MISSING`.

#### 3.4.2 Pure-Python parsing (unit-testable anywhere)

- **SID** at an offset: revision (1 byte, must be 1), sub-authority count (1 byte, ≤ 15), identifier authority (6 bytes big-endian), then `count` little-endian `DWORD`s. Output `S-1-<auth>-<sub1>-…`. Bounds-checked against the buffer.
- **Self-relative SD**: `Revision`(1) `Sbz1`(1) `Control`(2) `OffsetOwner`(4) `OffsetGroup`(4) `OffsetSacl`(4) `OffsetDacl`(4). Offsets must be inside the buffer.
- **ACL**: `AclRevision`(1) `Sbz1`(1) `AclSize`(2) `AceCount`(2) `Sbz2`(2), then `AceCount` ACEs; each begins `AceType`(1) `AceFlags`(1) `AceSize`(2) and `AceSize` must be ≥ 8 + minimal SID and keep the cursor in bounds.
- **ACE types accepted for parsing**: `0` ACCESS_ALLOWED, `1` ACCESS_DENIED, `9` ACCESS_ALLOWED_CALLBACK (same prefix `Header, Mask, Sid`, then condition bytes), `10` ACCESS_DENIED_CALLBACK. **Any other ACE type in a file/directory DACL → refuse (`ACL_UNSUPPORTED`)**: object, compound and audit types do not occur in ordinary file DACLs and a parser that guessed at them would be inventing semantics.

#### 3.4.3 Evaluation rule (conservative, order-independent)

Let `T` be the policy's trusted set. The DACL is **acceptable** iff:

1. the owner SID ∈ `T` (owner can always rewrite the DACL, so an unexpected owner is a refusal regardless of the DACL); and
2. for every **allow** ACE (type 0 or 9) that is **not** `INHERIT_ONLY_ACE (0x08)` and whose SID ∉ `T`: `Mask & DANGEROUS == 0`.

Deny ACEs are **ignored**. A deny can only remove rights, so treating it as absent yields a superset of the true allowed set: the check can refuse a configuration that is in fact safe (for example an allow for `Users` that an earlier deny cancels), but it can never accept an unsafe one. This is a deliberate false-positive trade (D7) that also makes the answer independent of ACE ordering, canonical or not.

Masks (values **[D]** from `winnt.h`; the implementer verifies each):

| Name | Value | Names |
|---|---|---|
| `FILE_WRITE_DATA` / `FILE_ADD_FILE` | `0x0002` | |
| `FILE_APPEND_DATA` / `FILE_ADD_SUBDIRECTORY` | `0x0004` | |
| `FILE_WRITE_EA` | `0x0010` | |
| `FILE_DELETE_CHILD` | `0x0040` | |
| `FILE_WRITE_ATTRIBUTES` | `0x0100` | |
| `DELETE` | `0x10000` | |
| `WRITE_DAC` | `0x40000` | |
| `WRITE_OWNER` | `0x80000` | |
| `GENERIC_ALL` / `GENERIC_WRITE` | `0x10000000` / `0x40000000` | should not appear in a stored DACL; refused if they do |

- `DANGEROUS` (profile root and everything below, files and the lock) = union of all rows.
- `ANCESTOR_DANGEROUS` (drive root and directories above the profile) = `FILE_DELETE_CHILD | DELETE | WRITE_DAC | WRITE_OWNER | GENERIC_ALL | GENERIC_WRITE`. Rationale: another user's `FILE_ADD_SUBDIRECTORY` on `C:\` (granted to *Authenticated Users* by default **[N]**) cannot displace the existing `C:\Users`, but `FILE_DELETE_CHILD` or `DELETE` could. This keeps the default Windows layout usable without accepting an ancestor another user can rename or replace. **[N]** N-ACL-06 shows the default `C:\` and `C:\Users` pass, and N-ACL-08 shows the default profile root passes `DANGEROUS`; if either fails on a stock Windows 11 or Server image the rule is wrong and the build stops (§8.5), because it would reject every default install.
- Anything unlisted that is not a clear match (for example a `CREATOR OWNER` ACE that is not inherit-only, or an `OWNER RIGHTS` ACE) is an SID ∉ `T` and is judged by its mask, so it is refused when it carries a dangerous right. Fail closed.
- Read rights for other principals are fine: the baseline is not secret.

#### 3.4.4 Creating objects with a known descriptor

Files and directories ORBIT creates (lock, temporary baseline, missing `ORBIT_HOME` components) are created **with an explicit protected DACL in `SECURITY_ATTRIBUTES`**, so there is no window in which they carry an inherited, broader descriptor:

- file: `ConvertStringSecurityDescriptorToSecurityDescriptorW("D:P(A;;FA;;;{user_sid})(A;;FA;;;SY)(A;;FA;;;BA)", SDDL_REVISION_1 = 1, &psd, NULL)`; `LocalFree` afterwards;
- directory: the same with `OICI` inheritance flags: `D:P(A;OICI;FA;;;{user_sid})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`.

`{user_sid}` is the string produced by §3.2 and is validated to match `^S-1-\d+(-\d+){1,15}$` before it is interpolated. `D:P` (protected) stops inheritance, so a later change to `.orbit`'s parent cannot widen the file. The created object's descriptor is then **read back and run through the same §3.4.3 evaluator** before use. Creation never relies on the descriptor *ORBIT asked for* being the one the kernel applied. **[N]** N-ACL-05.

Existing objects (for example an `.orbit` created by older ORBIT with the profile's inherited ACL) are vetted, not rewritten.

#### 3.4.5 Per-object checks (files)

For the baseline, lock and temporary file, from the handle:

- `FileAttributeTagInfo`: no `FILE_ATTRIBUTE_REPARSE_POINT (0x400)`, not `DIRECTORY (0x10)`, none of `OFFLINE (0x1000)`, `RECALL_ON_OPEN (0x40000)`, `RECALL_ON_DATA_ACCESS (0x400000)`, `DEVICE (0x40)`, `VIRTUAL (0x10000)`.
- `FileStandardInfo = 1`: `NumberOfLinks == 1` (hard links refused, matching the POSIX `st_nlink` rule), `DeletePending == FALSE`, `Directory == FALSE`.
- `FileIdInfo = 18`: identity `(VolumeSerialNumber, FileId[16])`; must not equal the identity of a legacy-manifest file (kept); recorded for later re-checks. Requires Windows 8 / Server 2012 or later (the project's supported Windows 10/11 satisfies this). If the class is unsupported on the volume the backend refuses (NTFS is the only accepted file system, so this should not occur; **[N]** N-VOL-06).
- Volume serial equals the chain's.
- `GetFinalPathNameByHandleW` equals the expected path.
- §3.4.3 owner/DACL evaluation with `DANGEROUS`.

Info-class numbers and struct layouts (`FILE_STANDARD_INFO`: `AllocationSize` 8, `EndOfFile` 8, `NumberOfLinks` 4, `DeletePending` 1, `Directory` 1; `FILE_ATTRIBUTE_TAG_INFO`: `FileAttributes` 4, `ReparseTag` 4; `FILE_ID_INFO`: `VolumeSerialNumber` 8, `FileId` 16; `FILE_BASIC_INFO` has 4 `LARGE_INTEGER` times, `FileAttributes` at offset 32, padded to 40) are **[D]**; they are copied from `minwinbase.h`/`winbase.h` and each is exercised by a native test (N-ID-03) that would fail on a layout error.

### 3.5 Unsupported storage and path classes (fail closed)

| Condition | Detection | Result |
|---|---|---|
| FAT/FAT32/exFAT, no persistent ACLs | `GetVolumeInformationByHandleW(h, …, &flags, fsname, n)`; require `flags & FILE_PERSISTENT_ACLS (0x8)` **and** `fsname == "NTFS"` | `VOLUME_UNSUPPORTED` |
| ReFS / Dev Drive | `fsname == "ReFS"` | refused in 1.5.1 until natively tested (D5, N-VOL-06); not "unsafe", just unproven |
| SMB, UNC, mapped network drive | text rule §3.3.1; `GetDriveTypeW(root)` must be `DRIVE_FIXED (3)`; `DRIVE_REMOTE (4)`, `DRIVE_REMOVABLE (2)`, `DRIVE_CDROM`, `DRIVE_RAMDISK`, unknown, no-root → refused; final path beginning `\\?\UNC\` → refused | `VOLUME_UNSUPPORTED` |
| `subst`/virtual drive letter | final-path comparison (§3.3.3) differs from the requested text | refused (**[N]** N-VOL-03: the exact `GetFinalPathNameByHandleW` form for `subst` and mapped drives) |
| OneDrive / cloud placeholder | any reparse tag, or `RECALL_*`/`OFFLINE` attributes; `FILE_FLAG_OPEN_NO_RECALL` prevents hydration | `LINKED` / `CLOUD_PLACEHOLDER` |
| Long path | `\\?\` form; refused only above the 32 000 limit | accepted below the limit |
| Case-sensitive directory (WSL per-directory flag) | `GetFileInformationByHandleEx(h, FileCaseSensitiveInfo = 23)`; refuse if the flag is set | **[N]** N-VOL-07: confirm the class number and layout; if it cannot be queried on a tested image, treat as "not set" only if the call reports not-supported **and** `fsname == "NTFS"`; otherwise refuse |
| Missing or unreadable security descriptor | §3.4.1 | `ACL_MISSING` / `ACL_UNREADABLE` |
| Any unexpected `GetLastError` | default branch | `STATE_UNAVAILABLE` (fixed text) |

Messages follow the existing rule: fixed text, never the path, never a SID.

### 3.6 Lock creation without following a reparse point

```
def lock(self, name, timeout):                       # name = "tool_hashes.json.lock"
    deadline = monotonic() + timeout
    sa = SECURITY_ATTRIBUTES(protected_file_sd(user), inherit=False)
    while True:
        self.assert_chain_intact()                   # final paths unchanged, pins still held
        h = api.create_file(join(home, name),
                            access = GENERIC_READ|GENERIC_WRITE|READ_CONTROL,
                            share  = 0,              # exclusive: this open IS the lock
                            sa     = sa,
                            disposition = OPEN_ALWAYS,
                            flags  = FILE_ATTRIBUTE_NORMAL|FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_OPEN_NO_RECALL)
        if h is invalid:
            if last_error == ERROR_SHARING_VIOLATION:        # another writer holds it
                if monotonic() >= deadline: raise StateBusy
                sleep(0.05); continue
            raise Unsafe(map_error(last_error))
        try:
            vet_file_handle(h, policy=FILE)                  # §3.4.5, BEFORE trusting the lock:
                                                             # reparse => reject, nlink==1, owner, DACL
        except BaseException:
            close(h); raise
        return Lock(h)                                       # CloseHandle releases; process death releases
```

- **No second lock mechanism.** Share mode `0` makes the kernel enforce exclusion. `msvcrt.locking` (a byte-range lock on a path-opened descriptor) is removed on Windows. The lock file is never deleted (deleting it would let two writers each "hold the lock" on different files), the same rule as today.
- **Crash safety.** The handle is released by the kernel when the process dies. **[N]** N-CONC-03.
- **Reparse at the lock path.** The open returns a handle to the link object (not its target); `vet_file_handle` sees `FILE_ATTRIBUTE_REPARSE_POINT` and the writer aborts having created nothing at the link's target. **[N]** N-LNK-04 (symlink, junction, dangling symlink, existing and absent).
- `ERROR_ALREADY_EXISTS (183)` after a *successful* `OPEN_ALWAYS` is informational only (the file existed).
- Mixed-version exclusion with the old `msvcrt` writer: **[N]** N-CONC-05.

### 3.7 Writing: temporary file, flush, atomic replace

Under the lock, `write_if_unchanged(name, data, expected)` runs:

```
1. cur = self.read_vetted(name)                      # §3.3 read protocol, may be absent
   require digest(cur) == expected.digest and identity(cur) == expected.identity   # compare-and-swap
2. temp = "." + name + "." + token_hex(8) + ".tmp"
   t = create_file(join(home, temp), GENERIC_WRITE|READ_CONTROL|DELETE, share=0,
                   sa=protected_file_sd, CREATE_NEW,
                   FILE_ATTRIBUTE_NORMAL|FILE_FLAG_OPEN_REPARSE_POINT)    # never an existing name or link
3. vet_file_handle(t, FILE)                          # owner/DACL as created; nlink==1; not reparse
   tid = file_id(t)
4. WriteFile loop until all bytes written; FlushFileBuffers(t); CloseHandle(t)
5. self.assert_chain_intact()
6. retry up to N times on ERROR_SHARING_VIOLATION / ERROR_ACCESS_DENIED (a reader or an
   anti-virus scanner has the target or temp open):
        MoveFileExW(join(home, temp), join(home, name), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)
7. v = open_for_read(name)                           # post-replace verification, same as a reader
   require file_id(v) == tid and sha256(read(v)) == sha256(data)    # what is published is exactly what was written
   vet_file_handle(v, FILE)
8. on any failure after step 2: delete the temp by name with DeleteFileW only if its identity is still tid
```

- **Why `MoveFileExW` and not `ReplaceFileW`.** `MoveFileExW(…, MOVEFILE_REPLACE_EXISTING)` is the call `os.replace` already makes on Windows, and its atomicity on NTFS is relied on widely but **not promised in the documentation** **[D]**. `ReplaceFileW` merges attributes and security from the replaced file, which can carry an older, broader descriptor onto the new file; that is the opposite of what we want, so it is rejected (D9). Post-verification in step 7 means we do not depend on the *documentation* of atomicity for correctness of the published identity: we check it.
- **Optional hardening, only if native tests justify it.** `SetFileInformationByHandle(t, FileRenameInfo (3) or FileRenameInfoEx (22), …)` renames by the already-open, already-verified handle, with `ReplaceIfExists`, which pins the source. **[N]** N-REP-01: whether `FileName` takes a full Win32 `\\?\` path, how `RootDirectory` behaves, and what `FileRenameInfoEx` with `FILE_RENAME_FLAG_POSIX_SEMANTICS` does against a reader that has the target open. It is not adopted unless step 6 proves inadequate (reader/AV contention that exceeds the retry budget).
- **Durability.** `FlushFileBuffers` on the temporary file flushes its data. `MOVEFILE_WRITE_THROUGH` is documented to guarantee flush for *copy-and-delete* moves, so for a same-volume rename it should be treated as a hint only **[D]**. The claim made is: after a crash the baseline is entirely the old file or entirely the new file (NTFS journals metadata) **[N]** N-CRASH-01/02 — and a truncated or absent file fails closed anyway, because §2.4 rejects invalid JSON and the gate then stays shut. Power-loss durability of the *latest* write is not claimed; an interrupted writer is simply re-run.
- **Reader interaction.** A reader holds the old file with `FILE_SHARE_READ` (no delete share) for milliseconds, so the rename in step 6 may briefly fail; hence the retry loop (today: 10 attempts × 0.1 s; propose 40 attempts with 0.05–0.25 s back-off, ≈ 5 s, because real-time anti-virus also opens new files). **[N]** N-CRASH-03 (Defender interference is recorded on the real-device run).
- **Temp-file hygiene.** Under the lock, orphaned names that match exactly `^\.tool_hashes\.json\.[0-9a-f]{16}\.tmp$`, that pass `vet_file_handle`, are deleted best-effort. Anything else in the directory is left alone.

### 3.8 Re-checking identities before trust or use

| Point | Re-check |
|---|---|
| End of `open_state_dir` | chain assembled with all checks; profile-depth ID equals the independent profile handle's |
| Immediately before returning bytes from `read` | (a) `assert_chain_intact()`: every pinned handle's `GetFinalPathNameByHandleW` still equals its expected path; (b) the file is re-opened by path (transient handle, same flags) and its `FileIdInfo` equals that of the read handle; (c) size and last-write time from `FileBasicInfo`/`FileStandardInfo` equal the values observed before the read |
| Immediately before `MoveFileExW` | `assert_chain_intact()`; lock handle still valid; the baseline identity still equals `expected.identity` |
| After `MoveFileExW` | step 7 above |
| `Binding.verify` and snapshot code | unchanged (different subsystem) |

### 3.9 What requires direct native verification, not mocks

A fake cannot establish any of the following; each is a gate item in §6.3 and §9.3:

1. Share-mode pinning of directories and ancestors (N-RACE-01/02).
2. `OPEN_ALWAYS | FILE_FLAG_OPEN_REPARSE_POINT` against symlink, junction, dangling link (N-LNK-04).
3. What `GetSecurityInfo` returns for a file handle: self-relative form, owner, protected/inherited flags (N-ACL-05).
4. The default ACLs of `C:\`, `C:\Users`, the profile root and a freshly created `.orbit` against §3.4.3 on stock images (N-ACL-06, N-ACL-08).
5. Owner assigned to files created by an elevated token versus a filtered token (N-ACL-07).
6. `GetFinalPathNameByHandleW` output for `subst`, mapped drives, 8.3 names, case (N-VOL-03/04).
7. `FileIdInfo`/`FileStandardInfo`/`FileAttributeTagInfo` layouts and the stability of the file ID across rename (N-ID-03).
8. Atomicity, crash behaviour and sharing behaviour of `MoveFileExW`, including with a reader and an anti-virus scanner (N-REP-01, N-CRASH-*).
9. Exclusive-share lock semantics, release on process death, non-inheritance, mixed-version exclusion (N-CONC-*).
10. Attribute-only opens (`FILE_READ_ATTRIBUTES | READ_CONTROL`) not conflicting with an exclusive-share handle, for the reader's lock probe (N-CONC-06); the fallback is that `ERROR_SHARING_VIOLATION` on the probe means "writer active" and the probe is skipped.
11. Rejection of FAT/exFAT/SMB/ReFS volumes and long paths (N-VOL-*).
12. Token and profile APIs: `GetUserProfileDirectoryW` access requirements and agreement with `USERPROFILE` (N-ID-01).
13. `TrustedInstaller` SID value (N-ACL-06).
14. Whether the ARM64 build behaves identically (N-VM-05).

---

## 4. macOS ACL closure

### 4.1 Problem

On macOS an extended ACL can grant another principal write access that the POSIX mode bits do not show, so `st_mode & 0o022` can say "closed" while the ACL says "open". The current policy checks mode bits only.

### 4.2 Chosen approach: native fd-based ACL read through `ctypes`, deny-only ACLs accepted

For every object the POSIX backend already vets by file descriptor — each directory in the walk (including root-owned ones), `ORBIT_HOME`, and each baseline, lock and temporary file — call:

```
acl = acl_get_fd_np(fd, ACL_TYPE_EXTENDED = 0x100)      # libc, errno via use_errno=True
if acl is NULL:
    errno == ENOENT  -> no ACL: acceptable
    anything else    -> refuse (ACL_UNREADABLE): the volume cannot be verified
else:
    try:
        walk entries: acl_get_entry(acl, ACL_FIRST_ENTRY=0 | ACL_NEXT_ENTRY=-1, &e)
            r == 0                      -> entry: acl_get_tag_type(e, &tag)
                                              tag == ACL_EXTENDED_DENY (2)  -> ignore (can only remove rights)
                                              anything else (ALLOW=1, undefined, unknown) -> refuse (ACL_ALLOW)
            r == -1 and errno == EINVAL -> end of list (macOS semantics, [V])
            r == -1 and other errno     -> refuse
    finally:
        acl_free(acl)
```

Why this shape:

- **Not "any ACL refuses".** [V] The default macOS home directory (the parent of `~/.orbit`) carries `group:everyone deny delete`. Refusing every ACL would reject every default install. A deny entry cannot grant anything, so ignoring it is a sound over-approximation of the effective permissions; any **allow** entry is refused without interpreting its qualifier, rights or inheritance, because interpreting a qualifier (users, groups, `everyone`, nested groups) is exactly the complexity we avoid.
- **fd-based (`acl_get_fd_np`)**, not `acl_get_file`/`acl_get_link_np`. [V] `acl_get_file` follows symlinks and both path variants re-resolve a path; the fd variant inspects the very object that was `fstat`-ed and opened with `O_NOFOLLOW`, closing the race. [V] It works on directory descriptors.
- **Minimal and dependency-free:** six libc symbols (`acl_get_fd_np`, `acl_get_entry`, `acl_get_tag_type`, `acl_free`, plus errno) resolved with `ctypes.CDLL(None, use_errno=True)`. If any symbol is missing on a Darwin host, the backend refuses rather than skipping the check.
- **Memory.** `acl_t` and the entry handle are `c_void_p`; `acl_free` is called exactly once per non-`NULL` ACL in a `finally`. The entry handle is owned by the `acl_t` and is not freed separately.
- **Placement.** After `_vet_dir` and `vet_file` have passed their mode checks; and again in the write path immediately before the rename (a re-check at the point of use) so an ACL added mid-update is caught. A failure raises `UnsafeState` with a fixed message ("a permission list (ACL) on the baseline path allows access to others; remove it with `chmod -N`, or set ORBIT_HOME elsewhere").
- **Non-APFS volumes** (exFAT, SMB, NFS) may return an errno other than `ENOENT`; the answer is refuse. That behaviour is **not verified** here and is covered by M-ACL-05 through an injected fake and by a note in the docs.

Rejected alternatives: parsing `ls -le` or `chmod`/`ls` subprocess output (locale and `PATH` dependent, a new race, a new process); evaluating allow entries against the user and groups (large, error-prone surface for no practical gain); a blanket "refuse if `+` appears in mode string" (refuses the default home).

### 4.3 What this does not cover

macOS file flags (`chflags`), extended attributes and sandbox/TCC policy do not change who can write the file in the ordinary UNIX/ACL model and are out of scope. Same-user and root remain trusted.

### 4.4 Linux

Existing descriptor-relative POSIX protections are kept unchanged. Linux POSIX ACLs are a separate case: when an ACL has named-user or named-group entries, the **group** permission bits in `st_mode` show the ACL **mask**, which caps every named entry and the owning group. A mode with no group-write bit therefore proves that no named user or group can write, so the existing `mode & 0o022` test already bounds POSIX ACLs. This is a property of POSIX ACL semantics, not something verified on this host. One Linux CI test (L-POSIX-03, `setfacl -m u:nobody:rwx` on a scratch file, mode shows `rwx` mask, existing check refuses) will establish it on `ubuntu-latest`. NFSv4/RichACL and network file systems are unsupported for `ORBIT_HOME`; no new code is planned for them in 1.5.1, and the docs must say so.

---

## 5. Internal interface design

### 5.1 Module boundaries

```
orbit/core/baseline_schema.py   NEW   pure: Binding, Baseline, parse_baseline(), dump_baseline(), error codes.
                                      No I/O, no platform branches except computing the expected Binding.
orbit/core/trusted_state.py     MOD   the only public entry: open_state_dir(); StateDir protocol;
                                      POSIX backend (existing walk, moved behind the protocol);
                                      macOS ACL check (_darwin_acl_ok); forbidden-location checks (kept).
orbit/core/state_win32.py       NEW   WindowsStateDir, normalise(), walk, lock, write_if_unchanged,
                                      DACL evaluator, SID/SD/ACL byte parsers (pure functions at top level).
orbit/core/win32_api.py         NEW   Win32Api: the ctypes layer only (signatures, constants, struct layouts);
                                      returns Python values, raises Win32Error(code).
orbit/core/manifest.py          MOD   update_manifest/seed_manifest use StateDir; no fds/handles.
orbit/core/hash_checker.py      MOD   load_baseline(); check_tool takes a Baseline, not a dict.
orbit/core/baseline.py          MOD   v2 seeding, LEGACY remediation text, exit codes.
```

No new dependency, no new top-level package. Constants for the Windows policy are defined once in `state_win32.py`.

### 5.2 The narrow interface

Callers receive a `StateDir`; they never receive a descriptor, a handle or a raw path to open:

```python
class StateDir(Protocol):
    def read(self, name: str) -> StateFile | None: ...
        # vet + read + identity re-check; None = absent (FileNotFoundError semantics only)
    def lock(self, name: str, timeout: float) -> ContextManager[None]: ...
    def write_if_unchanged(self, name: str, data: bytes,
                           expected: StateFile | None) -> StateFile: ...
        # requires the lock; compare-and-swap; temp + flush + atomic replace + post-verify
    def assert_chain_intact(self) -> None: ...     # raises UnsafeState(RACE)
    def close(self) -> None: ...

@dataclass(frozen=True)
class StateFile:  data: bytes; identity: tuple; digest: str     # identity is backend-specific, opaque
```

`open_state_dir(path, create=False) -> ContextManager[StateDir]` dispatches on `sys.platform`; the Windows branch calls `state_win32.open_state_dir_win32`. The existing public names `StateDir.open`, `vet_file`, `read_regular`, `lstat`, `replace`, `unlink`, `sync` become private (`_`-prefixed) on the POSIX class; `manifest.py` stops using them.

### 5.3 Shared use by readers and writers

```
reader:  open_state_dir(parent) -> state.read(name) -> StateFile -> parse_baseline(bytes, expected_binding) -> Baseline
writer:  open_state_dir(parent, create=True)
           -> with state.lock(name+".lock", LOCK_TIMEOUT):
                 cur = state.read(name)                       # same code path as the reader
                 baseline = seed-or-parse_baseline(cur)
                 ... record() ...
                 state.write_if_unchanged(name, dump_baseline(baseline), expected=cur)
```

The reader and the writer reach the file through the same `read`, so a policy gap cannot exist on one side only.

### 5.4 Invariants (and how each is enforced)

| # | Invariant | Enforcement |
|---|---|---|
| I1 | The only way to obtain a `StateDir` is `open_state_dir`; constructors require a module-private token. | token argument; U-INT-02 |
| I2 | Raw file access to the baseline directory happens only inside the backend classes. | AST/grep test U-INT-01: no `open(`, `os.open`, `Path.read_*`, `json.load(s)` of `tool_hashes` or `ORBIT_HOME` outside `trusted_state.py`, `state_win32.py`, `win32_api.py`, `baseline_schema.py` |
| I3 | `check_tool` accepts only a `Baseline` produced by `parse_baseline`; a plain `dict` is rejected. The current `manifest: dict \| None` parameter is replaced. Tests that need a baseline use a clearly named test constructor that production code never calls. | type check at runtime; U-INT-03 includes an AST rule that production modules never call the test constructor |
| I4 | `parse_baseline` is the single point that decides LEGACY/NEWER/binding. | U-SCH-* |
| I5 | `read` re-checks the chain and the file identity after the bytes are read and before they are returned (§3.8). | U-WIN-08, N-RACE-* |
| I6 | Any failure raises `UnsafeState` (or `ManifestError` in the writer); nothing is partially trusted. | existing pattern; tests assert the gate stays shut |
| I7 | All messages are fixed strings; no path or SID is formatted into them. | U-SCH-10, U-WIN-13 |
| I8 | Every Windows `CreateFileW` call carries `FILE_FLAG_OPEN_REPARSE_POINT`; no pinned handle is opened with `FILE_SHARE_DELETE`; every handle is non-inheritable and closed on every path. | recording-fake assertions U-WIN-06, U-WIN-14 |
| I9 | The Windows backend never calls `os.open`, `os.replace`, `os.rename`, `msvcrt.locking` or path-based `GetNamedSecurityInfoW`. | AST test U-INT-01 |

### 5.5 Lock state versus read trust

- **Readers do not acquire the writer lock.** A reader's safety comes from the atomic replace plus its own pinned handle and re-checks; making readers take the exclusive lock would let a stuck writer block all real-run gating for minutes.
- **Readers do reject an unsafe existing lock.** After the directory and baseline are vetted, the reader probes `tool_hashes.json.lock` if it exists, without creating it (`FILE_READ_ATTRIBUTES | READ_CONTROL`, shared, `OPEN_EXISTING`, `FILE_FLAG_OPEN_REPARSE_POINT`; POSIX: `lstat`/`O_NOFOLLOW` open then fd checks), and runs the file checks of §3.4.5. If the lock is a reparse point, has a foreign owner, a dangerous DACL, or more than one hard link, the baseline is `UNVERIFIED` (`LOCK_UNSAFE`).
  - *Reason.* The directory passed its policy, so no untrusted principal can currently create or alter entries; an unsafe reserved-name entry therefore proves the directory was writable by someone else at some earlier time, and the baseline's history cannot be trusted. It is a cheap tripwire and gives the reader and writer one definition of "the state directory is clean".
  - *Active writer.* If the probe gets `ERROR_SHARING_VIOLATION`, a writer is holding the lock and has already vetted it; the probe is skipped. **[N]** N-CONC-06 shows whether an attribute-only open conflicts at all.
- **Writers vet the lock before holding it** (§3.6) and abort without writing if it is unsafe.
- **A held lock never grants trust.** Holding the lock means "I may write", not "the directory is trusted"; trust comes only from the vetting in §3.3–§3.4, which the writer runs before taking the lock and re-runs at each trust point.

### 5.6 Likely files for a future implementation (none touched now)

Production: `orbit/core/baseline_schema.py` (new), `orbit/core/win32_api.py` (new), `orbit/core/state_win32.py` (new), `orbit/core/trusted_state.py`, `orbit/core/manifest.py`, `orbit/core/hash_checker.py`, `orbit/core/baseline.py`, `orbit/data/tool_hashes.template.json`.
Packaging/CI: `scripts/ci_package_checks.py` (schema 2, Windows-aware `baseline` subcommand), `pyproject.toml` (register the `windows_native` pytest marker only), `.github/workflows/ci.yml` (needs approval, §8.4), new `scripts/windows_native_gate.py`.
Tests: new `tests/test_baseline_schema.py`, `tests/test_state_win32_logic.py`, `tests/test_state_win32_parsers.py`, `tests/test_state_interfaces.py`, `tests/test_darwin_acl.py`, `tests/native/` (Windows-only); modified `tests/test_baseline_trust_path.py`, `tests/test_manifest_updates.py`, `tests/test_hash_checker.py`, `tests/test_package_resources.py`, `tests/conftest.py`.
Docs (after native evidence only): `docs/INSTALL.md:179` (replace the "documented limitation" paragraph), `SECURITY.md`, `AGENTS.md` line 5 (point to the new modules), `CHANGELOG.md`, `docs/PRIVACY.md` if the hashed binding needs a sentence.

---

## 6. Test strategy

### 6.1 What mocks can and cannot establish

| Mocks / fakes **can** establish | Mocks **cannot** establish (native Windows required) |
|---|---|
| Schema v2 parsing, LEGACY/NEWER/binding decisions | That Windows actually returns what the fake returns |
| SID/SD/ACL byte parsing against hand-built binary data | That `GetSecurityInfo` yields those bytes, in self-relative form |
| The DACL decision table, owner policy, masks | That stock ACLs on `C:\`, `C:\Users`, the profile and `.orbit` pass it |
| That the code *requests* the right flags, share modes, dispositions, in the right order | That those requests *behave* as intended (reparse not followed, share pinning, exclusive lock) |
| Error mapping, fixed messages, handle closing, retry loops (with injected clock) | Atomicity, crash outcomes, AV interaction, anti-virus sharing violations |
| Path normalisation and rejection of UNC/ADS/`..`/reserved names | `\\?\` long-path behaviour, final-path forms for `subst`, mapped, short names |
| Fault injection at every step of the write protocol | Real race outcomes between processes |

Fakes validate **our logic**. Passing them is necessary and is **not** evidence of Windows security.

### 6.2 Unit tests runnable on macOS and Linux

`FakeWin32Api` is an in-memory model: nodes with attributes, reparse tags, owner SID bytes, DACL bytes (built with `struct`), link counts, file IDs, volume serials, a call log (name, arguments, flags), injectable errors and an injectable clock. It implements the exact `Win32Api` interface. Tests parametrise over it; none require `sys.platform == "win32"`.

**Schema and migration** (`tests/test_baseline_schema.py`, plus POSIX end-to-end):

| ID | Case |
|---|---|
| U-SCH-01 | A genuine 1.5.0-style schema-1 manifest (synthesised: `{"schema":1,"tools":{…}}` with real-looking entries) is `LEGACY` when presented at: `ORBIT_HOME`, a temp dir, the cwd, `orbit/data`, the repo `data/`, a path named `tool_hashes.json` and one named `anything.json`. The decision uses content only. |
| U-SCH-02 | Full gate: schema-1 file at `ORBIT_HOME/tool_hashes.json` → `check_tool` returns `UNVERIFIED`; `launch_binding` returns no binding. |
| U-SCH-03 | The packaged template copied verbatim → `BINDING_MISSING`. |
| U-SCH-04 | `schema` matrix: `1`, `0`, `3`, `True`, `2.0`, `"2"`, `null`, absent with `tools` present, absent entirely. |
| U-SCH-05 | Binding matrix: missing, wrong types, uppercase hex, wrong length, other user, other machine, `os` mismatch, `machine: null` accepted on POSIX and rejected on win32. |
| U-SCH-06 | `tools` shape: non-dict, version not a dict, file keys with `..`, `/abs`, `C:\x`, NUL, empty; digests not 64 lowercase hex. |
| U-SCH-07 | Closed schema: an unknown top-level key, an unknown `binding` key, an unknown `generator` key each → `MALFORMED`. |
| U-SCH-08 | `seed_manifest` writes v2 with the correct binding; `update_manifest` on a v1 file raises `ManifestError(LEGACY)` and the file is byte-identical afterwards; a spy proves no legacy location is opened for reading by any command. |
| U-SCH-09 | `orbit-generate-hashes` with a v1 file: exit status 1, message contains the exact manual remediation, nothing written. |
| U-SCH-10 | Fixed messages: inject a marker path/SID into every failure route; assert it never appears in any message. |
| U-SCH-11 | Round trip: `dump_baseline` output re-parses; deterministic bytes. |

**Windows logic with fakes and pure parsers** (`tests/test_state_win32_parsers.py`, `tests/test_state_win32_logic.py`):

| ID | Case |
|---|---|
| U-WIN-01 | SID codec: `S-1-5-18`, `S-1-5-32-544`, `S-1-5-21-a-b-c-1001`, `S-1-1-0`, `S-1-5-11`; revision ≠ 1, sub-authority count 16, truncated buffers → error. |
| U-WIN-02 | SD/ACL parser: valid; truncated; `AceSize` smaller than the minimum, larger than the buffer; `AceCount` lying; ACE types `0,1,9,10` parsed; types `2,4,5,6,11,0x11` → `ACL_UNSUPPORTED`; non-self-relative control → refuse; offsets out of range → refuse. |
| U-WIN-03 | DACL decision table (each row: ACEs → expected): allow `U` full → ok; allow `SY`/`BA` full → ok; allow `Users` read → ok; allow `Users` write → refuse; allow `Everyone` `FILE_APPEND_DATA` → refuse; allow other-user SID `FILE_ADD_FILE` on a directory → refuse; allow `Users` `DELETE` only → refuse; allow `Users` `WRITE_DAC`/`WRITE_OWNER` → refuse; **deny `Users` write placed before allow `Users` write → refuse** (documented conservative false positive); **same ACEs in non-canonical order → same verdict**; `INHERIT_ONLY` allow `Users` write → ok; callback allow for foreign SID with write → refuse; `GENERIC_ALL` for foreign SID → refuse; `CREATOR OWNER` not inherit-only with write → refuse; null DACL → refuse; empty DACL with trusted owner → ok; ancestor mode: `Authenticated Users` `FILE_ADD_SUBDIRECTORY` → ok, `FILE_DELETE_CHILD` → refuse. |
| U-WIN-04 | Owner policy: `U`, `BA` accepted for files; `SY`/`TI` accepted only in ancestor mode; other user, `Everyone`, `Users` → refuse. |
| U-WIN-05 | Normaliser: UNC, `\\?\UNC\`, `\\.\`, `\\?\Volume{…}`, relative, no drive, `..`, `.`, trailing dot/space, `:stream`, `CON`, `nul.txt`, control characters, > 32 000 units → each refused with **zero** API calls recorded. Accepts a 300-character path. |
| U-WIN-06 | Walker: for each depth *d* (root child, intermediate, profile, `ORBIT_HOME`) make the node a symlink, a junction, a mount point, a cloud tag → `LINKED`, handles closed; a non-directory → `NOT_DIR`. Recording assertions: **every** `create_file` call has `FILE_FLAG_OPEN_REPARSE_POINT`; directory opens have `FILE_FLAG_BACKUP_SEMANTICS`; no pinned open has `FILE_SHARE_DELETE`. |
| U-WIN-07 | Volume class: `NTFS` ok; `FAT32`, `exFAT`, `ReFS`, missing `FILE_PERSISTENT_ACLS`, `DRIVE_REMOTE`, `DRIVE_REMOVABLE`, `DRIVE_CDROM`, `DRIVE_RAMDISK`, unknown → `VOLUME_UNSUPPORTED`; final path `\\?\UNC\…` → refused; case-sensitive flag set → refused. |
| U-WIN-08 | Identity: the file ID changes between read and re-check → `RACE`; final path of a chain handle changes → `RACE`; profile handle's ID ≠ chain element at profile depth → refuse; ORBIT_HOME not strictly inside the profile (equal, sibling, parent, prefix-confusion `C:\Users\al` vs `C:\Users\alice`) → refuse; **`USERPROFILE` set to another directory has no effect** (backend uses the token profile). |
| U-WIN-09 | File vetting: `NumberOfLinks` 2 → refuse; `DeletePending` → refuse; reparse, `OFFLINE`, `RECALL_*`, `DEVICE`, `VIRTUAL` → refuse; `GetSecurityInfo` errors (access denied, not supported, invalid function) and `NULL` owner/DACL → `ACL_UNREADABLE`/`ACL_MISSING`; volume serial differs from the chain's → refuse; identity equals a legacy file's → refuse. |
| U-WIN-10 | Lock: request has share `0`, `OPEN_ALWAYS`, `FILE_FLAG_OPEN_REPARSE_POINT`, `bInheritHandle = FALSE`, the protected-DACL descriptor; `ERROR_SHARING_VIOLATION` loops until the injected clock passes the deadline → `ManifestError`; a reparse/foreign-owner/2-link lock → refuse and close the handle without writing. |
| U-WIN-11 | Write protocol, with a failure injected after each of steps 1–8: the old baseline is untouched; the temp is removed only if its identity matches; `FlushFileBuffers` is called before `CloseHandle`; `MoveFileExW` flags are `REPLACE_EXISTING \| WRITE_THROUGH`; post-verify identity mismatch → error and no success; sharing-violation retry is bounded and uses the injected sleep. |
| U-WIN-12 | Reader/lock: unsafe existing lock → `LOCK_UNSAFE`; lock absent → no creation attempted (call log has no `CREATE`/`OPEN_ALWAYS`); sharing violation on the probe → skipped; reader never requests write access. |
| U-WIN-13 | Error mapping: every `ERROR_*` code in the table maps to a fixed message; none contains the path or SID. |
| U-WIN-14 | Handle hygiene: after every success and every injected failure the fake reports zero open handles. |
| U-WIN-15 | `import orbit.core.state_win32` and constructing the parsers works on a POSIX host. |

**Interfaces and bypass** (`tests/test_state_interfaces.py`):

| ID | Case |
|---|---|
| U-INT-01 | AST/grep: no raw I/O on the baseline path outside the four modules; the Windows backend never references `os.open`, `os.replace`, `os.rename`, `msvcrt.locking`, `GetNamedSecurityInfoW`. |
| U-INT-02 | `StateDir` cannot be constructed without the module-private token. |
| U-INT-03 | `check_tool` rejects a `dict`; production modules do not call the test constructor. |
| U-INT-04 | The same vetting entry is exercised by `load_baseline` and `update_manifest` (spy on `read`). |
| U-INT-05 | `pyproject.toml` runtime `dependencies` are unchanged by the implementation (no new dependency). |

**macOS** (`tests/test_darwin_acl.py`; real ACLs, `skipif(sys.platform != "darwin")`, using `chmod +a` on `tmp_path`):

| ID | Case |
|---|---|
| M-ACL-01 | Baseline file with `everyone allow write` → refused. |
| M-ACL-02 | `ORBIT_HOME` directory with an allow entry → refused; with a user-named allow entry → refused. |
| M-ACL-03 | A parent directory in the walk with an allow entry → refused. |
| M-ACL-04 | Default-style `group:everyone deny delete` on the parent → **accepted**; deny-only on file and directory → accepted. |
| M-ACL-05 | Injected fake libc: `acl_get_fd_np` returns `NULL` with `EOPNOTSUPP`/`EPERM`/`EINVAL` → refused; missing symbol → refused; `acl_free` called exactly once per ACL, including on the refuse path. |
| M-ACL-06 | ACL added to the baseline between the first check and the pre-rename re-check → refused. |
| M-ACL-07 | A symlink never reaches the ACL step (`O_NOFOLLOW` refuses first). |

**Linux** (`ubuntu-latest`): L-POSIX-01 existing POSIX suite unchanged and green; L-POSIX-02 the walk behaves identically with the interface refactor (golden call-sequence test); L-POSIX-03 `setfacl -m u:nobody:rwx` on a scratch file makes the mode show a group `w` bit and the existing check refuses.

### 6.3 Mandatory native Windows tests (`tests/native/`, marker `windows_native`)

Each test asserts `sys.platform == "win32"` and is listed in `tests/native/MANDATORY.txt`, which the CI gate (§7.5) requires to have **run and passed** (a skip is a failure).

**ACLs and owners**

| ID | Case |
|---|---|
| N-ACL-01 | File owned by another local user (set with `SetNamedSecurityInfoW`/`takeown` in the test harness) → refused. |
| N-ACL-02 | Explicit allow `Users` write on the baseline; on `ORBIT_HOME`; on the profile root (via injected profile) → each refused. |
| N-ACL-03 | **Ordering matrix:** deny-then-allow and allow-then-deny for the same principal, canonical and non-canonical (written with a raw `SetSecurityInfo`) → verdict independent of order; document where the conservative rule refuses a configuration `icacls`/`AccessCheck` says is safe. |
| N-ACL-04 | **Inherited ACEs:** parent with inheritable allow `Users` write; the child created without a protected DACL carries an `INHERITED_ACE` entry → refused; a child created by the backend (protected DACL) does not inherit. |
| N-ACL-05 | Backend-created lock/temp/dir read back: descriptor is self-relative, protected, exactly the expected three ACEs; the evaluator accepts it. |
| N-ACL-06 | Stock ancestors: `C:\` and `C:\Users` pass `ANCESTOR_DANGEROUS`; `TrustedInstaller` SID recorded. |
| N-ACL-07 | Owner produced by a filtered token vs an elevated token (`BA` vs `U`); both accepted. |
| N-ACL-08 | **Happy path:** a pristine profile root and a freshly created `.orbit` pass `DANGEROUS`, and a full generate-then-read cycle succeeds. (If this fails on a stock image the rule is unusable: stop.) |
| N-ACL-09 | Effective-rights oracle: for each of N-ACL-01..04, `AuthzInitializeContextFromSid` + `AuthzAccessCheck` for the other user's SID agrees that the object really is writable when we refuse (the evaluator is never *more* permissive than Windows). Test-only code. |

**Links, volumes, names**

| ID | Case |
|---|---|
| N-LNK-01 | Junction (`mklink /J`) at each depth: root child, intermediate, profile-level (injected), `.orbit` → refused; nothing written through it. |
| N-LNK-02 | Directory symlink (`mklink /D`) at each depth. |
| N-LNK-03 | File symlink as `tool_hashes.json`. |
| N-LNK-04 | **Lock redirection:** symlink, junction and dangling symlink at `tool_hashes.json.lock`, existing and absent targets → refused, **no file or directory created at the link target**, no write anywhere. |
| N-LNK-05 | Volume mount point folder (`mountvol`) at an intermediate component → refused. |
| N-LNK-06 | Hard link (`mklink /H`) to the baseline and to the lock from outside → `NumberOfLinks == 2` → refused. |
| N-LNK-07 | Alternate-data-stream name in `ORBIT_HOME` → refused before any open. |
| N-LNK-08 | 8.3 short-name spelling of the profile → refused by the final-path comparison; the long name accepted. |
| N-LNK-09 | `subst` drive letter → refused. |
| N-LNK-10 | Cloud placeholder: a file with `RECALL_ON_DATA_ACCESS`/cloud reparse tag (manual on a OneDrive device, §7.4) → refused without hydrating. |
| N-VOL-01 | FAT32 VHD volume → `VOLUME_UNSUPPORTED`. |
| N-VOL-02 | exFAT VHD volume → refused. |
| N-VOL-03 | UNC path and the loopback share `\\localhost\C$\…` → refused (text rule and drive type); record `GetFinalPathNameByHandleW` for mapped and `subst` drives. |
| N-VOL-04 | Case and Unicode folding: different-case spelling accepted when the final path matches ignoring case; an exotic-case path that NTFS folds differently only causes a refusal, never an accept. |
| N-VOL-05 | Long path: a 300-character `ORBIT_HOME` under an injected profile works end to end; a path above 32 000 units is refused. |
| N-VOL-06 | ReFS (if the image supports it) refused; NTFS with `FileIdInfo` supported. |
| N-VOL-07 | Per-directory case-sensitive flag (if `fsutil file setCaseSensitiveInfo` is available) → refused; record the `FileCaseSensitiveInfo` behaviour. |

**Races, concurrency, crash**

| ID | Case |
|---|---|
| N-RACE-01 | With the chain pinned, an adversary thread in a second process tries to rename `.orbit` to another name and put a junction at the old name: the rename **fails** (sharing/access error). Repeat 2 000 iterations. This proves the pin. |
| N-RACE-02 | Same for an ancestor: rename the profile-level directory (injected) that contains `.orbit`. |
| N-RACE-03 | While the reader reads, a second process replaces the baseline: the reader returns old-complete or new-complete or fails closed, never a mix, and the writer's rename retries then succeeds. |
| N-RACE-04 | Swap the lock path for a reparse point while the writer is looping in `OPEN_ALWAYS`. |
| N-RACE-05 | Stress: 10 000 iterations of create/delete reparse points at every component, with the reader running; the property "no result is `OK` through a link" holds. |
| N-CONC-01 | Two writer processes: no lost entries, no conflicting content blessed (port of the existing POSIX tests). |
| N-CONC-02 | Readers during writer replacement never see partial content (10 000 reads). |
| N-CONC-03 | A writer is killed with `TerminateProcess` while holding the lock: the next writer acquires immediately. |
| N-CONC-04 | The writer spawns a long-lived child with `close_fds=False` and exits: the lock is free (the handle is not inherited). |
| N-CONC-05 | Mixed version: a process holding the old `msvcrt.locking` open and a new exclusive-share writer exclude each other in both directions. |
| N-CONC-06 | Attribute-only lock probe while a writer holds the lock: record whether it conflicts; the reader behaves per §5.5 either way. |
| N-CRASH-01 | Kill at each step 2–7 of §3.7 (the harness subprocess calls `os._exit` after step *k* via test-side wrapper code): baseline is old or new, never partial; stale temp is harmless and swept on the next run. |
| N-CRASH-02 | Truncated/empty baseline file (simulated by direct write) → `NOT_JSON`/`MALFORMED`, gate shut. |
| N-CRASH-03 | Retry budget under contention: a reader holding the file for 1 s, then a scanner-like open, still lets the writer succeed within the budget. Real Defender behaviour recorded on the device run. |
| N-REP-01 | `MoveFileExW` replacement: atomic under kill; the error codes and retry behaviour when the target is open by a reader; and an exploratory run of `SetFileInformationByHandle(FileRenameInfo/Ex)` for D9's optional hardening. |

**Upgrade, migration, end to end**

| ID | Case |
|---|---|
| N-UPG-01 | `pip install` wheel A, generate a baseline (synthetic installation), `pip install` wheel B over it: `ORBIT_HOME` untouched, baseline still valid, package directory not confused with state. |
| N-UPG-02 | Uninstall and reinstall: baseline survives and still binds. |
| N-UPG-03 | Schema-1 file at `ORBIT_HOME` → `LEGACY`, remediation printed, file untouched; after moving it aside, generate succeeds. |
| N-UPG-04 | A schema-1 manifest planted at the old checkout location, in the cwd, in the package directory and in `ORBIT_HOME` never authorises a run. |
| N-UPG-05 | A schema-2 file copied from another account/machine (fixture with a different binding) → `BINDING_MISMATCH`. |
| N-E2E-01 | **Wheel-install end to end from outside the checkout:** build wheel, install into a clean venv, `cwd` in `%RUNNER_TEMP%`, `PYTHONPATH` unset, assert `orbit.__file__` is under `site-packages`, run `orbit-generate-hashes` against a synthetic installation, read through the real gate. |
| N-E2E-02 | The installed console script `orbit-generate-hashes` with no tools reports "No tools found" and seeds a valid v2 file. |
| N-E2E-03 | The existing guarded dry-run smoke test passes on Windows from the installed wheel. |
| N-ID-01 | `GetUserProfileDirectoryW` agrees with `%USERPROFILE%` on a pristine profile; setting `USERPROFILE` elsewhere does not move the trust anchor. |
| N-ID-02 | Profile identity by `FILE_ID_INFO` matches the chain element. |
| N-ID-03 | Info-class layouts: `FileAttributeTagInfo`, `FileStandardInfo`, `FileIdInfo`, `FileBasicInfo` round-trip known values; file ID is stable across rename. |

Standard-user and elevation cases need an account that is **not** an administrator, which hosted runners do not provide by default. They are covered by creating a local standard user and, if the secondary-logon service allows it, running a helper as that user (`CreateProcessWithLogonW`), with `AuthzAccessCheck` as the effective-access oracle when it does not (**[N]** N-CI-01: whether either works on a hosted runner). Otherwise they move to the manual VM/device checklist.

**Manual checklist on a Windows 11 client (VM or device):** N-VM-01 run as a *standard* (non-admin) user: full generate/read cycle; N-VM-02 UAC "over-the-shoulder" elevation: owner `BA` vs `U` and the binding; N-VM-03 OneDrive Known Folder Move enabled: `.orbit` outside the synced set, placeholder refusal for a synthetic synced file; N-VM-04 real Defender real-time scan during the write loop; N-VM-05 ARM64 vs x64 Python (only if the VM is ARM64, §7.2); N-VM-06 a managed/domain profile if available (otherwise recorded as unvalidated).

### 6.4 Requirements-to-tests traceability

Requirement keys: **R1** legacy/unbound content never authorises, at any location · **R2** binding to user (and machine on Windows) · **R3** no auto-import and fixed remediation · **R4** reparse points refused at every component and at the file and lock · **R5** owner and DACL policy · **R6** identity pinned and re-verified (TOCTOU) · **R7** lock without following links, exclusive, crash-safe, non-inheritable · **R8** atomic replace, flush, compare-and-swap, crash behaviour · **R9** hard links refused · **R10** unsupported volumes/paths fail closed · **R11** ORBIT_HOME inside the profile, by identity · **R12** one policy for reader and writer; no bypass · **R13** reader vets an existing lock and tolerates an active writer · **R14** fixed messages without paths or SIDs · **R15** macOS extended allow ACLs refused, deny-only accepted · **R16** Linux behaviour retained, ACL mask covered · **R17** same-user/admin limitation stated · **R18** Windows claims only after native evidence · **R19** no new runtime dependency.

| Req | Mock / unit evidence (logic only) | Native evidence (required for the claim) | Established by |
|---|---|---|---|
| R1 | U-SCH-01..04, U-SCH-02 (full gate) | N-UPG-03, N-UPG-04 | **Both fully establishable**; schema logic is platform-independent, native confirms the end-to-end gate on Windows |
| R2 | U-SCH-05, U-SCH-08 | N-UPG-05, N-ID-01 | Mocks for logic; native for SID/`MachineGuid` retrieval |
| R3 | U-SCH-08, U-SCH-09 | N-UPG-03 | Mocks sufficient for the no-import property; native for UX on Windows |
| R4 | U-WIN-06 (flag and request assertions) | N-LNK-01..06, N-LNK-04, N-RACE-04 | **Native only** for the claim that links are not followed |
| R5 | U-WIN-02..04, U-WIN-09 | N-ACL-01..09 | Mocks prove the evaluator; **native only** that stock Windows objects pass/fail as modelled |
| R6 | U-WIN-08, U-WIN-14 | N-RACE-01..05, N-ID-02, N-ID-03 | **Native only** (pinning is an OS behaviour) |
| R7 | U-WIN-10 | N-LNK-04, N-CONC-01, N-CONC-03..06 | **Native only** |
| R8 | U-WIN-11, U-SCH-11 | N-CRASH-01..03, N-REP-01, N-RACE-03 | **Native only** for atomicity/crash; mocks for step ordering |
| R9 | U-WIN-09 | N-LNK-06 | Mocks for logic; native for `NumberOfLinks` |
| R10 | U-WIN-05, U-WIN-07, U-WIN-09 | N-VOL-01..07, N-LNK-08..10 | Text rules by mocks; storage classes **native only** |
| R11 | U-WIN-08 | N-ID-01, N-ID-02, N-ACL-08 | Mocks for logic; native for APIs |
| R12 | U-INT-01..04 | N-E2E-01 | **Mocks fully establish** (structural), native confirms wiring |
| R13 | U-WIN-12 | N-CONC-06 | Mocks for logic; native for the open-conflict behaviour |
| R14 | U-SCH-10, U-WIN-13 | — | **Mocks fully establish** |
| R15 | M-ACL-01..07 | M-ACL (real `chmod +a` on macOS) | **Native macOS tests establish** (they run here); injected fake covers unsupported volumes |
| R16 | L-POSIX-01..03 | L-POSIX-03 on Linux CI | Existing tests + one Linux run |
| R17 | docs review (§8, release checklist) | — | Documentation gate |
| R18 | — | the entire §6.3 set and §7.5 gate | **Process gate** |
| R19 | `pyproject.toml` dependency diff test (U-INT-05: runtime `dependencies` unchanged) | — | Mocks |

---

## 7. Native validation plan without a current Windows device

### 7.1 Options compared

| | A. GitHub Actions `windows-latest` (and pinned `windows-2022`) | B. Local VM (UTM, VMware Fusion, Parallels) | C. Physical Windows 10/11 device |
|---|---|---|---|
| Real NTFS, real Win32, real ACLs | Yes (Windows Server image) | Yes (Windows 11 client) | Yes (client, real policy) |
| Reproducible, tied to a commit, reviewable log | **Yes** | No (manual; evidence is what you export) | No |
| Standard (non-admin) user | Hosted runner is an administrator; a local standard user can be created, whether a helper can run as that user is **[N]** | Yes, trivially | Yes |
| UAC split token / over-the-shoulder | No | Yes | Yes |
| OneDrive, Defender, managed policy | Defender present; OneDrive/domain no | OneDrive possible; Defender yes; no domain | Yes, all (the most representative) |
| FAT/exFAT/ReFS/SMB loopback/`subst`/mount points | Feasible with VHD and `net use \\localhost\C$` **[N]**, admin | Yes | Yes (more care needed) |
| Architecture | x64 | **Apple-silicon host → Windows 11 ARM64 only** (this host is arm64) | whatever it is |
| Cost / effort | Minutes billed (Windows runners cost more than Linux); no hardware | Licence/ISO download, ~64 GB disk, setup hours, an app to install (none is installed now) | Needs a device |
| Data exposure | Logs and artifacts leave the machine (synthetic data only) | None | None |
| Needs the workflow changed and a push | **Yes** | No | No |
| Violates a current rule? | `CLAUDE.md`: "never push to a remote" and "do not modify workflows" → **needs explicit approval** | Installing software and downloading an image are outside this spike's rules → needs approval | None, but the user must supply the device |

### 7.2 Recommendation

**Primary gate: option A** (Actions on `windows-latest` and `windows-2022`) because it is the only option that gives reproducible evidence bound to a commit that an independent reviewer can inspect, and it exercises the packaged wheel from outside the checkout. **Complement with one manual pass on a Windows 11 client (option C if the user has a device, otherwise B)** for the items hosted runners cannot show: a real standard user, UAC elevation, OneDrive and managed-profile behaviour, real Defender.

Limitations to state in the evidence:

- Hosted runners are **Windows Server**, with an administrator account and non-default profile history; they do not prove the default ACLs of a freshly installed Windows 11 client (N-ACL-08 must also pass on the client run).
- An Apple-silicon VM can only be **ARM64**; ctypes struct layouts are identical for LLP64 x64/ARM64, but ARM64 evidence does not prove x64 behaviour. It is acceptable only as the *manual* complement, not a substitute for the x64 Actions run.
- Neither option demonstrates domain-joined, roaming or redirected-profile behaviour; those are documented as **unsupported/unvalidated** and fail closed.

### 7.3 Prerequisites and approvals under the current workflow

| Item | Needed from the user | Why |
|---|---|---|
| A1 | Approval to modify `.github/workflows/ci.yml` (or add a workflow) and tests under `tests/native/` | `CLAUDE.md`/this spike forbid it now |
| A2 | Approval to push a throwaway branch to the remote, and to contact GitHub (Actions) | `CLAUDE.md`: never push; no network now |
| A3 | Approval that Actions installs `build`, `pytest` and the wheel's dependencies from the package index on the runner | no package-repository access is authorised now |
| A4 | Confirmation of repository visibility and plan (Windows minutes cost; logs public if the repo is public) | cost and exposure |
| A5 | For option B: approval to install a hypervisor and download a Windows image and its licence terms; for option C: access to a device and consent to create a local test user and junctions there | outside rules |
| A6 | Approval of a branch-protection rule that makes `windows-native` a required check before any tag | the release gate |

No workflow is modified and GitHub is not contacted by this spike.

### 7.4 Manual run (option B/C) procedure

On a Windows 11 client with Python 3.10 and 3.13, from an elevated and from a standard PowerShell: build and install the wheel into a venv outside the checkout, run `pytest -m windows_native tests\native -rA --junitxml evidence.xml`, then work through N-VM-01..06, and export `whoami /all`, `systeminfo`, `fsutil fsinfo volumeinfo C:`, the junit file and `icacls` dumps of `C:\`, `C:\Users`, the profile root and `.orbit`. A reviewer reads the raw files, not a summary.

### 7.5 Release gate

**No publication — tag, PyPI upload, GitHub Release, docs claiming Windows protection — until all of these hold:**

1. **G1.** On the exact commit to be released, the `windows-native` jobs on `windows-latest` **and** `windows-2022` (Python 3.10 and 3.13) are green with **zero skips** among the tests in `tests/native/MANDATORY.txt`, checked by `scripts/windows_native_gate.py` against the junit XML.
2. **G2.** The evidence artifacts (junit XML, environment capture, ACL dumps, runner image version) are retained and **reviewed by the user and by the independent Codex reviewer**, who must confirm that every **[N]** item in §3.9 has a recorded answer.
3. **G3.** The manual Windows 11 client run (N-VM-01..04, ideally 05) is completed and reviewed. If it cannot be done, the release notes and `docs/INSTALL.md` must state that standard-user, UAC, OneDrive and Defender behaviour is **unvalidated**, and the user must explicitly accept that residual risk in writing.
4. **G4.** Any failed or surprising result is resolved by a design change or a documented, user-accepted limitation, never by weakening a check to make a test pass.
5. **G5.** `docs/INSTALL.md` loses its "documented limitation" paragraph only in the same change that records G1–G3.
6. **G6.** The same-user/administrator limitation (§1.2) remains in `SECURITY.md` and `docs/INSTALL.md`.

If native evidence never becomes available, the fallback is **not** to ship with an untested Windows claim. It is to ship 1.5.1 with Windows real runs still governed by the current conservative profile rule *and said so plainly*, or to hold the release (user decision, §9.4).

### 7.6 Proposed CI job (not applied; for the approved implementation)

```yaml
  windows-native:
    name: Windows native secure-state (${{ matrix.os }}, Python ${{ matrix.python-version }})
    runs-on: ${{ matrix.os }}
    timeout-minutes: 45
    permissions:
      contents: read
    strategy:
      fail-fast: false
      matrix:
        os: [windows-latest, windows-2022]
        python-version: ["3.10", "3.13"]
    defaults:
      run:
        shell: pwsh
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false

      - uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}

      - name: Record the environment (evidence)
        run: |
          $e = Join-Path $env:RUNNER_TEMP "evidence"
          New-Item -ItemType Directory -Force $e | Out-Null
          "ImageOS=$env:ImageOS ImageVersion=$env:ImageVersion" | Out-File "$e\image.txt"
          git rev-parse HEAD | Out-File "$e\commit.txt"
          Get-CimInstance Win32_OperatingSystem | Format-List Caption,Version,BuildNumber,OSArchitecture | Out-File "$e\os.txt"
          whoami /user /groups | Out-File "$e\whoami.txt"
          fsutil fsinfo volumeinfo C: | Out-File "$e\volume-C.txt"
          icacls C:\ | Out-File "$e\acl-root.txt"
          icacls C:\Users | Out-File "$e\acl-users.txt"
          icacls $env:USERPROFILE | Out-File "$e\acl-profile.txt"
          sc.exe showsid TrustedInstaller | Out-File "$e\sid-trustedinstaller.txt"

      - name: Build the wheel
        run: |
          python -m pip install build
          python -m build --outdir "$env:RUNNER_TEMP\dist" .

      - name: Install the wheel alone, outside the checkout
        run: |
          python -m venv "$env:RUNNER_TEMP\venv"
          $wheels = @(Get-ChildItem "$env:RUNNER_TEMP\dist\orbit_m365-*.whl")
          if ($wheels.Count -ne 1) { throw "expected exactly one wheel" }
          & "$env:RUNNER_TEMP\venv\Scripts\python.exe" -m pip install --no-cache-dir $wheels[0].FullName pytest

      - name: Native secure-state tests against the installed package
        working-directory: ${{ runner.temp }}
        run: |
          Remove-Item Env:PYTHONPATH, Env:PYTHONHOME -ErrorAction SilentlyContinue
          $py = Join-Path $env:RUNNER_TEMP "venv\Scripts\python.exe"
          & $py -I -c "import orbit.config as c; assert 'site-packages' in c.__file__, c.__file__"
          & $py -m pytest -p no:cacheprovider --import-mode=importlib --strict-markers `
              -m windows_native -rA `
              --junitxml "$env:RUNNER_TEMP\evidence\native.xml" `
              "$env:GITHUB_WORKSPACE\tests\native"

      - name: Fail on any skipped or missing mandatory test
        run: python -I scripts/windows_native_gate.py "$env:RUNNER_TEMP\evidence\native.xml" tests/native/MANDATORY.txt

      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: windows-native-${{ matrix.os }}-py${{ matrix.python-version }}
          path: ${{ runner.temp }}\evidence
          retention-days: 30
```

Notes for the implementer: the first run is exploratory and may need adjustments (for example how `tests/conftest.py` interacts with `--import-mode=importlib`, the shell quoting of the `pytest` continuation, whether VHD creation, `mklink /D`, `mountvol` and `net use \\localhost\C$` are permitted on the image — **[N]** N-CI-01..03). `windows_native_gate.py` parses the junit XML, requires every ID in `MANDATORY.txt` to be present with no `skipped` or `failure` child, and fails if the count is below the list length, so a silently skipped native test can never pass the gate. It uses only the standard library.

Local VM command sketch (option B/C):

```powershell
py -3.13 -m venv C:\orbit-venv
C:\orbit-venv\Scripts\python.exe -m pip install --no-cache-dir C:\wheels\orbit_m365-1.5.1-py3-none-any.whl pytest
Set-Location $env:TEMP
C:\orbit-venv\Scripts\python.exe -m pytest -p no:cacheprovider --import-mode=importlib -m windows_native -rA --junitxml C:\evidence\native.xml C:\orbit-src\tests\native
```

---

## 8. Bounded future implementation plan

### 8.1 Slices

Each slice is independently reviewable and leaves the tree green (`pytest tests/ -v` per `CLAUDE.md`). Slices are ordered so that the highest-value, platform-independent fixes land first.

| Slice | Content | Owns (files) | Acceptance | Verification |
|---|---|---|---|---|
| **S0** Schema v2 | `baseline_schema.py`; template v2; `manifest.py` seed/update use it; `hash_checker` takes `Baseline`; `baseline.py` messages | `baseline_schema.py`, `manifest.py`, `hash_checker.py`, `baseline.py`, `tool_hashes.template.json`, `scripts/ci_package_checks.py` (template assertion), schema tests, adapted existing tests | U-SCH-01..11 green; a schema-1 file never authorises; template raw copy rejected; existing POSIX suite green | `pytest tests/ -v`; `ruff check .`; the package-contents check script on a built wheel (local) |
| **S1** Interface | `StateDir` protocol, `read`/`lock`/`write_if_unchanged`; POSIX class private methods; `manifest.py` uses the narrow API; reader probes the lock | `trusted_state.py`, `manifest.py`, `hash_checker.py`, `tests/test_state_interfaces.py` | I1–I9 enforced (U-INT-01..04); behaviour-preserving: golden call-sequence test L-POSIX-02; existing POSIX tests unchanged | full suite; diff review that no behaviour changed |
| **S2** macOS ACL | `_darwin_acl_ok`, placement points, pre-rename re-check, injected-libc hook | `trusted_state.py`, `tests/test_darwin_acl.py` | M-ACL-01..07 green on macOS; M-ACL-04 proves default homes accepted | `pytest tests/test_darwin_acl.py -v` on this host (real ACLs) |
| **S3** Win32 layer and pure policy | `win32_api.py` (signatures, constants, structs), SID/SD/ACL parsers, DACL evaluator, normaliser, `FakeWin32Api` | `win32_api.py`, `state_win32.py` (pure parts), `tests/test_state_win32_parsers.py`, `tests/fakes/` | U-WIN-01..05; every constant has a reviewed reference comment; every API has `argtypes`/`restype`; module imports on POSIX | unit tests; a written constants checklist reviewed against Microsoft docs |
| **S4** Windows backend | walk, read, lock, `write_if_unchanged`, creation with protected DACL, error mapping | `state_win32.py`, `trusted_state.py` (dispatch), `tests/test_state_win32_logic.py` | U-WIN-06..15 green; no use of `os.open`/`os.replace`/`msvcrt.locking` on the Windows path (U-INT-01); **no Windows security claim** | unit tests; Codex review (§8.3) |
| **S5** Native suite and CI | `tests/native/`, `MANDATORY.txt`, `windows_native_gate.py`, workflow job, `pyproject` marker | `tests/native/*`, `scripts/windows_native_gate.py`, `.github/workflows/ci.yml`, `pyproject.toml` (marker only) | **Requires approvals A1–A4, A6.** The job runs, the gate script rejects skips (self-test with a synthetic junit), the first results answer every §3.9 item or open a documented blocker | Actions run reviewed by user and Codex; evidence artifact reviewed |
| **S6** Resolve findings | Fix design or code per native evidence; extend tests | whichever files the finding implicates | G1–G4 satisfied | re-run S5 |
| **S7** Documentation and release | `INSTALL.md`, `SECURITY.md`, `AGENTS.md`, `CHANGELOG.md`, release notes; keep the same-user limitation | docs only | G5, G6; wording matches evidence exactly | docs read-through; `tests/test_privacy_wording.py` |

S0–S2 are independent of Windows and are valuable even if S3–S5 are delayed: S0 closes the legacy-manifest hole everywhere; S2 closes the macOS hole.

### 8.2 Model and turn budget (recommendation)

| Slice | Model | Turn ceiling |
|---|---|---|
| S0, S1, S2 | Claude Sonnet 5.5 | 40 turns each |
| S3, S4 (security-critical, ctypes, subtle semantics) | the most capable model available to the user (Claude Opus 5.5, or Fable 5.2 if enabled) | 60 turns each |
| S5 | Sonnet 5.5, with the user driving the Actions runs | 30 turns |
| S6 | model that wrote the failing slice | 40 turns, hard stop at §8.5 |
| S7 | Sonnet 5.5 | 20 turns |

These are budgets, not predictions; the stop conditions in §8.5 override them.

### 8.3 Independent Codex review scope

1. After S0–S2: schema binding and the legacy-rejection claim (can any pre-v2 content reach `OK`?), macOS ACL ctypes memory handling, interface invariants I1–I9, any behaviour change in the POSIX path.
2. After S3–S4 (before any Windows claim): every API's `argtypes`/`restype`, handle leaks, every `CreateFileW` call against the §3.3.2 table, DACL evaluator soundness (can any allowed-write ACE be accepted?), parser bounds checks, TOCTOU ordering in §3.3.3/§3.6/§3.7, the fail-closed default of every branch.
3. After S5/S6: read the **raw evidence** (junit, ACL dumps), not the summary; confirm each **[N]** item has a recorded answer and that no check was weakened; confirm the gate script rejects skipped tests.
4. Pre-release: documentation wording against the evidence.

### 8.4 Fresh user approvals required

Approval of this design before S0; each of A1–A6 (§7.3) before S5; approval to edit `AGENTS.md`/`CLAUDE.md` text (S7); explicit approval before any commit, tag, push or publication (`CLAUDE.md`: never push); a separate decision if the stop condition of §8.5 forces the `NtCreateFile` fallback (new, riskier surface) or a scope increase; acceptance of any residual risk under G3.

### 8.5 Stop conditions (stop, report, wait; do not improvise)

1. **Native API ambiguity:** an **[N]** or **[D]** item cannot be resolved from Microsoft documentation and a native test, and the design depends on it.
2. **Pinning does not hold:** N-RACE-01/02 show that a directory handle without `FILE_SHARE_DELETE` does not prevent rename of itself or an ancestor. The `NtCreateFile` fallback needs fresh approval.
3. **Unusable policy:** N-ACL-06 or N-ACL-08 shows a stock Windows 11 or Server image fails the DACL rule (every default install would be refused).
4. **Cannot verify ACL semantics:** `GetSecurityInfo` does not yield a self-relative descriptor and `GetKernelObjectSecurity` is also unusable, or the effective-rights oracle (N-ACL-09) shows the evaluator is *more permissive* than Windows.
5. **Lock redirection not fixed:** N-LNK-04 shows `OPEN_ALWAYS | FILE_FLAG_OPEN_REPARSE_POINT` follows or creates through a link.
6. **Repeated failures:** the same test or review finding fails after **two** fix attempts, or three consecutive CI runs fail for non-environmental reasons.
7. **Scope pressure:** a fix needs a new dependency, changes to unrelated modules, or work outside M0–M10.
8. **Any request** to weaken a check, add an override, or ship with a Windows security claim not backed by native evidence.

---

## 9. Decision log and open questions

### 9.1 Decisions

| # | Decision | Alternatives rejected, and why |
|---|---|---|
| D1 | Schema v2: closed schema, `kind`, hashed user (+machine) binding; legacy rejected on content | *More location blocklists / checkout search* (cannot find unknown copies, the original defect); *rename the file* (a copied v1 file renamed into place still validates, and `AGENTS.md` fixes the path); *auto-convert v1 → v2* (would import an unattested baseline) |
| D2 | No HMAC/checksum in the file | *HMAC with a keyring key* (a same-user process reads the key, so no cross-principal benefit, plus secret handling); *self-checksum* (breaks the documented hand-delete workflow, gives only accidental-corruption detection that JSON validity already gives) |
| D3 | `ctypes` + stdlib only | *`pywin32`* (new dependency, large, and not needed because parsing is pure Python); *`icacls`/PowerShell `Get-Acl` subprocesses* (locale-dependent output, `PATH` hijack, race, extra process); *`cffi`* (dependency) |
| D4 | `CreateFileW` with pinned handles and final-path/ID re-checks | *`NtCreateFile` relative opens with `OBJ_DONT_REPARSE`* (closest to POSIX `openat`, but an undocumented-by-comparison ntdll surface; kept as the §8.5 fallback) |
| D5 | NTFS on a fixed local drive only | *Allow ReFS/others with persistent ACLs* (unproven; refuse until natively tested) |
| D6 | `ORBIT_HOME` must stay inside the token-derived profile; profile identity by file ID | *Arbitrary locations with per-component ACL checks* (possible with this backend but widens the matrix; revisit in a later release); *`USERPROFILE`/`Path.home()` as anchor* (environment-controlled) |
| D7 | Conservative DACL rule: ignore denies, refuse any non-trusted allow with a dangerous right, ancestors judged by a narrower mask | *Full effective-rights simulation* (group expansion, ordering, generic mapping: large and error-prone); *`AccessCheck` for well-known groups only* (misses a named other-user ACE) |
| D8 | The exclusive-share handle *is* the lock | *`msvcrt.locking`* (byte-range lock on a path-opened descriptor that follows links); *lock directory/mutex* (extra objects, same race surface) |
| D9 | `MoveFileExW(REPLACE_EXISTING \| WRITE_THROUGH)` plus mandatory post-verify; handle-based rename as an optional, test-gated hardening | *`ReplaceFileW`* (merges attributes/ACLs from the old file); *handle-based rename now* (layout/semantics unproven, **[N]**) |
| D10 | Readers do not take the lock but reject an unsafe existing lock; skip the probe if a writer holds it | *Readers take the lock* (a stuck writer blocks gating); *ignore the lock* (loses a cheap tripwire) |
| D11 | macOS: fd-based `acl_get_fd_np`; deny-only ACLs accepted, any allow refused | *Refuse any ACL* (rejects every default home, [V]); *parse allow entries* (complexity); *`ls -le` parsing* |
| D12 | Linux: rely on the ACL mask in the group bits; confirm with one CI test | *Read `system.posix_acl_access`* (unnecessary given the mask) |
| D13 | Validation: Actions as the gate plus one manual Windows 11 client pass | *VM only* (not reproducible/reviewable, ARM64 on this host); *device only* (same); *Actions only* (no standard user/UAC/OneDrive) |
| D14 | Identity is `FILE_ID_INFO` (volume serial + 128-bit ID), not the 64-bit index | *`GetFileInformationByHandle` index* (not unique on ReFS; NTFS-only is accepted, but the 128-bit form costs nothing) |
| D15 | Refuse **every** reparse point on the Windows chain, file and lock | *Refuse name surrogates only* (the current `is_link`): lets cloud/dedup/WSL placeholders through |
| D16 | Created objects carry an explicit protected DACL and are read back and re-evaluated | *Rely on inheritance* (depends on whatever the parent carries) |
| D17 | Hashed principal/machine in the file | *Plain SID/GUID* (discloses identifiers in shared bug reports) |
| D18 | Keep existing location checks as defence in depth | *Delete them* (no reason to lose them; they are no longer load-bearing) |

### 9.2 Alternatives not pursued now (candidates for later)

Allowing `ORBIT_HOME` outside the profile (D6); ReFS support (D5); `--compare-with` import-as-report (§2.5); handle-based rename (D9); a `--replace-legacy` option (§2.6).

### 9.3 Open questions requiring native evidence

| # | Question | Test |
|---|---|---|
| Q1 | Does an open directory handle without `FILE_SHARE_DELETE` block rename/delete of that directory and of its ancestors? | N-RACE-01/02 |
| Q2 | `OPEN_ALWAYS` + `FILE_FLAG_OPEN_REPARSE_POINT` on symlink, junction and dangling symlink: handle to the link, no creation at the target? | N-LNK-04 |
| Q3 | Does `GetSecurityInfo` return a self-relative descriptor for file handles; what do protected/inherited flags look like? | N-ACL-05 |
| Q4 | Do stock `C:\`, `C:\Users`, profile root and new `.orbit` pass the rules on Windows 11 and on Server images? | N-ACL-06/08 |
| Q5 | Owner of files created by an elevated vs filtered token? | N-ACL-07 |
| Q6 | `GetFinalPathNameByHandleW` form for `subst`, mapped drives, 8.3 and case; behaviour for exotic Unicode | N-VOL-03/04, N-LNK-08/09 |
| Q7 | Layouts and numbers of `FILE_STANDARD_INFO`, `FILE_ATTRIBUTE_TAG_INFO`, `FILE_ID_INFO`, `FILE_BASIC_INFO`; ID stability across rename | N-ID-03 |
| Q8 | Is `MoveFileExW` replacement atomic under kill? Error codes and timing when a reader or Defender holds the target? | N-REP-01, N-CRASH-01..03 |
| Q9 | Handle-based rename: path form, `RootDirectory`, POSIX-semantics flag | N-REP-01 |
| Q10 | Does an attribute-only open conflict with an exclusive-share handle? | N-CONC-06 |
| Q11 | Do exclusive-share locks release on `TerminateProcess`, stay non-inherited, and exclude the old `msvcrt` writer? | N-CONC-03..05 |
| Q12 | `GetUserProfileDirectoryW` token access requirements; agreement with `USERPROFILE` | N-ID-01 |
| Q13 | `TrustedInstaller` SID value | N-ACL-06 |
| Q14 | Case-sensitive directory query class and layout | N-VOL-07 |
| Q15 | Are FAT/exFAT VHDs, `mklink`, `mountvol`, loopback SMB and secondary logon available on hosted runners? | N-CI-01..03 |
| Q16 | ReFS/Dev Drive behaviour (kept refused until answered) | N-VOL-06 |
| Q17 | Any difference on Windows 11 ARM64 | N-VM-05 |
| Q18 | Does Defender or another scanner exceed the rename retry budget? | N-CRASH-03, N-VM-04 |
| Q19 | Do standard-user, UAC, OneDrive and managed-profile cases behave as designed? | N-VM-01..06 |

### 9.4 Current release status and residual blockers

**Status.** ORBIT 1.5.1 is an **unreleased release candidate** (`main` at `d365a9e` plus uncommitted changes). **It must not be published, and no document may claim cross-user protection of the baseline on Windows**, until the gate in §7.5 passes.

| # | Blocker | Closed by |
|---|---|---|
| B1 | Reader accepts a schema-1 manifest copied into `ORBIT_HOME` (code-verified: no `schema` check anywhere on the read path); path-based legacy detection cannot find unrelated checkouts | S0 |
| B2 | macOS extended allow ACLs bypass mode-bit checks | S2 |
| B3 | Windows policy is path-based: no owner or DACL check, `Path.home()` trust anchor, TOCTOU between check and use | S3, S4, native evidence |
| B4 | Windows lock opens (`os.open` with `O_CREAT`) can follow a reparse point before rejection | S4, N-LNK-04 |
| B5 | No native Windows execution has occurred; macOS simulation is not Windows evidence | S5, G1–G3 |
| B6 | `docs/INSTALL.md:179` documents the weaker Windows rule; it stays until evidence exists | S7 |
| B7 | `KICKOFF.md`, referenced by `CLAUDE.md`/`AGENTS.md`, is absent from the repository | user decision |

**User decision needed regarding Windows if native validation is unavailable:** ship 1.5.1 with the current documented conservative Windows rule and an explicit "unvalidated on Windows" note, or hold the release.

---

## 10. Approval-ready build specification

**Goal.** Make the integrity baseline structurally unable to authorise a run from legacy or unbound content, and, on Windows, hold the baseline directory and files to the property P1/P2 with a native Win32 backend, with release blocked until native Windows evidence is reviewed.

**Scope.** `orbit/core/{baseline_schema,win32_api,state_win32}.py` (new); `trusted_state.py`, `manifest.py`, `hash_checker.py`, `baseline.py`, the packaged template, `scripts/ci_package_checks.py` (modified); tests; one CI job and a gate script (after approval); documentation (after evidence). No new runtime dependency. No change to discovery, snapshot, reporting, TUI, secrets, SMTP or tenant behaviour. Same-user/administrator limitation unchanged.

**Design in one paragraph.** A schema-v2 baseline (`schema == 2`, `kind`, closed keys, hashed user and Windows machine binding, validated entries) is the only content accepted, wherever it is; schema-1 is refused with a fixed message and never imported. Readers and writers use one narrow `StateDir` (`read`, `lock`, `write_if_unchanged`, `assert_chain_intact`) with POSIX, macOS-ACL-aware and native Windows backends. The Windows backend opens every directory and file with `CreateFileW` and `FILE_FLAG_OPEN_REPARSE_POINT`, refuses any reparse point, pins the chain without `FILE_SHARE_DELETE`, checks `FILE_ID_INFO`, final path and volume class (local NTFS only), evaluates owner and DACL from pure-Python-parsed descriptors obtained by handle (`GetSecurityInfo`) with a conservative order-independent rule, anchors `ORBIT_HOME` to the token-derived profile by file ID, uses an exclusive-share `OPEN_ALWAYS` handle as the writer lock, writes a protected-DACL temporary file, `FlushFileBuffers`, `MoveFileExW(REPLACE_EXISTING | WRITE_THROUGH)`, and verifies the published identity and bytes. macOS refuses any allow-type extended ACL via `acl_get_fd_np`, accepting deny-only lists.

**Slices.** S0 schema; S1 interface; S2 macOS ACL; S3 Win32 layer and pure policy; S4 Windows backend; S5 native suite and CI (needs approval); S6 resolve findings; S7 documentation and release. Models and turn ceilings per §8.2; Codex review per §8.3.

**Acceptance.** All of U-SCH, U-WIN, U-INT, M-ACL and L-POSIX pass; the full `pytest tests/ -v` and `ruff check .` pass; every requirement R1–R19 maps to at least one test (§6.4); the Windows native job is green with zero skipped mandatory tests on `windows-latest` and `windows-2022` (G1); evidence reviewed by the user and Codex (G2); the manual Windows 11 client pass completed or its absence accepted in writing (G3).

**Stop conditions.** §8.5.

**Approvals required from the user.** This design; A1–A6 (§7.3) before S5; docs edits to `AGENTS.md`/`CLAUDE.md` text; any commit, push, tag or publication; any scope increase or fallback to `NtCreateFile`; acceptance of residual Windows risk.

**Explicit non-claims until G1–G3.** Windows cross-user protection of the baseline; atomic and crash-safe replacement on Windows; behaviour under standard-user, UAC, OneDrive, managed profile or ARM64.

---

## Appendix A. Constants and layouts the implementer must verify against the SDK (all **[D]**)

Values below are transcribed from memory of `winnt.h`, `fileapi.h`, `minwinbase.h`, `winbase.h` and `aclapi.h` and **must be checked against Microsoft documentation before use**; native tests N-ID-03 and N-ACL-05 will fail loudly on a wrong layout, but a wrong constant that happens to be benign would not.

| Group | Constants |
|---|---|
| `CreateFileW` access | `GENERIC_READ 0x80000000`, `GENERIC_WRITE 0x40000000`, `FILE_READ_DATA/FILE_LIST_DIRECTORY 0x1`, `FILE_WRITE_DATA/FILE_ADD_FILE 0x2`, `FILE_APPEND_DATA/FILE_ADD_SUBDIRECTORY 0x4`, `FILE_READ_EA 0x8`, `FILE_WRITE_EA 0x10`, `FILE_DELETE_CHILD 0x40`, `FILE_READ_ATTRIBUTES 0x80`, `FILE_WRITE_ATTRIBUTES 0x100`, `DELETE 0x10000`, `READ_CONTROL 0x20000`, `WRITE_DAC 0x40000`, `WRITE_OWNER 0x80000`, `SYNCHRONIZE 0x100000` |
| Share | `FILE_SHARE_READ 1`, `FILE_SHARE_WRITE 2`, `FILE_SHARE_DELETE 4` |
| Disposition | `CREATE_NEW 1`, `CREATE_ALWAYS 2`, `OPEN_EXISTING 3`, `OPEN_ALWAYS 4`, `TRUNCATE_EXISTING 5` |
| Flags | `FILE_ATTRIBUTE_NORMAL 0x80`, `FILE_FLAG_OPEN_NO_RECALL 0x00100000`, `FILE_FLAG_OPEN_REPARSE_POINT 0x00200000`, `FILE_FLAG_BACKUP_SEMANTICS 0x02000000`, `INVALID_HANDLE_VALUE` = `(HANDLE)-1` |
| File attributes | `DIRECTORY 0x10`, `DEVICE 0x40`, `REPARSE_POINT 0x400`, `OFFLINE 0x1000`, `ENCRYPTED 0x4000`, `VIRTUAL 0x10000`, `RECALL_ON_OPEN 0x40000`, `RECALL_ON_DATA_ACCESS 0x400000` |
| `FILE_INFO_BY_HANDLE_CLASS` | `FileBasicInfo 0`, `FileStandardInfo 1`, `FileAttributeTagInfo 9`, `FileIdInfo 18`, `FileRenameInfo 3`, `FileRenameInfoEx 22`, `FileCaseSensitiveInfo 23` (the last two to be confirmed first) |
| Security | `SE_FILE_OBJECT 1`, `OWNER_SECURITY_INFORMATION 1`, `DACL_SECURITY_INFORMATION 4`, `SE_DACL_PRESENT 0x4`, `SE_DACL_PROTECTED 0x1000`, `SE_SELF_RELATIVE 0x8000`, `SDDL_REVISION_1 1`, `TOKEN_QUERY 0x8`, `TOKEN_DUPLICATE 0x2`, `TOKEN_IMPERSONATE 0x4`, `TokenUser 1` |
| ACE | types `0` allowed, `1` denied, `9` allowed-callback, `10` denied-callback; flags `OBJECT_INHERIT 1`, `CONTAINER_INHERIT 2`, `NO_PROPAGATE_INHERIT 4`, `INHERIT_ONLY 8`, `INHERITED 0x10` |
| Volume | `FILE_PERSISTENT_ACLS 0x8`, `DRIVE_REMOVABLE 2`, `DRIVE_FIXED 3`, `DRIVE_REMOTE 4`, `DRIVE_CDROM 5`, `DRIVE_RAMDISK 6`, `FILE_NAME_NORMALIZED 0`, `VOLUME_NAME_DOS 0` |
| Move | `MOVEFILE_REPLACE_EXISTING 1`, `MOVEFILE_WRITE_THROUGH 8` |
| Errors | `FILE_NOT_FOUND 2`, `PATH_NOT_FOUND 3`, `ACCESS_DENIED 5`, `NOT_SUPPORTED 50`, `SHARING_VIOLATION 32`, `LOCK_VIOLATION 33`, `FILE_EXISTS 80`, `INSUFFICIENT_BUFFER 122`, `ALREADY_EXISTS 183` |
| Well-known SIDs | `S-1-1-0` Everyone, `S-1-5-11` Authenticated Users, `S-1-5-18` SYSTEM, `S-1-5-32-544` Administrators, `S-1-5-32-545` Users, `S-1-3-0` Creator Owner, `S-1-3-4` Owner Rights |

Struct sizes the code must assert at import time on Windows: `FILE_ID_INFO` 24, `FILE_ATTRIBUTE_TAG_INFO` 8, `FILE_STANDARD_INFO` 24, `FILE_BASIC_INFO` 40.

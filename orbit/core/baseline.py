"""``orbit-generate-hashes``: record the integrity baseline in ORBIT_HOME.

Run it once after installing tools, and again after any update:

    orbit-generate-hashes

Run it only against installations you already trust: it records what is on disk, it does not
establish where that came from. It uses the same discovery and file set as the run gate.
Entries for other versions are preserved. An existing entry that differs is never replaced;
delete it by hand after investigating why the files changed.

The baseline is the user's own trust state and is written only to ``ORBIT_HOME/tool_hashes.json``
(normally ``~/.orbit/tool_hashes.json``), never into the installed package. The first run seeds
it from the packaged empty template, adding a schema-2 binding to the current user (and, on
Windows, machine). A baseline in any other form (schema 1, newer, unbound, recorded for another
user or computer, damaged) is never imported, rewritten or upgraded: the command leaves the file
as it is, says why, and exits 1 until you move it aside; see ``legacy_manifests``. The whole
read, compare and update holds a local lock, and the manifest is replaced atomically.

The location is held to the same policy as the real-run gate (``orbit.core.trusted_state``): an
ORBIT_HOME you do not own, that others can write to, that contains links, or that lies inside
ORBIT's own install or a legacy data directory is refused before anything is read or written.
"""
from __future__ import annotations

import sys
from pathlib import Path

import orbit
from orbit.core import hash_checker, trusted_state
from orbit.core.baseline_schema import ErrorCode, is_safe_relative_name
from orbit.core.hash_checker import hash_tree
from orbit.core.manifest import ManifestError, seed_manifest, update_manifest
from orbit.core.tools import all_tools
from orbit.core.tools.discovery import DiscoveryError

USAGE = ("usage: orbit-generate-hashes\n\n"
         "Record SHA-256 hashes of the installed tools in ORBIT_HOME/tool_hashes.json\n"
         "(normally ~/.orbit/tool_hashes.json). Takes no arguments.")

# Fixed text: the exact manual step when an existing baseline was refused. No path is formatted in.
MOVE_ASIDE = (
    "ORBIT will not change or replace that file. To start again, move it aside yourself\n"
    "(adjust the folder if you set ORBIT_HOME), then run orbit-generate-hashes again:\n"
    '  PowerShell:  Move-Item "$env:USERPROFILE\\.orbit\\tool_hashes.json" '
    '"$env:USERPROFILE\\.orbit\\tool_hashes.json.v1"\n'
    "  macOS/Linux: mv ~/.orbit/tool_hashes.json ~/.orbit/tool_hashes.json.v1")


def legacy_manifests() -> list[Path]:
    """Baselines an older layout kept beside the code. Reported, never read as trusted state.

    Releases up to 1.5.0 kept ``data/tool_hashes.json`` in the source checkout, and an interim
    build kept ``orbit/data/tool_hashes.json`` in the package. Importing either would trust
    hashes that were recorded for a different install, so a person has to decide.
    """
    package = Path(orbit.__file__).resolve().parent
    candidates = [d / hash_checker.MANIFEST_NAME for d in trusted_state.legacy_dirs(package)]
    return [c for c in candidates if c.is_file()]


def record(manifest: dict) -> bool:
    """Add baselines to the manifest. Returns True if any could not be recorded."""
    tools_section: dict = manifest.setdefault("tools", {})
    any_found = failed = False

    for tool in all_tools():
        versions: dict = tools_section.setdefault(tool.name, {}).setdefault("versions", {})

        print(f"Scanning {tool.name} ...", end=" ", flush=True)
        try:
            inst = tool.discover()
        except DiscoveryError as exc:
            print(f"skipped ({exc})")
            continue

        any_found = True
        print(f"v{inst.version} at {inst.root} ...", end=" ", flush=True)
        try:
            files = hash_tree(inst.root, inst.members, inst.strict_member)
        except (OSError, ValueError) as exc:
            print(f"NOT recorded ({exc})")
            failed = True
            continue
        if not files:
            print("NOT recorded (no files)")
            failed = True
            continue
        if not all(is_safe_relative_name(rel) for rel in files):
            print("NOT recorded (a file name cannot be stored in the baseline)")
            failed = True
            continue
        recorded = versions.get(inst.version, {}).get("files")
        if recorded and recorded != files:
            print("NOT recorded (files differ from the existing baseline for this version)")
            failed = True
            continue
        versions[inst.version] = {"install_dir": str(inst.root), "files": files}
        print(f"✓ {len(files)} files hashed")

    if not any_found:
        print(
            "\nNo tools found. Install tools first (use ORBIT's Installer screen or\n"
            "see docs/INSTALL.md), then re-run orbit-generate-hashes.",
            file=sys.stderr,
        )
        sys.exit(1)

    return failed


def main(args: list[str] | None = None) -> None:
    """Record the baseline. ``args`` are the command-line arguments; there are none to give."""
    args = args or []
    if args in (["-h"], ["--help"]):
        print(USAGE)
        sys.exit(0)
    if args:
        print(USAGE, file=sys.stderr)
        sys.exit(2)

    path = hash_checker.manifest_path()
    for legacy in legacy_manifests():
        print(f"Note: ignoring the older baseline at {legacy}. It is not trusted and was not "
              f"imported; the baseline for this install is {path}.", file=sys.stderr)
    try:
        template = hash_checker.TEMPLATE_PATH.read_bytes()
        if seed_manifest(path, template):
            print(f"Created {path} from the packaged empty template.")
        with update_manifest(path) as manifest:  # written only if this block completes
            failed = record(manifest)
    except (ManifestError, trusted_state.UnsafeState, OSError) as exc:
        print(f"\nManifest NOT updated: {exc}", file=sys.stderr)
        if getattr(exc, "code", None) not in (None, ErrorCode.BINDING_UNAVAILABLE):  # content refused
            print(MOVE_ASIDE, file=sys.stderr)
        sys.exit(1)
    print(f"\nManifest written to {path}")
    print("Re-run orbit-generate-hashes any time you install or update a tool.")
    if failed:
        sys.exit(1)


def cli() -> None:
    """Console-script entry point (``orbit-generate-hashes``): reads the real command line."""
    main(sys.argv[1:])


if __name__ == "__main__":
    cli()

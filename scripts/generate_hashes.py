#!/usr/bin/env python3
"""Populate data/tool_hashes.json with SHA-256 hashes of installed tools.

Run once after installing tools, and again after any update:

    python scripts/generate_hashes.py

Run it only against installations you already trust: it records what is on disk, it
does not establish where that came from. It uses the same discovery and file set as the
run gate. Entries for other versions are preserved. An existing entry that differs is
never replaced; delete it by hand after investigating why the files changed.

The whole read, compare and update holds a local lock, and the manifest is replaced atomically.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from orbit.core.hash_checker import MANIFEST_PATH, hash_tree
from orbit.core.manifest import ManifestError, update_manifest
from orbit.core.tools import all_tools
from orbit.core.tools.discovery import DiscoveryError

MANIFEST = MANIFEST_PATH


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
            "see docs/INSTALL.md), then re-run this script.",
            file=sys.stderr,
        )
        sys.exit(1)

    # Remove legacy _note if present (replaced by README docs)
    manifest.pop("_note", None)
    return failed


def main() -> None:
    try:
        with update_manifest(MANIFEST) as manifest:  # written only if this block completes
            failed = record(manifest)
    except (ManifestError, OSError) as exc:
        print(f"\nManifest NOT updated: {exc}", file=sys.stderr)
        sys.exit(1)
    print(f"\nManifest written to {MANIFEST}")
    print("Re-run this script any time you install or update a tool.")
    if failed:
        sys.exit(1)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Source-checkout shim for ``orbit-generate-hashes`` (``orbit.core.baseline``).

    python scripts/generate_hashes.py

It records the integrity baseline in ORBIT_HOME/tool_hashes.json (normally
~/.orbit/tool_hashes.json), the same file the installed command writes, and never writes to
the checkout. See ``orbit/core/baseline.py`` for the behaviour.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from orbit.core.baseline import cli

if __name__ == "__main__":
    cli()

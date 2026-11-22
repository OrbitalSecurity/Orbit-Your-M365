# AGENTS.md
ORBIT - M365 security audit orchestrator (Textual TUI). Full spec: `KICKOFF.md`.
- Scope is milestones M0-M10 only; do not expand.
- Secrets never in args, logs, or plaintext on disk. No network calls from ORBIT itself, other than the optional GitHub release check (`orbit/core/update_check.py`) and user-configured, user-enabled SMTP email (`orbit/core/emailer.py`). No telemetry or analytics. User-configured SMTP sends report data to the user-chosen SMTP server and recipients, never automatically to the author.
- The integrity baseline is mutable user state: `ORBIT_HOME/tool_hashes.json` via `hash_checker.manifest_path()` (resolved per call), written only by `orbit-generate-hashes` (`orbit/core/baseline.py`). Package data under `orbit/data/` is read-only; `tool_hashes.template.json` is only a seed. Never import a legacy checkout manifest as trusted. Reads (`hash_checker.load_manifest`) and writes (`orbit/core/manifest.py`) share one location policy in `orbit/core/trusted_state.py` (ownership, modes, no links, not inside the package or a legacy data dir); do not bypass it.
- Setup: `uv venv && uv pip install -e ".[dev]"`; test: `pytest tests/ -v`.
- Dry-run: `python orbit.py --dry-run` plays back `orbit/data/fixtures/` (bundled package data, resolved via `orbit.config`).

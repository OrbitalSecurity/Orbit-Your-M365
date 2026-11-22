"""Headless (no TUI) run: execute tools, score, return a JSON-serialisable summary."""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from pathlib import Path

from orbit.config import VERSION
from orbit.core import config_store
from orbit.core.outputs import FORMATS, OutputConfig, make_run_folder
from orbit.core.pipeline import finalize
from orbit.core.runner import Runner, RunError, RunStatus, prepare_run
from orbit.core.secrets import SecretStore
from orbit.core.tools import all_tools
from orbit.core.workspace import Workspace
from orbit.reporting import scorer
from orbit.reporting.parser import Finding

log = logging.getLogger(__name__)


class HeadlessError(Exception):
    """Bad arguments or configuration (reported on stderr, exit 1)."""


def select_tools(names: list[str], configured: list[str], dry_run: bool):
    tools = all_tools()
    known = {t.name for t in tools}
    unknown = [n for n in names if n not in known]
    if unknown:
        raise HeadlessError(f"Unknown tool(s): {', '.join(unknown)}. Choose from: "
                            f"{', '.join(sorted(known))}")
    wanted = names or configured
    chosen = [t for t in tools if t.name in wanted]
    if not chosen and dry_run:
        chosen = [t for t in tools if t.fixture]
    if not chosen:
        raise HeadlessError("No tools selected; pass --tools or select tools in ~/.orbit/config.toml")
    return chosen


def _assessment(findings: list[Finding], folder: Path) -> dict:
    """The part of the payload that claims an assessment took place."""
    s = scorer.summarize(findings)
    return {
        "score": round(s.posture),
        "total_controls": s.total_controls,
        "passed": s.passed_controls,
        "critical": s.counts["Critical"],
        "high": s.counts["High"],
        "medium": s.counts["Medium"],
        "low": s.counts["Low"],
        "top_findings": [
            {"control_id": f.control_id, "tool": f.tool, "severity": f.severity,
             "title": f.title, "remediation": f.remediation, "cve_ids": f.cve_ids}
            for f in scorer.top_n(findings, 3)
        ],
        "output_dir": str(folder.resolve()),
    }


def run_headless(dry_run: bool = False, tool_names: list[str] | None = None) -> tuple[dict, int]:
    """Returns (payload, exit_code); exit_code is 1 if any tool failed or was skipped.

    If no tool was launched, the payload holds diagnostics only: the assessment keys are absent.
    """
    cfg = config_store.load()
    tools = select_tools(tool_names or [], cfg["tools"]["selected"], dry_run)
    base = Path(cfg["output"]["directory"] or "output")
    formats = {f.upper() for f in cfg["output"]["formats"]} & set(FORMATS)
    out_cfg = OutputConfig(base_dir=base, formats=formats)
    hashes, creds, secrets = [], {}, {}
    with Workspace() as workspace:  # snapshots and tokens are gone on every way out of here
        try:
            if not dry_run:
                hashes, creds, secrets = prepare_run(tools, SecretStore, workspace)
        except PermissionError as exc:
            raise HeadlessError(f"Cannot load credentials: {exc}") from exc
        folder = make_run_folder(base)
        runner = Runner(folder, creds, secrets, dry_run, hashes)
        try:
            runs = asyncio.run(runner.run_all(tools))
        except RunError as exc:
            raise HeadlessError(str(exc)) from exc
    failed = [r.tool.name for r in runs.values() if r.status is not RunStatus.COMPLETE]
    blocked = {r.tool.name: r.note for r in runs.values() if r.status is RunStatus.SKIPPED}
    not_started = {r.tool.name: r.note for r in runs.values()
                   if r.status is RunStatus.FAILED and not r.launched}
    for name in [*blocked, *not_started]:
        log.warning("%s", "\n".join(runs[name].log))  # stderr; stdout carries only the JSON

    launched = [r.tool.display for r in runs.values() if r.launched]
    assessment = {}
    if launched:  # otherwise nothing was assessed: no report, history, score, counts or path
        findings, _ = finalize(folder, launched, out_cfg, dry_run)
        assessment = _assessment(findings, folder)
    payload = {
        "orbit_version": VERSION,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        **assessment,
        "dry_run": dry_run,
        "failed_tools": failed,
        "blocked_tools": blocked,
        "launch_failures": not_started,
    }
    return payload, (1 if failed else 0)

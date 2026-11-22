"""Post-run pipeline: parse results, write ORBIT summary reports, optionally encrypt."""
from __future__ import annotations

from pathlib import Path

from orbit.core import history
from orbit.core.outputs import OutputConfig, package
from orbit.reporting.context import ReportContext
from orbit.reporting.docx_report import generate_docx
from orbit.reporting.parser import Finding, parse_folder
from orbit.reporting.pdf_report import generate_pdf
from orbit.security.auth_material import purge_auth_material


def finalize(run_folder: Path, tools_used: list[str], cfg: OutputConfig, dry_run: bool,
             passphrase: str | None = None, client: str = "",
             ) -> tuple[list[Finding], list[Path]]:
    purge_auth_material(run_folder)  # before anything is parsed, reported or packaged
    findings = parse_folder(run_folder)
    ctx = ReportContext(findings, tools_used, dry_run=dry_run, client=client.strip() or "Confidential")
    written: list[Path] = []
    if "PDF" in cfg.formats:
        written.append(generate_pdf(ctx, run_folder))
    if "DOCX" in cfg.formats:
        written.append(generate_docx(ctx, run_folder))
    archive = package(run_folder, cfg, passphrase)
    if archive:
        written.append(archive)
    try:  # last: a run whose report could not be finalised is not a run on record
        history.append(history.make_record(findings, tools_used, ctx.client_label, dry_run))
    except OSError:
        pass  # history is best-effort; never fail a run over it
    return findings, written

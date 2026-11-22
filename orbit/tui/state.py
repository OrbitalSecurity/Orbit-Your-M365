"""Session state shared between screens."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from orbit.core.outputs import OutputConfig
from orbit.core.runner import ToolRun
from orbit.reporting.parser import Finding


@dataclass
class SessionState:
    dry_run: bool = False
    selected: set[str] = field(default_factory=set)
    output: OutputConfig = field(default_factory=OutputConfig)
    passphrase: str | None = None
    run_folder: Path | None = None  # set only once a run has started and its report is finalised
    run_notice: str = ""            # otherwise, why there is no report
    runs: dict[str, ToolRun] = field(default_factory=dict)
    client_name: str = ""
    findings: list[Finding] = field(default_factory=list)  # of run_folder, published with it

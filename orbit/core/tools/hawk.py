from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from orbit.core.tools.base import LaunchSpec, Tool, cred_env

if TYPE_CHECKING:
    from orbit.core.hash_checker import Binding


class Hawk(Tool):
    name = "hawk"
    display = "Hawk"
    github = "https://github.com/T0pCyber/hawk"
    route = "psgallery"
    package = "Hawk"
    fixture = ""

    def launch_spec(self, creds: dict, out_dir: Path, binding: Binding) -> LaunchSpec:
        script = (
            "Start-HawkTenantInvestigation -FilePath $env:ORBIT_OUT_DIR -SkipUpdate"
        )
        env = cred_env("HAWK", creds)
        env["ORBIT_OUT_DIR"] = str(out_dir)
        return self.ps_launch(script, env, out_dir, binding)

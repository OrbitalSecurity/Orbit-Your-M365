from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from orbit.core.tools.base import LaunchSpec, Tool, cred_env

if TYPE_CHECKING:
    from orbit.core.hash_checker import Binding


class Monkey365(Tool):
    name = "monkey365"
    display = "Monkey365"
    github = "https://github.com/silverhack/monkey365"
    route = "psgallery"
    package = "monkey365"
    fixture = "monkey365_sample.json"
    output_name = "monkey365.json"

    def launch_spec(self, creds: dict, out_dir: Path, binding: Binding) -> LaunchSpec:
        script = (
            "Invoke-Monkey365 -Instance Microsoft365 -Analysis All "
            "-ClientId $env:ORBIT_MONKEY_CLIENT_ID -ClientSecret $env:ORBIT_MONKEY_CLIENT_SECRET "
            "-TenantId $env:ORBIT_MONKEY_TENANT_ID -SubscriptionId $env:ORBIT_MONKEY_SUBSCRIPTION_ID "
            "-ExportTo JSON -OutDir $env:ORBIT_OUT_DIR"
        )
        env = cred_env("MONKEY", creds)
        env["ORBIT_OUT_DIR"] = str(out_dir)
        return self.ps_launch(script, env, out_dir, binding)

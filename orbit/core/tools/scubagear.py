from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from orbit.core.tools.base import LaunchSpec, Tool, cred_env

if TYPE_CHECKING:
    from orbit.core.hash_checker import Binding


class ScubaGear(Tool):
    name = "scubagear"
    display = "ScubaGear"
    github = "https://github.com/cisagov/ScubaGear"
    route = "psgallery"
    package = "ScubaGear"
    needs_admin = True
    supported_os = ("windows",)
    fixture = "scubagear_sample.json"
    output_name = "ScubaResults.json"

    def launch_spec(self, creds: dict, out_dir: Path, binding: Binding) -> LaunchSpec:
        script = (
            "Invoke-SCuBA -ProductNames * -OutPath $env:ORBIT_OUT_DIR "
            "-AppID $env:ORBIT_SCUBA_CLIENT_ID -Organization $env:ORBIT_SCUBA_TENANT_ID "
            "-CertificateThumbprint $env:ORBIT_SCUBA_CERT_THUMBPRINT"
        )
        env = cred_env("SCUBA", creds)
        env["ORBIT_OUT_DIR"] = str(out_dir)
        return self.ps_launch(script, env, out_dir, binding)

    def opa_spec(self, binding: Binding) -> LaunchSpec:
        """Initialize-SCuBA from the verified snapshot, with the verified PowerShell."""
        return self.ps_launch("Initialize-SCuBA", {}, binding.private_dir, binding)

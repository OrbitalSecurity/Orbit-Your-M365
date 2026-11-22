from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from orbit.core.executables import ExecutableError
from orbit.core.tools.base import LaunchSpec, Tool, cred_env

if TYPE_CHECKING:
    from orbit.core.hash_checker import Binding

REAL_RUN_BLOCK = "real runs are disabled because sign-in writes plaintext tokens to disk; use --dry-run"

# Not reachable while REAL_RUN_BLOCK stands: `auth -f` writes the token in plaintext.
# Runs under `-I -S`: no site-packages, .pth, sitecustomize or usercustomize. The only code
# outside the standard library that can be imported is the verified snapshot. The namespace is
# bound by hand, because a normal import would recompute it from every sys.path entry.
# The token directory is also removed here, in case ORBIT itself has died by then.
_LAUNCHER = """\
import os, shutil, signal, sys, types

def stop(number, frame):
    signal.signal(number, signal.SIG_IGN)
    raise SystemExit(128 + number)

private = os.environ['ORBIT_AUTH_DIR']
try:
    for name in ('SIGTERM', 'SIGHUP'):
        if hasattr(signal, name):
            signal.signal(getattr(signal, name), stop)
    os.umask(0o077)
    snapshot = os.environ['ORBIT_SNAPSHOT']
    sys.path.insert(0, snapshot)
    package = types.ModuleType('roadtools')
    package.__path__ = [os.path.join(snapshot, 'roadtools')]
    sys.modules['roadtools'] = package
    from roadtools.roadrecon.main import main

    tokens = os.path.join(private, '.roadtools_auth.json')
    auth = ['auth', '-f', tokens]
    client = os.environ.get('ORBIT_ROAD_CLIENT_ID')
    if client:
        auth += ['-c', client]
    if os.environ.get('ORBIT_ROAD_DEVICE_CODE'):
        auth += ['--device-code']
    sys.argv = ['roadrecon'] + auth
    main()
    sys.argv = ['roadrecon', 'gather', '-f', tokens,
                '-d', os.path.join(os.environ['ORBIT_OUT_DIR'], 'roadrecon.db')]
    main()
finally:
    os.chdir(os.path.dirname(private))
    shutil.rmtree(private, ignore_errors=True)
"""


class ROADtools(Tool):
    name = "roadtools"
    display = "ROADtools"
    github = "https://github.com/dirkjanm/ROADtools"
    route = "pypi"
    package = "roadrecon"
    needs_pwsh = False
    import_root = "roadtools"  # namespace directory shared with roadlib, so both get hashed
    import_package = "roadrecon"
    auth_material = True
    real_run_block = REAL_RUN_BLOCK

    def launch_spec(self, creds: dict, out_dir: Path, binding: Binding) -> LaunchSpec:
        if self.real_run_block:
            raise ExecutableError(f"{self.display}: {self.real_run_block}")
        # Client ID and flow are read from env by a tiny launcher so argv stays secret-free.
        env = cred_env("ROAD", creds)
        env.update(ORBIT_OUT_DIR=str(out_dir), ORBIT_SNAPSHOT=str(binding.root),
                   ORBIT_AUTH_DIR=str(binding.private_dir))
        # -I: ignore PYTHON* variables, the user site and the working directory.
        # -S: no site processing at all. -B: never write bytecode into the snapshot.
        # cwd is the private directory, so a token written to a default relative path stays there.
        return LaunchSpec([str(binding.executable.path), "-I", "-S", "-B", "-c", _LAUNCHER],
                          env, binding.private_dir)

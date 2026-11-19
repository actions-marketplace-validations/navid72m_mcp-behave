"""Container sandboxing support (Docker / Podman) for mcp-behave.
Executes target MCP servers inside ephemeral, isolated containers with dropped capabilities,
read-only workspace mounts, isolated network namespaces, and canary $HOME redirection.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from typing import Literal

DEFAULT_PYTHON_IMAGE = "python:3.12-slim"
DEFAULT_NODE_IMAGE = "node:20-slim"


def detect_container_runtime() -> str | None:
    """Detect if Podman or Docker is installed and its daemon/socket is responsive.
    Prefers Podman for rootless container execution, then Docker.
    Returns 'podman', 'docker', or None.
    """
    for runtime in ("podman", "docker"):
        path = shutil.which(runtime)
        if not path:
            continue
        try:
            res = subprocess.run(
                [path, "info"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=2.0,
            )
            if res.returncode == 0:
                return runtime
        except (subprocess.TimeoutExpired, OSError):
            continue
    return None


def select_default_image(server_cmd: list[str]) -> str:
    """Infer an appropriate slim container image based on server executable."""
    if not server_cmd:
        return DEFAULT_PYTHON_IMAGE
    exe = os.path.basename(server_cmd[0]).lower()
    if any(k in exe for k in ("node", "npm", "npx", "bun")):
        return DEFAULT_NODE_IMAGE
    return DEFAULT_PYTHON_IMAGE


def build_sandbox_command(
    server_cmd: list[str],
    runtime: str,
    canary_dir: str | None = None,
    cwd: str | None = None,
    network: Literal["none", "bridge", "host"] = "none",
    image: str | None = None,
    env_vars: dict[str, str] | None = None,
) -> list[str]:
    """Wraps an MCP server launch command in an ephemeral, locked-down container invocation.
    
    Security properties:
    - --rm: container is destroyed immediately upon process exit.
    - -i: keeps stdin open for MCP JSON-RPC stdio protocol.
    - --network=none (or user choice): prevents unauthorized remote phoning home.
    - --cap-drop=ALL: strips all Linux capabilities (cannot mount, cannot sniff network).
    - --security-opt=no-new-privileges: forbids privilege escalation via setuid.
    - Read-only workspace bind mount: prevents tampering with host repository code.
    - Canary $HOME bind mount: isolates sensitive host directories from discovery.
    """
    img = image or select_default_image(server_cmd)
    workdir = cwd or os.getcwd()

    cmd = [
        runtime, "run",
        "--rm",
        "-i",
        f"--network={network}",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "-v", f"{workdir}:/workspace:ro",
        "-w", "/workspace",
    ]

    if canary_dir and os.path.exists(canary_dir):
        cmd.extend(["-v", f"{canary_dir}:/canary_home:rw"])
        cmd.extend(["-e", "HOME=/canary_home"])
        cmd.extend(["-e", "USERPROFILE=/canary_home"])
        cmd.extend(["-e", "XDG_CONFIG_HOME=/canary_home/.config"])
        cmd.extend(["-e", "XDG_DATA_HOME=/canary_home/.local/share"])

    if env_vars:
        for k, v in env_vars.items():
            cmd.extend(["-e", f"{k}={v}"])

    cmd.append(img)
    cmd.extend(server_cmd)
    return cmd

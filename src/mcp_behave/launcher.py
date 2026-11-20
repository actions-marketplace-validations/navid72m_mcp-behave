"""Subprocess management, process group signaling, and server ID derivation for mcp-behave wrap.

Spawns monitored target servers in isolated process groups (start_new_session=True),
safely terminates descendants across npx/uvx wrapper boundaries, and passes child stderr
directly to parent stderr without polluting JSON-RPC stdout.
"""
from __future__ import annotations

import asyncio
import hashlib
import os
import re
import signal
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional


def derive_server_id(server_cmd: List[str]) -> str:
    """Derive a stable, descriptive identifier for a server command.

    Format: <command_basename>_<short_hash_of_argv>
    e.g. npx_server-everything_a1b2c3d4 or uvx_mcp-server-time_e5f6g7h8
    """
    if not server_cmd:
        return "unknown_server"

    base = Path(server_cmd[0]).name
    # If launched through a package runner, include the target tool/package name
    if base in ("npx", "uvx", "uv", "python", "python3", "node", "bun", "deno") and len(server_cmd) > 1:
        for arg in server_cmd[1:]:
            if not arg.startswith("-"):
                target_base = Path(arg).name.lstrip("@").replace("/", "_")
                base = f"{base}_{target_base}"
                break

    argv_str = " ".join(server_cmd)
    short_hash = hashlib.sha256(argv_str.encode("utf-8")).hexdigest()[:8]
    clean_name = re.sub(r"[^a-zA-Z0-9_\-]", "_", base)
    return f"{clean_name}_{short_hash}"


def resolve_server_executable(cmd: str, env: Optional[Dict[str, str]] = None) -> str:
    """Resolve executable path, expanding ~ and searching standard macOS directories if PATH is minimal.

    GUI MCP clients (Claude Desktop, Cursor) often launch processes with a minimal launchd PATH
    (e.g. /usr/bin:/bin:/usr/sbin:/sbin), missing Homebrew (/opt/homebrew/bin), Cargo, and uv paths.
    """
    import shutil

    if os.path.isabs(cmd) or os.path.sep in cmd:
        expanded = os.path.expanduser(cmd)
        if os.path.exists(expanded):
            return expanded
        return cmd

    current_path = (env.get("PATH") if env else None) or os.environ.get("PATH", "")
    extra_dirs = [
        os.path.expanduser("~/.local/bin"),
        os.path.expanduser("~/.cargo/bin"),
        "/opt/homebrew/bin",
        "/opt/homebrew/sbin",
        "/usr/local/bin",
        "/usr/bin",
        "/bin",
    ]
    path_dirs = [d for d in current_path.split(os.path.pathsep) if d]
    for d in extra_dirs:
        if d not in path_dirs:
            path_dirs.append(d)

    augmented_path = os.path.pathsep.join(path_dirs)
    resolved = shutil.which(cmd, path=augmented_path)
    return resolved if resolved else cmd


async def spawn_child_server(
    server_cmd: List[str],
    env: Optional[Dict[str, str]] = None,
) -> asyncio.subprocess.Process:
    """Spawn target MCP server subprocess with start_new_session=True.

    stdin: PIPE (fed by wrap)
    stdout: PIPE (read by wrap)
    stderr: None (inherits parent stderr directly, ensuring stdout purity)
    """
    if not server_cmd:
        raise ValueError("Cannot spawn child server with empty command list.")

    child_env = dict(os.environ)
    if env:
        child_env.update(env)

    # Augment child PATH with standard directories if launched with minimal PATH (e.g. Claude Desktop GUI)
    current_path = child_env.get("PATH", "")
    extra_dirs = [
        os.path.expanduser("~/.local/bin"),
        os.path.expanduser("~/.cargo/bin"),
        "/opt/homebrew/bin",
        "/opt/homebrew/sbin",
        "/usr/local/bin",
    ]
    path_dirs = [d for d in current_path.split(os.path.pathsep) if d]
    for d in extra_dirs:
        if d not in path_dirs and os.path.isdir(d):
            path_dirs.append(d)
    child_env["PATH"] = os.path.pathsep.join(path_dirs)

    # Resolve executable path even under minimal PATH environments
    resolved_binary = resolve_server_executable(server_cmd[0], child_env)
    eff_cmd = [resolved_binary] + list(server_cmd[1:])

    # start_new_session=True ensures the child becomes a process group leader,
    # allowing os.killpg() to cleanly reap all descendants (e.g. npx/uvx grandchildren).
    proc = await asyncio.create_subprocess_exec(
        *eff_cmd,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=None,  # pass-through to sys.stderr
        start_new_session=True,
        env=child_env,
    )
    return proc


async def terminate_process_group(
    proc: asyncio.subprocess.Process,
    grace_period: float = 3.0,
    close_stdin: bool = True,
) -> int:
    """Terminate the child and its entire process group cleanly.

    Order:
    1. Close child stdin (if open)
    2. Wait for child to exit within grace_period (default 3s)
    3. If not exited, SIGTERM process group (os.killpg(proc.pid, signal.SIGTERM))
    4. Wait up to 1s
    5. If still not exited, SIGKILL process group (os.killpg(proc.pid, signal.SIGKILL))
    6. Return exit code.
    """
    if proc.returncode is not None:
        return proc.returncode

    # 1. Close child stdin
    if close_stdin and proc.stdin:
        try:
            proc.stdin.close()
            await proc.stdin.wait_closed()
        except (BrokenPipeError, ConnectionResetError, Exception):
            pass

    # 2. Wait for graceful exit
    try:
        await asyncio.wait_for(proc.wait(), timeout=grace_period)
        return proc.returncode if proc.returncode is not None else 0
    except asyncio.TimeoutError:
        pass

    # 3. SIGTERM process group
    pid = proc.pid
    try:
        os.killpg(pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        pass

    # 4. Wait up to 1.0s for SIGTERM
    try:
        await asyncio.wait_for(proc.wait(), timeout=1.0)
        return proc.returncode if proc.returncode is not None else 0
    except asyncio.TimeoutError:
        pass

    # 5. SIGKILL process group
    try:
        os.killpg(pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass

    try:
        await asyncio.wait_for(proc.wait(), timeout=1.0)
    except asyncio.TimeoutError:
        pass

    return proc.returncode if proc.returncode is not None else 137

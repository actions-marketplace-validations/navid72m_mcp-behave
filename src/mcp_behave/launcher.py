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


STANDARD_FALLBACK_DIRS = [
    "/opt/homebrew/bin",
    "/opt/homebrew/sbin",
    "/usr/local/bin",
    "/usr/bin",
    "/bin",
    os.path.expanduser("~/.local/bin"),
    os.path.expanduser("~/.cargo/bin"),
]


def resolve_server_executable(
    cmd: str, env: Optional[Dict[str, str]] = None
) -> Tuple[str, Optional[str]]:
    """Resolve executable path and compute its sha256 checksum.

    To prevent PATH hijacking vulnerabilities, existing PATH entries always take
    precedence; fallback system/Homebrew directories are only appended AFTER the existing PATH
    if the command is not found in the primary PATH.

    Returns:
        (resolved_absolute_path_or_cmd, sha256_checksum_or_none)
    """
    import shutil

    resolved_path: Optional[str] = None

    if os.path.isabs(cmd) or os.path.sep in cmd:
        expanded = os.path.expanduser(cmd)
        if os.path.exists(expanded):
            resolved_path = os.path.abspath(expanded)
        else:
            resolved_path = cmd
    else:
        current_path = (env.get("PATH") if env else None) or os.environ.get("PATH", "")
        path_dirs = [d for d in current_path.split(os.path.pathsep) if d]

        # 1. First attempt resolution strictly on the existing PATH (never hijacked by fallbacks)
        resolved = shutil.which(cmd, path=os.path.pathsep.join(path_dirs))
        if resolved:
            resolved_path = os.path.abspath(resolved)
        else:
            # 2. Append fallback dirs strictly after the existing PATH
            fallback_search = list(path_dirs)
            for fb in STANDARD_FALLBACK_DIRS:
                if fb not in fallback_search and os.path.isdir(fb):
                    fallback_search.append(fb)
            fallback_resolved = shutil.which(cmd, path=os.path.pathsep.join(fallback_search))
            resolved_path = os.path.abspath(fallback_resolved) if fallback_resolved else cmd

    # Compute SHA-256 if resolved to a readable regular file
    sha256_hex: Optional[str] = None
    if resolved_path and os.path.isfile(resolved_path):
        try:
            with open(resolved_path, "rb") as f:
                sha256_hex = hashlib.sha256(f.read()).hexdigest()
        except (OSError, PermissionError):
            sha256_hex = None

    return resolved_path, sha256_hex


async def spawn_child_server(
    server_cmd: List[str],
    env: Optional[Dict[str, str]] = None,
    augment_path: bool = False,
) -> Tuple[asyncio.subprocess.Process, str, Optional[str]]:
    """Spawn target MCP server subprocess with start_new_session=True.

    stdin: PIPE (fed by wrap)
    stdout: PIPE (read by wrap)
    stderr: None (inherits parent stderr directly, ensuring stdout purity)

    By default, child environment PATH is left UNCHANGED to avoid path hijacking.
    If augment_path=True, standard fallback directories are appended strictly after
    existing PATH entries.

    Returns:
        (child_proc, resolved_command_path, resolved_command_sha256)
    """
    if not server_cmd:
        raise ValueError("Cannot spawn child server with empty command list.")

    child_env = dict(os.environ)
    if env:
        child_env.update(env)

    # Resolve executable path (using fallback dirs strictly for resolution)
    resolved_binary, resolved_sha256 = resolve_server_executable(server_cmd[0], child_env)
    eff_cmd = [resolved_binary] + list(server_cmd[1:])

    # Child PATH augmentation is opt-in only
    if augment_path:
        current_path = child_env.get("PATH", "")
        path_dirs = [d for d in current_path.split(os.path.pathsep) if d]
        for fb in STANDARD_FALLBACK_DIRS:
            if fb not in path_dirs and os.path.isdir(fb):
                path_dirs.append(fb)
        child_env["PATH"] = os.path.pathsep.join(path_dirs)

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
    return proc, resolved_binary, resolved_sha256


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

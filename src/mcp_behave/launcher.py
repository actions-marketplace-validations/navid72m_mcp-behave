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
from typing import Any, Dict, List, Optional, Tuple


def get_tracer_environment(
    resolved_binary: str,
    enable_trace: bool = True,
) -> Tuple[Dict[str, str], Optional[str]]:
    """Determine dynamic tracer interposition library and environment.

    Returns:
        (tracer_env_dict, disabled_reason_or_none)
    """
    if not enable_trace:
        return {}, "disabled_by_config"

    import platform
    from .probe import _linux_tracer_so, _macos_tracer_dylib, _target_is_hardened

    sys_name = platform.system()
    if sys_name == "Darwin":
        # Check hardened runtime (SIP/hardened binaries refuse injection)
        is_hardened = _target_is_hardened(resolved_binary)
        if is_hardened:
            return {}, "hardened_runtime"

        dylib_path = _macos_tracer_dylib()
        if not dylib_path or not os.path.isfile(dylib_path):
            return {}, "no_compiler"

        return {"DYLD_INSERT_LIBRARIES": dylib_path}, None

    elif sys_name == "Linux":
        so_path = _linux_tracer_so()
        if not so_path or not os.path.isfile(so_path):
            return {}, "no_compiler"

        return {"LD_PRELOAD": so_path}, None

    return {}, "unsupported_os"


def prepare_sandbox_command(
    server_cmd: List[str],
    sandbox: str = "none",
    server_lock: Optional[Any] = None,
    fail_mode: str = "fail-closed",
) -> Tuple[List[str], Dict[str, Any]]:
    """Determine effective sandboxing command wrapping and metadata (Milestone 5).

    Returns:
        (sandboxed_cmd, sandbox_status_dict)
    """
    if not server_cmd:
        return server_cmd, {"status": "disabled", "reason": "empty_command"}

    mode = (sandbox or "none").lower()
    if mode == "none":
        return server_cmd, {"status": "disabled", "reason": "disabled_by_config"}

    import sys
    from .sandbox import build_sandbox_command, detect_container_runtime
    from .seatbelt import build_seatbelt_command, generate_seatbelt_profile, is_seatbelt_available

    target_backend = mode
    if mode == "auto":
        if sys.platform == "darwin":
            target_backend = "seatbelt"
        elif sys.platform == "linux":
            target_backend = "container"
        else:
            target_backend = "none"

    if target_backend == "seatbelt":
        if is_seatbelt_available():
            try:
                profile = generate_seatbelt_profile(server_lock=server_lock)
                sandboxed = build_seatbelt_command(server_cmd, profile)
                return sandboxed, {"status": "active", "backend": "seatbelt"}
            except Exception as exc:
                if fail_mode == "fail-closed":
                    raise RuntimeError(f"Seatbelt sandbox initialization failed: {exc}")
                return server_cmd, {"status": "disabled", "reason": "seatbelt_initialization_failed"}
        else:
            if fail_mode == "fail-closed":
                raise RuntimeError("Darwin Seatbelt (sandbox-exec) is unavailable on this host under fail-closed mode.")
            return server_cmd, {"status": "disabled", "reason": "seatbelt_unavailable"}

    elif target_backend == "container":
        runtime = detect_container_runtime()
        if runtime:
            try:
                sandboxed = build_sandbox_command(server_cmd, runtime=runtime)
                return sandboxed, {"status": "active", "backend": "container", "runtime": runtime}
            except Exception as exc:
                if fail_mode == "fail-closed":
                    raise RuntimeError(f"Container sandbox initialization failed: {exc}")
                return server_cmd, {"status": "disabled", "reason": "container_initialization_failed"}
        else:
            if fail_mode == "fail-closed":
                raise RuntimeError("Container runtime (docker/podman) is unavailable under fail-closed mode.")
            return server_cmd, {"status": "disabled", "reason": "container_unavailable"}

    return server_cmd, {"status": "disabled", "reason": "unsupported_platform"}


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

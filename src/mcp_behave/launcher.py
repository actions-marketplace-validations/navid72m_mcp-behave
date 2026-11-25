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

    # Check hardened runtime (SIP/hardened binaries refuse injection)
    is_hardened = _target_is_hardened(resolved_binary)
    if is_hardened:
        return {}, "hardened_runtime"

    sys_name = platform.system()
    if sys_name == "Darwin":
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


PROCESS_POLL_INTERVAL = 0.02
TERM_TIMEOUT = 1.0
KILL_TIMEOUT = 1.0


async def wait_for_root_exit(proc: asyncio.subprocess.Process) -> None:
    """Observe root exit even when a descendant holds a subprocess pipe open."""
    while proc.returncode is None:
        await asyncio.sleep(PROCESS_POLL_INTERVAL)


async def terminate_process_group(
    proc: asyncio.subprocess.Process,
    grace_period: float = 3.0,
    close_stdin: bool = True,
) -> int:
    """Close stdin and escalate against the session created by spawn_child_server.

    Preserves the root's original exit code if it already exited, while still
    signaling and reaping any surviving process-group members.
    """
    original_exit_code: Optional[int] = proc.returncode

    if close_stdin and proc.stdin and original_exit_code is None:
        try:
            proc.stdin.close()
        except Exception as exc:
            print(f"mcp-behave wrap: incomplete cleanup of child stdin: {exc}", file=sys.stderr)

    # start_new_session establishes PGID == pid. Looking up a departed root
    # cannot tell us whether the original group still has members.
    pgid = proc.pid
    loop = asyncio.get_running_loop()

    def signal_group(sig: int) -> bool:
        try:
            os.killpg(pgid, sig)
        except ProcessLookupError:
            return False
        except OSError as exc:
            print(f"mcp-behave wrap: cannot signal owned group {pgid}: {exc}", file=sys.stderr)
        return True

    async def wait_until_gone(timeout: float) -> bool:
        deadline = loop.time() + timeout
        while True:
            if not signal_group(0):
                # Once the group is absent, never signal that numeric ID again.
                return True
            remaining = deadline - loop.time()
            if remaining <= 0:
                return False
            await asyncio.sleep(min(PROCESS_POLL_INTERVAL, remaining))

    gone = await wait_until_gone(grace_period if original_exit_code is None else 0)
    for sig, timeout in ((signal.SIGTERM, TERM_TIMEOUT), (signal.SIGKILL, KILL_TIMEOUT)):
        if gone:
            break
        if not signal_group(sig):
            gone = True
            break
        gone = await wait_until_gone(timeout)

    if not gone:
        print(f"mcp-behave wrap: incomplete cleanup: group {pgid} still exists after SIGKILL",
              file=sys.stderr)
    if proc.returncode is None:
        try:
            await asyncio.wait_for(wait_for_root_exit(proc), timeout=KILL_TIMEOUT)
        except asyncio.TimeoutError:
            print(f"mcp-behave wrap: incomplete cleanup: root status unavailable for {pgid}",
                  file=sys.stderr)
    if original_exit_code is not None:
        return original_exit_code
    return proc.returncode if proc.returncode is not None else 137

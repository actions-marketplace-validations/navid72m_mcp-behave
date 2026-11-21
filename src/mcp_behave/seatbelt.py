"""macOS Darwin Seatbelt (sandbox-exec) profile generator and launcher (Milestone 5).

Translates behavioral lockfile safety declarations into kernel-enforced Scheme (.sb) rules:
- Restricts filesystem writes according to readOnlyHint declarations.
- Restricts network egress to localhost when openWorldHint=False.
- Canonicalizes and sanitizes all paths to prevent escaping sandbox rules.
"""
from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from .lockfile import ServerLock


def is_seatbelt_available() -> bool:
    """Check if macOS Darwin sandbox-exec is available on host."""
    return sys.platform == "darwin" and shutil.which("sandbox-exec") is not None


def escape_scheme_path(path: str) -> str:
    """Canonicalize path and escape quotes/backslashes for Scheme string literals."""
    if not path:
        return ""
    # Canonicalize path to prevent symlink traversal escaping sandbox rules
    try:
        resolved = os.path.realpath(path)
    except Exception:
        resolved = os.path.abspath(path)

    # Escape backslashes and double quotes
    return resolved.replace("\\", "\\\\").replace('"', '\\"')


def generate_seatbelt_profile(
    server_lock: Optional[ServerLock] = None,
    allowed_write_paths: Optional[List[str]] = None,
    allow_network: Optional[bool] = None,
    workspace_path: Optional[str] = None,
) -> str:
    """Generate a macOS Seatbelt profile string (.sb) derived from server lockfile.

    Rules:
    - Base: (version 1) (allow default)
    - If server is read-only (all tools declare readOnlyHint=True), deny writes
      except /tmp, /private/tmp, /dev/null, /dev/zero, /dev/tty, and declared allowed_write_paths.
    - If server denies open-world egress (openWorldHint=False), deny network-outbound
      except to localhost:*.
    """
    rules: List[str] = [
        "(version 1)",
        "(allow default)",
    ]

    # Evaluate safety hints across tools
    read_only = False
    open_world = True

    if server_lock and server_lock.manifest and "tools" in server_lock.manifest:
        tools = server_lock.manifest["tools"]
        if tools:
            # If all tools declare readOnlyHint=True, the server is strictly read-only
            read_only = all(
                t.annotations.get("readOnlyHint", False)
                for t in tools.values()
                if t.annotations
            )
            # If any tool declares openWorldHint=True, network egress is allowed
            open_world = any(
                t.annotations.get("openWorldHint", True)
                for t in tools.values()
                if t.annotations
            )

    # CLI / argument overrides take precedence
    if allow_network is not None:
        open_world = allow_network

    # Filesystem write restrictions
    if read_only:
        # Deny writes by default
        rules.append('(deny file-write*)')

        # Always allow temporary files and system virtual devices
        rules.append('(allow file-write* (subpath "/tmp"))')
        rules.append('(allow file-write* (subpath "/private/tmp"))')
        rules.append('(allow file-write* (literal "/dev/null"))')
        rules.append('(allow file-write* (literal "/dev/zero"))')
        rules.append('(allow file-write* (literal "/dev/tty"))')

        # Allow explicitly permitted write paths
        if allowed_write_paths:
            for p in allowed_write_paths:
                escaped = escape_scheme_path(p)
                if os.path.isdir(p):
                    rules.append(f'(allow file-write* (subpath "{escaped}"))')
                else:
                    rules.append(f'(allow file-write* (literal "{escaped}"))')

    # Network restrictions
    if not open_world:
        # Restrict network outbound strictly to localhost
        rules.append('(deny network-outbound)')
        rules.append('(allow network-outbound (to ip "localhost:*"))')

    return "\n".join(rules) + "\n"


def build_seatbelt_command(
    server_cmd: List[str],
    profile_text: str,
) -> List[str]:
    """Prefix server command with sandbox-exec and inline profile."""
    sandbox_exec = shutil.which("sandbox-exec") or "/usr/bin/sandbox-exec"
    return [sandbox_exec, "-p", profile_text] + list(server_cmd)

"""mcp-behave install / uninstall / status: automated client configuration management.

Provides zero-friction, non-destructive onboarding and management for MCP clients
(Claude Desktop, Cursor, Claude Code) by automatically wrapping/unwrapping configured
servers with `mcp-behave wrap`.
"""
from __future__ import annotations

import argparse
import difflib
import json
import os
import platform
import shutil
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import __version__
from .lockfile import find_lockfile, load_lockfile

# Option flags known to `mcp-behave wrap` that take an argument
WRAP_VALUE_OPTIONS = {
    "--sandbox",
    "--fail-mode",
    "--reverify-interval",
    "--reverify-period",
    "--canary",
    "--canary-file",
    "--lockfile",
    "--tracer",
    "--canary-dir",
    "--state-dir",
    "--server-id",
    "-c",
    "--config",
}

# Option flags known to `mcp-behave wrap` that are boolean flags
WRAP_BOOL_OPTIONS = {
    "--enforce",
    "--redact",
    "--no-reverify",
    "--no-content-scan",
    "--no-trace",
    "--dry-run",
}


@dataclass
class ConfigTarget:
    client_id: str  # "claude", "cursor", "claude-code"
    display_name: str  # e.g. "Claude Desktop"
    path: Path
    container_key: str = "mcpServers"


def get_client_config_targets(
    client_filter: str = "all",
    custom_paths: Optional[List[Path]] = None,
    workspace: Optional[Path] = None,
) -> List[ConfigTarget]:
    """Resolve candidate configuration file locations across macOS, Linux, and Windows."""
    system = platform.system()
    home = Path.home()
    candidates: List[ConfigTarget] = []

    if custom_paths:
        for p in custom_paths:
            path_obj = Path(p).resolve()
            candidates.append(ConfigTarget(
                client_id="custom",
                display_name="Custom Config",
                path=path_obj,
            ))
        return candidates

    # 1. Claude Desktop
    if client_filter in ("all", "claude"):
        if system == "Darwin":
            claude_path = home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
        elif system == "Windows":
            appdata = os.environ.get("APPDATA")
            claude_path = Path(appdata) / "Claude" / "claude_desktop_config.json" if appdata else home / "Claude" / "claude_desktop_config.json"
        else:  # Linux / Unix
            claude_path = home / ".config" / "Claude" / "claude_desktop_config.json"
        candidates.append(ConfigTarget(client_id="claude", display_name="Claude Desktop", path=claude_path))

    # 2. Cursor
    if client_filter in ("all", "cursor"):
        cursor_global = home / ".cursor" / "mcp.json"
        candidates.append(ConfigTarget(client_id="cursor", display_name="Cursor (Global)", path=cursor_global))

        cwd_path = (workspace or Path.cwd()) / ".cursor" / "mcp.json"
        if cwd_path != cursor_global:
            candidates.append(ConfigTarget(client_id="cursor", display_name="Cursor (Project)", path=cwd_path))

    # 3. Claude Code
    if client_filter in ("all", "claude-code"):
        claude_code_dir = home / ".claude" / "mcp.json"
        claude_code_root = home / ".claude.json"
        candidates.append(ConfigTarget(client_id="claude-code", display_name="Claude Code (~/.claude/mcp.json)", path=claude_code_dir))
        candidates.append(ConfigTarget(client_id="claude-code", display_name="Claude Code (~/.claude.json)", path=claude_code_root))

    return candidates


def is_server_wrapped(server_def: Dict[str, Any]) -> bool:
    """Determine whether a server configuration dictionary is wrapped by mcp-behave."""
    if not isinstance(server_def, dict):
        return False
    cmd = str(server_def.get("command", "")).strip()
    args = server_def.get("args", [])
    if not isinstance(args, list):
        return False

    cmd_base = Path(cmd).name.lower()
    if cmd_base in ("mcp-behave", "mcp-behave.exe") or cmd == "mcp-behave":
        if args and args[0] == "wrap":
            return True

    # Check for direct python / uvx runner wrappers
    if args and len(args) >= 3 and "mcp_behave" in " ".join(args[:3]) and "wrap" in args:
        return True

    return False


def unwrap_server_definition(server_def: Dict[str, Any]) -> Dict[str, Any]:
    """Safely remove mcp-behave wrapping and restore original executable and args."""
    if not is_server_wrapped(server_def):
        return dict(server_def)

    unwrapped = dict(server_def)
    args = list(server_def.get("args", []))

    # Pattern A: Standard explicit delimiter "--"
    if "--" in args:
        dash_idx = args.index("--")
        if dash_idx + 1 < len(args):
            unwrapped["command"] = args[dash_idx + 1]
            unwrapped["args"] = list(args[dash_idx + 2:])
        else:
            unwrapped["command"] = ""
            unwrapped["args"] = []
        return unwrapped

    # Pattern B: Legacy or manual wrap without "--"
    i = 1  # Skip "wrap"
    orig_cmd = None
    orig_args: List[str] = []
    while i < len(args):
        token = args[i]
        if token in WRAP_VALUE_OPTIONS:
            i += 2
        elif any(token.startswith(f"{opt}=") for opt in WRAP_VALUE_OPTIONS):
            i += 1
        elif token in WRAP_BOOL_OPTIONS:
            i += 1
        elif token.startswith("-"):
            i += 1
        else:
            orig_cmd = token
            orig_args = list(args[i + 1:])
            break

    if orig_cmd is not None:
        unwrapped["command"] = orig_cmd
        unwrapped["args"] = orig_args

    return unwrapped


def wrap_server_definition(
    server_def: Dict[str, Any],
    enforce: bool = False,
    sandbox: str = "none",
) -> Dict[str, Any]:
    """Wrap server configuration with mcp-behave wrap, enforcing idempotency."""
    # Ensure idempotency: if already wrapped, unwrap first to prevent nesting
    base_def = unwrap_server_definition(server_def) if is_server_wrapped(server_def) else dict(server_def)

    orig_cmd = str(base_def.get("command", "")).strip()
    orig_args = list(base_def.get("args", []))

    wrap_args = ["wrap"]
    if enforce:
        wrap_args.append("--enforce")
    if sandbox and sandbox != "none":
        wrap_args.extend(["--sandbox", sandbox])

    wrap_args.append("--")
    wrap_args.append(orig_cmd)
    wrap_args.extend([str(a) for a in orig_args])

    wrapped = dict(base_def)
    wrapped["command"] = "mcp-behave"
    wrapped["args"] = wrap_args
    return wrapped


def extract_wrapper_options(server_def: Dict[str, Any]) -> Dict[str, Any]:
    """Extract options configured in an active wrapper."""
    if not is_server_wrapped(server_def):
        return {"wrapped": False}

    args = list(server_def.get("args", []))
    enforce = "--enforce" in args
    sandbox = "none"
    if "--sandbox" in args:
        idx = args.index("--sandbox")
        if idx + 1 < len(args):
            sandbox = args[idx + 1]

    unwrapped = unwrap_server_definition(server_def)
    orig_cmd_parts = [unwrapped.get("command", "")] + [str(a) for a in unwrapped.get("args", [])]
    target_cmd = " ".join([p for p in orig_cmd_parts if p]).strip()

    return {
        "wrapped": True,
        "enforce": enforce,
        "sandbox": sandbox,
        "target_command": target_cmd,
    }


def create_backup_file(config_path: Path) -> Optional[Path]:
    """Create <config_path>.bak if it does not already exist."""
    bak_path = config_path.with_name(config_path.name + ".bak")
    if not config_path.exists():
        return None

    if bak_path.exists():
        # Preserve existing pre-wrap baseline backup
        return bak_path

    try:
        content = config_path.read_bytes()
        bak_path.write_bytes(content)
        return bak_path
    except Exception as exc:
        print(f"Warning: Failed to create backup file {bak_path}: {exc}", file=sys.stderr)
        return None


def atomic_write_json(config_path: Path, data: Dict[str, Any]) -> None:
    """Atomically write JSON data using tempfile + os.replace in target directory."""
    config_path.parent.mkdir(parents=True, exist_ok=True)
    temp_dir = config_path.parent

    payload = json.dumps(data, indent=2) + "\n"

    fd, temp_path = tempfile.mkstemp(dir=temp_dir, prefix=f"{config_path.name}.tmp-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(payload)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp_path, config_path)
    except Exception:
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                pass
        raise


def parse_json_config(path: Path) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Parse JSON configuration, handling comments if present."""
    if not path.is_file():
        return None, f"file not found: {path}"
    try:
        content = path.read_text(encoding="utf-8")
    except Exception as exc:
        return None, f"failed to read {path}: {exc}"

    cleaned_lines = []
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("//"):
            continue
        cleaned_lines.append(line)
    cleaned_content = "\n".join(cleaned_lines)

    try:
        data = json.loads(cleaned_content)
        if not isinstance(data, dict):
            return None, f"root JSON element in {path} must be an object"
        return data, None
    except json.JSONDecodeError as exc:
        return None, f"invalid JSON in {path}: {exc}"


def check_lockfile_for_server(server_name: str, config_dir: Optional[Path] = None) -> str:
    """Determine lockfile status for a server: 'PRESENT' or 'MISSING'."""
    lockfile_path = find_lockfile(config_dir or Path.cwd())
    if not lockfile_path or not lockfile_path.is_file():
        return "MISSING"

    loaded = load_lockfile(lockfile_path)
    if not loaded:
        return "MISSING"

    # Multi-server Lockfile (v2)
    if hasattr(loaded, "servers"):
        if server_name in loaded.servers:
            return "PRESENT"
        for sid in loaded.servers.keys():
            if sid.startswith(f"{server_name}-") or sid == server_name:
                return "PRESENT"
    # Legacy Lockfile
    elif isinstance(loaded, dict):
        if loaded.get("server_id") == server_name or server_name in str(loaded.get("command", "")):
            return "PRESENT"

    return "PRESENT" if loaded else "MISSING"


def execute_install(
    server_name: Optional[str] = None,
    client: str = "all",
    enforce: bool = False,
    sandbox: str = "none",
    dry_run: bool = False,
    custom_paths: Optional[List[Path]] = None,
    workspace: Optional[Path] = None,
) -> Tuple[int, List[str]]:
    """Install mcp-behave wrap into client configurations."""
    messages = []
    targets = get_client_config_targets(client_filter=client, custom_paths=custom_paths, workspace=workspace)

    existing_targets = [t for t in targets if t.path.is_file()]
    if not existing_targets:
        messages.append(f"No existing MCP client configurations found for client selector '{client}'.")
        return 0, messages

    total_modified = 0

    for target in existing_targets:
        data, err = parse_json_config(target.path)
        if err or data is None:
            messages.append(f"[{target.display_name}] Skipped: {err}")
            continue

        container_key = "mcpServers" if "mcpServers" in data else ("servers" if "servers" in data else "mcpServers")
        servers_map = data.setdefault(container_key, {})
        if not isinstance(servers_map, dict):
            messages.append(f"[{target.display_name}] Invalid container key '{container_key}' (not a dict)")
            continue

        file_modified = False
        target_servers = [server_name] if server_name else list(servers_map.keys())

        for sname in target_servers:
            if sname not in servers_map:
                if server_name:
                    messages.append(f"[{target.display_name}] Server '{sname}' not found in configuration.")
                continue

            sdef = servers_map[sname]
            if not isinstance(sdef, dict):
                continue

            current_wrapped = is_server_wrapped(sdef)
            new_sdef = wrap_server_definition(sdef, enforce=enforce, sandbox=sandbox)

            if sdef == new_sdef:
                messages.append(f"[{target.display_name}] Already wrapped: '{sname}' (no change needed)")
                continue

            # State changed
            servers_map[sname] = new_sdef
            file_modified = True
            total_modified += 1
            action_desc = "Updating wrapper" if current_wrapped else "Wrapping"
            messages.append(f"[{target.display_name}] {action_desc}: '{sname}' -> mcp-behave wrap {'--enforce ' if enforce else ''}{f'--sandbox {sandbox} ' if sandbox != 'none' else ''}-- {sdef.get('command')}")

        if file_modified:
            if dry_run:
                messages.append(f"[{target.display_name}] [DRY-RUN] Would update {target.path}")
            else:
                bak = create_backup_file(target.path)
                bak_msg = f" (backup: {bak.name})" if bak else ""
                atomic_write_json(target.path, data)
                messages.append(f"[{target.display_name}] Saved updated configuration to {target.path}{bak_msg}")

    summary = f"Install complete: {total_modified} server(s) {'would be ' if dry_run else ''}wrapped."
    messages.append(summary)
    return 0, messages


def execute_uninstall(
    server_name: Optional[str] = None,
    client: str = "all",
    dry_run: bool = False,
    custom_paths: Optional[List[Path]] = None,
    workspace: Optional[Path] = None,
) -> Tuple[int, List[str]]:
    """Uninstall mcp-behave wrap from client configurations."""
    messages = []
    targets = get_client_config_targets(client_filter=client, custom_paths=custom_paths, workspace=workspace)

    existing_targets = [t for t in targets if t.path.is_file()]
    if not existing_targets:
        messages.append(f"No existing MCP client configurations found for client selector '{client}'.")
        return 0, messages

    total_unwrapped = 0

    for target in existing_targets:
        data, err = parse_json_config(target.path)
        if err or data is None:
            messages.append(f"[{target.display_name}] Skipped: {err}")
            continue

        container_key = "mcpServers" if "mcpServers" in data else ("servers" if "servers" in data else "mcpServers")
        servers_map = data.get(container_key, {})
        if not isinstance(servers_map, dict):
            continue

        file_modified = False
        target_servers = [server_name] if server_name else list(servers_map.keys())

        for sname in target_servers:
            if sname not in servers_map:
                if server_name:
                    messages.append(f"[{target.display_name}] Server '{sname}' not found in configuration.")
                continue

            sdef = servers_map[sname]
            if not isinstance(sdef, dict):
                continue

            if not is_server_wrapped(sdef):
                messages.append(f"[{target.display_name}] Server '{sname}' is not wrapped (no change)")
                continue

            unwrapped_sdef = unwrap_server_definition(sdef)
            servers_map[sname] = unwrapped_sdef
            file_modified = True
            total_unwrapped += 1
            messages.append(f"[{target.display_name}] Unwrapped: '{sname}' -> {unwrapped_sdef.get('command')}")

        if file_modified:
            if dry_run:
                messages.append(f"[{target.display_name}] [DRY-RUN] Would restore {target.path}")
            else:
                atomic_write_json(target.path, data)
                messages.append(f"[{target.display_name}] Restored original configuration to {target.path}")

    summary = f"Uninstall complete: {total_unwrapped} server(s) {'would be ' if dry_run else ''}unwrapped."
    messages.append(summary)
    return 0, messages


def get_configuration_status(
    client: str = "all",
    custom_paths: Optional[List[Path]] = None,
    workspace: Optional[Path] = None,
) -> List[Dict[str, Any]]:
    """Gather status across client configurations."""
    results = []
    targets = get_client_config_targets(client_filter=client, custom_paths=custom_paths, workspace=workspace)

    for target in targets:
        exists = target.path.is_file()
        t_info: Dict[str, Any] = {
            "client_id": target.client_id,
            "display_name": target.display_name,
            "path": str(target.path),
            "exists": exists,
            "servers": [],
            "error": None,
        }

        if not exists:
            results.append(t_info)
            continue

        data, err = parse_json_config(target.path)
        if err or data is None:
            t_info["error"] = err
            results.append(t_info)
            continue

        container_key = "mcpServers" if "mcpServers" in data else ("servers" if "servers" in data else "mcpServers")
        servers_map = data.get(container_key, {})
        if isinstance(servers_map, dict):
            for sname, sdef in servers_map.items():
                if not isinstance(sdef, dict):
                    continue
                wrapped = is_server_wrapped(sdef)
                wrapper_opts = extract_wrapper_options(sdef)
                lock_status = check_lockfile_for_server(sname, target.path.parent)

                unwrapped_cmd_parts = [sdef.get("command", "")] + [str(a) for a in sdef.get("args", [])]
                if wrapped:
                    unwrapped = unwrap_server_definition(sdef)
                    unwrapped_cmd_parts = [unwrapped.get("command", "")] + [str(a) for a in unwrapped.get("args", [])]

                target_cmd_str = " ".join([p for p in unwrapped_cmd_parts if p]).strip()

                t_info["servers"].append({
                    "name": sname,
                    "wrapped": wrapped,
                    "enforce": wrapper_opts.get("enforce", False),
                    "sandbox": wrapper_opts.get("sandbox", "none"),
                    "target_command": target_cmd_str,
                    "lockfile": lock_status,
                })

        results.append(t_info)
    return results


def main_install(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="mcp-behave install",
        description="Safely inject mcp-behave wrap into MCP client configurations.",
    )
    parser.add_argument(
        "server_name", nargs="?", default=None,
        help="Optional server name to wrap. If omitted, wraps all servers in target configs.",
    )
    parser.add_argument(
        "--client", choices=["claude", "cursor", "claude-code", "all"], default="all",
        help="Target client configuration (default: all).",
    )
    parser.add_argument(
        "--enforce", action="store_true", default=False,
        help="Wrap server with strict behavioral lockfile enforcement (--enforce).",
    )
    parser.add_argument(
        "--sandbox", choices=["auto", "seatbelt", "container", "none"], default="none",
        help="Wrap server with OS sandboxing profile (default: none).",
    )
    parser.add_argument(
        "--dry-run", action="store_true", default=False,
        help="Preview configuration changes without writing to disk.",
    )
    parser.add_argument(
        "--config-path", dest="custom_path", default=None,
        help="Explicit path to client configuration file.",
    )

    args = parser.parse_args(argv)
    custom_paths = [Path(args.custom_path)] if args.custom_path else None

    code, msgs = execute_install(
        server_name=args.server_name,
        client=args.client,
        enforce=args.enforce,
        sandbox=args.sandbox,
        dry_run=args.dry_run,
        custom_paths=custom_paths,
    )

    for m in msgs:
        print(m)
    return code


def main_uninstall(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="mcp-behave uninstall",
        description="Safely remove mcp-behave wrap from MCP client configurations.",
    )
    parser.add_argument(
        "server_name", nargs="?", default=None,
        help="Optional server name to unwrap. If omitted, unwraps all servers in target configs.",
    )
    parser.add_argument(
        "--client", choices=["claude", "cursor", "claude-code", "all"], default="all",
        help="Target client configuration (default: all).",
    )
    parser.add_argument(
        "--dry-run", action="store_true", default=False,
        help="Preview configuration changes without writing to disk.",
    )
    parser.add_argument(
        "--config-path", dest="custom_path", default=None,
        help="Explicit path to client configuration file.",
    )

    args = parser.parse_args(argv)
    custom_paths = [Path(args.custom_path)] if args.custom_path else None

    code, msgs = execute_uninstall(
        server_name=args.server_name,
        client=args.client,
        dry_run=args.dry_run,
        custom_paths=custom_paths,
    )

    for m in msgs:
        print(m)
    return code


def main_status(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="mcp-behave status",
        description="Inspect MCP client configurations, wrapping status, and behavioral lockfiles.",
    )
    parser.add_argument(
        "--client", choices=["claude", "cursor", "claude-code", "all"], default="all",
        help="Target client configuration (default: all).",
    )
    parser.add_argument(
        "--json", action="store_true", default=False,
        help="Emit status inspection report as JSON.",
    )
    parser.add_argument(
        "--config-path", dest="custom_path", default=None,
        help="Explicit path to client configuration file.",
    )

    args = parser.parse_args(argv)
    custom_paths = [Path(args.custom_path)] if args.custom_path else None

    status_data = get_configuration_status(
        client=args.client,
        custom_paths=custom_paths,
    )

    if args.json:
        print(json.dumps(status_data, indent=2))
        return 0

    print("mcp-behave Client Configuration Status")
    print("=" * 45)
    print()

    found_any = False
    for item in status_data:
        if not item["exists"]:
            continue
        found_any = True
        print(f"[{item['display_name']}] {item['path']}")
        if item.get("error"):
            print(f"  Error: {item['error']}")
            print()
            continue

        servers = item.get("servers", [])
        if not servers:
            print("  (no servers configured)")
            print()
            continue

        for s in servers:
            status_tag = "[WRAPPED]  " if s["wrapped"] else "[UNWRAPPED]"
            print(f"  {status_tag} {s['name']}")
            print(f"    Command:  {s['target_command']}")
            if s["wrapped"]:
                opts = []
                if s["enforce"]:
                    opts.append("--enforce")
                if s["sandbox"] != "none":
                    opts.append(f"--sandbox {s['sandbox']}")
                opts_str = ", ".join(opts) if opts else "(standard monitoring)"
                print(f"    Options:  {opts_str}")
            print(f"    Lockfile: {s['lockfile']}")
            print()

    if not found_any:
        print(f"No existing client configurations found for selector '{args.client}'.")
        print()

    return 0

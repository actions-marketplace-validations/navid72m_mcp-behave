"""mcp-behave MCP server: exposes behavioral audit and inspection tools over MCP.

Enables AI agents and MCP clients (Claude Desktop, Cursor, Glama sandbox, etc.)
to audit and inspect MCP servers dynamically.
"""
import argparse
import os
import shlex
import sys
import tempfile
from typing import Any, Dict, List, Optional, Union

try:
    from mcp.server.fastmcp import FastMCP
    from mcp.types import ToolAnnotations
except (ImportError, ModuleNotFoundError):
    from mcp.server.mcpserver import MCPServer as FastMCP
    ToolAnnotations = None

from . import __version__
from . import probe as probe_mod
from . import report as report_mod

_ALLOW_ALL_EXEC = False


def set_allow_all_exec(val: bool = True):
    global _ALLOW_ALL_EXEC
    _ALLOW_ALL_EXEC = val


def _get_allowed_commands() -> list[str]:
    env_cmds = os.environ.get("MCP_BEHAVE_ALLOWED_COMMANDS")
    if env_cmds:
        return [c.strip() for c in env_cmds.replace(":", ",").split(",") if c.strip()]
    from . import config as config_mod
    cfg = config_mod.load_config()
    return cfg.get("allowed_commands", [])


def _is_command_allowed(cmd: list[str]) -> bool:
    if _ALLOW_ALL_EXEC or os.environ.get("MCP_BEHAVE_ALLOW_ALL_EXEC") in ("1", "true", "yes"):
        return True
    allowed_list = _get_allowed_commands()
    if not allowed_list:
        return False
    cmd_str = " ".join(cmd).strip()
    cmd_base = os.path.basename(cmd[0]) if cmd else ""
    for pattern in allowed_list:
        pattern = pattern.strip()
        if not pattern:
            continue
        if pattern == "*":
            return True
        if cmd_str == pattern or cmd == shlex.split(pattern):
            return True
        if cmd_str.startswith(pattern):
            return True
        if cmd_base == pattern or (cmd and cmd[0] == pattern):
            return True
    return False

mcp = FastMCP(
    "mcp-behave",
    instructions=(
        "mcp-behave is a runtime behavioral auditor and security scanner for MCP servers. "
        "It verifies whether an MCP server's actual runtime behavior matches what it declares."
    ),
)


@mcp.tool(
    name="audit_server",
    description=(
        "Run a runtime behavioral audit on an MCP server. Exercises tools, resources, and "
        "prompts using canary inputs, captures system calls (network, files, subprocesses), "
        "and detects undeclared behaviors or manifest rug-pulls."
    ),
    annotations=ToolAnnotations(readOnlyHint=False, idempotentHint=False) if ToolAnnotations else None,
)
async def audit_server(
    command: Union[List[str], str],
    timeout: float = 15.0,
    no_trace: bool = False,
    tracer: str = "auto",
    transport: str = "stdio",
    resolve_dns: bool = True,
) -> Dict[str, Any]:
    """Audit an MCP server.

    Args:
        command: Command to spawn (e.g. 'python -m my_server' or ['python', '-m', 'my_server']) or server URL.
        timeout: Seconds to wait per tool/resource/prompt call during exercise.
        no_trace: If True, skips syscall tracing and runs manifest analysis only.
        tracer: Tracer backend ('auto', 'preload', 'dylib', 'strace', 'none').
        transport: Transport type ('stdio', 'sse', 'streamable-http').
        resolve_dns: Whether to perform reverse-DNS lookups for observed remote IPs.
    """
    if isinstance(command, str):
        cmd = shlex.split(command) if transport == "stdio" else [command]
    else:
        cmd = list(command)

    if not cmd:
        return {"error": "command must not be empty", "findings": []}

    if transport == "stdio" and not _is_command_allowed(cmd):
        cmd_repr = " ".join(cmd)
        return {
            "error": (
                "Security refusal: arbitrary command execution in MCP serve mode is blocked by default. "
                f"Command '{cmd_repr}' is not in allowed_commands. "
                "Add it to 'allowed_commands' in .mcpbehaverc.json or launch mcp-behave serve with --allow-all-exec."
            ),
            "server_cmd": cmd,
            "findings": [
                {
                    "severity": "HIGH",
                    "message": (
                        f"Blocked unapproved command execution: {cmd_repr}. "
                        "Configure 'allowed_commands' in .mcpbehaverc.json or run serve with --allow-all-exec."
                    ),
                }
            ],
        }

    with tempfile.TemporaryDirectory(prefix="mcp_behave_") as tmpdir:
        tracer_choice = "none" if no_trace else tracer
        error_msg = None
        try:
            if transport == "stdio":
                await probe_mod.run(cmd, call_timeout=timeout, tracer=tracer_choice, out_dir=tmpdir)
            else:
                await probe_mod.run_remote(cmd[0], transport=transport, call_timeout=timeout, out_dir=tmpdir)
        except Exception as exc:
            error_msg = str(exc)

        manifest_file = os.path.join(tmpdir, "manifest.json")
        if os.path.exists(manifest_file):
            result = report_mod.report_json(tmpdir, resolve_dns=resolve_dns)
            if error_msg:
                result["warning"] = f"probe completed with error: {error_msg}"
            return result
        else:
            return {
                "error": error_msg or "Failed to produce manifest from target server",
                "server_cmd": cmd,
                "findings": [
                    {
                        "severity": "HIGH",
                        "message": f"Server probe failed: {error_msg or 'Connection closed unexpectedly'}",
                    }
                ],
            }


@mcp.tool(
    name="inspect_manifest",
    description=(
        "Inspect an MCP server's declared capabilities (tools, resources, prompts) "
        "without executing tool actions or tracing syscalls. Also checks for manifest "
        "rug-pulls against prior recorded runs."
    ),
    annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True) if ToolAnnotations else None,
)
async def inspect_manifest(
    command: Union[List[str], str],
    timeout: float = 15.0,
    transport: str = "stdio",
) -> Dict[str, Any]:
    """Inspect declared tools, resources, and prompts from an MCP server.

    Args:
        command: Command to spawn (e.g. 'python -m my_server') or URL to connect to.
        timeout: Seconds to wait during connection and discovery.
        transport: Transport type ('stdio', 'sse', 'streamable-http').
    """
    if isinstance(command, str):
        cmd = shlex.split(command) if transport == "stdio" else [command]
    else:
        cmd = list(command)

    if not cmd:
        return {"error": "command must not be empty"}

    if transport == "stdio" and not _is_command_allowed(cmd):
        cmd_repr = " ".join(cmd)
        return {
            "error": (
                "Security refusal: arbitrary command execution in MCP serve mode is blocked by default. "
                f"Command '{cmd_repr}' is not in allowed_commands. "
                "Add it to 'allowed_commands' in .mcpbehaverc.json or launch mcp-behave serve with --allow-all-exec."
            ),
            "server_cmd": cmd,
        }

    try:
        manifest = await probe_mod.fetch_manifest(cmd, transport=transport, call_timeout=timeout)
        rug = report_mod._rugpull_check(manifest)
        descs = report_mod._all_descriptions(manifest)
        claims_local = any(w in descs for w in ("local", "offline", "no network"))

        return {
            "server_cmd": cmd,
            "manifest_sha256": manifest.get("manifest_sha256"),
            "declared": {
                "tools": manifest.get("tools", []),
                "resources": manifest.get("resources", []),
                "prompts": manifest.get("prompts", []),
            },
            "scope_hints": {
                "claims_local_offline": claims_local,
            },
            "rug_pull": {"severity": rug[0], "message": rug[1]} if rug else None,
        }
    except Exception as exc:
        return {
            "error": str(exc),
            "server_cmd": cmd,
        }


@mcp.tool(
    name="scan_client_configs",
    description=(
        "Scan local AI client configurations (Claude Desktop, Cursor, VS Code, Windsurf, Zed) "
        "to discover all configured MCP servers and detect security risks (hardcoded API keys/tokens, "
        "over-privileged root/home directory mounts, shell command wrappers)."
    ),
    annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True) if ToolAnnotations else None,
)
async def scan_client_configs(
    custom_config_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Scan local MCP client configurations for servers and security risks.

    Args:
        custom_config_path: Optional path to a specific client config file to inspect.
    """
    from . import config_scanner
    custom_paths = [custom_config_path] if custom_config_path else None
    scan_data = config_scanner.scan_all_configs(custom_paths=custom_paths)
    return {
        "configs_found": scan_data.get("configs_found", []),
        "servers": scan_data.get("servers", []),
        "config_findings": {
            k: [{"severity": sev, "message": msg} for sev, msg in v]
            for k, v in scan_data.get("config_findings", {}).items()
        },
        "errors": scan_data.get("errors", []),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="mcp-behave serve",
        description=f"mcp-behave {__version__} MCP server.",
    )
    parser.add_argument(
        "--transport",
        choices=("stdio", "sse", "streamable-http"),
        default="stdio",
        help="MCP transport to run (default: %(default)s).",
    )
    parser.add_argument(
        "--allow-all-exec",
        action="store_true",
        help="Allow connected agents to audit arbitrary commands (disables command allowlist restriction).",
    )
    args = parser.parse_args(argv)
    if args.allow_all_exec:
        set_allow_all_exec(True)
    mcp.run(transport=args.transport)


if __name__ == "__main__":
    main()

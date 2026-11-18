"""Client configuration scanner: discovers and audits MCP servers configured in local
AI clients (Claude Desktop, Cursor, VS Code/Cline/Roo, Windsurf, Zed).

Performs:
1. Discovery of all configured MCP servers across known client config paths.
2. Static configuration security audits:
   - Hardcoded plaintext secrets/tokens in environment variables or arguments.
   - Over-privileged directory mounts (e.g. root '/', home '~', sensitive keys).
   - Shell command wrappers (e.g. bash -c, powershell -c).
   - Unpinned remote package execution (e.g. npx without version tag).
3. Optional batch runtime behavioral auditing (--audit) across all discovered servers.
"""
import asyncio
import json
import os
import platform
import re
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Known client configuration paths per platform
def get_known_config_locations() -> List[Tuple[str, Path]]:
    system = platform.system()
    home = Path.home()
    candidates = []

    # 1. Claude Desktop
    if system == "Darwin":
        candidates.append(("Claude Desktop", home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"))
    elif system == "Windows":
        appdata = os.environ.get("APPDATA")
        if appdata:
            candidates.append(("Claude Desktop", Path(appdata) / "Claude" / "claude_desktop_config.json"))
    else:  # Linux
        candidates.append(("Claude Desktop", home / ".config" / "Claude" / "claude_desktop_config.json"))

    # 2. Cursor
    candidates.append(("Cursor (Global)", home / ".cursor" / "mcp.json"))
    candidates.append(("Cursor (Project)", Path.cwd() / ".cursor" / "mcp.json"))

    # 3. VS Code - Cline & Roo Code
    if system == "Darwin":
        code_storage = home / "Library" / "Application Support" / "Code" / "User" / "globalStorage"
        code_user = home / "Library" / "Application Support" / "Code" / "User" / "settings.json"
    elif system == "Windows":
        appdata = os.environ.get("APPDATA")
        code_storage = Path(appdata) / "Code" / "User" / "globalStorage" if appdata else home
        code_user = Path(appdata) / "Code" / "User" / "settings.json" if appdata else home
    else:
        code_storage = home / ".config" / "Code" / "User" / "globalStorage"
        code_user = home / ".config" / "Code" / "User" / "settings.json"

    candidates.append(("VS Code (Cline)", code_storage / "saoudrizwan.claude-dev" / "settings" / "cline_mcp_settings.json"))
    candidates.append(("VS Code (Roo Code)", code_storage / "rooveterinaryinc.roo-cline" / "settings" / "cline_mcp_settings.json"))
    candidates.append(("VS Code (Settings)", code_user))

    # 4. Windsurf
    candidates.append(("Windsurf", home / ".codeium" / "windsurf" / "mcp_config.json"))

    # 5. Zed
    candidates.append(("Zed", home / ".config" / "zed" / "settings.json"))

    return candidates


# Secret detection patterns (specific prefixes before generic)
KNOWN_SECRET_PATTERNS = [
    (re.compile(r"sk-ant-[a-zA-Z0-9_\-]{20,}"), "Anthropic API Key"),
    (re.compile(r"sk-[a-zA-Z0-9_\-]{20,}"), "OpenAI API Key"),
    (re.compile(r"gh[pousr]_[a-zA-Z0-9]{36}"), "GitHub Personal Access Token"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS Access Key ID"),
    (re.compile(r"xox[baprs]-[0-9a-zA-Z]{10,}"), "Slack Token"),
]

SENSITIVE_KEY_NAME_PATTERN = re.compile(
    r"(?i)(?:api[_-]?key|access[_-]?token|auth[_-]?token|secret|token|password|passwd|private[_-]?key|credential)"
)

PLACEHOLDER_REGEX = re.compile(
    r"(?i)^(?:(?:\$\{[^\}]+\})|(?:\$[A-Z0-9_]+)|(?:<[^>]+>)|(?:your[_-]?.*)|(?:dummy.*)|(?:placeholder.*)|(?:test.*)|(?:todo.*)|none|null|)$"
)


def mask_secret(val: str) -> str:
    """Mask a secret value for safe reporting without disclosing credentials."""
    if not val:
        return ""
    if len(val) <= 8:
        return "****"
    return f"{val[:4]}...{val[-4:]}"


def find_existing_configs(custom_paths: Optional[List[str]] = None) -> List[Tuple[str, Path]]:
    """Return all config locations that currently exist on disk."""
    results = []
    seen = set()

    if custom_paths:
        for p in custom_paths:
            path_obj = Path(p).resolve()
            if path_obj.exists() and path_obj not in seen:
                seen.add(path_obj)
                results.append(("Custom Config", path_obj))

    for client_name, path_obj in get_known_config_locations():
        try:
            resolved = path_obj.resolve()
            if resolved.is_file() and resolved not in seen:
                seen.add(resolved)
                results.append((client_name, resolved))
        except (OSError, PermissionError):
            continue

    return results


def parse_config_file(client_name: str, path: Path) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Parse an MCP config file and return a list of server specifications and any read errors."""
    servers = []
    errors = []

    try:
        content = path.read_text(encoding="utf-8")
    except Exception as exc:
        return [], [f"could not read config file {path}: {exc}"]

    # Strip simple comments if JSON with comments (e.g. VS Code settings.json)
    cleaned_lines = []
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("//"):
            continue
        cleaned_lines.append(line)
    cleaned_content = "\n".join(cleaned_lines)

    try:
        data = json.loads(cleaned_content)
    except json.JSONDecodeError as exc:
        return [], [f"invalid JSON in {path}: {exc}"]

    if not isinstance(data, dict):
        return [], [f"expected JSON object in {path}"]

    # Common MCP server container keys
    raw_servers = {}
    if "mcpServers" in data and isinstance(data["mcpServers"], dict):
        raw_servers = data["mcpServers"]
    elif "servers" in data and isinstance(data["servers"], dict):
        raw_servers = data["servers"]
    elif "mcp.servers" in data and isinstance(data["mcp.servers"], dict):
        raw_servers = data["mcp.servers"]
    elif "context_servers" in data and isinstance(data["context_servers"], dict):
        raw_servers = data["context_servers"]

    for name, sdef in raw_servers.items():
        if not isinstance(sdef, dict):
            continue

        cmd = sdef.get("command") or ""
        args = sdef.get("args") or []
        if isinstance(args, str):
            args = [args]
        env = sdef.get("env") or {}
        if not isinstance(env, dict):
            env = {}

        # Reconstruct full execution command tokens
        full_command = []
        if cmd:
            full_command.append(str(cmd))
        for a in args:
            full_command.append(str(a))

        servers.append({
            "client": client_name,
            "config_path": str(path),
            "name": name,
            "command": str(cmd),
            "args": [str(a) for a in args],
            "full_command": full_command,
            "env": {str(k): str(v) for k, v in env.items()},
            "disabled": bool(sdef.get("disabled", False)),
        })

    return servers, errors


def analyze_server_config(server: Dict[str, Any]) -> List[Tuple[str, str]]:
    """Analyze a single server configuration for security risks and misconfigurations.
    Returns list of (severity, message) tuples."""
    findings = []
    name = server.get("name", "unknown")
    cmd = server.get("command", "")
    args = server.get("args", [])
    env = server.get("env", {})

    # 1. Secret Scanning in Environment Variables
    for k, v in env.items():
        # A. Known token pattern check
        matched_known = False
        for pat, desc in KNOWN_SECRET_PATTERNS:
            if pat.search(v):
                findings.append((
                    "HIGH",
                    f"server '{name}': hardcoded {desc} in env['{k}'] ({mask_secret(v)})"
                ))
                matched_known = True
                break

        # B. Generic sensitive key heuristic
        if not matched_known and SENSITIVE_KEY_NAME_PATTERN.search(k):
            # Check if it looks like a real non-placeholder value
            if len(v) >= 8 and not PLACEHOLDER_REGEX.match(v.strip()):
                findings.append((
                    "HIGH",
                    f"server '{name}': hardcoded secret/credential in env['{k}'] ({mask_secret(v)})"
                ))

    # 2. Secret Scanning in Command Arguments
    for arg in args:
        for pat, desc in KNOWN_SECRET_PATTERNS:
            if pat.search(arg):
                findings.append((
                    "HIGH",
                    f"server '{name}': hardcoded {desc} in command argument ({mask_secret(arg)})"
                ))
                break

    # 3. Over-privileged Filesystem Mount Arguments
    home_dir = str(Path.home())
    for arg in args:
        arg_norm = os.path.normpath(os.path.expanduser(arg))
        if arg in ("/", "\\") or (len(arg) == 3 and arg[1:] == ":\\"):
            findings.append((
                "HIGH",
                f"server '{name}': over-privileged root filesystem mount argument '{arg}'"
            ))
        elif arg == "~" or arg_norm == home_dir:
            findings.append((
                "HIGH",
                f"server '{name}': over-privileged user home directory mount argument '{arg}'"
            ))
        elif any(sens in arg_norm for sens in ("/.ssh", "/.aws", "/.kube", "/.gnupg", "/etc/shadow")):
            findings.append((
                "HIGH",
                f"server '{name}': sensitive directory mount argument '{arg}'"
            ))

    # 4. Arbitrary Shell Command Wrapper Execution
    cmd_base = os.path.basename(cmd).lower()
    if cmd_base in ("sh", "bash", "zsh", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh"):
        if any(a in ("-c", "/c", "-Command") for a in args):
            findings.append((
                "HIGH",
                f"server '{name}': launched via raw shell execution wrapper ({cmd_base} -c)"
            ))

    # 5. Unpinned Package Execution
    if cmd_base in ("npx", "uvx"):
        # Check packages in args (skip flags starting with -)
        pkg_args = [a for a in args if not a.startswith("-")]
        if pkg_args:
            target_pkg = pkg_args[0]
            if "@" not in target_pkg.lstrip("@"):  # e.g. @modelcontextprotocol/server-filesystem without @version
                findings.append((
                    "INFO",
                    f"server '{name}': unpinned package '{target_pkg}' (runs latest without version lock)"
                ))

    return findings


def scan_all_configs(custom_paths: Optional[List[str]] = None) -> Dict[str, Any]:
    """Scan all existing client configs and analyze discovered servers."""
    config_files = find_existing_configs(custom_paths)
    all_servers = []
    read_errors = []

    for client_name, path in config_files:
        servers, errors = parse_config_file(client_name, path)
        all_servers.extend(servers)
        read_errors.extend(errors)

    findings_by_server = {}
    for s in all_servers:
        skey = f"{s['client']}::{s['name']}"
        findings_by_server[skey] = analyze_server_config(s)

    return {
        "configs_found": [str(p) for _, p in config_files],
        "servers": all_servers,
        "config_findings": findings_by_server,
        "errors": read_errors,
    }


async def audit_configured_servers(
    servers: List[Dict[str, Any]],
    *,
    timeout: float = 15.0,
    tracer: str = "auto",
    no_trace: bool = False,
    resolve_dns: bool = True,
) -> Dict[str, Any]:
    """Run full behavioral auditing on each discovered server in isolated environments."""
    from . import probe as probe_mod
    from . import report as report_mod

    audit_results = {}
    effective_tracer = "none" if no_trace else tracer

    for s in servers:
        skey = f"{s['client']}::{s['name']}"
        full_cmd = s.get("full_command") or []
        if not full_cmd:
            audit_results[skey] = {
                "error": "empty command",
                "findings": [],
            }
            continue

        with tempfile.TemporaryDirectory(prefix=f"mcp_behave_{s['name']}_") as tmpdir:
            try:
                # Merge server-specified env with current env for probe execution
                custom_env = {**os.environ, **s.get("env", {})}
                orig_env = os.environ.copy()
                os.environ.clear()
                os.environ.update(custom_env)

                try:
                    await probe_mod.run(
                        full_cmd,
                        call_timeout=timeout,
                        tracer=effective_tracer,
                        out_dir=tmpdir,
                    )
                finally:
                    os.environ.clear()
                    os.environ.update(orig_env)

                manifest, profile = report_mod.load(tmpdir)
                findings = report_mod.build_findings(manifest, profile, resolve_dns=resolve_dns)
                audit_results[skey] = {
                    "findings": [{"severity": sev, "message": msg} for sev, msg in findings],
                    "stats": manifest.get("_stats", {}),
                    "syscalls_available": manifest.get("syscalls_available", False),
                }
            except Exception as exc:
                audit_results[skey] = {
                    "error": str(exc),
                    "findings": [],
                }

    return audit_results


def print_config_scan_report(scan_data: Dict[str, Any], audit_data: Optional[Dict[str, Any]] = None):
    """Print a clean human-readable terminal report."""
    configs = scan_data.get("configs_found", [])
    servers = scan_data.get("servers", [])
    config_findings = scan_data.get("config_findings", {})
    errors = scan_data.get("errors", [])

    print("\n" + "=" * 64)
    print("  MCP CLIENT CONFIGURATION SCANNER")
    print("=" * 64)
    print(f"  Discovered config files: {len(configs)}")
    for c in configs:
        print(f"    - {c}")
    print(f"  Discovered servers:      {len(servers)}")
    print("-" * 64)

    if errors:
        print("  Errors encountered while reading configs:")
        for err in errors:
            print(f"    [!] {err}")
        print("-" * 64)

    if not servers:
        print("  No MCP servers found in client configuration files.\n")
        return

    total_high = 0
    for s in servers:
        skey = f"{s['client']}::{s['name']}"
        c_findings = config_findings.get(skey, [])
        a_findings = []
        a_info = audit_data.get(skey) if audit_data else None
        if a_info and "findings" in a_info:
            a_findings = [(f["severity"], f["message"]) for f in a_info["findings"]]

        all_findings = c_findings + a_findings
        high_count = sum(1 for sev, _ in all_findings if sev == "HIGH")
        total_high += high_count

        status_badge = "[!] HIGH RISK" if high_count > 0 else "[OK] CLEAN"
        print(f"\n  ▶ {s['name']}  ({s['client']})  [{status_badge}]")
        print(f"    Config:  {s['config_path']}")
        print(f"    Command: {' '.join(s['full_command'])}")
        if s.get("env"):
            masked_env = ", ".join(f"{k}={mask_secret(v)}" for k, v in s["env"].items())
            print(f"    Env:     {masked_env}")

        if not all_findings:
            print("    Findings: None (Clean)")
        else:
            if c_findings:
                print("    Config Security:")
                for sev, msg in c_findings:
                    icon = "[!]" if sev == "HIGH" else "[i]"
                    print(f"      {icon} {sev:4} {msg}")
            if a_findings:
                print("    Behavioral Audit:")
                for sev, msg in a_findings:
                    icon = "[!]" if sev == "HIGH" else "[i]"
                    print(f"      {icon} {sev:4} {msg}")

        if a_info and a_info.get("error"):
            print(f"    Audit Error: {a_info['error']}")

    print("\n" + "=" * 64)
    if total_high > 0:
        print(f"  SUMMARY: {total_high} HIGH severity finding(s) detected across {len(servers)} server(s).")
    else:
        print(f"  SUMMARY: All {len(servers)} server configurations are clean.")
    print("=" * 64 + "\n")


def main(argv=None, default_audit=False) -> int:
    import argparse
    parser = argparse.ArgumentParser(
        prog="mcp-behave scan-configs",
        description="Discover and audit MCP servers configured in local AI clients "
                    "(Claude Desktop, Cursor, VS Code/Cline/Roo, Windsurf, Zed).",
    )
    parser.add_argument(
        "--config", action="append", dest="configs", metavar="PATH",
        help="Path to a specific client config file to scan (can be repeated).",
    )
    parser.add_argument(
        "--audit", action="store_true", default=default_audit,
        help="Run runtime behavioral audits on each discovered server.",
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Emit results as JSON on stdout.",
    )
    parser.add_argument(
        "--no-trace", action="store_true",
        help="Skip syscall tracing during server audits (manifest analysis only).",
    )
    parser.add_argument(
        "--tracer", choices=("auto", "preload", "dylib", "strace", "none"), default="auto",
        help="Tracer backend to use when --audit is enabled (default: auto).",
    )
    parser.add_argument(
        "--timeout", type=float, default=15.0,
        help="Seconds to wait per tool/resource call during audit (default: 15.0).",
    )
    parser.add_argument(
        "--fail-on", choices=("never", "info", "high"), default="high",
        help="Exit code 3 threshold (default: high).",
    )

    args = parser.parse_args(argv)

    scan_data = scan_all_configs(custom_paths=args.configs)
    audit_data = None
    if args.audit and scan_data.get("servers"):
        audit_data = asyncio.run(audit_configured_servers(
            scan_data["servers"],
            timeout=args.timeout,
            tracer=args.tracer,
            no_trace=args.no_trace,
        ))

    total_findings = []
    for skey, c_finds in scan_data.get("config_findings", {}).items():
        total_findings.extend(c_finds)
    if audit_data:
        for skey, a_info in audit_data.items():
            for f in a_info.get("findings", []):
                total_findings.append((f["severity"], f["message"]))

    if args.json:
        payload = {
            "configs_found": scan_data.get("configs_found", []),
            "servers": scan_data.get("servers", []),
            "config_findings": {
                k: [{"severity": sev, "message": msg} for sev, msg in v]
                for k, v in scan_data.get("config_findings", {}).items()
            },
            "audit_findings": audit_data or {},
            "errors": scan_data.get("errors", []),
        }
        print(json.dumps(payload, indent=2))
    else:
        print_config_scan_report(scan_data, audit_data)

    sev_rank = {"INFO": 1, "HIGH": 2}
    if args.fail_on == "never":
        return 0
    threshold = sev_rank[args.fail_on.upper()]
    return 3 if any(sev_rank.get(s, 0) >= threshold for s, _ in total_findings) else 0

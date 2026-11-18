"""MCP Behavioral Inspector: live correlated JSON-RPC traffic and OS syscall stream.

Correlates high-level MCP tool invocations directly with the exact low-level operating
system operations (file reads, network connections, child subprocesses) they triggered.
"""
import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import probe as probe_mod
from . import report as report_mod
from .analyze import interesting_file, interesting_net, real_port


def parse_correlated_trace(trace_path: str) -> Dict[str, Any]:
    """Parse trace.log lines and group syscalls by the active tool or phase."""
    sections: Dict[str, List[Dict[str, str]]] = {
        "startup": []
    }
    current_key = "startup"

    if not os.path.exists(trace_path):
        return sections

    with open(trace_path, "r", errors="replace") as f:
        for line in f:
            s = line.strip()
            if not s:
                continue

            # Marker emitted by Python probe
            if s.startswith("M "):
                parts = s[2:].split(" ", 1)
                tag = parts[0]
                val = parts[1] if len(parts) > 1 else ""
                if tag == "CALL_START":
                    current_key = f"tool::{val}"
                    sections.setdefault(current_key, [])
                elif tag == "CALL_END":
                    current_key = "idle"
                    sections.setdefault(current_key, [])
                elif tag == "RES_START":
                    current_key = f"resource::{val}"
                    sections.setdefault(current_key, [])
                elif tag == "RES_END":
                    current_key = "idle"
                elif tag == "PR_START":
                    current_key = f"prompt::{val}"
                    sections.setdefault(current_key, [])
                elif tag == "PR_END":
                    current_key = "idle"
                continue

            # Tracer records
            if len(s) >= 2 and s[1] == " ":
                tag = s[0]
                val = s[2:]
                if tag == "F":
                    if interesting_file(val):
                        is_sensitive = any(sens in val for sens in report_mod.SENSITIVE)
                        sections[current_key].append({
                            "type": "file",
                            "value": val,
                            "sensitive": is_sensitive,
                        })
                elif tag == "N":
                    ip, _, port = val.rpartition(" ")
                    if ip and interesting_net(ip) and real_port(f"{ip}:{port}"):
                        sections[current_key].append({
                            "type": "network",
                            "value": f"{ip}:{port}",
                            "sensitive": True,
                        })
                elif tag == "X":
                    sections[current_key].append({
                        "type": "exec",
                        "value": val,
                        "sensitive": False,
                    })

    return sections


def print_inspector_timeline(manifest: Dict[str, Any], sections: Dict[str, Any], findings: List[Any]):
    """Render a human-readable correlated execution timeline."""
    server_cmd = manifest.get("server_cmd") or []
    tools = manifest.get("tools") or []
    tool_outputs = manifest.get("tool_outputs") or {}
    syscalls_available = manifest.get("syscalls_available", True)

    print("\n" + "=" * 70)
    print("  MCP BEHAVIORAL INSPECTOR (Correlated Traffic & Syscall Stream)")
    print("=" * 70)
    print(f"  Target Server: {' '.join(server_cmd)}")
    print(f"  Syscall Trace: {'Active' if syscalls_available else 'Disabled (untraced mode)'}")
    print(f"  Tools Exposed: {len(tools)} declared tool(s)")
    print("-" * 70)

    # 1. Startup phase
    startup_calls = sections.get("startup", [])
    print("\n[PHASE 1: INITIALIZATION & HANDSHAKE]")
    print("  [RPC] -> initialize(protocolVersion=\"2024-11-05\")")
    print("  [RPC] <- initialized()")
    print(f"  [RPC] -> tools/list()  ({len(tools)} tools returned)")
    if startup_calls:
        for sc in startup_calls:
            icon = "[!] SENSITIVE:" if sc.get("sensitive") else "[SYS]        "
            print(f"  {icon} {sc['type']:7} {sc['value']}")
    else:
        print("  [SYS]    (no background syscalls during initialization)")

    # 2. Tool calls
    print("\n[PHASE 2: CAPABILITY EXECUTION]")
    for t in tools:
        tname = t["name"]
        skey = f"tool::{tname}"
        t_calls = sections.get(skey, [])

        print(f"\n  ▶ tools/call \"{tname}\"")
        if not syscalls_available:
            print("    [SYS]  (tracing unavailable)")
        elif not t_calls:
            print("    [SYS]  clean (zero network, sensitive file, or process syscalls)")
        else:
            for sc in t_calls:
                badge = "[!] VIOLATION:" if sc.get("sensitive") else "[SYS]        "
                print(f"    {badge} {sc['type']:7} {sc['value']}")

        output = tool_outputs.get(tname)
        if output:
            preview = output.replace("\n", " ")[:80]
            if len(output) > 80:
                preview += "..."
            print(f"    [RPC]  <- response text: \"{preview}\"")

    # 3. Correlated findings summary
    print("\n" + "=" * 70)
    if not findings:
        print("  VERDICT: CLEAN (No undeclared syscalls or injection vectors detected)")
    else:
        print("  VERDICT: POLICY FINDINGS DETECTED")
        for sev, msg in findings:
            icon = "[!]" if sev == "HIGH" else "[i]"
            print(f"    {icon} {sev:4} {msg}")
    print("=" * 70 + "\n")


def main(argv=None) -> int:
    import argparse
    parser = argparse.ArgumentParser(
        prog="mcp-behave inspect",
        description="Run an MCP server and display a live correlated timeline connecting "
                    "JSON-RPC tool invocations with operating system syscalls.",
    )
    parser.add_argument(
        "--timeout", type=float, default=15.0,
        help="Seconds to wait per tool call (default: 15.0).",
    )
    parser.add_argument(
        "--tracer", choices=("auto", "preload", "dylib", "strace", "none"), default="auto",
        help="Tracer backend (default: auto).",
    )
    parser.add_argument(
        "--no-trace", action="store_true",
        help="Skip syscall tracing and show JSON-RPC timeline only.",
    )
    parser.add_argument(
        "--fuzz", action="store_true",
        help="Run adversarial input fuzzing during inspection.",
    )
    parser.add_argument(
        "server_command", nargs=argparse.REMAINDER,
        help="Command to spawn the MCP server (e.g. 'python targets/leaky_server.py').",
    )

    args = parser.parse_args(argv)
    if args.server_command and args.server_command[0] == "--":
        args.server_command = args.server_command[1:]

    if not args.server_command:
        parser.error("no server command given. Example: mcp-behave inspect python targets/leaky_server.py")

    # If the user passed an existing output directory containing manifest.json
    if len(args.server_command) == 1 and os.path.isdir(args.server_command[0]):
        target_dir = args.server_command[0]
        manifest, profile = report_mod.load(target_dir)
        findings = report_mod.build_findings(manifest, profile, resolve_dns=False)
        trace_file = os.path.join(target_dir, "trace.log")
        sections = parse_correlated_trace(trace_file)
        print_inspector_timeline(manifest, sections, findings)
        sev_rank = {"INFO": 1, "HIGH": 2}
        return 3 if any(sev_rank.get(s, 0) >= 2 for s, _ in findings) else 0

    with tempfile.TemporaryDirectory(prefix="mcp_behave_inspect_") as tmpdir:
        tracer_choice = "none" if args.no_trace else args.tracer
        try:
            asyncio.run(probe_mod.run(
                args.server_command,
                call_timeout=args.timeout,
                tracer=tracer_choice,
                out_dir=tmpdir,
                fuzz=args.fuzz,
            ))
        except SystemExit:
            raise
        except BaseException as exc:
            print(f"\nmcp-behave inspect: target failed: {exc!r}", file=sys.stderr)
            return 1

        manifest, profile = report_mod.load(tmpdir)
        findings = report_mod.build_findings(manifest, profile, resolve_dns=False)
        trace_file = os.path.join(tmpdir, "trace.log")
        sections = parse_correlated_trace(trace_file)

        print_inspector_timeline(manifest, sections, findings)

    sev_rank = {"INFO": 1, "HIGH": 2}
    return 3 if any(sev_rank.get(s, 0) >= 2 for s, _ in findings) else 0

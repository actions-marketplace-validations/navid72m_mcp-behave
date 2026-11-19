"""Behavioral regression testing lockfile module for mcp-behave.

Implements behavioral lockfiles (mcp-behave.lock) and regression diffing:
- `mcp-behave init [server-cmd...]` establishes a committed baseline of observed runtime behavior
- `mcp-behave check [server-cmd...]` diffs live server behavior against the baseline in CI,
  failing only on undeclared behavioral regressions.
"""
import argparse
import asyncio
import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import __version__
from . import analyze as analyze_mod
from . import probe as probe_mod
from . import report as report_mod

DEFAULT_LOCKFILE_NAME = "mcp-behave.lock"


def generate_lockfile_data(manifest: Dict[str, Any], profile: Dict[str, Any]) -> Dict[str, Any]:
    """Generate structured lockfile content from probed manifest and behavioral profile."""
    tools = [t.get("name") for t in manifest.get("tools", []) if t.get("name")]
    tool_network = profile.get("tool_network_connects", {})

    tool_behaviors = {}
    for t in sorted(tools):
        tool_behaviors[t] = {
            "network_endpoints": sorted(set(tool_network.get(t, []))),
        }

    # Identify sensitive files from profile
    sensitive_files = []
    for f in profile.get("files_opened", []):
        is_sens, _ = analyze_mod.is_sensitive_path(f)
        if is_sens:
            sensitive_files.append(f)

    return {
        "$schema": "https://raw.githubusercontent.com/navid72m/mcp-behave/main/schemas/lockfile.v1.json",
        "lockfile_version": 1,
        "mcp_behave_version": __version__,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "server_cmd": manifest.get("server_cmd"),
        "manifest_sha256": manifest.get("manifest_sha256"),
        "declared_tools": sorted(tools),
        "baseline_behavior": {
            "network_endpoints": sorted(profile.get("network_connects", [])),
            "sensitive_files": sorted(set(sensitive_files)),
            "files_written": sorted(profile.get("files_written", [])),
            "unix_sockets": sorted(profile.get("unix_sockets", [])),
            "subprocesses": sorted(profile.get("subprocesses", [])),
        },
        "tool_behavior": tool_behaviors,
    }


def write_lockfile(lock_data: Dict[str, Any], lockfile_path: os.PathLike | str = DEFAULT_LOCKFILE_NAME) -> Path:
    """Serialize and write lockfile data to disk."""
    p = Path(lockfile_path).resolve()
    p.write_text(json.dumps(lock_data, indent=2) + "\n", encoding="utf-8")
    return p


def load_lockfile(lockfile_path: os.PathLike | str = DEFAULT_LOCKFILE_NAME) -> Optional[Dict[str, Any]]:
    """Load and parse an existing lockfile. Returns None if file does not exist."""
    p = Path(lockfile_path).resolve()
    if not p.is_file():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"[lockfile] error: failed to read lockfile at {p}: {exc}", file=sys.stderr)
        return None


def diff_against_lockfile(lock_data: Dict[str, Any], manifest: Dict[str, Any], profile: Dict[str, Any]) -> List[str]:
    """Compare live observed behavior against lockfile baseline.

    Returns a list of regression violation descriptions. If empty, behavior conforms to baseline.
    """
    diffs: List[str] = []
    baseline = lock_data.get("baseline_behavior", {})

    # 1. Network endpoints regression
    base_nets = set(baseline.get("network_endpoints", []))
    curr_nets = set(profile.get("network_connects", []))
    new_nets = curr_nets - base_nets
    for net in sorted(new_nets):
        diffs.append(f"Undeclared network egress: '{net}' was contacted (not in lockfile baseline)")

    # 2. Sensitive files regression
    base_sens = set(baseline.get("sensitive_files", []))
    curr_sens = set()
    for f in profile.get("files_opened", []):
        is_sens, _ = analyze_mod.is_sensitive_path(f)
        if is_sens:
            curr_sens.add(f)
    new_sens = curr_sens - base_sens
    for s in sorted(new_sens):
        diffs.append(f"Undeclared sensitive file read: '{s}' was accessed (not in lockfile baseline)")

    # 3. File modifications/writes regression
    base_written = set(baseline.get("files_written", []))
    curr_written = set(profile.get("files_written", []))
    new_written = curr_written - base_written
    for w in sorted(new_written):
        diffs.append(f"Undeclared file write/modification: '{w}' was written (not in lockfile baseline)")

    # 4. Unix domain sockets regression
    base_unix = set(baseline.get("unix_sockets", []))
    curr_unix = set(profile.get("unix_sockets", []))
    new_unix = curr_unix - base_unix
    for u in sorted(new_unix):
        diffs.append(f"Undeclared unix socket connection: '{u}' (not in lockfile baseline)")

    # 5. Subprocess executions regression
    base_procs = set(baseline.get("subprocesses", []))
    curr_procs = set(profile.get("subprocesses", []))
    new_procs = curr_procs - base_procs
    for proc in sorted(new_procs):
        diffs.append(f"Undeclared subprocess spawned: '{proc}' (not in lockfile baseline)")

    # 6. Manifest capability drift / rug-pull
    base_sha = lock_data.get("manifest_sha256")
    curr_sha = manifest.get("manifest_sha256")
    if base_sha and curr_sha and base_sha != curr_sha:
        base_tools = set(lock_data.get("declared_tools", []))
        curr_tools = set(t.get("name") for t in manifest.get("tools", []) if t.get("name"))
        added_tools = curr_tools - base_tools
        removed_tools = base_tools - curr_tools
        details = []
        if added_tools:
            details.append(f"added tools: {sorted(added_tools)}")
        if removed_tools:
            details.append(f"removed tools: {sorted(removed_tools)}")
        det_str = f" ({', '.join(details)})" if details else ""
        diffs.append(f"Declared capability surface changed{det_str} (manifest sha: {base_sha[:12]} -> {curr_sha[:12]})")

    return diffs


def main_init(argv=None) -> int:
    """Entrypoint for `mcp-behave init [server-cmd...]`."""
    parser = argparse.ArgumentParser(
        prog="mcp-behave init",
        description="Establish a committed baseline behavior lockfile (mcp-behave.lock) for an MCP server.",
    )
    parser.add_argument(
        "--lockfile", default=DEFAULT_LOCKFILE_NAME,
        help="Path where the lockfile will be written (default: %(default)s).",
    )
    parser.add_argument(
        "--timeout", type=float, default=probe_mod.DEFAULT_CALL_TIMEOUT,
        help="Seconds to wait per tool/resource call during audit (default: %(default)s).",
    )
    parser.add_argument(
        "--probe-rounds", type=int, default=1,
        help="Number of probe rounds to execute (default: 1).",
    )
    parser.add_argument(
        "--tracer", choices=("auto", "preload", "dylib", "strace", "none"), default="auto",
        help="Tracer backend to use (default: auto).",
    )
    parser.add_argument(
        "--unsafe-host", action="store_true",
        help="Disable canary $HOME redirection and run against the real host environment.",
    )
    parser.add_argument(
        "server_command", nargs=argparse.REMAINDER,
        help="Command to spawn the MCP server under test.",
    )

    args = parser.parse_args(argv)
    cmd = args.server_command
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        parser.error("no server command given. Example: mcp-behave init python -m my_server")

    with tempfile.TemporaryDirectory(prefix="mcp_behave_init_") as tmpdir:
        try:
            asyncio.run(probe_mod.run(
                cmd,
                call_timeout=args.timeout,
                tracer=args.tracer,
                out_dir=tmpdir,
                rounds=args.probe_rounds,
                unsafe_host=args.unsafe_host,
            ))
        except Exception as exc:
            print(f"mcp-behave init: probe failed: {exc}", file=sys.stderr)
            return 1

        manifest, profile = report_mod.load(tmpdir)
        lock_data = generate_lockfile_data(manifest, profile)
        out_p = write_lockfile(lock_data, args.lockfile)

        b = lock_data["baseline_behavior"]
        print(f"\n[lockfile] Baseline behavioral lockfile generated -> {out_p}")
        print(f"  • Tools Declared:     {len(lock_data['declared_tools'])} ({', '.join(lock_data['declared_tools']) or 'none'})")
        print(f"  • Network Endpoints:  {len(b['network_endpoints'])} ({', '.join(b['network_endpoints']) or 'none'})")
        print(f"  • Sensitive Files:    {len(b['sensitive_files'])} ({', '.join(b['sensitive_files']) or 'none'})")
        print(f"  • Files Written:      {len(b['files_written'])}")
        print(f"  • Subprocesses:       {len(b['subprocesses'])}\n")
        print("Commit this file to git to track runtime behavioral regressions in CI:\n"
              f"    git add {args.lockfile} && git commit -m 'chore: update mcp-behave.lock'\n")
        return 0


def main_check(argv=None) -> int:
    """Entrypoint for `mcp-behave check [server-cmd...]`."""
    parser = argparse.ArgumentParser(
        prog="mcp-behave check",
        description="Verify an MCP server against its committed behavior lockfile (mcp-behave.lock) in CI.",
    )
    parser.add_argument(
        "--lockfile", default=DEFAULT_LOCKFILE_NAME,
        help="Path to the committed lockfile to verify against (default: %(default)s).",
    )
    parser.add_argument(
        "--timeout", type=float, default=probe_mod.DEFAULT_CALL_TIMEOUT,
        help="Seconds to wait per tool/resource call during audit (default: %(default)s).",
    )
    parser.add_argument(
        "--probe-rounds", type=int, default=1,
        help="Number of probe rounds to execute (default: 1).",
    )
    parser.add_argument(
        "--tracer", choices=("auto", "preload", "dylib", "strace", "none"), default="auto",
        help="Tracer backend to use (default: auto).",
    )
    parser.add_argument(
        "--unsafe-host", action="store_true",
        help="Disable canary $HOME redirection and run against the real host environment.",
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Emit verification results as JSON on stdout.",
    )
    parser.add_argument(
        "server_command", nargs=argparse.REMAINDER,
        help="Command to spawn the MCP server under test (defaults to command recorded in lockfile).",
    )

    args = parser.parse_args(argv)
    lock_data = load_lockfile(args.lockfile)
    if not lock_data:
        print(
            f"mcp-behave check: lockfile not found at '{args.lockfile}'.\n"
            "Run 'mcp-behave init <command>' first to establish a committed behavioral baseline.",
            file=sys.stderr,
        )
        return 1

    cmd = args.server_command
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        cmd = lock_data.get("server_cmd")
    if not cmd:
        parser.error("no server command provided or recorded in lockfile.")

    with tempfile.TemporaryDirectory(prefix="mcp_behave_check_") as tmpdir:
        try:
            asyncio.run(probe_mod.run(
                cmd,
                call_timeout=args.timeout,
                tracer=args.tracer,
                out_dir=tmpdir,
                rounds=args.probe_rounds,
                unsafe_host=args.unsafe_host,
            ))
        except Exception as exc:
            print(f"mcp-behave check: probe failed: {exc}", file=sys.stderr)
            return 1

        manifest, profile = report_mod.load(tmpdir)
        diffs = diff_against_lockfile(lock_data, manifest, profile)

        if args.json:
            result = {
                "lockfile": args.lockfile,
                "passed": len(diffs) == 0,
                "regressions_detected": len(diffs),
                "diffs": diffs,
                "manifest_sha256": manifest.get("manifest_sha256"),
            }
            print(json.dumps(result, indent=2))
            return 3 if diffs else 0

        if diffs:
            print("\n" + "=" * 64)
            print("  === BEHAVIORAL REGRESSION DETECTED ===")
            print("=" * 64)
            print(f"Target server runtime behavior violated baseline in '{args.lockfile}':\n")
            for d in diffs:
                print(f"  [!] REGRESSION: {d}")
            print("\nIf this new behavior is intentional, update your baseline:")
            print(f"    mcp-behave init {' '.join(cmd)}")
            print("=" * 64 + "\n")
            return 3
        else:
            print("\n" + "=" * 64)
            print("  === BEHAVIORAL VERIFICATION PASSED ===")
            print("=" * 64)
            print(f"Observed runtime behavior conforms to baseline in '{args.lockfile}'.")
            print("Zero undeclared regressions detected.")
            print("=" * 64 + "\n")
            return 0

"""Interactive and batch approval workflow for behavioral drift and lockfiles (Milestone 3).

Reads pending unapproved drift from SQLite manifest_history, displays structured diffs,
prompts for developer confirmation, and atomically commits approved baselines into mcp-behave.lock.json.
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import sqlite3
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .lockfile import (
    Lockfile,
    PackageLock,
    RuntimeLock,
    ServerLock,
    ToolLock,
    canonical_hash,
    compute_effective_annotations,
    find_lockfile,
    load_lockfile,
    save_lockfile,
)


def format_manifest_diff(
    server_id: str,
    locked_server: Optional[ServerLock],
    new_manifest: Dict[str, Any],
) -> str:
    """Format human-readable colored terminal diff comparing locked vs pending manifest."""
    lines: List[str] = [f"\n[mcp-behave] Pending Behavioral Drift for server '{server_id}':"]

    locked_tools = locked_server.manifest.get("tools", {}) if locked_server else {}
    new_tools_raw = new_manifest.get("tools", {})

    # Normalize new_tools to dict
    if isinstance(new_tools_raw, list):
        new_tools = {t.get("name"): t for t in new_tools_raw if isinstance(t, dict) and t.get("name")}
    elif isinstance(new_tools_raw, dict):
        new_tools = new_tools_raw
    else:
        new_tools = {}

    # 1. Added tools
    for name, tool_obj in new_tools.items():
        if name not in locked_tools:
            ann = compute_effective_annotations(tool_obj.get("annotations") if isinstance(tool_obj, dict) else None)
            lines.append(f"  + Added Tool: {name} (readOnly={ann['readOnlyHint']}, destructive={ann['destructiveHint']})")

    # 2. Modified tools
    for name, tool_obj in new_tools.items():
        if name in locked_tools:
            t_lock = locked_tools[name]
            if isinstance(t_lock, dict):
                t_lock = ToolLock.from_dict(t_lock)

            changes = []
            if isinstance(tool_obj, dict):
                live_schema_hash = canonical_hash(tool_obj.get("inputSchema"))
                if live_schema_hash != t_lock.input_schema_hash:
                    changes.append("schema changed")

                live_desc_hash = canonical_hash(tool_obj.get("description", ""))
                if live_desc_hash != t_lock.description_hash:
                    changes.append("description changed")

                live_ann = compute_effective_annotations(tool_obj.get("annotations"))
                locked_ann = compute_effective_annotations(t_lock.annotations)
                if live_ann != locked_ann:
                    changes.append(f"annotations changed ({locked_ann} -> {live_ann})")

            if changes:
                lines.append(f"  ~ Modified Tool: {name} ({', '.join(changes)})")

    # 3. Removed tools
    for name in locked_tools:
        if name not in new_tools:
            lines.append(f"  - Removed Tool: {name}")

    # 4. Instructions
    old_inst_hash = locked_server.manifest.get("instructions_hash") if locked_server else None
    new_inst = new_manifest.get("instructions")
    if new_inst is not None:
        new_inst_hash = canonical_hash(new_inst)
        if old_inst_hash and new_inst_hash != old_inst_hash:
            lines.append("  ~ Modified System Instructions")

    if len(lines) == 1:
        lines.append("  (No manifest structural differences detected)")

    return "\n".join(lines)


def approve_drift(
    server_id: Optional[str] = None,
    lockfile_path: Optional[str | Path] = None,
    state_dir: Optional[str | Path] = None,
    session_id: Optional[str] = None,
    auto_approve: bool = False,
    stdout: Optional[Any] = None,
) -> int:
    """Review and approve untrusted drift snapshots from SQLite into mcp-behave.lock.json."""
    out = stdout or sys.stdout

    # 1. Resolve SQLite database path
    eff_state_dir = Path(state_dir) if state_dir else Path.home() / ".mcp-behave"
    db_path = eff_state_dir / "telemetry.db"
    if not db_path.is_file():
        # Check current working directory
        cwd_db = Path.cwd() / "telemetry.db"
        if cwd_db.is_file():
            db_path = cwd_db
        else:
            print(f"[mcp-behave] Error: Telemetry database not found at {db_path}", file=sys.stderr)
            return 1

    # 2. Query latest untrusted manifest from manifest_history
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    query = "SELECT id, server_id, ts, manifest_json, approved_state FROM manifest_history WHERE approved_state = 'untrusted'"
    params: List[Any] = []
    if server_id:
        query += " AND server_id = ?"
        params.append(server_id)
    query += " ORDER BY id DESC LIMIT 1"

    cur.execute(query, params)
    row = cur.fetchone()
    if not row:
        print("[mcp-behave] No pending unapproved drift found in telemetry database.", file=out)
        conn.close()
        return 0

    record_id, target_server_id, ts, manifest_json_str, approved_state = row
    try:
        new_manifest = json.loads(manifest_json_str)
    except Exception as e:
        print(f"[mcp-behave] Error parsing stored manifest JSON: {e}", file=sys.stderr)
        conn.close()
        return 1

    # 3. Resolve target lockfile path
    target_lock_path = Path(lockfile_path).resolve() if lockfile_path else find_lockfile()
    if not target_lock_path:
        target_lock_path = Path.cwd() / "mcp-behave.lock.json"

    # 4. Load or create lockfile
    lockfile = load_lockfile(target_lock_path)
    if not lockfile:
        lockfile = Lockfile()

    locked_server = lockfile.get_server(target_server_id)

    # 5. Display diff
    diff_text = format_manifest_diff(target_server_id, locked_server, new_manifest)
    print(diff_text, file=out)

    # 6. Prompt for user confirmation if not auto-approved
    if not auto_approve:
        try:
            choice = input(f"\nApprove changes into '{target_lock_path.name}'? [y/N]: ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            print("\nApproval aborted.", file=out)
            conn.close()
            return 130
        if choice not in ("y", "yes"):
            print("Approval aborted.", file=out)
            conn.close()
            return 1

    # 7. Compile updated ServerLock
    new_tools_raw = new_manifest.get("tools", {})
    if isinstance(new_tools_raw, list):
        tools_dict = {}
        for t in new_tools_raw:
            if isinstance(t, dict) and "name" in t:
                tools_dict[t["name"]] = ToolLock(
                    description_hash=canonical_hash(t.get("description", "")),
                    input_schema_hash=canonical_hash(t.get("inputSchema")),
                    annotations=compute_effective_annotations(t.get("annotations")),
                )
    elif isinstance(new_tools_raw, dict):
        tools_dict = {}
        for name, t in new_tools_raw.items():
            if isinstance(t, dict):
                tools_dict[name] = ToolLock(
                    description_hash=t.get("description_hash") or canonical_hash(t.get("description", "")),
                    input_schema_hash=t.get("input_schema_hash") or canonical_hash(t.get("inputSchema")),
                    annotations=compute_effective_annotations(t.get("annotations")),
                )
            elif isinstance(t, ToolLock):
                tools_dict[name] = t
    else:
        tools_dict = {}

    inst = new_manifest.get("instructions")
    inst_hash = canonical_hash(inst) if inst is not None else (locked_server.manifest.get("instructions_hash", "") if locked_server else "")

    updated_manifest: Dict[str, Any] = {
        "server_info": new_manifest.get("server_info") or (locked_server.manifest.get("server_info", {}) if locked_server else {}),
        "instructions_hash": inst_hash,
        "capabilities": new_manifest.get("capabilities") or (locked_server.manifest.get("capabilities", {}) if locked_server else {}),
        "tools": tools_dict,
        "prompts": new_manifest.get("prompts") or (locked_server.manifest.get("prompts", {}) if locked_server else {}),
        "resources": new_manifest.get("resources") or (locked_server.manifest.get("resources", {}) if locked_server else {}),
    }

    pkg_lock = locked_server.package if locked_server else None
    rt_lock = locked_server.runtime if locked_server else None
    cmd_list = locked_server.command if locked_server else []

    updated_server_lock = ServerLock(
        server_id=target_server_id,
        command=cmd_list,
        package=pkg_lock,
        runtime=rt_lock,
        audit=locked_server.audit if locked_server else {"approved_at": datetime.datetime.now(datetime.timezone.utc).isoformat()},
        manifest=updated_manifest,
    )

    lockfile.add_or_update_server(updated_server_lock)

    # 8. Atomically save lockfile
    save_lockfile(lockfile, target_lock_path)

    # 9. Mark SQLite snapshot as trusted
    cur.execute("UPDATE manifest_history SET approved_state = 'trusted' WHERE id = ?", (record_id,))
    conn.commit()
    conn.close()

    print(f"[mcp-behave] Successfully approved changes for '{target_server_id}' into '{target_lock_path}'.", file=out)
    return 0


def main_approve(argv: Optional[List[str]] = None) -> int:
    """CLI entrypoint for 'mcp-behave approve'."""
    parser = argparse.ArgumentParser(
        prog="mcp-behave approve",
        description="Review and approve behavioral drift snapshots into mcp-behave.lock.json.",
    )
    parser.add_argument(
        "--server", default=None,
        help="Target server ID to approve (defaults to latest unapproved server).",
    )
    parser.add_argument(
        "--lockfile", default=None,
        help="Path to mcp-behave.lock.json (defaults to auto-discovery up to git root).",
    )
    parser.add_argument(
        "--state-dir", default=None,
        help="State directory containing telemetry.db.",
    )
    parser.add_argument(
        "--yes", "-y", action="store_true",
        help="Automatically approve changes without interactive confirmation.",
    )

    args = parser.parse_args(argv)
    return approve_drift(
        server_id=args.server,
        lockfile_path=args.lockfile,
        state_dir=args.state_dir,
        auto_approve=args.yes,
    )


if __name__ == "__main__":
    sys.exit(main_approve())

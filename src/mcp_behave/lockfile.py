"""Behavioral lockfile management, canonical hashing, regression testing, and multi-server verification.

Supports:
- Milestone 3: multi-server JSON lockfiles (`mcp-behave.lock.json`), canonical schema hashing,
  atomic flock persistence, and runtime policy diffing.
- Legacy backwards compatibility: behavioral regression baseline (`mcp-behave.lock`),
  `mcp-behave init`, and `mcp-behave check`.
"""
from __future__ import annotations

import argparse
import asyncio
import datetime
import fcntl
import hashlib
import json
import os
import re
import sys
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import __version__
from .events import (
    DRIFT_ANNOTATION_RELAXATION,
    DRIFT_CONSTRAINT_RELAXATION,
    KIND_LOCKFILE_DRIFT,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
)
from .heuristics import check_prompt_injection

DEFAULT_LOCKFILE_NAME = "mcp-behave.lock"
DEFAULT_M3_LOCKFILE_NAME = "mcp-behave.lock.json"


# ---------------------------------------------------------------------------
# Milestone 3 Data Structures & Hashing
# ---------------------------------------------------------------------------

def canonical_hash(obj: Any) -> str:
    """Compute deterministic SHA-256 hash over canonical JSON representation."""
    if obj is None:
        return "sha256:" + hashlib.sha256(b"null").hexdigest()
    if isinstance(obj, str):
        b = obj.encode("utf-8")
        return "sha256:" + hashlib.sha256(b).hexdigest()
    if isinstance(obj, bytes):
        return "sha256:" + hashlib.sha256(obj).hexdigest()

    # Canonicalize dictionary / list (sorted keys, compact delimiters, UTF-8 encoded)
    canonical_json = json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return "sha256:" + hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


@dataclass
class ToolLock:
    """Locked specification of an individual tool."""
    description_hash: str
    input_schema_hash: str
    annotations: Dict[str, bool] = field(default_factory=lambda: {
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False,
        "openWorldHint": True,
    })

    def to_dict(self) -> Dict[str, Any]:
        return {
            "description_hash": self.description_hash,
            "input_schema_hash": self.input_schema_hash,
            "annotations": dict(self.annotations),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ToolLock:
        return cls(
            description_hash=data.get("description_hash", ""),
            input_schema_hash=data.get("input_schema_hash", ""),
            annotations=data.get("annotations", {}),
        )


@dataclass
class PackageLock:
    """Locked package identity for ephemeral runners (npx, uvx)."""
    ecosystem: str
    name: str
    version: str
    resolved_source: str = "local_cache"
    integrity: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ecosystem": self.ecosystem,
            "name": self.name,
            "version": self.version,
            "resolved_source": self.resolved_source,
            "integrity": self.integrity,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> PackageLock:
        return cls(
            ecosystem=data.get("ecosystem", "unknown"),
            name=data.get("name", ""),
            version=data.get("version", ""),
            resolved_source=data.get("resolved_source", "local_cache"),
            integrity=data.get("integrity", ""),
        )


@dataclass
class RuntimeLock:
    """Locked runtime executable path and hash."""
    executable_path: str = ""
    executable_sha256: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "executable_path": self.executable_path,
            "executable_sha256": self.executable_sha256,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> RuntimeLock:
        return cls(
            executable_path=data.get("executable_path", ""),
            executable_sha256=data.get("executable_sha256", ""),
        )


@dataclass
class ServerLock:
    """Locked behavioral baseline for a specific MCP server."""
    server_id: str
    command: List[str] = field(default_factory=list)
    package: Optional[PackageLock] = None
    runtime: Optional[RuntimeLock] = None
    environment: Dict[str, Any] = field(default_factory=dict)
    audit: Dict[str, Any] = field(default_factory=dict)
    manifest: Dict[str, Any] = field(default_factory=dict)

    def get_tool(self, tool_name: str) -> Optional[ToolLock]:
        tools = self.manifest.get("tools") or {}
        t_data = tools.get(tool_name)
        if not t_data:
            return None
        if isinstance(t_data, ToolLock):
            return t_data
        return ToolLock.from_dict(t_data)

    def to_dict(self) -> Dict[str, Any]:
        tools_dict = {}
        raw_tools = self.manifest.get("tools") or {}
        for name, t in raw_tools.items():
            if isinstance(t, ToolLock):
                tools_dict[name] = t.to_dict()
            elif isinstance(t, dict):
                tools_dict[name] = t

        manifest_out = dict(self.manifest)
        manifest_out["tools"] = tools_dict

        res: Dict[str, Any] = {
            "server_id": self.server_id,
            "command": list(self.command),
            "environment": dict(self.environment),
            "audit": dict(self.audit),
            "manifest": manifest_out,
        }
        if self.package:
            res["package"] = self.package.to_dict()
        if self.runtime:
            res["runtime"] = self.runtime.to_dict()
        return res

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ServerLock:
        pkg = PackageLock.from_dict(data["package"]) if "package" in data and isinstance(data["package"], dict) else None
        rt = RuntimeLock.from_dict(data["runtime"]) if "runtime" in data and isinstance(data["runtime"], dict) else None

        manifest_raw = dict(data.get("manifest") or {})
        tools_dict = {}
        for name, t_data in (manifest_raw.get("tools") or {}).items():
            if isinstance(t_data, dict):
                tools_dict[name] = ToolLock.from_dict(t_data)
            elif isinstance(t_data, ToolLock):
                tools_dict[name] = t_data
        manifest_raw["tools"] = tools_dict

        return cls(
            server_id=data.get("server_id", "default"),
            command=data.get("command", []),
            package=pkg,
            runtime=rt,
            environment=data.get("environment", {}),
            audit=data.get("audit", {}),
            manifest=manifest_raw,
        )


@dataclass
class Lockfile:
    """Root multi-server behavioral lockfile representation."""
    version: int = 1
    created_at: str = field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    mcp_behave_version: str = __version__
    servers: Dict[str, ServerLock] = field(default_factory=dict)

    def __getitem__(self, key: str) -> Any:
        return self.to_dict()[key]

    def get_server(self, server_id: Optional[str] = None) -> Optional[ServerLock]:
        """Look up a server by ID. If server_id is None (or not found) and exactly 1 server is locked, return it."""
        if server_id and server_id in self.servers:
            return self.servers[server_id]
        if len(self.servers) == 1:
            return next(iter(self.servers.values()))
        return None

    def add_or_update_server(self, server_lock: ServerLock) -> None:
        """Add or update a server lock, updating timestamp."""
        self.servers[server_lock.server_id] = server_lock
        self.updated_at = datetime.datetime.now(datetime.timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "$schema": "https://mcp-behave.dev/schemas/v1/lockfile.json",
            "version": self.version,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "mcp_behave_version": self.mcp_behave_version,
            "servers": {sid: s.to_dict() for sid, s in self.servers.items()},
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Lockfile:
        servers = {}
        # Support multi-server "servers" map
        if "servers" in data and isinstance(data["servers"], dict):
            for sid, sdata in data["servers"].items():
                if isinstance(sdata, dict):
                    servers[sid] = ServerLock.from_dict(sdata)
        # Backwards compatibility: single root "server"
        elif "server" in data and isinstance(data["server"], dict):
            sdata = data["server"]
            sid = sdata.get("server_id", "default")
            servers[sid] = ServerLock.from_dict(sdata)

        return cls(
            version=data.get("version", 1),
            created_at=data.get("created_at", ""),
            updated_at=data.get("updated_at", ""),
            mcp_behave_version=data.get("mcp_behave_version", __version__),
            servers=servers,
        )


def find_lockfile(start_path: Optional[str | Path] = None) -> Optional[Path]:
    """Auto-discover mcp-behave.lock.json or mcp-behave.lock by checking start_path and traversing parent dirs to git root."""
    current = Path(start_path or Path.cwd()).resolve()
    if current.is_file():
        current = current.parent

    while True:
        candidate_json = current / DEFAULT_M3_LOCKFILE_NAME
        if candidate_json.is_file():
            return candidate_json
        candidate_lock = current / DEFAULT_LOCKFILE_NAME
        if candidate_lock.is_file():
            return candidate_lock

        # Stop at git root or filesystem root
        if (current / ".git").exists() or current.parent == current:
            break
        current = current.parent

    return None


def load_lockfile(path: Optional[str | Path] = None) -> Any:
    """Load and parse lockfile from path, or via auto-discovery.

    Returns:
        - `Lockfile` object for v2/multi-server JSON lockfiles (`mcp-behave.lock.json`).
        - `Dict[str, Any]` for legacy behavioral lockfiles (`mcp-behave.lock`).
        - `None` if file does not exist or cannot be parsed.
    """
    target_path = Path(path).resolve() if path else find_lockfile()
    if not target_path or not target_path.is_file():
        return None

    try:
        with open(target_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        # Detect legacy behavioral profile lockfile
        if "baseline_behavior" in data or "lockfile_version" in data or target_path.name.endswith(".lock"):
            return data
        return Lockfile.from_dict(data)
    except Exception as exc:
        print(f"[lockfile] error: failed to read lockfile at {target_path}: {exc}", file=sys.stderr)
        return None


def save_lockfile(lockfile: Lockfile, path: str | Path) -> None:
    """Atomically write lockfile using temporary file and advisory file locking."""
    target_path = Path(path).resolve()
    target_dir = target_path.parent
    target_dir.mkdir(parents=True, exist_ok=True)

    lock_file_path = target_dir / f"{target_path.name}.lock"
    content_bytes = json.dumps(lockfile.to_dict(), indent=2).encode("utf-8") + b"\n"

    # Acquire advisory file lock during read-modify-write
    with open(lock_file_path, "w", encoding="utf-8") as lock_f:
        fcntl.flock(lock_f, fcntl.LOCK_EX)
        try:
            temp_file = tempfile.NamedTemporaryFile(
                dir=str(target_dir),
                prefix=f".{target_path.name}.tmp",
                delete=False,
            )
            temp_file_path = Path(temp_file.name)
            try:
                temp_file.write(content_bytes)
                temp_file.flush()
                os.fsync(temp_file.fileno())
                temp_file.close()
                os.replace(temp_file_path, target_path)
            except Exception:
                if temp_file_path.exists():
                    os.unlink(temp_file_path)
                raise
        finally:
            fcntl.flock(lock_f, fcntl.LOCK_UN)


def compute_effective_annotations(raw_annotations: Optional[Dict[str, Any]]) -> Dict[str, bool]:
    """Compute effective safety annotations using strict MCP spec defaults."""
    ann = raw_annotations or {}
    return {
        "readOnlyHint": bool(ann.get("readOnlyHint", False)),
        "destructiveHint": bool(ann.get("destructiveHint", True)),
        "idempotentHint": bool(ann.get("idempotentHint", False)),
        "openWorldHint": bool(ann.get("openWorldHint", True)),
    }


def _diff_m3_lockfile(
    server_lock: ServerLock,
    live_tools: List[Dict[str, Any]],
    live_instructions: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Compare observed tools and instructions against locked server baseline.

    Returns list of drift records with strictly evidence_tier='observed'.
    """
    drifts: List[Dict[str, Any]] = []
    locked_tools = server_lock.manifest.get("tools") or {}

    # 1. Check for unexpected tool additions (tools present live but not in lockfile)
    for live_tool in live_tools:
        name = live_tool.get("name", "")
        if name not in locked_tools:
            ann = compute_effective_annotations(live_tool.get("annotations"))
            drifts.append({
                "category": "tool_addition_unlocked",
                "tool": name,
                "severity": SEVERITY_HIGH,
                "evidence_tier": "observed",
                "would_block": True,
                "message": f"Tool '{name}' observed on server is NOT approved in lockfile.",
                "details": {"annotations": ann},
            })
            continue

        # Compare existing locked tool
        t_lock = locked_tools[name]
        if isinstance(t_lock, dict):
            t_lock = ToolLock.from_dict(t_lock)

        # 1a. Input schema change (constraint relaxation)
        live_schema = live_tool.get("inputSchema") or {}
        live_schema_hash = canonical_hash(live_schema)
        if live_schema_hash != t_lock.input_schema_hash:
            drifts.append({
                "category": "schema_constraint_relaxation",
                "tool": name,
                "severity": SEVERITY_HIGH,
                "evidence_tier": "observed",
                "would_block": True,
                "message": f"Input schema for tool '{name}' has changed compared to lockfile.",
                "details": {
                    "locked_schema_hash": t_lock.input_schema_hash,
                    "live_schema_hash": live_schema_hash,
                },
            })

        # 1b. Safety annotation relaxation
        live_ann = compute_effective_annotations(live_tool.get("annotations"))
        locked_ann = compute_effective_annotations(t_lock.annotations)

        # Claims tool got safer: readOnly false->true, destructive true->false, openWorld true->false
        is_relaxed = (
            (not locked_ann["readOnlyHint"] and live_ann["readOnlyHint"])
            or (locked_ann["destructiveHint"] and not live_ann["destructiveHint"])
            or (locked_ann["openWorldHint"] and not live_ann["openWorldHint"])
        )
        if is_relaxed:
            drifts.append({
                "category": "annotation_relaxation",
                "tool": name,
                "severity": SEVERITY_HIGH,
                "evidence_tier": "observed",
                "would_block": True,
                "message": f"Safety annotations for tool '{name}' relaxed claims compared to lockfile.",
                "details": {"locked": locked_ann, "live": live_ann},
            })

        # 1c. Description mutation with injection check
        live_desc = live_tool.get("description", "")
        live_desc_hash = canonical_hash(live_desc)
        if live_desc_hash != t_lock.description_hash:
            is_inj, reasons = check_prompt_injection(live_desc)
            drifts.append({
                "category": "description_mutation",
                "tool": name,
                "severity": SEVERITY_HIGH if is_inj else SEVERITY_MEDIUM,
                "evidence_tier": "observed",
                "would_block": is_inj,
                "message": f"Description for tool '{name}' changed compared to lockfile." + (f" (Prompt injection cues: {reasons})" if is_inj else ""),
                "details": {"reasons": reasons if is_inj else []},
            })

    # 2. Check for tool deletions (in lockfile but missing from live server)
    live_names = {t.get("name") for t in live_tools if t.get("name")}
    for locked_name in locked_tools:
        if locked_name not in live_names:
            drifts.append({
                "category": "tool_removal",
                "tool": locked_name,
                "severity": SEVERITY_MEDIUM,
                "evidence_tier": "observed",
                "would_block": False,
                "message": f"Approved tool '{locked_name}' is missing from live server.",
                "details": {},
            })

    # 3. System instruction override check
    if live_instructions is not None:
        locked_inst_hash = server_lock.manifest.get("instructions_hash", "")
        live_inst_hash = canonical_hash(live_instructions)
        if locked_inst_hash and live_inst_hash != locked_inst_hash:
            is_inj, reasons = check_prompt_injection(live_instructions)
            drifts.append({
                "category": "instruction_override",
                "tool": None,
                "severity": SEVERITY_HIGH if is_inj else SEVERITY_MEDIUM,
                "evidence_tier": "observed",
                "would_block": is_inj,
                "message": "Server system instructions changed compared to lockfile." + (f" (Injection cues: {reasons})" if is_inj else ""),
                "details": {"reasons": reasons if is_inj else []},
            })

    return drifts


# ---------------------------------------------------------------------------
# Legacy Behavioral Lockfile & Regression Testing API
# ---------------------------------------------------------------------------

_PYC_ATOMIC_RE = re.compile(r"^(.*/__pycache__/[^/]+\.pyc)\.\d+$")
_ONNX_DEVICEID_RE = re.compile(
    r"^(\$CANARY_HOME/\.cache/Microsoft/DeveloperTools/\.onnxruntime/deviceid\.tmp)\.[0-9a-fA-F-]+$"
)
_LEGACY_CANARY_RE = re.compile(r"^(?:/private)?/tmp/mcp_behave_canary_home_[A-Za-z0-9_]+(?=/|$)")


def normalize_baseline_path(
    path: str,
    *,
    canary_home: Optional[str] = None,
    legacy_canary_fallback: bool = False,
) -> str:
    """Canonicalize ephemeral audit-specific path noise without hiding real filesystem writes.

    - Canonicalizes ONLY the actual canary_home root associated with the current audit
      (plus its realpath) to '$CANARY_HOME'.
    - Strips Python importlib._write_atomic numeric suffixes on __pycache__/*.pyc.<id> files.
    - Canonicalizes onnxruntime's randomized deviceid.tmp.<uuid> ONLY underneath $CANARY_HOME.
    """
    norm = path
    if canary_home:
        roots = []
        for candidate in (canary_home, os.path.realpath(canary_home)):
            c = candidate.rstrip("/")
            if c and c not in roots:
                roots.append(c)
        for root in roots:
            if norm == root:
                norm = "$CANARY_HOME"
                break
            if norm.startswith(root + "/"):
                norm = "$CANARY_HOME" + norm[len(root):]
                break
    elif legacy_canary_fallback:
        norm = _LEGACY_CANARY_RE.sub("$CANARY_HOME", norm, count=1)

    m_onnx = _ONNX_DEVICEID_RE.match(norm)
    if m_onnx:
        norm = f"{m_onnx.group(1)}.<UUID>"

    m_pyc = _PYC_ATOMIC_RE.match(norm)
    if m_pyc:
        norm = m_pyc.group(1)

    return norm


def generate_lockfile_data(manifest: Dict[str, Any], profile: Dict[str, Any]) -> Dict[str, Any]:
    """Generate structured lockfile content from probed manifest and behavioral profile (legacy)."""
    from . import analyze as analyze_mod

    canary_home = manifest.get("canary_home")
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
            sensitive_files.append(normalize_baseline_path(f, canary_home=canary_home))

    files_written = sorted({
        normalize_baseline_path(f, canary_home=canary_home)
        for f in profile.get("files_written", [])
    })

    return {
        "$schema": "https://raw.githubusercontent.com/navid72m/mcp-behave/main/schemas/lockfile.v1.json",
        "lockfile_version": 1,
        "mcp_behave_version": __version__,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "server_cmd": manifest.get("server_cmd"),
        "manifest_sha256": manifest.get("manifest_sha256"),
        "canary_home_canonicalized": True,
        "declared_tools": sorted(tools),
        "baseline_behavior": {
            "network_endpoints": sorted(profile.get("network_connects", [])),
            "sensitive_files": sorted(set(sensitive_files)),
            "files_written": files_written,
            "unix_sockets": sorted(profile.get("unix_sockets", [])),
            "subprocesses": sorted(profile.get("subprocesses", [])),
        },
        "tool_behavior": tool_behaviors,
    }


def write_lockfile(lock_data: Dict[str, Any], lockfile_path: os.PathLike | str = DEFAULT_LOCKFILE_NAME) -> Path:
    """Serialize and write legacy lockfile data to disk."""
    p = Path(lockfile_path).resolve()
    p.write_text(json.dumps(lock_data, indent=2) + "\n", encoding="utf-8")
    return p


def _diff_legacy_lockfile(lock_data: Dict[str, Any], manifest: Dict[str, Any], profile: Dict[str, Any]) -> List[str]:
    """Compare live observed behavior against legacy lockfile baseline."""
    from . import analyze as analyze_mod

    diffs: List[str] = []
    baseline = lock_data.get("baseline_behavior", {})

    # 1. Network endpoints regression
    base_nets = set(baseline.get("network_endpoints", []))
    curr_nets = set(profile.get("network_connects", []))
    new_nets = curr_nets - base_nets
    for net in sorted(new_nets):
        diffs.append(f"Undeclared network egress: '{net}' was contacted (not in lockfile baseline)")

    canary_home = manifest.get("canary_home") if isinstance(manifest, dict) else None
    legacy_fallback = not bool(lock_data.get("canary_home_canonicalized"))

    # 2. Sensitive files regression
    base_sens = {
        normalize_baseline_path(s, legacy_canary_fallback=legacy_fallback)
        for s in baseline.get("sensitive_files", [])
    }
    curr_sens = set()
    for f in profile.get("files_opened", []):
        is_sens, _ = analyze_mod.is_sensitive_path(f)
        if is_sens:
            curr_sens.add(normalize_baseline_path(f, canary_home=canary_home))
    new_sens = curr_sens - base_sens
    for s in sorted(new_sens):
        diffs.append(f"Undeclared sensitive file read: '{s}' was accessed (not in lockfile baseline)")

    # 3. File modifications/writes regression
    base_written = {
        normalize_baseline_path(w, legacy_canary_fallback=legacy_fallback)
        for w in baseline.get("files_written", [])
    }
    curr_written = {
        normalize_baseline_path(w, canary_home=canary_home)
        for w in profile.get("files_written", [])
    }
    new_written = curr_written - base_written
    for w in sorted(new_written):
        diffs.append(f"Undeclared file write/modification: '{w}' was written (not in lockfile baseline)")

    # 4. Unix domain sockets regression
    base_unix = set(baseline.get("unix_sockets", []))
    curr_unix = set(profile.get("unix_sockets", []))
    new_unix = curr_unix - base_unix
    for u in sorted(new_unix):
        diffs.append(f"Undeclared unix socket connect: '{u}' was accessed (not in lockfile baseline)")

    # 5. Spawned subprocesses regression
    base_subs = set(baseline.get("subprocesses", []))
    curr_subs = set(profile.get("subprocesses", []))
    new_subs = curr_subs - base_subs
    for sub in sorted(new_subs):
        diffs.append(f"Undeclared subprocess spawned: '{sub}' was executed (not in lockfile baseline)")

    # 6. Tool-level behavior regression
    base_tool_behaviors = lock_data.get("tool_behavior", {})
    curr_tool_networks = profile.get("tool_network_connects", {})
    for tool_name, tool_data in sorted(curr_tool_networks.items()):
        base_tool = base_tool_behaviors.get(tool_name, {})
        base_tool_nets = set(base_tool.get("network_endpoints", []))
        curr_tool_nets = set(tool_data)
        new_tool_nets = curr_tool_nets - base_tool_nets
        for n in sorted(new_tool_nets):
            diffs.append(f"Tool '{tool_name}' made undeclared network egress to '{n}'")

    return diffs


def diff_against_lockfile(
    lock_or_server: Any,
    manifest_or_tools: Any,
    profile_or_instructions: Any = None,
    *,
    live_instructions: Optional[str] = None,
) -> Any:
    """Unified entrypoint for diffing against lockfiles (supports both M3 and legacy)."""
    instructions = live_instructions if live_instructions is not None else (
        profile_or_instructions if isinstance(profile_or_instructions, str) else None
    )
    if isinstance(lock_or_server, ServerLock):
        return _diff_m3_lockfile(lock_or_server, manifest_or_tools, instructions)
    if isinstance(lock_or_server, dict) and "baseline_behavior" in lock_or_server:
        return _diff_legacy_lockfile(lock_or_server, manifest_or_tools, profile_or_instructions)
    if isinstance(manifest_or_tools, dict) and isinstance(profile_or_instructions, dict):
        return _diff_legacy_lockfile(lock_or_server, manifest_or_tools, profile_or_instructions)
    if isinstance(lock_or_server, dict) and ("tools" in lock_or_server or "manifest" in lock_or_server):
        sl = ServerLock.from_dict(lock_or_server) if "manifest" in lock_or_server else ServerLock(server_id="default", manifest=lock_or_server)
        return _diff_m3_lockfile(sl, manifest_or_tools, instructions)
    return _diff_legacy_lockfile(lock_or_server, manifest_or_tools, profile_or_instructions)


def main_init(argv=None) -> int:
    """Entrypoint for `mcp-behave init [server-cmd...]`."""
    from . import probe as probe_mod
    from . import report as report_mod

    parser = argparse.ArgumentParser(
        prog="mcp-behave init",
        description="Establish a committed runtime behavioral lockfile (mcp-behave.lock).",
    )
    parser.add_argument(
        "--lockfile", default=DEFAULT_LOCKFILE_NAME,
        help="Where to write the lockfile (default: %(default)s).",
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
        parser.error("no server command provided. Example: mcp-behave init python -m my_server")

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
    from . import probe as probe_mod
    from . import report as report_mod

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
        cmd = lock_data.get("server_cmd") if isinstance(lock_data, dict) else None
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

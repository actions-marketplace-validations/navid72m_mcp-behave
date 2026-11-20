"""Unified event model for mcp-behave runtime observability.

Decouples behavioral analysis and security scoring from underlying tracer implementations
(macOS DYLD interposition, Linux LD_PRELOAD, Linux ptrace/strace, and Linux eBPF tracepoints).

All backends emit or are normalized into `BehavioralEvent` instances, ensuring that
the analysis engine evaluates identical event structures regardless of whether an event
was captured at the kernel tracepoint level or userspace libc interposition layer.
"""
from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


# Event types
EVENT_PROCESS_EXEC = "process_exec"
EVENT_PROCESS_FORK = "process_fork"
EVENT_PROCESS_EXIT = "process_exit"
EVENT_FILE_OPEN = "file_open"
EVENT_FILE_WRITE = "file_write"
EVENT_FILE_UNLINK = "file_unlink"
EVENT_FILE_RENAME = "file_rename"
EVENT_NETWORK_CONNECT = "network_connect"
EVENT_UNIX_CONNECT = "unix_socket_connect"
EVENT_TOOL_MARKER = "tool_marker"

# Runtime monitor evidence tiers
EVIDENCE_TIER_OBSERVED = "observed"
EVIDENCE_TIER_CORRELATED = "correlated"
EVIDENCE_TIER_STRUCTURAL = "structural"
EVIDENCE_TIER_HEURISTIC = "heuristic"

# Mapping between scorecard classifications and monitor evidence tiers
TIER_SCORECARD_TO_MONITOR = {
    "CONFIRMED": EVIDENCE_TIER_OBSERVED,
    "STRONG_EVIDENCE": EVIDENCE_TIER_STRUCTURAL,
    "HEURISTIC": EVIDENCE_TIER_HEURISTIC,
    "INFORMATIONAL": "informational",
}

TIER_MONITOR_TO_SCORECARD = {
    EVIDENCE_TIER_OBSERVED: "CONFIRMED",
    EVIDENCE_TIER_CORRELATED: "STRONG_EVIDENCE",
    EVIDENCE_TIER_STRUCTURAL: "STRONG_EVIDENCE",
    EVIDENCE_TIER_HEURISTIC: "HEURISTIC",
    "informational": "INFORMATIONAL",
}

# Runtime monitor event severities
SEVERITY_INFO = "INFO"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_HIGH = "HIGH"
SEVERITY_CRITICAL = "CRITICAL"

# Runtime monitor event kinds
KIND_PROTOCOL_REQUEST = "protocol_request"
KIND_PROTOCOL_RESPONSE = "protocol_response"
KIND_PROTOCOL_NOTIFICATION = "protocol_notification"
KIND_PROTOCOL_ANOMALY = "protocol_anomaly"
KIND_STDOUT_POLLUTION = "stdout_pollution"
KIND_OS_TRACING = "os_tracing"
KIND_TELEMETRY_DROP = "telemetry_drop"
KIND_SESSION_START = "session_start"
KIND_SESSION_END = "session_end"
KIND_BLIND_SPOT = "blind_spot"
KIND_MANIFEST_BASELINE = "manifest_baseline"
KIND_MANIFEST_DRIFT = "manifest_drift"
KIND_CROSS_SESSION_DRIFT = "cross_session_drift"

# Content inspection event kinds (Milestone 2b)
KIND_SECRET_LEAK = "secret_leak"
KIND_SECRET_EXPOSURE = "secret_exposure"
KIND_CANARY_EXFILTRATION = "canary_exfiltration"
KIND_INDIRECT_INJECTION = "indirect_injection"
KIND_ARGUMENT_HEURISTIC = "argument_heuristic"

# Manifest drift categories
DRIFT_COVERT_ADDITION = "covert_addition"
DRIFT_ANNOUNCED_ADDITION = "announced_addition"
DRIFT_REMOVAL_OR_RENAME = "removal_or_rename"
DRIFT_CAPABILITY_EXPANSION = "capability_expansion"
DRIFT_CONSTRAINT_RELAXATION = "constraint_relaxation"
DRIFT_ANNOTATION_RELAXATION = "annotation_relaxation"
DRIFT_TRUSTED_TOOL_ESCALATION = "trusted_tool_escalation"
DRIFT_DESCRIPTION_MUTATION = "description_mutation"
DRIFT_DESCRIPTION_INJECTION = "description_injection"
DRIFT_INSTRUCTIONS_MUTATION = "instructions_mutation"
DRIFT_INSTRUCTIONS_INJECTION = "instructions_injection"


@dataclass
class BehavioralEvent:
    """Normalized runtime observation event emitted by any tracer backend or monitor proxy."""

    event: str
    pid: int | None = None
    ppid: int | None = None
    process: str | None = None
    target: str | None = None              # Path, binary, socket, or tool name
    destination_ip: str | None = None
    destination_port: int | None = None
    timestamp: float | None = None
    source: str = "interposition"          # "ebpf", "preload", "dylib", "strace", "mock", "monitor"
    current_tool: str | None = None        # Correlated active MCP tool
    flags: str | None = None
    return_code: int | None = None
    session_id: str | None = None          # Monitor session UUID
    server_id: str | None = None           # Monitored server ID
    kind: str | None = None                # Monitor event kind (e.g. protocol_request, stdout_pollution)
    request_id: str | int | None = None    # Correlated JSON-RPC request ID
    evidence_tier: str | None = None       # "observed" | "correlated" | "structural" | "heuristic"
    severity: str | None = None            # "INFO" | "MEDIUM" | "HIGH" | "CRITICAL"
    payload: dict[str, Any] = field(default_factory=dict)
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        if self.timestamp is not None:
            # Add ISO format timestamp representation for logs
            d["iso_time"] = datetime.fromtimestamp(self.timestamp, tz=timezone.utc).isoformat()
        return {k: v for k, v in d.items() if v is not None}

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BehavioralEvent:
        clean = dict(data)
        clean.pop("iso_time", None)
        return cls(**clean)


def _clean_path(p: str) -> str:
    """Clean and normalize a filesystem path."""
    if p.endswith("\\0"):
        p = p[:-2]
    if p.endswith("\0"):
        p = p[:-1]
    return p.strip()


def parse_native_line(line: str, current_tool: str | None = None) -> tuple[BehavioralEvent | None, str | None]:
    """Parse a single line from native tracer (dylib or LD_PRELOAD) into a BehavioralEvent.

    Returns (event, updated_current_tool).
    Native format tags:
      M CALL_START <tool> / M CALL_END <tool>
      F <path> (file open)
      W <path> (file write)
      U <socket_path> (unix socket)
      N <ip> <port> (network connect)
      X <binary> (process exec)
      ! TRUNCATED <tag> <tail>
    """
    s = line.rstrip("\n")
    if not s:
        return None, current_tool

    if s.startswith("! TRUNCATED "):
        parts = s[12:].split(" ", 1)
        t_tag = parts[0] if parts else ""
        t_tail = parts[1] if len(parts) > 1 else ""
        if t_tail:
            evt_type = EVENT_FILE_WRITE if t_tag == "W" else EVENT_FILE_OPEN
            return BehavioralEvent(
                event=evt_type,
                target=os.path.normpath(_clean_path(t_tail)),
                source="interposition",
                current_tool=current_tool,
                extra={"truncated": True},
            ), current_tool
        return None, current_tool

    if len(s) < 2 or s[1] != " ":
        return None, current_tool

    tag, val = s[0], s[2:]

    if tag == "M":
        if val.startswith("CALL_START "):
            tname = val[11:].strip()
            return BehavioralEvent(
                event=EVENT_TOOL_MARKER,
                target=tname,
                source="interposition",
                current_tool=tname,
                flags="CALL_START",
            ), tname
        elif val.startswith("CALL_END "):
            tname = val[9:].strip()
            return BehavioralEvent(
                event=EVENT_TOOL_MARKER,
                target=tname,
                source="interposition",
                current_tool=tname,
                flags="CALL_END",
            ), None

    elif tag == "F":
        norm = os.path.normpath(_clean_path(val))
        return BehavioralEvent(
            event=EVENT_FILE_OPEN,
            target=norm,
            source="interposition",
            current_tool=current_tool,
        ), current_tool

    elif tag == "W":
        norm = os.path.normpath(_clean_path(val))
        return BehavioralEvent(
            event=EVENT_FILE_WRITE,
            target=norm,
            source="interposition",
            current_tool=current_tool,
        ), current_tool

    elif tag == "U":
        norm = os.path.normpath(_clean_path(val))
        return BehavioralEvent(
            event=EVENT_UNIX_CONNECT,
            target=norm,
            source="interposition",
            current_tool=current_tool,
        ), current_tool

    elif tag == "N":
        ip, _, port_str = val.rpartition(" ")
        port = int(port_str) if port_str.isdigit() else None
        return BehavioralEvent(
            event=EVENT_NETWORK_CONNECT,
            destination_ip=ip,
            destination_port=port,
            source="interposition",
            current_tool=current_tool,
        ), current_tool

    elif tag == "X":
        norm = os.path.normpath(_clean_path(val))
        return BehavioralEvent(
            event=EVENT_PROCESS_EXEC,
            target=norm,
            process=norm,
            source="interposition",
            current_tool=current_tool,
        ), current_tool

    return None, current_tool


def parse_native_trace(lines: Iterable[str]) -> list[BehavioralEvent]:
    """Parse entire native trace into normalized BehavioralEvent stream."""
    events: list[BehavioralEvent] = []
    current_tool: str | None = None
    for line in lines:
        evt, current_tool = parse_native_line(line, current_tool)
        if evt:
            events.append(evt)
    return events


def events_to_profile(events: Iterable[BehavioralEvent], is_interesting_file=None, is_interesting_net=None) -> dict[str, Any]:
    """Reduce a normalized stream of BehavioralEvents into the standard behavioral profile dict.

    This profile dict is consumed by report.py, lockfile.py, and scorecard.py.
    """
    if is_interesting_file is None:
        from .analyze import interesting_file as default_interesting_file
        is_interesting_file = default_interesting_file
    if is_interesting_net is None:
        from .analyze import interesting_net as default_interesting_net
        is_interesting_net = default_interesting_net

    files_opened: set[str] = set()
    files_written: set[str] = set()
    unix_sockets: set[str] = set()
    nets: set[str] = set()
    execs: set[str] = set()
    truncated_paths: set[str] = set()
    tool_network_connects: dict[str, list[str]] = {}
    filtered_files = 0

    for evt in events:
        if evt.event in (EVENT_FILE_OPEN, EVENT_FILE_WRITE):
            target = evt.target or ""
            if not target:
                continue
            norm = os.path.normpath(target)
            if len(norm) > 1024 or evt.extra.get("truncated"):
                truncated_paths.add(norm)

            if evt.event == EVENT_FILE_WRITE:
                files_written.add(norm)

            if is_interesting_file(norm):
                files_opened.add(norm)
            else:
                filtered_files += 1

            # Check symlink dereference
            try:
                if os.path.islink(norm) or os.path.islink(target):
                    real = os.path.realpath(norm)
                    if real != norm and is_interesting_file(real):
                        files_opened.add(real)
                        if evt.event == EVENT_FILE_WRITE:
                            files_written.add(real)
            except (OSError, ValueError):
                pass

        elif evt.event == EVENT_NETWORK_CONNECT:
            ip = evt.destination_ip or ""
            port = evt.destination_port
            if ip and port is not None and port > 0:
                if is_interesting_net(ip):
                    endpoint = f"{ip}:{port}"
                    nets.add(endpoint)
                    if evt.current_tool:
                        tool_network_connects.setdefault(evt.current_tool, []).append(endpoint)

        elif evt.event == EVENT_UNIX_CONNECT:
            if evt.target:
                unix_sockets.add(os.path.normpath(evt.target))

        elif evt.event == EVENT_PROCESS_EXEC:
            proc = evt.process or evt.target or ""
            if proc:
                execs.add(os.path.normpath(proc))

    return {
        "files_opened": sorted(files_opened),
        "files_written": sorted(files_written),
        "unix_sockets": sorted(unix_sockets),
        "network_connects": sorted(nets),
        "subprocesses": sorted(execs),
        "truncated_paths": sorted(truncated_paths),
        "tool_network_connects": tool_network_connects,
        "_meta": {"files_filtered_as_noise": filtered_files},
    }

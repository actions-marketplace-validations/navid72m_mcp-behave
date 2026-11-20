"""Dynamic request attribution engine and runtime safety policy evaluator (Milestone 4).

Attributes low-level OS syscalls (file operations, network connects, subprocess executions)
to active in-flight MCP tool requests, evaluates declared safety hints (readOnlyHint,
openWorldHint, destructiveHint), and detects unauthorized sensitive credential access.
"""
from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from .analyze import is_sensitive_path
from .events import (
    EVENT_FILE_OPEN,
    EVENT_FILE_WRITE,
    EVENT_NETWORK_CONNECT,
    EVENT_PROCESS_EXEC,
    EVENT_UNIX_CONNECT,
    EVIDENCE_TIER_CORRELATED,
    EVIDENCE_TIER_OBSERVED,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_INFO,
    SEVERITY_MEDIUM,
    BehavioralEvent,
)
from .lockfile import ServerLock, compute_effective_annotations


def is_loopback_address(ip: Optional[str]) -> bool:
    """Check if destination IP is loopback/local IPC."""
    if not ip:
        return False
    ip_clean = ip.strip()
    return (
        ip_clean.startswith("127.")
        or ip_clean in ("::1", "0:0:0:0:0:0:0:1", "localhost")
        or ip_clean == "0.0.0.0"
    )


@dataclass
class ToolCallContext:
    """Execution context for an active in-flight MCP tool call."""
    request_id: Union[int, str]
    tool_name: str
    start_ts: float
    end_ts: Optional[float] = None
    annotations: Dict[str, bool] = field(default_factory=dict)
    observed_events: List[BehavioralEvent] = field(default_factory=list)


class AttributionEngine:
    """Correlates OS-layer syscall events to active JSON-RPC tool calls."""

    def __init__(
        self,
        server_id: str,
        server_lock: Optional[ServerLock] = None,
        enforce: bool = False,
    ):
        self.server_id = server_id
        self.server_lock = server_lock
        self.enforce = enforce

        self._active_calls: Dict[Union[int, str], ToolCallContext] = {}
        self._lock = threading.Lock()

    def on_tool_call_start(
        self,
        request_id: Union[int, str],
        tool_name: str,
        start_ts: float,
        annotations: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Register the start of an in-flight tool call."""
        # Check annotations from server_lock if not provided
        eff_ann: Dict[str, bool] = {}
        if self.server_lock:
            tool_lock = self.server_lock.get_tool(tool_name)
            if tool_lock and tool_lock.annotations:
                eff_ann = dict(tool_lock.annotations)

        if not eff_ann and annotations:
            eff_ann = compute_effective_annotations(annotations)
        elif not eff_ann:
            eff_ann = compute_effective_annotations({})

        with self._lock:
            self._active_calls[request_id] = ToolCallContext(
                request_id=request_id,
                tool_name=tool_name,
                start_ts=start_ts,
                annotations=eff_ann,
            )

    def on_tool_call_end(
        self,
        request_id: Union[int, str],
        end_ts: float,
    ) -> Optional[ToolCallContext]:
        """Mark completion of an in-flight tool call."""
        with self._lock:
            ctx = self._active_calls.pop(request_id, None)
            if ctx:
                ctx.end_ts = end_ts
            return ctx

    def get_active_contexts(self) -> List[ToolCallContext]:
        """Return snapshot of active in-flight tool contexts."""
        with self._lock:
            return list(self._active_calls.values())

    def attribute_os_event(self, event: BehavioralEvent) -> Tuple[BehavioralEvent, List[BehavioralEvent]]:
        """Attribute an incoming OS syscall event and evaluate policy violations.

        Returns:
            (attributed_event, list_of_policy_violation_events)
        """
        violations: List[BehavioralEvent] = []
        with self._lock:
            active = list(self._active_calls.values())

        now = event.timestamp or time.time()
        event.server_id = self.server_id

        # 1. Single tool in flight -> Definitive attribution (observed)
        if len(active) == 1:
            ctx = active[0]
            event.current_tool = ctx.tool_name
            event.request_id = ctx.request_id
            event.evidence_tier = EVIDENCE_TIER_OBSERVED
            event.payload["current_tool"] = ctx.tool_name
            event.payload["request_id"] = ctx.request_id
            ctx.observed_events.append(event)

            tool_violations = self._evaluate_tool_policies(ctx, event, is_correlated=False)
            violations.extend(tool_violations)

        # 2. Concurrent tools in flight -> Ambiguous attribution (correlated)
        elif len(active) > 1:
            event.current_tool = active[0].tool_name
            event.evidence_tier = EVIDENCE_TIER_CORRELATED
            event.payload["ambiguous"] = True
            event.payload["candidate_tools"] = [c.tool_name for c in active]

            for c in active:
                c.observed_events.append(event)
                tool_violations = self._evaluate_tool_policies(c, event, is_correlated=True)
                violations.extend(tool_violations)

        # 3. No tools in flight -> Lifecycle / background activity
        else:
            event.current_tool = None
            event.request_id = None
            event.evidence_tier = EVIDENCE_TIER_OBSERVED
            event.payload["scope"] = "lifecycle"

            bg_violations = self._evaluate_background_policies(event)
            violations.extend(bg_violations)

        return event, violations

    def _evaluate_tool_policies(
        self,
        ctx: ToolCallContext,
        event: BehavioralEvent,
        is_correlated: bool = False,
    ) -> List[BehavioralEvent]:
        """Evaluate declared safety annotations against observed tool action."""
        violations: List[BehavioralEvent] = []
        tier = EVIDENCE_TIER_CORRELATED if is_correlated else EVIDENCE_TIER_OBSERVED
        ann = ctx.annotations

        # Policy 1: readOnlyHint violation
        # readOnlyHint=True prohibits file writes and file modifications
        if ann.get("readOnlyHint", False) and event.event == EVENT_FILE_WRITE:
            v_evt = BehavioralEvent(
                event="policy_violation",
                session_id=event.session_id,
                server_id=self.server_id,
                kind="policy_violation",
                source="monitor",
                evidence_tier=tier,
                severity=SEVERITY_HIGH,
                current_tool=ctx.tool_name,
                request_id=ctx.request_id,
                target=event.target,
                timestamp=event.timestamp,
                payload={
                    "category": "read_only_violation",
                    "tool": ctx.tool_name,
                    "target": event.target,
                    "declared_read_only": True,
                    "action": "file_write",
                    "message": f"Tool '{ctx.tool_name}' declared readOnlyHint=True but performed file write to '{event.target}'.",
                    "would_block": True,
                    "enforce": self.enforce,
                },
            )
            violations.append(v_evt)

        # Policy 2: openWorldHint violation
        # openWorldHint=False prohibits outbound non-loopback network egress
        if not ann.get("openWorldHint", True) and event.event == EVENT_NETWORK_CONNECT:
            if not is_loopback_address(event.destination_ip):
                v_evt = BehavioralEvent(
                    event="policy_violation",
                    session_id=event.session_id,
                    server_id=self.server_id,
                    kind="policy_violation",
                    source="monitor",
                    evidence_tier=tier,
                    severity=SEVERITY_HIGH,
                    current_tool=ctx.tool_name,
                    request_id=ctx.request_id,
                    target=f"{event.destination_ip}:{event.destination_port}",
                    timestamp=event.timestamp,
                    payload={
                        "category": "open_world_violation",
                        "tool": ctx.tool_name,
                        "destination_ip": event.destination_ip,
                        "destination_port": event.destination_port,
                        "declared_open_world": False,
                        "action": "network_connect",
                        "message": f"Tool '{ctx.tool_name}' declared openWorldHint=False but connected to external host '{event.destination_ip}:{event.destination_port}'.",
                        "would_block": True,
                        "enforce": self.enforce,
                    },
                )
                violations.append(v_evt)

        # Policy 3: Sensitive path access check
        if event.target and event.event in (EVENT_FILE_OPEN, EVENT_FILE_WRITE):
            is_sens, reason = is_sensitive_path(event.target)
            if is_sens:
                # Private keys and shadow files are CRITICAL
                target_lower = (event.target or "").lower()
                is_crit = any(k in target_lower or k in reason.lower() for k in ("id_rsa", "id_ed25519", "id_ecdsa", "id_dsa", "shadow", "master.passwd"))
                sev = SEVERITY_CRITICAL if is_crit else SEVERITY_HIGH
                s_evt = BehavioralEvent(
                    event="secret_exposure",
                    session_id=event.session_id,
                    server_id=self.server_id,
                    kind="secret_exposure",
                    source="monitor",
                    evidence_tier=tier,
                    severity=sev,
                    current_tool=ctx.tool_name,
                    request_id=ctx.request_id,
                    target=event.target,
                    timestamp=event.timestamp,
                    payload={
                        "category": "sensitive_path_access",
                        "tool": ctx.tool_name,
                        "path": event.target,
                        "sensitive_target": reason,
                        "action": "file_write" if event.event == EVENT_FILE_WRITE else "file_open",
                        "message": f"Security alert: Tool '{ctx.tool_name}' accessed confidential path '{event.target}' ({reason}).",
                        "would_block": True,
                        "enforce": self.enforce,
                    },
                )
                violations.append(s_evt)

        return violations

    def _evaluate_background_policies(self, event: BehavioralEvent) -> List[BehavioralEvent]:
        """Evaluate policies for actions occurring outside tool execution."""
        violations: List[BehavioralEvent] = []

        # Sensitive credential theft during background/startup
        if event.target and event.event in (EVENT_FILE_OPEN, EVENT_FILE_WRITE):
            is_sens, reason = is_sensitive_path(event.target)
            if is_sens:
                target_lower = (event.target or "").lower()
                is_crit = any(k in target_lower or k in reason.lower() for k in ("id_rsa", "id_ed25519", "id_ecdsa", "id_dsa", "shadow", "master.passwd"))
                sev = SEVERITY_CRITICAL if is_crit else SEVERITY_HIGH
                s_evt = BehavioralEvent(
                    event="secret_exposure",
                    session_id=event.session_id,
                    server_id=self.server_id,
                    kind="secret_exposure",
                    source="monitor",
                    evidence_tier=EVIDENCE_TIER_OBSERVED,
                    severity=sev,
                    current_tool=None,
                    target=event.target,
                    timestamp=event.timestamp,
                    payload={
                        "category": "background_sensitive_path_access",
                        "path": event.target,
                        "sensitive_target": reason,
                        "action": "file_write" if event.event == EVENT_FILE_WRITE else "file_open",
                        "message": f"Security alert: Server accessed confidential path '{event.target}' ({reason}) outside active tool call.",
                        "would_block": True,
                        "enforce": self.enforce,
                    },
                )
                violations.append(s_evt)

        return violations

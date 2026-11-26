"""Dynamic request attribution engine and runtime safety policy evaluator (Milestone 4).

Attributes low-level OS syscalls (file operations, network connects, subprocess executions)
to active in-flight MCP tool requests, evaluates declared safety hints (readOnlyHint,
openWorldHint, destructiveHint), and detects unauthorized sensitive credential access.
"""
from __future__ import annotations

import os
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

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
    events_truncated: bool = False
    dropped_events_count: int = 0


class AttributionEngine:
    """Correlates OS-layer syscall events to active JSON-RPC tool calls."""

    def __init__(
        self,
        server_id: str,
        server_lock: Optional[ServerLock] = None,
        enforce: bool = False,
        max_active_calls: int = 1000,
        stale_call_ttl: float = 300.0,
        max_events_per_call: int = 1000,
        max_total_buffered_events: int = 5000,
        max_total_buffered_bytes: int = 2 * 1024 * 1024,
        evicted_policy_ttl: float = 3600.0,
        max_evicted_policies: int = 64,
        gap_emit_interval_s: float = 5.0,
        on_event_fn: Optional[Callable[[BehavioralEvent], None]] = None,
    ):
        self.server_id = server_id
        self.server_lock = server_lock
        self.enforce = enforce
        self.max_active_calls = max(1, max_active_calls)
        self.stale_call_ttl = max(0.0, stale_call_ttl)
        self.max_events_per_call = max(1, max_events_per_call)
        self.max_total_buffered_events = max(1, max_total_buffered_events)
        self.max_total_buffered_bytes = max(256, max_total_buffered_bytes)
        self.evicted_policy_ttl = max(0.0, evicted_policy_ttl)
        self.max_evicted_policies = max(1, max_evicted_policies)
        self.gap_emit_interval_s = max(0.0, gap_emit_interval_s)
        self.on_event_fn = on_event_fn

        self._active_calls: Dict[Union[int, str], ToolCallContext] = {}
        self._lock = threading.Lock()
        self._total_buffered_events: int = 0
        self._total_buffered_bytes: int = 0
        self._ctx_buffered_bytes: Dict[Union[int, str], int] = {}
        self._evicted_read_only_tools: Dict[str, float] = {}
        self._evicted_closed_world_tools: Dict[str, float] = {}
        self._eviction_uncertainty_active: bool = False
        self._evicted_read_only_ever: bool = False
        self._evicted_closed_world_ever: bool = False
        self._evicted_policy_overflow: bool = False
        self._last_eviction_ts: Optional[float] = None
        self._unparseable_gap_active: bool = False
        self._last_gap_emit_ts: Dict[str, float] = {}
        self.evicted_stale_calls: int = 0
        self.evicted_overflow_calls: int = 0
        self.unparseable_protocol_messages: int = 0
        self.dropped_monitor_lines: int = 0
        self.dropped_observed_events: int = 0
        self.incomplete_attribution: bool = False

    @staticmethod
    def _estimate_event_bytes(event: BehavioralEvent) -> int:
        """Fast shallow byte estimate for a BehavioralEvent to bound memory usage."""
        size = 256 + len(event.target or "") + len(event.current_tool or "")
        for k, v in (event.payload or {}).items():
            size += len(str(k)) + len(str(v))
        return size

    def _release_context_accounting_locked(self, ctx: ToolCallContext) -> None:
        self._total_buffered_events = max(0, self._total_buffered_events - len(ctx.observed_events))
        ctx_bytes = self._ctx_buffered_bytes.pop(ctx.request_id, 0)
        self._total_buffered_bytes = max(0, self._total_buffered_bytes - ctx_bytes)

    def _track_evicted_policies_locked(self, ctx: ToolCallContext, now: float) -> None:
        self._last_eviction_ts = now
        self._eviction_uncertainty_active = True
        if ctx.annotations.get("readOnlyHint", False):
            self._evicted_read_only_ever = True
            if ctx.tool_name not in self._evicted_read_only_tools and len(self._evicted_read_only_tools) >= self.max_evicted_policies:
                oldest = next(iter(self._evicted_read_only_tools))
                self._evicted_read_only_tools.pop(oldest, None)
                self._evicted_policy_overflow = True
            self._evicted_read_only_tools.pop(ctx.tool_name, None)
            self._evicted_read_only_tools[ctx.tool_name] = now
        if not ctx.annotations.get("openWorldHint", True):
            self._evicted_closed_world_ever = True
            if ctx.tool_name not in self._evicted_closed_world_tools and len(self._evicted_closed_world_tools) >= self.max_evicted_policies:
                oldest = next(iter(self._evicted_closed_world_tools))
                self._evicted_closed_world_tools.pop(oldest, None)
                self._evicted_policy_overflow = True
            self._evicted_closed_world_tools.pop(ctx.tool_name, None)
            self._evicted_closed_world_tools[ctx.tool_name] = now

    def _prune_evicted_policies_locked(self, now: float) -> None:
        """Bound retained evicted-tool names after evicted_policy_ttl without clearing sticky uncertainty."""
        if self.evicted_policy_ttl <= 0.0:
            return
        for store in (self._evicted_read_only_tools, self._evicted_closed_world_tools):
            expired = [t for t, ts in store.items() if (now - ts) > self.evicted_policy_ttl]
            if expired:
                self._evicted_policy_overflow = True
            for t in expired:
                store.pop(t, None)

    def record_unparseable_message(self, direction: str, size_bytes: int, now: float) -> None:
        """Mark attribution incomplete when a protocol message cannot be parsed."""
        gap_evt: Optional[BehavioralEvent] = None
        with self._lock:
            self.unparseable_protocol_messages += 1
            self._unparseable_gap_active = True
            self.incomplete_attribution = True
            if self._should_emit_gap_locked("unparseable_protocol_message", now):
                gap_evt = self._build_incomplete_event(
                    "unparseable_protocol_message",
                    f"Unparseable {direction} protocol message ({size_bytes} bytes); attribution coverage is incomplete.",
                    timestamp=now,
                    extra={"direction": direction, "size_bytes": size_bytes},
                )
        if gap_evt and self.on_event_fn:
            self.on_event_fn(gap_evt)

    def record_queue_drop(self, direction: str, dropped_bytes: int = 0, now: Optional[float] = None) -> None:
        """Mark attribution incomplete when monitor queue overflow drops protocol lines."""
        ts = now if now is not None else time.time()
        gap_evt: Optional[BehavioralEvent] = None
        with self._lock:
            self.dropped_monitor_lines += 1
            self._unparseable_gap_active = True
            self.incomplete_attribution = True
            if self._should_emit_gap_locked("monitor_queue_drop", ts):
                gap_evt = self._build_incomplete_event(
                    "monitor_queue_drop",
                    f"Monitor queue dropped {direction} protocol line ({dropped_bytes} bytes); attribution coverage is incomplete.",
                    timestamp=ts,
                    extra={"direction": direction, "size_bytes": dropped_bytes},
                )
        if gap_evt and self.on_event_fn:
            self.on_event_fn(gap_evt)

    def on_protocol_resync(self, *, trusted_boundary: bool = False) -> bool:
        """Clear session uncertainty only at a demonstrably trustworthy lifecycle boundary with no active calls."""
        with self._lock:
            if not trusted_boundary or self._active_calls:
                return False
            self._unparseable_gap_active = False
            self._eviction_uncertainty_active = False
            self._evicted_read_only_ever = False
            self._evicted_closed_world_ever = False
            self._evicted_policy_overflow = False
            self._evicted_read_only_tools.clear()
            self._evicted_closed_world_tools.clear()
            self._last_eviction_ts = None
            return True

    def _should_emit_gap_locked(self, reason: str, now: float) -> bool:
        """Rate-limit attribution_incomplete notifications per reason to prevent telemetry amplification."""
        last_ts = self._last_gap_emit_ts.get(reason)
        if last_ts is not None and (now - last_ts) < self.gap_emit_interval_s:
            return False
        self._last_gap_emit_ts[reason] = now
        return True

    def _build_incomplete_event(
        self,
        reason: str,
        message: str,
        *,
        timestamp: float,
        request_id: Optional[Union[int, str]] = None,
        tool_name: Optional[str] = None,
        severity: str = SEVERITY_HIGH,
        extra: Optional[Dict[str, Any]] = None,
    ) -> BehavioralEvent:
        payload: Dict[str, Any] = {
            "category": "attribution_incomplete",
            "reason": reason,
            "message": message,
            "incomplete_attribution": True,
        }
        if tool_name:
            payload["tool"] = tool_name
        if extra:
            payload.update(extra)
        return BehavioralEvent(
            event="attribution_incomplete",
            session_id="",
            server_id=self.server_id,
            kind="attribution_gap",
            source="monitor",
            evidence_tier=EVIDENCE_TIER_OBSERVED,
            severity=severity,
            current_tool=tool_name,
            request_id=request_id,
            timestamp=timestamp,
            payload=payload,
        )

    def _prune_stale_locked(self, now: float) -> List[BehavioralEvent]:
        """Evict stale in-flight tool calls that exceeded stale_call_ttl (caller holds _lock)."""
        if self.stale_call_ttl <= 0.0 or not self._active_calls:
            return []
        stale_keys = [
            rid for rid, ctx in self._active_calls.items()
            if (now - ctx.start_ts) > self.stale_call_ttl
        ]
        if not stale_keys:
            return []
        last_ctx: Optional[ToolCallContext] = None
        evicted_count = 0
        for rid in stale_keys:
            ctx = self._active_calls.pop(rid, None)
            if ctx is None:
                continue
            self._release_context_accounting_locked(ctx)
            self._track_evicted_policies_locked(ctx, now)
            self.evicted_stale_calls += 1
            self.incomplete_attribution = True
            evicted_count += 1
            last_ctx = ctx

        if evicted_count == 0 or last_ctx is None:
            return []
        if not self._should_emit_gap_locked("stale_call_evicted", now):
            return []
        return [
            self._build_incomplete_event(
                "stale_call_evicted",
                f"Evicted {evicted_count} stale tool call(s) exceeding TTL ({self.stale_call_ttl}s) without completion; attribution is incomplete.",
                timestamp=now,
                request_id=last_ctx.request_id,
                tool_name=last_ctx.tool_name,
                extra={"evicted_count": evicted_count, "age_s": round(now - last_ctx.start_ts, 3)},
            )
        ]

    def get_attribution_health(self) -> Dict[str, Any]:
        """Return bounded-state and attribution completeness metrics."""
        with self._lock:
            return {
                "incomplete_attribution": self.incomplete_attribution,
                "active_calls": len(self._active_calls),
                "total_buffered_events": self._total_buffered_events,
                "total_buffered_bytes": self._total_buffered_bytes,
                "evicted_stale_calls": self.evicted_stale_calls,
                "evicted_overflow_calls": self.evicted_overflow_calls,
                "unparseable_protocol_messages": self.unparseable_protocol_messages,
                "dropped_observed_events": self.dropped_observed_events,
            }

    def on_tool_call_start(
        self,
        request_id: Union[int, str],
        tool_name: str,
        start_ts: float,
        annotations: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Register the start of an in-flight tool call."""
        eff_ann: Dict[str, bool] = {}
        if self.server_lock:
            tool_lock = self.server_lock.get_tool(tool_name)
            if tool_lock and tool_lock.annotations:
                eff_ann = dict(tool_lock.annotations)

        if not eff_ann and annotations:
            eff_ann = compute_effective_annotations(annotations)
        elif not eff_ann:
            eff_ann = compute_effective_annotations({})

        gap_events: List[BehavioralEvent] = []
        with self._lock:
            gap_events.extend(self._prune_stale_locked(start_ts))
            if request_id in self._active_calls:
                prev = self._active_calls.pop(request_id)
                self._release_context_accounting_locked(prev)
                self._track_evicted_policies_locked(prev, start_ts)
                self.evicted_overflow_calls += 1
                self.incomplete_attribution = True
                if self._should_emit_gap_locked("reused_active_request_id", start_ts):
                    gap_events.append(
                        self._build_incomplete_event(
                            "reused_active_request_id",
                            f"Active request ID {request_id!r} reused while '{prev.tool_name}' was still in flight; attribution is incomplete.",
                            timestamp=start_ts,
                            request_id=request_id,
                            tool_name=prev.tool_name,
                        )
                    )
            elif len(self._active_calls) >= self.max_active_calls:
                oldest_id = next(iter(self._active_calls))
                evicted = self._active_calls.pop(oldest_id)
                self._release_context_accounting_locked(evicted)
                self._track_evicted_policies_locked(evicted, start_ts)
                self.evicted_overflow_calls += 1
                self.incomplete_attribution = True
                if self._should_emit_gap_locked("active_call_limit_exceeded", start_ts):
                    gap_events.append(
                        self._build_incomplete_event(
                            "active_call_limit_exceeded",
                            f"Active call limit ({self.max_active_calls}) reached; evicted oldest call '{evicted.tool_name}' (id={oldest_id}); attribution is incomplete.",
                            timestamp=start_ts,
                            request_id=oldest_id,
                            tool_name=evicted.tool_name,
                        )
                    )
            self._active_calls[request_id] = ToolCallContext(
                request_id=request_id,
                tool_name=tool_name,
                start_ts=start_ts,
                annotations=eff_ann,
            )

        if self.on_event_fn and gap_events:
            for ge in gap_events:
                self.on_event_fn(ge)

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
                self._release_context_accounting_locked(ctx)
            return ctx

    def get_active_contexts(self) -> List[ToolCallContext]:
        """Return snapshot of active in-flight tool contexts."""
        with self._lock:
            return list(self._active_calls.values())

    def _record_context_event_locked(
        self,
        ctx: ToolCallContext,
        event: BehavioralEvent,
        now: float,
    ) -> Optional[BehavioralEvent]:
        """Append event to ctx.observed_events within per-call, global count, and global byte bounds."""
        est_bytes = self._estimate_event_bytes(event)
        if (
            self._total_buffered_events >= self.max_total_buffered_events
            or (self._total_buffered_bytes + est_bytes) > self.max_total_buffered_bytes
        ):
            ctx.dropped_events_count += 1
            self.dropped_observed_events += 1
            self.incomplete_attribution = True
            event.payload["attribution_incomplete"] = True
            if not ctx.events_truncated:
                ctx.events_truncated = True
            if self._should_emit_gap_locked("global_event_buffer_limit_exceeded", now):
                return self._build_incomplete_event(
                    "global_event_buffer_limit_exceeded",
                    f"Global attribution event buffer limit ({self.max_total_buffered_events} events / {self.max_total_buffered_bytes} bytes) reached; further per-call event buffering truncated.",
                    timestamp=now,
                    request_id=ctx.request_id,
                    tool_name=ctx.tool_name,
                    severity=SEVERITY_MEDIUM,
                )
            return None

        if len(ctx.observed_events) < self.max_events_per_call:
            ctx.observed_events.append(event)
            self._total_buffered_events += 1
            self._total_buffered_bytes += est_bytes
            self._ctx_buffered_bytes[ctx.request_id] = self._ctx_buffered_bytes.get(ctx.request_id, 0) + est_bytes
            return None
        ctx.dropped_events_count += 1
        self.dropped_observed_events += 1
        self.incomplete_attribution = True
        event.payload["attribution_incomplete"] = True
        if not ctx.events_truncated:
            ctx.events_truncated = True
            if self._should_emit_gap_locked("per_call_event_limit_exceeded", now):
                return self._build_incomplete_event(
                    "per_call_event_limit_exceeded",
                    f"Tool call '{ctx.tool_name}' (id={ctx.request_id}) exceeded max_events_per_call ({self.max_events_per_call}); further per-call event buffering truncated.",
                    timestamp=now,
                    request_id=ctx.request_id,
                    tool_name=ctx.tool_name,
                    severity=SEVERITY_MEDIUM,
                )
        return None

    def attribute_os_event(self, event: BehavioralEvent) -> Tuple[BehavioralEvent, List[BehavioralEvent]]:
        """Attribute an incoming OS syscall event and evaluate policy violations.

        Returns:
            (attributed_event, list_of_policy_violation_events)
        """
        violations: List[BehavioralEvent] = []
        now = event.timestamp or time.time()
        with self._lock:
            violations.extend(self._prune_stale_locked(now))
            self._prune_evicted_policies_locked(now)
            active = list(self._active_calls.values())
            prior_evictions = self.evicted_stale_calls + self.evicted_overflow_calls
            has_eviction_uncertainty = (
                self._eviction_uncertainty_active
                or self._last_eviction_ts is not None
                or bool(self._evicted_read_only_tools)
                or bool(self._evicted_closed_world_tools)
            )
            degraded = has_eviction_uncertainty or self._unparseable_gap_active

            event.server_id = self.server_id

            # 1. Single tool in flight -> Observed unless eviction or protocol-gap uncertainty exists
            if len(active) == 1:
                ctx = active[0]
                event.current_tool = ctx.tool_name
                event.request_id = ctx.request_id
                if degraded:
                    event.evidence_tier = EVIDENCE_TIER_CORRELATED
                    event.payload["attribution_incomplete"] = True
                    if has_eviction_uncertainty:
                        event.payload["evicted_calls_active_risk"] = prior_evictions
                    if self._unparseable_gap_active:
                        event.payload["unparseable_protocol_messages"] = self.unparseable_protocol_messages
                else:
                    event.evidence_tier = EVIDENCE_TIER_OBSERVED
                event.payload["current_tool"] = ctx.tool_name
                event.payload["request_id"] = ctx.request_id
                trunc_evt = self._record_context_event_locked(ctx, event, now)
                if trunc_evt:
                    violations.append(trunc_evt)

                tool_violations = self._evaluate_tool_policies(
                    ctx,
                    event,
                    is_correlated=degraded,
                    attribution_incomplete=degraded,
                )
                violations.extend(tool_violations)

            # 2. Concurrent tools in flight -> Ambiguous attribution (correlated)
            elif len(active) > 1:
                event.current_tool = active[0].tool_name
                event.evidence_tier = EVIDENCE_TIER_CORRELATED
                event.payload["ambiguous"] = True
                event.payload["candidate_tools"] = [c.tool_name for c in active]
                if degraded:
                    event.payload["attribution_incomplete"] = True
                    if has_eviction_uncertainty:
                        event.payload["evicted_calls_active_risk"] = prior_evictions
                    if self._unparseable_gap_active:
                        event.payload["unparseable_protocol_messages"] = self.unparseable_protocol_messages

                for c in active:
                    trunc_evt = self._record_context_event_locked(c, event, now)
                    if trunc_evt:
                        violations.append(trunc_evt)
                    tool_violations = self._evaluate_tool_policies(
                        c,
                        event,
                        is_correlated=True,
                        attribution_incomplete=degraded,
                    )
                    violations.extend(tool_violations)

            # 3. No tools in flight -> Lifecycle / background activity (downgrade if degraded)
            else:
                event.current_tool = None
                event.request_id = None
                if degraded:
                    event.evidence_tier = EVIDENCE_TIER_CORRELATED
                    event.payload["attribution_incomplete"] = True
                    if has_eviction_uncertainty:
                        event.payload["evicted_calls_active_risk"] = prior_evictions
                    if self._unparseable_gap_active:
                        event.payload["unparseable_protocol_messages"] = self.unparseable_protocol_messages
                else:
                    event.evidence_tier = EVIDENCE_TIER_OBSERVED
                event.payload["scope"] = "lifecycle"

                bg_violations = self._evaluate_background_policies(
                    event,
                    is_correlated=degraded,
                    attribution_incomplete=degraded,
                )
                violations.extend(bg_violations)

            # Evaluate retained evicted-call policies across ALL active-call counts (0, 1, or >1),
            # preserving evicted candidate awareness even when an active call already triggered the category.
            if has_eviction_uncertainty:
                has_ro = any(v.payload.get("category") == "read_only_violation" for v in violations)
                has_ow = any(v.payload.get("category") == "open_world_violation" for v in violations)
                if has_ro and (self._evicted_read_only_tools or self._evicted_read_only_ever):
                    ro_cands = list(self._evicted_read_only_tools.keys())
                    for v in violations:
                        if v.payload.get("category") == "read_only_violation":
                            existing = list(v.payload.get("candidate_tools") or [])
                            for t in ro_cands:
                                if t not in existing:
                                    existing.append(t)
                            if existing:
                                v.payload["candidate_tools"] = existing
                            if self._evicted_policy_overflow:
                                v.payload["evicted_policy_overflow"] = True
                if has_ow and (self._evicted_closed_world_tools or self._evicted_closed_world_ever):
                    ow_cands = list(self._evicted_closed_world_tools.keys())
                    for v in violations:
                        if v.payload.get("category") == "open_world_violation":
                            existing = list(v.payload.get("candidate_tools") or [])
                            for t in ow_cands:
                                if t not in existing:
                                    existing.append(t)
                            if existing:
                                v.payload["candidate_tools"] = existing
                            if self._evicted_policy_overflow:
                                v.payload["evicted_policy_overflow"] = True
                violations.extend(
                    self._evaluate_evicted_tool_policies_locked(
                        event,
                        active_tools=[c.tool_name for c in active],
                        skip_read_only=has_ro,
                        skip_open_world=has_ow,
                    )
                )

        return event, violations

    def _evaluate_tool_policies(
        self,
        ctx: ToolCallContext,
        event: BehavioralEvent,
        is_correlated: bool = False,
        attribution_incomplete: bool = False,
    ) -> List[BehavioralEvent]:
        """Evaluate declared safety annotations against observed tool action."""
        violations: List[BehavioralEvent] = []
        tier = EVIDENCE_TIER_CORRELATED if is_correlated else EVIDENCE_TIER_OBSERVED
        ann = ctx.annotations

        # Policy 1: readOnlyHint violation
        # readOnlyHint=True prohibits file writes and file modifications
        if ann.get("readOnlyHint", False) and event.event == EVENT_FILE_WRITE:
            if is_correlated or attribution_incomplete:
                msg = (
                    f"Possible policy violation: file write to '{event.target}' occurred while "
                    f"readOnlyHint=True tool '{ctx.tool_name}' was active "
                    "(correlated attribution; may involve other concurrent or unobserved calls)."
                )
            else:
                msg = f"Tool '{ctx.tool_name}' declared readOnlyHint=True but performed file write to '{event.target}'."
            payload = {
                "category": "read_only_violation",
                "tool": ctx.tool_name,
                "target": event.target,
                "declared_read_only": True,
                "action": "file_write",
                "message": msg,
                "would_block": True,
                "enforce": self.enforce,
            }
            if attribution_incomplete:
                payload["attribution_incomplete"] = True
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
                payload=payload,
            )
            violations.append(v_evt)

        # Policy 2: openWorldHint violation
        # openWorldHint=False prohibits outbound non-loopback network egress
        if not ann.get("openWorldHint", True) and event.event == EVENT_NETWORK_CONNECT:
            if not is_loopback_address(event.destination_ip):
                if is_correlated or attribution_incomplete:
                    msg = (
                        f"Possible policy violation: outbound network connect to "
                        f"'{event.destination_ip}:{event.destination_port}' occurred while "
                        f"openWorldHint=False tool '{ctx.tool_name}' was active "
                        "(correlated attribution; may involve other concurrent or unobserved calls)."
                    )
                else:
                    msg = f"Tool '{ctx.tool_name}' declared openWorldHint=False but connected to external host '{event.destination_ip}:{event.destination_port}'."
                payload = {
                    "category": "open_world_violation",
                    "tool": ctx.tool_name,
                    "destination_ip": event.destination_ip,
                    "destination_port": event.destination_port,
                    "declared_open_world": False,
                    "action": "network_connect",
                    "message": msg,
                    "would_block": True,
                    "enforce": self.enforce,
                }
                if attribution_incomplete:
                    payload["attribution_incomplete"] = True
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
                    payload=payload,
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
                if is_correlated or attribution_incomplete:
                    sens_msg = (
                        f"Security alert (correlated attribution): confidential path '{event.target}' ({reason}) "
                        f"was accessed while tool '{ctx.tool_name}' was active; attribution is uncertain."
                    )
                else:
                    sens_msg = f"Security alert: Tool '{ctx.tool_name}' accessed confidential path '{event.target}' ({reason})."
                payload = {
                    "category": "sensitive_path_access",
                    "tool": ctx.tool_name,
                    "path": event.target,
                    "sensitive_target": reason,
                    "action": "file_write" if event.event == EVENT_FILE_WRITE else "file_open",
                    "message": sens_msg,
                    "would_block": True,
                    "enforce": self.enforce,
                }
                if attribution_incomplete:
                    payload["attribution_incomplete"] = True
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
                    payload=payload,
                )
                violations.append(s_evt)

        return violations

    def _evaluate_evicted_tool_policies_locked(
        self,
        event: BehavioralEvent,
        *,
        active_tools: Optional[List[str]] = None,
        skip_read_only: bool = False,
        skip_open_world: bool = False,
    ) -> List[BehavioralEvent]:
        """Propagate safety-hint policy checks from evicted uncompleted calls across any active-call count."""
        violations: List[BehavioralEvent] = []
        if not skip_read_only and event.event == EVENT_FILE_WRITE and (self._evicted_read_only_tools or self._evicted_read_only_ever):
            tools = list(self._evicted_read_only_tools.keys())
            payload: Dict[str, Any] = {
                "category": "read_only_violation",
                "candidate_tools": tools,
                "target": event.target,
                "declared_read_only": True,
                "action": "file_write",
                "attribution_incomplete": True,
                "message": f"File write to '{event.target}' occurred while uncompleted readOnlyHint=True tool(s) {tools or ['<evicted>']} were evicted.",
                "would_block": True,
                "enforce": self.enforce,
            }
            if self._evicted_policy_overflow:
                payload["evicted_policy_overflow"] = True
            if active_tools:
                payload["active_tools"] = list(active_tools)
            violations.append(
                BehavioralEvent(
                    event="policy_violation",
                    session_id=event.session_id,
                    server_id=self.server_id,
                    kind="policy_violation",
                    source="monitor",
                    evidence_tier=EVIDENCE_TIER_CORRELATED,
                    severity=SEVERITY_HIGH,
                    current_tool=None,
                    request_id=None,
                    target=event.target,
                    timestamp=event.timestamp,
                    payload=payload,
                )
            )
        if not skip_open_world and event.event == EVENT_NETWORK_CONNECT and (self._evicted_closed_world_tools or self._evicted_closed_world_ever):
            if not is_loopback_address(event.destination_ip):
                tools = list(self._evicted_closed_world_tools.keys())
                payload = {
                    "category": "open_world_violation",
                    "candidate_tools": tools,
                    "destination_ip": event.destination_ip,
                    "destination_port": event.destination_port,
                    "declared_open_world": False,
                    "action": "network_connect",
                    "attribution_incomplete": True,
                    "message": f"Outbound network connect to '{event.destination_ip}:{event.destination_port}' occurred while uncompleted openWorldHint=False tool(s) {tools or ['<evicted>']} were evicted.",
                    "would_block": True,
                    "enforce": self.enforce,
                }
                if self._evicted_policy_overflow:
                    payload["evicted_policy_overflow"] = True
                if active_tools:
                    payload["active_tools"] = list(active_tools)
                violations.append(
                    BehavioralEvent(
                        event="policy_violation",
                        session_id=event.session_id,
                        server_id=self.server_id,
                        kind="policy_violation",
                        source="monitor",
                        evidence_tier=EVIDENCE_TIER_CORRELATED,
                        severity=SEVERITY_HIGH,
                        current_tool=None,
                        request_id=None,
                        target=f"{event.destination_ip}:{event.destination_port}",
                        timestamp=event.timestamp,
                        payload=payload,
                    )
                )
        return violations

    def _evaluate_background_policies(
        self,
        event: BehavioralEvent,
        is_correlated: bool = False,
        attribution_incomplete: bool = False,
    ) -> List[BehavioralEvent]:
        """Evaluate policies for actions occurring outside tool execution."""
        violations: List[BehavioralEvent] = []
        tier = EVIDENCE_TIER_CORRELATED if is_correlated else EVIDENCE_TIER_OBSERVED

        # Sensitive credential theft during background/startup
        if event.target and event.event in (EVENT_FILE_OPEN, EVENT_FILE_WRITE):
            is_sens, reason = is_sensitive_path(event.target)
            if is_sens:
                target_lower = (event.target or "").lower()
                is_crit = any(k in target_lower or k in reason.lower() for k in ("id_rsa", "id_ed25519", "id_ecdsa", "id_dsa", "shadow", "master.passwd"))
                sev = SEVERITY_CRITICAL if is_crit else SEVERITY_HIGH
                if is_correlated or attribution_incomplete:
                    bg_msg = (
                        f"Security alert (correlated attribution): confidential path '{event.target}' ({reason}) "
                        "was accessed; no active tool call could be reliably identified and unobserved activity may exist."
                    )
                else:
                    bg_msg = f"Security alert: Server accessed confidential path '{event.target}' ({reason}) outside active tool call."
                payload = {
                    "category": "background_sensitive_path_access",
                    "path": event.target,
                    "sensitive_target": reason,
                    "action": "file_write" if event.event == EVENT_FILE_WRITE else "file_open",
                    "message": bg_msg,
                    "would_block": True,
                    "enforce": self.enforce,
                }
                if attribution_incomplete:
                    payload["attribution_incomplete"] = True
                s_evt = BehavioralEvent(
                    event="secret_exposure",
                    session_id=event.session_id,
                    server_id=self.server_id,
                    kind="secret_exposure",
                    source="monitor",
                    evidence_tier=tier,
                    severity=sev,
                    current_tool=None,
                    target=event.target,
                    timestamp=event.timestamp,
                    payload=payload,
                )
                violations.append(s_evt)

        return violations

"""Trust-On-First-Use (TOFU) manifest pinning, drift detection, and active re-verification.

Enforces in-session baseline integrity, detects announced and covert tool/prompt/resource drift,
classifies annotation relaxation and schema widening, performs synthetic non-fingerprintable
active re-verification, and persists cross-session history in SQLite.
"""
from __future__ import annotations

import asyncio
import copy
import random
import time
import uuid
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set, Tuple

from .events import (
    BehavioralEvent,
    DRIFT_ANNOTATION_RELAXATION,
    DRIFT_ANNOUNCED_ADDITION,
    DRIFT_CAPABILITY_EXPANSION,
    DRIFT_CONSTRAINT_RELAXATION,
    DRIFT_COVERT_ADDITION,
    DRIFT_DESCRIPTION_INJECTION,
    DRIFT_DESCRIPTION_MUTATION,
    DRIFT_INSTRUCTIONS_INJECTION,
    DRIFT_INSTRUCTIONS_MUTATION,
    DRIFT_REMOVAL_OR_RENAME,
    DRIFT_TRUSTED_TOOL_ESCALATION,
    EVIDENCE_TIER_CORRELATED,
    EVIDENCE_TIER_OBSERVED,
    KIND_CROSS_SESSION_DRIFT,
    KIND_LOCKFILE_DRIFT,
    KIND_MANIFEST_BASELINE,
    KIND_MANIFEST_DRIFT,
    KIND_PACKAGE_DRIFT,
    KIND_PACKAGE_TAMPER,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_INFO,
    SEVERITY_MEDIUM,
)
from .heuristics import check_prompt_injection
from .identity import check_package_tamper
from .lockfile import ServerLock, diff_against_lockfile


def get_effective_annotations(tool: Dict[str, Any]) -> Dict[str, bool]:
    """Calculate effective tool safety annotations using MCP specification defaults when absent.

    Spec defaults:
    - readOnlyHint: False
    - destructiveHint: True
    - idempotentHint: False
    - openWorldHint: True
    """
    raw = tool.get("annotations") or {}
    return {
        "readOnlyHint": bool(raw.get("readOnlyHint", tool.get("readOnlyHint", False))),
        "destructiveHint": bool(raw.get("destructiveHint", tool.get("destructiveHint", True))),
        "idempotentHint": bool(raw.get("idempotentHint", tool.get("idempotentHint", False))),
        "openWorldHint": bool(raw.get("openWorldHint", tool.get("openWorldHint", True))),
    }


def diff_annotations(old_ann: Dict[str, bool], new_ann: Dict[str, bool]) -> List[Dict[str, Any]]:
    """Compare annotations in both directions against effective defaults."""
    findings = []

    # 1. annotation_relaxation (claims got safer):
    # readOnly: False -> True
    if not old_ann["readOnlyHint"] and new_ann["readOnlyHint"]:
        findings.append({
            "category": DRIFT_ANNOTATION_RELAXATION,
            "annotation": "readOnlyHint",
            "old": False,
            "new": True,
            "message": "Tool annotation claimed safer: readOnlyHint relaxed from false to true",
            "severity": SEVERITY_HIGH,
            "would_block": True,
        })
    # destructive: True -> False
    if old_ann["destructiveHint"] and not new_ann["destructiveHint"]:
        findings.append({
            "category": DRIFT_ANNOTATION_RELAXATION,
            "annotation": "destructiveHint",
            "old": True,
            "new": False,
            "message": "Tool annotation claimed safer: destructiveHint relaxed from true to false",
            "severity": SEVERITY_HIGH,
            "would_block": True,
        })
    # openWorld: True -> False
    if old_ann["openWorldHint"] and not new_ann["openWorldHint"]:
        findings.append({
            "category": DRIFT_ANNOTATION_RELAXATION,
            "annotation": "openWorldHint",
            "old": True,
            "new": False,
            "message": "Tool annotation claimed safer: openWorldHint relaxed from true to false",
            "severity": SEVERITY_HIGH,
            "would_block": True,
        })
    # idempotent: False -> True
    if not old_ann["idempotentHint"] and new_ann["idempotentHint"]:
        findings.append({
            "category": DRIFT_ANNOTATION_RELAXATION,
            "annotation": "idempotentHint",
            "old": False,
            "new": True,
            "message": "Tool annotation claimed safer: idempotentHint relaxed from false to true",
            "severity": SEVERITY_HIGH,
            "would_block": True,
        })

    # 2. trusted_tool_escalation (claims got riskier on an established baseline tool):
    # readOnly: True -> False
    if old_ann["readOnlyHint"] and not new_ann["readOnlyHint"]:
        findings.append({
            "category": DRIFT_TRUSTED_TOOL_ESCALATION,
            "annotation": "readOnlyHint",
            "old": True,
            "new": False,
            "message": "Baseline tool escalated risk: readOnlyHint changed from true to false",
            "severity": SEVERITY_HIGH,
            "would_block": True,
        })
    # destructive: False -> True
    if not old_ann["destructiveHint"] and new_ann["destructiveHint"]:
        findings.append({
            "category": DRIFT_TRUSTED_TOOL_ESCALATION,
            "annotation": "destructiveHint",
            "old": False,
            "new": True,
            "message": "Baseline tool escalated risk: destructiveHint changed from false to true",
            "severity": SEVERITY_HIGH,
            "would_block": True,
        })

    return findings


def diff_schemas(old_schema: Dict[str, Any], new_schema: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Compare inputSchema for capability_expansion and constraint_relaxation."""
    findings = []
    old_props = old_schema.get("properties") or {}
    new_props = new_schema.get("properties") or {}
    old_req = set(old_schema.get("required") or [])
    new_req = set(new_schema.get("required") or [])

    # 1. Check capability expansion (new parameters added, widened types, additionalProperties)
    old_add_props = old_schema.get("additionalProperties")
    new_add_props = new_schema.get("additionalProperties")
    if old_add_props is False and new_add_props is not False:
        findings.append({
            "category": DRIFT_CAPABILITY_EXPANSION,
            "property": "additionalProperties",
            "message": "Schema capability expansion: additionalProperties relaxed from false to true",
            "severity": SEVERITY_HIGH,
            "would_block": True,
        })

    for prop_name, new_def in new_props.items():
        if prop_name not in old_props:
            findings.append({
                "category": DRIFT_CAPABILITY_EXPANSION,
                "property": prop_name,
                "message": f"Schema capability expansion: new property '{prop_name}' declared",
                "severity": SEVERITY_HIGH,
                "would_block": True,
            })
        else:
            old_def = old_props[prop_name]
            old_type = old_def.get("type")
            new_type = new_def.get("type")
            if old_type != new_type and new_type is not None:
                findings.append({
                    "category": DRIFT_CAPABILITY_EXPANSION,
                    "property": prop_name,
                    "old_type": old_type,
                    "new_type": new_type,
                    "message": f"Schema capability expansion: property '{prop_name}' type widened from {old_type} to {new_type}",
                    "severity": SEVERITY_HIGH,
                    "would_block": True,
                })

    # 2. Check constraint relaxation (enums removed/expanded, pattern/maxLength removed, required dropped)
    # Required fields dropped
    dropped_req = old_req - new_req
    for dr in dropped_req:
        findings.append({
            "category": DRIFT_CONSTRAINT_RELAXATION,
            "property": dr,
            "message": f"Schema constraint relaxation: previously required parameter '{dr}' is no longer required",
            "severity": SEVERITY_HIGH,
            "would_block": True,
        })

    # Property-level constraint relaxation
    for prop_name, old_def in old_props.items():
        if prop_name in new_props:
            new_def = new_props[prop_name]

            # Enum removal or expansion
            if "enum" in old_def:
                if "enum" not in new_def:
                    findings.append({
                        "category": DRIFT_CONSTRAINT_RELAXATION,
                        "property": prop_name,
                        "message": f"Schema constraint relaxation: enum restriction removed on '{prop_name}'",
                        "severity": SEVERITY_HIGH,
                        "would_block": True,
                    })
                else:
                    added_enums = set(new_def["enum"]) - set(old_def["enum"])
                    if added_enums:
                        findings.append({
                            "category": DRIFT_CONSTRAINT_RELAXATION,
                            "property": prop_name,
                            "added_enums": list(added_enums),
                            "message": f"Schema constraint relaxation: enum on '{prop_name}' widened with {list(added_enums)}",
                            "severity": SEVERITY_HIGH,
                            "would_block": True,
                        })

            # Pattern removal
            if "pattern" in old_def and "pattern" not in new_def:
                findings.append({
                    "category": DRIFT_CONSTRAINT_RELAXATION,
                    "property": prop_name,
                    "message": f"Schema constraint relaxation: regex pattern constraint removed on '{prop_name}'",
                    "severity": SEVERITY_HIGH,
                    "would_block": True,
                })

            # maxLength removal or loosening
            if "maxLength" in old_def:
                if "maxLength" not in new_def or new_def["maxLength"] > old_def["maxLength"]:
                    findings.append({
                        "category": DRIFT_CONSTRAINT_RELAXATION,
                        "property": prop_name,
                        "old_maxLength": old_def["maxLength"],
                        "new_maxLength": new_def.get("maxLength"),
                        "message": f"Schema constraint relaxation: maxLength loosened on '{prop_name}'",
                        "severity": SEVERITY_HIGH,
                        "would_block": True,
                    })

            # minimum removal or lowering
            if "minimum" in old_def:
                if "minimum" not in new_def or new_def["minimum"] < old_def["minimum"]:
                    findings.append({
                        "category": DRIFT_CONSTRAINT_RELAXATION,
                        "property": prop_name,
                        "old_minimum": old_def["minimum"],
                        "new_minimum": new_def.get("minimum"),
                        "message": f"Schema constraint relaxation: minimum loosened on '{prop_name}'",
                        "severity": SEVERITY_HIGH,
                        "would_block": True,
                    })

            # maximum removal or raising
            if "maximum" in old_def:
                if "maximum" not in new_def or new_def["maximum"] > old_def["maximum"]:
                    findings.append({
                        "category": DRIFT_CONSTRAINT_RELAXATION,
                        "property": prop_name,
                        "old_maximum": old_def["maximum"],
                        "new_maximum": new_def.get("maximum"),
                        "message": f"Schema constraint relaxation: maximum loosened on '{prop_name}'",
                        "severity": SEVERITY_HIGH,
                        "would_block": True,
                    })

            # format removal or change
            if "format" in old_def:
                if "format" not in new_def or new_def["format"] != old_def["format"]:
                    findings.append({
                        "category": DRIFT_CONSTRAINT_RELAXATION,
                        "property": prop_name,
                        "old_format": old_def["format"],
                        "new_format": new_def.get("format"),
                        "message": f"Schema constraint relaxation: format constraint '{old_def['format']}' removed or modified on '{prop_name}'",
                        "severity": SEVERITY_HIGH,
                        "would_block": True,
                    })

    return findings


class ManifestTracker:
    """Tracks session TOFU manifest, handles pagination, compares diffs, and coordinates active re-verification."""

    def __init__(
        self,
        session_id: str,
        server_id: str,
        send_probe_fn: Optional[Callable[[bytes], Coroutine[Any, Any, None]]] = None,
        reverify_interval: int = 20,
        reverify_period: float = 300.0,
        enable_reverify: bool = True,
        min_probe_interval: float = 10.0,
        pagination_timeout: float = 30.0,
        loop: Optional[asyncio.AbstractEventLoop] = None,
        on_event_fn: Optional[Callable[[BehavioralEvent], None]] = None,
        get_active_ids_fn: Optional[Callable[[], List[Any]]] = None,
        server_lock: Optional[ServerLock] = None,
        enforce: bool = False,
        live_identity: Optional[Dict[str, Any]] = None,
    ):
        self.session_id = session_id
        self.server_id = server_id
        self.send_probe_fn = send_probe_fn
        self.reverify_interval = reverify_interval
        self.reverify_period = reverify_period
        self.enable_reverify = enable_reverify and (send_probe_fn is not None)
        self.min_probe_interval = min_probe_interval
        self.pagination_timeout = pagination_timeout
        self.on_event_fn = on_event_fn
        self.get_active_ids_fn = get_active_ids_fn
        self.server_lock = server_lock
        self.enforce = enforce
        self.live_identity = live_identity

        if loop is not None:
            self.loop = loop
        else:
            try:
                self.loop = asyncio.get_running_loop()
            except RuntimeError:
                self.loop = None

        # Session baseline storage
        self.server_info: Dict[str, Any] = {}
        self.instructions: Optional[str] = None
        self.capabilities: Dict[str, Any] = {}
        self.tools_baseline: Optional[Dict[str, Dict[str, Any]]] = None
        self.resources_baseline: Optional[Dict[str, Dict[str, Any]]] = None
        self.prompts_baseline: Optional[Dict[str, Dict[str, Any]]] = None

        # Tracking state
        self.initialized = False
        self.client_initialized = False
        self.has_high_drift = False
        self._list_changed_announced: Set[str] = set()

        # In-flight pagination aggregation
        self._client_pending_tools: List[Dict[str, Any]] = []
        self._client_pagination_timer: Optional[asyncio.TimerHandle] = None

        # Active re-verification state with 600s probe expiry retention
        self._issued_probe_ids: Dict[Any, float] = {}  # probe_id -> issued timestamp
        self._probe_expiry: float = 600.0
        self._probe_in_flight = False
        self._last_probe_time: float = 0.0
        self._tool_calls_since_last_probe: int = 0
        self._seen_tools: Set[str] = set()
        self._periodic_task: Optional[asyncio.Task] = None
        self._probe_pagination_tools: List[Dict[str, Any]] = []
        self._client_uses_int_ids: Optional[bool] = None
        self._client_uses_uuid: Optional[bool] = None

    def _schedule_coroutine(self, coro: Coroutine[Any, Any, Any]) -> Optional[Any]:
        """Safely schedule a coroutine on the event loop from any thread context."""
        if not self.loop or not self.loop.is_running():
            try:
                running = asyncio.get_running_loop()
                return running.create_task(coro)
            except RuntimeError:
                return None
        try:
            running = asyncio.get_running_loop()
            if running is self.loop:
                return self.loop.create_task(coro)
        except RuntimeError:
            pass
        return asyncio.run_coroutine_threadsafe(coro, self.loop)

    def mark_client_initialized(self) -> None:
        """Mark client's notifications/initialized received; probes only start after this."""
        self.client_initialized = True
        self.start_periodic_reverify()

    def start_periodic_reverify(self) -> None:
        """Start periodic timer loop with jitter if reverify is enabled and client initialized."""
        if not self.enable_reverify or not self.client_initialized or self._periodic_task is not None:
            return

        async def _timer_loop():
            while True:
                # Add +/- 10% jitter to period
                jittered_period = self.reverify_period * (0.9 + random.random() * 0.2)
                try:
                    await asyncio.sleep(jittered_period)
                    await self.trigger_reverify(source="periodic_timer")
                except asyncio.CancelledError:
                    break
                except Exception:
                    pass

        self._periodic_task = self._schedule_coroutine(_timer_loop())

    def stop(self) -> None:
        """Cancel periodic timer and in-flight handles."""
        if self._periodic_task:
            try:
                self._periodic_task.cancel()
            except Exception:
                pass
            self._periodic_task = None
        if self._client_pagination_timer:
            try:
                self._client_pagination_timer.cancel()
            except Exception:
                pass
            self._client_pagination_timer = None

    def record_client_id_style(self, req_id: Any) -> None:
        """Observe client's JSON-RPC ID style to mimic it during synthetic probes."""
        if req_id is not None and self._client_uses_int_ids is None:
            if isinstance(req_id, int):
                self._client_uses_int_ids = True
            elif isinstance(req_id, str):
                self._client_uses_int_ids = False
                import uuid
                try:
                    uuid.UUID(req_id)
                    self._client_uses_uuid = True
                except (ValueError, AttributeError):
                    self._client_uses_uuid = False

    def generate_probe_id(self, exclude_ids: Optional[Set[Any]] = None) -> Any:
        """Generate synthetic probe ID mimicking client format while avoiding collisions."""
        now = time.time()
        # Purge expired probe IDs
        expired = [pid for pid, ts in self._issued_probe_ids.items() if (now - ts) > self._probe_expiry]
        for pid in expired:
            self._issued_probe_ids.pop(pid, None)

        excluded = set(self._issued_probe_ids.keys())
        if exclude_ids:
            excluded |= set(exclude_ids)
        if self.get_active_ids_fn:
            try:
                excluded |= set(self.get_active_ids_fn())
            except Exception:
                pass

        if self._client_uses_int_ids is not False:
            # Client uses ints or unknown: generate random int in high range
            while True:
                candidate = random.randint(900000000, 999999999)
                if candidate not in excluded:
                    return candidate
        elif getattr(self, "_client_uses_uuid", False):
            # Client uses standard UUIDs with hyphens
            while True:
                candidate = str(uuid.uuid4())
                if candidate not in excluded:
                    return candidate
        else:
            # Client uses strings: generate 12-char hex string
            while True:
                candidate = uuid.uuid4().hex[:12]
                if candidate not in excluded:
                    return candidate

    def is_probe_response(self, resp_id: Any) -> bool:
        """Check if response ID matches an issued probe ID within the 600s retention window."""
        now = time.time()
        expired = [pid for pid, ts in self._issued_probe_ids.items() if (now - ts) > self._probe_expiry]
        for pid in expired:
            self._issued_probe_ids.pop(pid, None)
        return resp_id in self._issued_probe_ids

    def mark_list_changed(self, primitive: str) -> None:
        """Record server-emitted notifications/*_changed."""
        self._list_changed_announced.add(primitive)

    def schedule_client_tool_call(self, tool_name: Optional[str]) -> None:
        """Thread-safe scheduling of tool call count and reverification trigger."""
        self._schedule_coroutine(self.on_client_tool_call(tool_name))

    def schedule_reverify(self, source: str = "manual") -> None:
        """Thread-safe scheduling of manual/forced re-verification."""
        self._schedule_coroutine(self.trigger_reverify(source=source))

    async def on_client_tool_call(self, tool_name: Optional[str]) -> None:
        """Trigger re-verification on first call to a tool or every N tool calls."""
        if not self.enable_reverify or not self.initialized or not self.client_initialized:
            return

        should_probe = False
        source = "reverify_interval"

        # 1. First invocation of a specific tool
        if tool_name and tool_name not in self._seen_tools:
            self._seen_tools.add(tool_name)
            should_probe = True
            source = f"first_call_{tool_name}"

        # 2. Every N tool calls (with +/- 20% jitter)
        self._tool_calls_since_last_probe += 1
        jittered_interval = max(5, int(self.reverify_interval * (0.8 + random.random() * 0.4)))
        if self._tool_calls_since_last_probe >= jittered_interval:
            should_probe = True
            source = "tool_call_frequency"

        if should_probe:
            await self.trigger_reverify(source=source)

    async def trigger_reverify(self, source: str = "manual") -> bool:
        """Coalesce and inject synthetic tools/list probe."""
        if not self.enable_reverify or not self.initialized or not self.client_initialized:
            return False

        now = time.time()
        # Coalesce: at most 1 probe in flight, minimum interval 10s
        if self._probe_in_flight:
            return False
        if (now - self._last_probe_time) < self.min_probe_interval:
            return False

        self._probe_in_flight = True
        self._last_probe_time = now
        self._tool_calls_since_last_probe = 0

        probe_id = self.generate_probe_id()
        self._issued_probe_ids[probe_id] = now
        self._probe_pagination_tools.clear()

        req_obj = {
            "jsonrpc": "2.0",
            "id": probe_id,
            "method": "tools/list",
            "params": {},
        }
        import json
        line_bytes = json.dumps(req_obj).encode("utf-8") + b"\n"
        if self.send_probe_fn:
            await self.send_probe_fn(line_bytes)
        return True

    def handle_initialize_response(self, result: Dict[str, Any]) -> List[BehavioralEvent]:
        """Record serverInfo, capabilities, instructions, and check for instruction drift/injection."""
        self.initialized = True
        self.server_info = result.get("serverInfo") or {}
        self.capabilities = result.get("capabilities") or {}
        old_instructions = self.instructions
        self.instructions = result.get("instructions")

        events: List[BehavioralEvent] = []

        # Check package identity against lockfile baseline (Milestone 3)
        if self.server_lock:
            pkg_events = self.evaluate_package_identity()
            events.extend(pkg_events)

        if self.instructions:
            is_suspicious, reasons = check_prompt_injection(self.instructions)
            if is_suspicious:
                self.has_high_drift = True
                event = BehavioralEvent(
                    event="manifest_drift",
                    session_id=self.session_id,
                    server_id=self.server_id,
                    kind=KIND_MANIFEST_DRIFT,
                    source="monitor",
                    evidence_tier=EVIDENCE_TIER_OBSERVED,
                    severity=SEVERITY_HIGH,
                    timestamp=time.time(),
                    payload={
                        "category": DRIFT_INSTRUCTIONS_INJECTION,
                        "reasons": reasons,
                        "would_block": True,
                        "drift_origin": "client_visible",
                        "message": f"Server instructions contained prompt injection heuristics: {reasons}",
                    },
                )
                events.append(event)
            elif old_instructions is not None and old_instructions != self.instructions:
                # Instructions mutated cleanly without prompt injection
                event = BehavioralEvent(
                    event="manifest_drift",
                    session_id=self.session_id,
                    server_id=self.server_id,
                    kind=KIND_MANIFEST_DRIFT,
                    source="monitor",
                    evidence_tier=EVIDENCE_TIER_OBSERVED,
                    severity=SEVERITY_MEDIUM,
                    timestamp=time.time(),
                    payload={
                        "category": DRIFT_INSTRUCTIONS_MUTATION,
                        "old_instructions": old_instructions[:100],
                        "new_instructions": self.instructions[:100],
                        "would_block": False,
                        "drift_origin": "client_visible",
                        "message": "Server instructions modified without injection heuristics",
                    },
                )
                events.append(event)

        return events

    def handle_tools_list_response(
        self,
        resp_id: Any,
        result: Optional[Dict[str, Any]],
        is_error: bool = False,
    ) -> Tuple[List[BehavioralEvent], bool]:
        """Handle tools/list response from either client or proxy probe.

        Returns:
            (events_to_emit, is_probe_response)
        """
        is_probe = self.is_probe_response(resp_id)

        if is_error or not isinstance(result, dict):
            if is_probe:
                self._probe_in_flight = False
                # Proxy probe error is logged as info and ignored
                evt = BehavioralEvent(
                    event="probe_error",
                    session_id=self.session_id,
                    server_id=self.server_id,
                    kind=KIND_MANIFEST_DRIFT,
                    severity=SEVERITY_INFO,
                    source="monitor",
                    evidence_tier=EVIDENCE_TIER_OBSERVED,
                    timestamp=time.time(),
                    payload={"message": "Server returned error on synthetic probe; ignored", "would_block": False},
                )
                return [evt], True
            return [], False

        raw_tools = result.get("tools") or []
        next_cursor = result.get("nextCursor")

        # 1. Handle synthetic proxy probe response
        if is_probe:
            self._probe_pagination_tools.extend(raw_tools)
            if next_cursor:
                # Keep probe in flight during multi-page pagination
                self._probe_in_flight = True
                # Follow nextCursor until exhausted
                next_id = self.generate_probe_id()
                self._issued_probe_ids[next_id] = time.time()
                req_obj = {
                    "jsonrpc": "2.0",
                    "id": next_id,
                    "method": "tools/list",
                    "params": {"cursor": next_cursor},
                }
                import json
                probe_line = json.dumps(req_obj).encode("utf-8") + b"\n"
                if self.send_probe_fn:
                    self._schedule_coroutine(self.send_probe_fn(probe_line))
                return [], True
            else:
                self._probe_in_flight = False
                completed_tools = list(self._probe_pagination_tools)
                self._probe_pagination_tools.clear()
                events = self._evaluate_tools_manifest(completed_tools, drift_origin="proxy_observed")
                return events, True

        # 2. Handle client-initiated tools/list response
        self._client_pending_tools.extend(raw_tools)
        if next_cursor:
            # Start client pagination timeout (default 30s)
            if self._client_pagination_timer:
                try:
                    self._client_pagination_timer.cancel()
                except Exception:
                    pass
            if self.loop and self.loop.is_running():
                self._client_pagination_timer = self.loop.call_later(
                    self.pagination_timeout, self._finalize_client_partial_manifest
                )
            return [], False
        else:
            if self._client_pagination_timer:
                try:
                    self._client_pagination_timer.cancel()
                except Exception:
                    pass
                self._client_pagination_timer = None
            completed_tools = list(self._client_pending_tools)
            self._client_pending_tools.clear()
            events = self._evaluate_tools_manifest(completed_tools, drift_origin="client_visible")
            return events, False

    def _finalize_client_partial_manifest(self) -> None:
        """Timeout handler for client pagination: finalize partial baseline."""
        if self._client_pending_tools:
            tools = list(self._client_pending_tools)
            self._client_pending_tools.clear()
            events = self._evaluate_tools_manifest(tools, drift_origin="client_visible", is_partial=True)
            if self.on_event_fn:
                for evt in events:
                    self.on_event_fn(evt)

    def evaluate_package_identity(self) -> List[BehavioralEvent]:
        """Verify live resolved package identity against locked package baseline."""
        if not self.server_lock or not self.server_lock.package or not self.live_identity:
            return []

        tamper_findings = check_package_tamper(self.server_lock.package, self.live_identity)
        events: List[BehavioralEvent] = []
        for f in tamper_findings:
            if f["severity"] in (SEVERITY_HIGH, SEVERITY_CRITICAL):
                self.has_high_drift = True
            evt = BehavioralEvent(
                event="package_tamper" if f["kind"] == KIND_PACKAGE_TAMPER else "package_drift",
                session_id=self.session_id,
                server_id=self.server_id,
                kind=f["kind"],
                source="monitor",
                evidence_tier=EVIDENCE_TIER_OBSERVED,
                severity=f["severity"],
                target=self.server_id,
                timestamp=time.time(),
                payload={
                    "server_id": self.server_id,
                    "category": f["category"],
                    "message": f["message"],
                    "details": f.get("details", {}),
                    "would_block": f["would_block"] or self.enforce,
                    "enforce": self.enforce,
                },
            )
            events.append(evt)
            if self.on_event_fn:
                self.on_event_fn(evt)
        return events

    def _evaluate_lockfile_drift(self, tools_list: List[Dict[str, Any]]) -> List[BehavioralEvent]:
        """Evaluate tools list against locked baseline."""
        if not self.server_lock:
            return []
        diffs = diff_against_lockfile(self.server_lock, tools_list, self.instructions)
        events: List[BehavioralEvent] = []
        for d in diffs:
            if d["severity"] in (SEVERITY_HIGH, SEVERITY_CRITICAL):
                self.has_high_drift = True
            evt = BehavioralEvent(
                event="lockfile_drift",
                session_id=self.session_id,
                server_id=self.server_id,
                kind=KIND_LOCKFILE_DRIFT,
                source="monitor",
                evidence_tier=EVIDENCE_TIER_OBSERVED,
                severity=d["severity"],
                current_tool=d.get("tool"),
                target=d.get("tool") or self.server_id,
                timestamp=time.time(),
                payload={
                    "server_id": self.server_id,
                    "category": d["category"],
                    "tool": d.get("tool"),
                    "message": d["message"],
                    "details": d.get("details", {}),
                    "would_block": d["would_block"] or self.enforce,
                    "enforce": self.enforce,
                },
            )
            events.append(evt)
            if self.on_event_fn:
                self.on_event_fn(evt)
        return events

    def _evaluate_tools_manifest(
        self,
        tools_list: List[Dict[str, Any]],
        drift_origin: str = "client_visible",
        is_partial: bool = False,
    ) -> List[BehavioralEvent]:
        """Evaluate tools list: establish baseline if first time; otherwise diff for drift."""
        current_map: Dict[str, Dict[str, Any]] = {
            t["name"]: t for t in tools_list if isinstance(t, dict) and "name" in t
        }

        # 1. First observation establishes the session TOFU baseline
        if self.tools_baseline is None:
            self.tools_baseline = copy.deepcopy(current_map)
            evt = BehavioralEvent(
                event="manifest_baseline",
                session_id=self.session_id,
                server_id=self.server_id,
                kind=KIND_MANIFEST_BASELINE,
                source="monitor",
                evidence_tier=EVIDENCE_TIER_OBSERVED,
                timestamp=time.time(),
                payload={
                    "tools": list(current_map.keys()),
                    "tool_count": len(current_map),
                    "is_partial": is_partial,
                    "drift_origin": drift_origin,
                },
            )
            events = [evt]
            if self.server_lock:
                lockfile_events = self._evaluate_lockfile_drift(tools_list)
                events.extend(lockfile_events)
            return events

        # 2. Subsequent observation: Diff against baseline
        events = self._diff_against_tools_baseline(current_map, drift_origin=drift_origin)
        if self.server_lock:
            lockfile_events = self._evaluate_lockfile_drift(tools_list)
            events.extend(lockfile_events)
        return events

    def _diff_against_tools_baseline(
        self,
        new_map: Dict[str, Dict[str, Any]],
        drift_origin: str = "client_visible",
    ) -> List[BehavioralEvent]:
        """Compare new tools map against TOFU baseline."""
        assert self.tools_baseline is not None
        events: List[BehavioralEvent] = []
        old_map = self.tools_baseline

        old_names = set(old_map.keys())
        new_names = set(new_map.keys())

        removed_names = old_names - new_names
        added_names = new_names - old_names
        common_names = old_names & new_names

        has_announced = "tools" in self._list_changed_announced
        self._list_changed_announced.discard("tools")

        # Check for renames: identical schema and effective annotations under a new name
        renamed_pairs: List[Tuple[str, str]] = []
        unmatched_removed = set(removed_names)
        unmatched_added = set(added_names)

        for old_n in removed_names:
            old_t = old_map[old_n]
            old_schema = old_t.get("inputSchema") or {}
            old_ann = get_effective_annotations(old_t)

            for new_n in list(unmatched_added):
                new_t = new_map[new_n]
                new_schema = new_t.get("inputSchema") or {}
                new_ann = get_effective_annotations(new_t)

                if old_schema == new_schema and old_ann == new_ann:
                    renamed_pairs.append((old_n, new_n))
                    unmatched_removed.discard(old_n)
                    unmatched_added.discard(new_n)
                    break

        # Emit renames
        for old_n, new_n in renamed_pairs:
            evt = BehavioralEvent(
                event="manifest_drift",
                session_id=self.session_id,
                server_id=self.server_id,
                kind=KIND_MANIFEST_DRIFT,
                source="monitor",
                evidence_tier=EVIDENCE_TIER_OBSERVED,
                severity=SEVERITY_MEDIUM,
                timestamp=time.time(),
                payload={
                    "category": DRIFT_REMOVAL_OR_RENAME,
                    "old_name": old_n,
                    "new_name": new_n,
                    "is_rename": True,
                    "drift_origin": drift_origin,
                    "would_block": False,
                    "message": f"Tool '{old_n}' renamed to '{new_n}' with identical schema and annotations",
                },
            )
            events.append(evt)

        # Emit remaining removals
        for rem_n in unmatched_removed:
            self.has_high_drift = True
            evt = BehavioralEvent(
                event="manifest_drift",
                session_id=self.session_id,
                server_id=self.server_id,
                kind=KIND_MANIFEST_DRIFT,
                source="monitor",
                evidence_tier=EVIDENCE_TIER_OBSERVED,
                severity=SEVERITY_HIGH,
                timestamp=time.time(),
                payload={
                    "category": DRIFT_REMOVAL_OR_RENAME,
                    "tool": rem_n,
                    "is_rename": False,
                    "drift_origin": drift_origin,
                    "would_block": True,
                    "message": f"Tool '{rem_n}' was removed from manifest",
                },
            )
            events.append(evt)

        # Emit additions (announced vs covert)
        for add_n in unmatched_added:
            category = DRIFT_ANNOUNCED_ADDITION if has_announced else DRIFT_COVERT_ADDITION
            sev = SEVERITY_MEDIUM if has_announced else SEVERITY_HIGH
            would_block = not has_announced
            if would_block:
                self.has_high_drift = True

            evt = BehavioralEvent(
                event="manifest_drift",
                session_id=self.session_id,
                server_id=self.server_id,
                kind=KIND_MANIFEST_DRIFT,
                source="monitor",
                evidence_tier=EVIDENCE_TIER_OBSERVED,
                severity=sev,
                timestamp=time.time(),
                payload={
                    "category": category,
                    "tool": add_n,
                    "drift_origin": drift_origin,
                    "would_block": would_block,
                    "message": f"{'Announced' if has_announced else 'Covert (unannounced)'} tool addition: '{add_n}'",
                },
            )
            events.append(evt)

        # Check modifications on common tools
        for name in common_names:
            old_t = old_map[name]
            new_t = new_map[name]

            # 1. Description diff
            old_desc = old_t.get("description") or ""
            new_desc = new_t.get("description") or ""
            if old_desc != new_desc:
                is_inj, reasons = check_prompt_injection(new_desc)
                if is_inj:
                    self.has_high_drift = True
                    evt = BehavioralEvent(
                        event="manifest_drift",
                        session_id=self.session_id,
                        server_id=self.server_id,
                        kind=KIND_MANIFEST_DRIFT,
                        source="monitor",
                        evidence_tier=EVIDENCE_TIER_OBSERVED,
                        severity=SEVERITY_HIGH,
                        timestamp=time.time(),
                        payload={
                            "category": DRIFT_DESCRIPTION_INJECTION,
                            "tool": name,
                            "reasons": reasons,
                            "drift_origin": drift_origin,
                            "would_block": True,
                            "message": f"Tool '{name}' description modified with injection heuristics: {reasons}",
                        },
                    )
                else:
                    evt = BehavioralEvent(
                        event="manifest_drift",
                        session_id=self.session_id,
                        server_id=self.server_id,
                        kind=KIND_MANIFEST_DRIFT,
                        source="monitor",
                        evidence_tier=EVIDENCE_TIER_OBSERVED,
                        severity=SEVERITY_MEDIUM,
                        timestamp=time.time(),
                        payload={
                            "category": DRIFT_DESCRIPTION_MUTATION,
                            "tool": name,
                            "drift_origin": drift_origin,
                            "would_block": False,
                            "message": f"Tool '{name}' description altered from '{old_desc[:40]}' to '{new_desc[:40]}'",
                        },
                    )
                events.append(evt)

            # 2. Annotation diffs
            old_ann = get_effective_annotations(old_t)
            new_ann = get_effective_annotations(new_t)
            ann_diffs = diff_annotations(old_ann, new_ann)
            for diff in ann_diffs:
                if diff["would_block"]:
                    self.has_high_drift = True
                evt = BehavioralEvent(
                    event="manifest_drift",
                    session_id=self.session_id,
                    server_id=self.server_id,
                    kind=KIND_MANIFEST_DRIFT,
                    source="monitor",
                    evidence_tier=EVIDENCE_TIER_OBSERVED,
                    severity=diff["severity"],
                    timestamp=time.time(),
                    payload={
                        "category": diff["category"],
                        "tool": name,
                        "annotation": diff["annotation"],
                        "old": diff["old"],
                        "new": diff["new"],
                        "drift_origin": drift_origin,
                        "would_block": diff["would_block"],
                        "message": f"Tool '{name}': {diff['message']}",
                    },
                )
                events.append(evt)

            # 3. Schema diffs
            old_schema = old_t.get("inputSchema") or {}
            new_schema = new_t.get("inputSchema") or {}
            schema_diffs = diff_schemas(old_schema, new_schema)
            for sdiff in schema_diffs:
                if sdiff["would_block"]:
                    self.has_high_drift = True
                evt = BehavioralEvent(
                    event="manifest_drift",
                    session_id=self.session_id,
                    server_id=self.server_id,
                    kind=KIND_MANIFEST_DRIFT,
                    source="monitor",
                    evidence_tier=EVIDENCE_TIER_OBSERVED,
                    severity=sdiff["severity"],
                    timestamp=time.time(),
                    payload={
                        "category": sdiff["category"],
                        "tool": name,
                        "property": sdiff.get("property"),
                        "drift_origin": drift_origin,
                        "would_block": sdiff["would_block"],
                        "message": f"Tool '{name}': {sdiff['message']}",
                    },
                )
                events.append(evt)

        return events

    def evaluate_cross_session_drift(self, prior_manifest: Optional[Dict[str, Any]]) -> List[BehavioralEvent]:
        """Compare session baseline against persisted SQLite trusted manifest."""
        if not prior_manifest or not self.tools_baseline:
            return []

        events: List[BehavioralEvent] = []
        prior_tools: Dict[str, Dict[str, Any]] = {
            t["name"]: t for t in prior_manifest.get("tools", []) if isinstance(t, dict) and "name" in t
        }
        prior_version = (prior_manifest.get("serverInfo") or {}).get("version")
        current_version = self.server_info.get("version")

        version_bumped = bool(prior_version and current_version and prior_version != current_version)

        # Temporary tracker using prior tools as baseline
        temp_tracker = ManifestTracker(
            session_id=self.session_id,
            server_id=self.server_id,
            send_probe_fn=self.send_probe_fn,
            enable_reverify=False,
        )
        temp_tracker.tools_baseline = copy.deepcopy(prior_tools)

        drift_events = temp_tracker._diff_against_tools_baseline(self.tools_baseline, drift_origin="cross_session")

        for de in drift_events:
            p = de.payload
            cat = p.get("category")
            # If version bumped and changes are purely additive (or renames): classify as MEDIUM
            is_additive = cat in (DRIFT_ANNOUNCED_ADDITION, DRIFT_COVERT_ADDITION) or (
                cat == DRIFT_REMOVAL_OR_RENAME and p.get("is_rename") is True
            )
            if version_bumped and is_additive:
                sev = SEVERITY_MEDIUM
                wb = False
            else:
                sev = de.severity or SEVERITY_HIGH
                wb = p.get("would_block", True)

            if wb or sev == SEVERITY_HIGH:
                self.has_high_drift = True

            evt = BehavioralEvent(
                event="cross_session_drift",
                session_id=self.session_id,
                server_id=self.server_id,
                kind=KIND_CROSS_SESSION_DRIFT,
                source="monitor",
                evidence_tier=EVIDENCE_TIER_OBSERVED,
                severity=sev,
                timestamp=time.time(),
                payload={
                    **p,
                    "prior_version": prior_version,
                    "current_version": current_version,
                    "version_bumped": version_bumped,
                    "would_block": wb,
                },
            )
            events.append(evt)

        return events

    def get_manifest_snapshot(self) -> Dict[str, Any]:
        """Export full manifest snapshot for SQLite persistence."""
        return {
            "serverInfo": self.server_info,
            "capabilities": self.capabilities,
            "instructions": self.instructions,
            "tools": list(self.tools_baseline.values()) if self.tools_baseline else [],
        }

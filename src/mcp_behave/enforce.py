"""Active runtime policy enforcement, JSON-RPC error synthesis, and payload redaction (Milestone 5).

Provides inline interception for mcp-behave wrap:
1. Rejects unauthorized tool invocations (not in lockfile) with standard JSON-RPC error (-32003).
2. Intercepts confidential credential or canary exfiltration in server responses (-32004).
3. Redacts detected secrets (AWS, OpenAI, Slack, GitHub, private keys) with [REDACTED: <type>]
   while strictly preserving JSON structure and client request ID types.
"""
from __future__ import annotations

import json
import re
import time
from typing import Any, Dict, List, Optional, Tuple, Union

from .events import (
    BehavioralEvent,
    EVIDENCE_TIER_OBSERVED,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
)
from .telemetry import hash_content
from .lockfile import ServerLock
from .scanner import COMBINED_TEXT_PREFILTER, SECRET_RULES, CanaryManager

# Standard JSON-RPC policy violation error codes
ERROR_CODE_TOOL_BLOCKED = -32003
ERROR_CODE_RESPONSE_BLOCKED = -32004

KIND_ENFORCEMENT_ACTION = "enforcement_action"


class PolicyEnforcer:
    """Inline policy enforcer evaluating JSON-RPC streams between client and server."""

    def __init__(
        self,
        session_id: str,
        server_id: str,
        server_lock: Optional[ServerLock] = None,
        enforce: bool = False,
        fail_mode: str = "fail-closed",  # "fail-closed" | "fail-open"
        redact: bool = False,
        canary_mgr: Optional[CanaryManager] = None,
    ):
        self.session_id = session_id
        self.server_id = server_id
        self.server_lock = server_lock
        self.enforce = enforce
        self.fail_mode = fail_mode
        self.redact = redact
        self.canary_mgr = canary_mgr or CanaryManager()

    def evaluate_client_request(
        self, line_bytes: bytes
    ) -> Tuple[Optional[bytes], Optional[BehavioralEvent]]:
        """Inspect client-to-server request before forwarding.

        Returns:
            (synthetic_error_bytes_or_none, enforcement_event_or_none)
            If synthetic_error_bytes is returned, the original line MUST NOT be forwarded to the child.
        """
        if self.enforce and self.server_lock is None:
            raise RuntimeError(
                f"PolicyEnforcer cannot enforce without a valid ServerLock for server '{self.server_id}'"
            )

        # Fast path: only tools/call can be rejected by lockfile policy
        if b'"tools/call"' not in line_bytes:
            return None, None

        try:
            line_str = line_bytes.decode("utf-8", errors="replace")
            msg = json.loads(line_str)
        except Exception:
            return None, None

        if not isinstance(msg, dict):
            return None, None

        method = msg.get("method")
        if method != "tools/call":
            return None, None

        msg_id = msg.get("id")
        params = msg.get("params") or {}
        tool_name = params.get("name") if isinstance(params, dict) else None

        if not tool_name:
            return None, None

        # When --enforce is active, check against locked tools
        if self.enforce:
            if not self.server_lock:
                raise RuntimeError(
                    f"PolicyEnforcer cannot enforce without a valid ServerLock for server '{self.server_id}'"
                )
            locked_tool = self.server_lock.get_tool(tool_name)
            if not locked_tool:
                # Tool not permitted in lockfile
                if self.fail_mode == "fail-closed":
                    err_msg = f"Policy violation: Tool '{tool_name}' invocation blocked by mcp-behave lockfile policy."
                    # Strict preservation of ID type (int, string, or None)
                    resp = {
                        "jsonrpc": "2.0",
                        "id": msg_id,
                        "error": {
                            "code": ERROR_CODE_TOOL_BLOCKED,
                            "message": err_msg,
                        },
                    }
                    err_bytes = json.dumps(resp, ensure_ascii=False).encode("utf-8") + b"\n"

                    event = BehavioralEvent(
                        event="enforcement_action",
                        session_id=self.session_id,
                        server_id=self.server_id,
                        kind=KIND_ENFORCEMENT_ACTION,
                        source="monitor",
                        evidence_tier=EVIDENCE_TIER_OBSERVED,
                        severity=SEVERITY_HIGH,
                        current_tool=tool_name,
                        request_id=msg_id,
                        timestamp=time.time(),
                        payload={
                            "action": "blocked",
                            "direction": "client_to_server",
                            "tool": tool_name,
                            "reason": "unapproved_tool",
                            "error_code": ERROR_CODE_TOOL_BLOCKED,
                            "message": err_msg,
                        },
                    )
                    return err_bytes, event

        return None, None

    def filter_server_response(
        self, line_bytes: bytes
    ) -> Tuple[bytes, List[BehavioralEvent]]:
        """Inspect and sanitize server-to-client response before delivery to client.

        Returns:
            (forwardable_bytes, list_of_enforcement_events)
        """
        # If neither redaction nor enforcement is enabled, pass through unmodified
        if not self.redact and not self.enforce:
            return line_bytes, []

        try:
            line_str = line_bytes.decode("utf-8", errors="replace")
        except Exception:
            return line_bytes, []

        # Fast pre-filter: skip deep JSON inspection if clean
        has_canary = bool(self.canary_mgr.canaries)
        has_suspicious = bool(COMBINED_TEXT_PREFILTER.search(line_str.lower()))
        if not has_canary and not has_suspicious:
            return line_bytes, []

        try:
            msg = json.loads(line_str)
        except Exception:
            return line_bytes, []

        if not isinstance(msg, dict):
            return line_bytes, []

        msg_id = msg.get("id")
        events: List[BehavioralEvent] = []

        # 1. Check active canary tokens
        canaries_found = self.canary_mgr.find_canaries(line_str)
        if canaries_found and self.enforce and self.fail_mode == "fail-closed":
            err_msg = "Policy violation: Server response blocked due to confidential credential or canary token exfiltration."
            resp = {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {
                    "code": ERROR_CODE_RESPONSE_BLOCKED,
                    "message": err_msg,
                },
            }
            err_bytes = json.dumps(resp, ensure_ascii=False).encode("utf-8") + b"\n"
            evt = BehavioralEvent(
                event="enforcement_action",
                session_id=self.session_id,
                server_id=self.server_id,
                kind=KIND_ENFORCEMENT_ACTION,
                source="monitor",
                evidence_tier=EVIDENCE_TIER_OBSERVED,
                severity=SEVERITY_CRITICAL,
                request_id=msg_id,
                timestamp=time.time(),
                payload={
                    "action": "blocked",
                    "direction": "server_to_client",
                    "reason": "canary_exfiltration",
                    "canary_count": len(canaries_found),
                    "error_code": ERROR_CODE_RESPONSE_BLOCKED,
                },
            )
            return err_bytes, [evt]

        # 2. Check critical secrets (private keys) for blocking under enforce
        if self.enforce and self.fail_mode == "fail-closed":
            for rule_name, pattern, _, is_crit in SECRET_RULES:
                if is_crit and pattern.search(line_str):
                    err_msg = f"Policy violation: Server response blocked due to critical credential exposure ({rule_name})."
                    resp = {
                        "jsonrpc": "2.0",
                        "id": msg_id,
                        "error": {
                            "code": ERROR_CODE_RESPONSE_BLOCKED,
                            "message": err_msg,
                        },
                    }
                    err_bytes = json.dumps(resp, ensure_ascii=False).encode("utf-8") + b"\n"
                    evt = BehavioralEvent(
                        event="enforcement_action",
                        session_id=self.session_id,
                        server_id=self.server_id,
                        kind=KIND_ENFORCEMENT_ACTION,
                        source="monitor",
                        evidence_tier=EVIDENCE_TIER_OBSERVED,
                        severity=SEVERITY_CRITICAL,
                        request_id=msg_id,
                        timestamp=time.time(),
                        payload={
                            "action": "blocked",
                            "direction": "server_to_client",
                            "reason": "critical_secret_exposure",
                            "detector": rule_name,
                            "error_code": ERROR_CODE_RESPONSE_BLOCKED,
                        },
                    )
                    return err_bytes, [evt]

        # 3. Inline Redaction (when --redact is active)
        if self.redact:
            redacted_msg, redact_events = self._redact_json_object(msg, msg_id)
            if redact_events:
                redacted_bytes = json.dumps(redacted_msg, ensure_ascii=False).encode("utf-8") + b"\n"
                return redacted_bytes, redact_events

        return line_bytes, events

    def _redact_json_object(
        self, obj: Any, msg_id: Any
    ) -> Tuple[Any, List[BehavioralEvent]]:
        """Recursively redact secrets and canaries inside JSON values."""
        events: List[BehavioralEvent] = []

        def walk(val: Any) -> Any:
            if isinstance(val, dict):
                return {k: walk(v) for k, v in val.items()}
            elif isinstance(val, list):
                return [walk(item) for item in val]
            elif isinstance(val, str):
                redacted_str = val
                # Redact canaries
                canaries = self.canary_mgr.find_canaries(redacted_str)
                for canary in canaries:
                    redacted_str = redacted_str.replace(canary, "[REDACTED: canary_token]")
                    events.append(
                        BehavioralEvent(
                            event="enforcement_action",
                            session_id=self.session_id,
                            server_id=self.server_id,
                            kind=KIND_ENFORCEMENT_ACTION,
                            source="monitor",
                            evidence_tier=EVIDENCE_TIER_OBSERVED,
                            severity=SEVERITY_HIGH,
                            request_id=msg_id,
                            timestamp=time.time(),
                            payload={
                                "action": "redacted",
                                "target": hash_content(canary),
                                "detector": "canary_token",
                            },
                        )
                    )

                # Redact secrets
                for rule_name, pattern, _, _ in SECRET_RULES:
                    matches = list(pattern.finditer(redacted_str))
                    for m in matches:
                        matched_text = m.group(0)
                        redacted_str = redacted_str.replace(
                            matched_text, f"[REDACTED: {rule_name}]"
                        )
                        events.append(
                            BehavioralEvent(
                                event="enforcement_action",
                                session_id=self.session_id,
                                server_id=self.server_id,
                                kind=KIND_ENFORCEMENT_ACTION,
                                source="monitor",
                                evidence_tier=EVIDENCE_TIER_OBSERVED,
                                severity=SEVERITY_HIGH,
                                request_id=msg_id,
                                timestamp=time.time(),
                                payload={
                                    "action": "redacted",
                                    "target": hash_content(matched_text),
                                    "detector": rule_name,
                                },
                            )
                        )
                return redacted_str
            return val

        new_obj = walk(obj)
        return new_obj, events

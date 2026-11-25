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

    def _build_error_response(self, msg_id: Any, code: int, message: str) -> bytes:
        resp = {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {
                "code": code,
                "message": message,
            },
        }
        return json.dumps(resp, ensure_ascii=False).encode("utf-8") + b"\n"

    def _build_enforcement_event(
        self,
        *,
        direction: str,
        reason: str,
        error_code: int,
        message: str,
        severity: str = SEVERITY_HIGH,
        tool_name: Optional[str] = None,
        msg_id: Any = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> BehavioralEvent:
        payload: Dict[str, Any] = {
            "action": "blocked",
            "direction": direction,
            "reason": reason,
            "error_code": error_code,
            "message": message,
        }
        if tool_name:
            payload["tool"] = tool_name
        if extra:
            payload.update(extra)
        return BehavioralEvent(
            event="enforcement_action",
            session_id=self.session_id,
            server_id=self.server_id,
            kind=KIND_ENFORCEMENT_ACTION,
            source="monitor",
            evidence_tier=EVIDENCE_TIER_OBSERVED,
            severity=severity,
            current_tool=tool_name,
            request_id=msg_id,
            timestamp=time.time(),
            payload=payload,
        )

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

        if not self.enforce:
            return None, None

        # Fast path only when neither tools/call nor JSON unicode escapes are present
        if b'"tools/call"' not in line_bytes and b"\\u" not in line_bytes and not line_bytes.lstrip().startswith(b"["):
            # Still validate JSON object structure under fail-closed if line is non-empty
            stripped = line_bytes.lstrip()
            if stripped.startswith(b"{"):
                try:
                    msg = json.loads(line_bytes.decode("utf-8", errors="replace"))
                    if isinstance(msg, dict) and msg.get("method") != "tools/call":
                        return None, None
                except Exception:
                    pass

        try:
            line_str = line_bytes.decode("utf-8", errors="replace")
            msg = json.loads(line_str)
        except Exception:
            if self.fail_mode == "fail-closed":
                err_msg = "Policy violation: Malformed JSON-RPC request blocked under fail-closed enforcement."
                err_bytes = self._build_error_response(None, ERROR_CODE_TOOL_BLOCKED, err_msg)
                evt = self._build_enforcement_event(
                    direction="client_to_server",
                    reason="malformed_json",
                    error_code=ERROR_CODE_TOOL_BLOCKED,
                    message=err_msg,
                )
                return err_bytes, evt
            return None, None

        if isinstance(msg, list):
            if self.fail_mode == "fail-closed":
                err_msg = "Policy violation: JSON-RPC batch arrays are unsupported under fail-closed enforcement."
                err_bytes = self._build_error_response(None, ERROR_CODE_TOOL_BLOCKED, err_msg)
                evt = self._build_enforcement_event(
                    direction="client_to_server",
                    reason="unsupported_batch_message",
                    error_code=ERROR_CODE_TOOL_BLOCKED,
                    message=err_msg,
                )
                return err_bytes, evt
            return None, None

        if not isinstance(msg, dict):
            if self.fail_mode == "fail-closed":
                err_msg = "Policy violation: Non-object JSON-RPC payload blocked under fail-closed enforcement."
                err_bytes = self._build_error_response(None, ERROR_CODE_TOOL_BLOCKED, err_msg)
                evt = self._build_enforcement_event(
                    direction="client_to_server",
                    reason="non_object_payload",
                    error_code=ERROR_CODE_TOOL_BLOCKED,
                    message=err_msg,
                )
                return err_bytes, evt
            return None, None

        method = msg.get("method")
        if method != "tools/call":
            return None, None

        msg_id = msg.get("id")
        if isinstance(msg_id, (dict, list, bool)):
            msg_id = None
        params = msg.get("params")
        tool_name = params.get("name") if isinstance(params, dict) else None

        if not isinstance(tool_name, str) or not tool_name:
            if self.fail_mode == "fail-closed":
                err_msg = "Policy violation: tools/call missing valid tool name blocked under fail-closed enforcement."
                err_bytes = self._build_error_response(msg_id, ERROR_CODE_TOOL_BLOCKED, err_msg)
                evt = self._build_enforcement_event(
                    direction="client_to_server",
                    reason="invalid_tool_call_params",
                    error_code=ERROR_CODE_TOOL_BLOCKED,
                    message=err_msg,
                    msg_id=msg_id,
                )
                return err_bytes, evt
            return None, None

        locked_tool = self.server_lock.get_tool(tool_name)
        if not locked_tool:
            if self.fail_mode == "fail-closed":
                err_msg = f"Policy violation: Tool '{tool_name}' invocation blocked by mcp-behave lockfile policy."
                err_bytes = self._build_error_response(msg_id, ERROR_CODE_TOOL_BLOCKED, err_msg)
                evt = self._build_enforcement_event(
                    direction="client_to_server",
                    reason="unapproved_tool",
                    error_code=ERROR_CODE_TOOL_BLOCKED,
                    message=err_msg,
                    tool_name=tool_name,
                    msg_id=msg_id,
                )
                return err_bytes, evt

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

        # Fast pre-filter: skip deep JSON inspection if clean and no unicode escapes / batches
        has_canary = bool(self.canary_mgr.canaries)
        has_suspicious = bool(COMBINED_TEXT_PREFILTER.search(line_str.lower()))
        has_escape_or_batch = ("\\u" in line_str) or line_str.lstrip().startswith("[")
        if not has_canary and not has_suspicious and not has_escape_or_batch and not (self.enforce and self.fail_mode == "fail-closed"):
            return line_bytes, []

        try:
            msg = json.loads(line_str)
        except Exception:
            if self.enforce and self.fail_mode == "fail-closed":
                err_msg = "Policy violation: Malformed JSON-RPC server response blocked under fail-closed enforcement."
                err_bytes = self._build_error_response(None, ERROR_CODE_RESPONSE_BLOCKED, err_msg)
                evt = self._build_enforcement_event(
                    direction="server_to_client",
                    reason="malformed_json",
                    error_code=ERROR_CODE_RESPONSE_BLOCKED,
                    message=err_msg,
                    severity=SEVERITY_CRITICAL,
                )
                return err_bytes, [evt]
            return line_bytes, []

        if isinstance(msg, list):
            if self.enforce and self.fail_mode == "fail-closed":
                err_msg = "Policy violation: JSON-RPC batch response blocked under fail-closed enforcement."
                err_bytes = self._build_error_response(None, ERROR_CODE_RESPONSE_BLOCKED, err_msg)
                evt = self._build_enforcement_event(
                    direction="server_to_client",
                    reason="unsupported_batch_message",
                    error_code=ERROR_CODE_RESPONSE_BLOCKED,
                    message=err_msg,
                    severity=SEVERITY_CRITICAL,
                )
                return err_bytes, [evt]
            if self.redact:
                redacted_list, redact_events = self._redact_json_object(msg, None)
                if redact_events:
                    redacted_bytes = json.dumps(redacted_list, ensure_ascii=False).encode("utf-8") + b"\n"
                    return redacted_bytes, redact_events
            return line_bytes, []

        if not isinstance(msg, dict):
            if self.enforce and self.fail_mode == "fail-closed":
                err_msg = "Policy violation: Non-object JSON-RPC server response blocked under fail-closed enforcement."
                err_bytes = self._build_error_response(None, ERROR_CODE_RESPONSE_BLOCKED, err_msg)
                evt = self._build_enforcement_event(
                    direction="server_to_client",
                    reason="non_object_payload",
                    error_code=ERROR_CODE_RESPONSE_BLOCKED,
                    message=err_msg,
                    severity=SEVERITY_CRITICAL,
                )
                return err_bytes, [evt]
            return line_bytes, []

        msg_id = msg.get("id")
        if isinstance(msg_id, (dict, list, bool)):
            msg_id = None
        events: List[BehavioralEvent] = []

        # Inspect decoded text (catches \uXXXX escapes that bypass raw-byte prefilters)
        decoded_str = json.dumps(msg, ensure_ascii=False)

        # 1. Check active canary tokens
        canaries_found = self.canary_mgr.find_canaries(decoded_str)
        if canaries_found and self.enforce and self.fail_mode == "fail-closed":
            err_msg = "Policy violation: Server response blocked due to confidential credential or canary token exfiltration."
            err_bytes = self._build_error_response(msg_id, ERROR_CODE_RESPONSE_BLOCKED, err_msg)
            evt = self._build_enforcement_event(
                direction="server_to_client",
                reason="canary_exfiltration",
                error_code=ERROR_CODE_RESPONSE_BLOCKED,
                message=err_msg,
                severity=SEVERITY_CRITICAL,
                msg_id=msg_id,
                extra={"canary_count": len(canaries_found)},
            )
            return err_bytes, [evt]

        # 2. Check critical secrets (private keys) for blocking under enforce
        if self.enforce and self.fail_mode == "fail-closed":
            for rule_name, pattern, _, is_crit in SECRET_RULES:
                if is_crit and pattern.search(decoded_str):
                    err_msg = f"Policy violation: Server response blocked due to critical credential exposure ({rule_name})."
                    err_bytes = self._build_error_response(msg_id, ERROR_CODE_RESPONSE_BLOCKED, err_msg)
                    evt = self._build_enforcement_event(
                        direction="server_to_client",
                        reason="critical_secret_exposure",
                        error_code=ERROR_CODE_RESPONSE_BLOCKED,
                        message=err_msg,
                        severity=SEVERITY_CRITICAL,
                        msg_id=msg_id,
                        extra={"detector": rule_name},
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

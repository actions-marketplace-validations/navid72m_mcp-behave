"""Differential equivalence tests comparing original vs optimized PolicyEnforcer.

Verifies identical security decisions, error payloads, request-ID handling,
redaction outputs, and enforcement events across clean, malformed,
Unicode-escaped, nested, adversarial, and secret-containing payloads.
"""
from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Optional, Tuple

import pytest

from mcp_behave.canary import CanaryManager
from mcp_behave.enforce import (
    ERROR_CODE_RESPONSE_BLOCKED,
    ERROR_CODE_TOOL_BLOCKED,
    KIND_ENFORCEMENT_ACTION,
    PolicyEnforcer,
)
from mcp_behave.events import (
    BehavioralEvent,
    EVIDENCE_TIER_OBSERVED,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
)
from mcp_behave.lockfile import ServerLock, ToolLock
from mcp_behave.scanner import COMBINED_TEXT_PREFILTER, SECRET_RULES
from mcp_behave.telemetry import hash_content


class _ReferencePolicyEnforcer:
    """Faithful copy of the pre-optimization PolicyEnforcer for differential testing."""

    def __init__(
        self,
        session_id: str,
        server_id: str,
        server_lock: Optional[ServerLock] = None,
        enforce: bool = False,
        fail_mode: str = "fail-closed",
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
        resp = {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}
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
        if self.enforce and self.server_lock is None:
            raise RuntimeError(
                f"PolicyEnforcer cannot enforce without a valid ServerLock for server '{self.server_id}'"
            )
        if not self.enforce:
            return None, None

        if b'"tools/call"' not in line_bytes and b"\\u" not in line_bytes and not line_bytes.lstrip().startswith(b"["):
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

    def filter_server_response(self, line_bytes: bytes) -> Tuple[bytes, List[BehavioralEvent]]:
        if not self.redact and not self.enforce:
            return line_bytes, []

        try:
            line_str = line_bytes.decode("utf-8", errors="replace")
        except Exception:
            return line_bytes, []

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
                    return json.dumps(redacted_list, ensure_ascii=False).encode("utf-8") + b"\n", redact_events
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
        decoded_str = json.dumps(msg, ensure_ascii=False)

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

        if self.redact:
            redacted_msg, redact_events = self._redact_json_object(msg, msg_id)
            if redact_events:
                return json.dumps(redacted_msg, ensure_ascii=False).encode("utf-8") + b"\n", redact_events

        return line_bytes, []

    def _redact_json_object(self, obj: Any, msg_id: Any) -> Tuple[Any, List[BehavioralEvent]]:
        events: List[BehavioralEvent] = []

        def walk(val: Any) -> Any:
            if isinstance(val, dict):
                return {k: walk(v) for k, v in val.items()}
            if isinstance(val, list):
                return [walk(item) for item in val]
            if isinstance(val, str):
                redacted_str = val
                for canary in self.canary_mgr.find_canaries(redacted_str):
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
                            payload={"action": "redacted", "target": hash_content(canary), "detector": "canary_token"},
                        )
                    )
                for rule_name, pattern, _, _ in SECRET_RULES:
                    matches = list(pattern.finditer(redacted_str))
                    for m in matches:
                        matched_text = m.group(0)
                        redacted_str = redacted_str.replace(matched_text, f"[REDACTED: {rule_name}]")
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
                                payload={"action": "redacted", "target": hash_content(matched_text), "detector": rule_name},
                            )
                        )
                return redacted_str
            return val

        return walk(obj), events


def _norm_event(evt: Optional[BehavioralEvent]) -> Optional[Tuple[Any, ...]]:
    if evt is None:
        return None
    return (evt.event, evt.kind, evt.severity, evt.current_tool, evt.request_id, evt.payload)


def _make_lock() -> ServerLock:
    return ServerLock(
        server_id="diff_srv",
        command=["python", "mock.py"],
        manifest={"tools": {"allowed_tool": ToolLock("sha256:a", "sha256:b")}},
    )


CLIENT_CASES: List[bytes] = [
    b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"allowed_tool","arguments":{"x":1}}}\n',
    b'{"jsonrpc":"2.0","id":"req-2","method":"tools/call","params":{"name":"blocked_tool"}}\n',
    b'{"jsonrpc":"2.0","id":3,"method":"\\u0074ools/call","params":{"name":"\\u0062locked_tool"}}\n',
    b'{"jsonrpc":"2.0","id":4,"method":"\\u0074ools/call","params":{"name":"\\u0061llowed_tool"}}\n',
    b'{"jsonrpc":"2.0","id":true,"method":"tools/call","params":{"name":"blocked_tool"}}\n',
    b'{"jsonrpc":"2.0","id":[1,2],"method":"tools/call","params":{"name":""}}\n',
    b'{"jsonrpc":"2.0","id":5,"method":"tools/list","params":{}}\n',
    b'[{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"allowed_tool"}}]\n',
    b"{not valid json\n",
    b"42\n",
    b"\xff\xfe{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/call\",\"params\":{\"name\":\"blocked\"}}\n",
]

_SYNTH_AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"
_SYNTH_OPENAI_KEY = "sk-" + "proj-" + ("a1B2c3D4" * 4)
_SYNTH_GH_TOKEN = "ghp_" + ("x9Y8z7W6" * 4) + "abcd"
_SYNTH_SLACK_TOKEN = "xoxb-12345678901-123456789012-" + ("A1b2C3d4" * 3)
_SYNTH_PRIV_KEY = "-----BEGIN " + "RSA PRIVATE KEY-----\nMIIE..."
_SYNTH_AWS_SECRET = 'aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'
_SYNTH_CANARY = "mcpb_canary_deadbeef1234"

SERVER_CASES: List[bytes] = [
    b'{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"clean payload"}]}}\n',
    b'{"jsonrpc":"2.0","id":"u1","result":{"nested":[{"a":"' + ("Z" * 1024).encode() + b'"}]}}\n',
    b"{broken json response\n",
    b"null\n",
    b'[{"jsonrpc":"2.0","id":2,"result":{"ok":true}}]\n',
    b'[{"jsonrpc":"2.0","id":3,"result":{"text":"' + _SYNTH_AWS_KEY.encode() + b'"}}]\n',
    json.dumps({"jsonrpc": "2.0", "id": 10, "result": {"text": _SYNTH_AWS_KEY}}).encode() + b"\n",
    json.dumps({"jsonrpc": "2.0", "id": 11, "result": {"deep": [{"k": _SYNTH_OPENAI_KEY}, _SYNTH_GH_TOKEN]}}).encode() + b"\n",
    json.dumps({"jsonrpc": "2.0", "id": 12, "result": {"slack": _SYNTH_SLACK_TOKEN}}).encode() + b"\n",
    json.dumps({"jsonrpc": "2.0", "id": 13, "result": {"pem": _SYNTH_PRIV_KEY}}).encode() + b"\n",
    json.dumps({"jsonrpc": "2.0", "id": 14, "result": {"cfg": _SYNTH_AWS_SECRET}}).encode() + b"\n",
    json.dumps({"jsonrpc": "2.0", "id": 15, "result": {"leak": _SYNTH_CANARY}}).encode() + b"\n",
    # Unicode-escaped secret & canary variants
    b'{"jsonrpc":"2.0","id":16,"result":{"text":"\\u0041KIAIOSFODNN7EXAMPLE"}}\n',
    b'{"jsonrpc":"2.0","id":17,"result":{"text":"\\u006dcpb_canary_deadbeef1234"}}\n',
    b'{"jsonrpc":"2.0","id":18,"result":{"text":"-----\\u0042EGIN RSA PRIVATE KEY-----"}}\n',
    # Mixed-case adversarial secret key
    b'{"jsonrpc":"2.0","id":19,"result":{"text":"SeCrEt_KeY = \\"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\\""}}\n',
    # Non-primitive id normalization
    b'{"jsonrpc":"2.0","id":true,"result":{"text":"' + _SYNTH_AWS_KEY.encode() + b'"}}\n',
    # Invalid UTF-8 bytes
    b'{"jsonrpc":"2.0","id":20,"result":{"text":"bad\xffbytes ' + _SYNTH_AWS_KEY.encode() + b'"}}\n',
]


@pytest.mark.parametrize("enforce", [False, True])
@pytest.mark.parametrize("fail_mode", ["fail-closed", "fail-open"])
def test_differential_evaluate_client_request(enforce: bool, fail_mode: str):
    lock = _make_lock()
    ref = _ReferencePolicyEnforcer("s1", "diff_srv", server_lock=lock, enforce=enforce, fail_mode=fail_mode)
    opt = PolicyEnforcer("s1", "diff_srv", server_lock=lock, enforce=enforce, fail_mode=fail_mode)

    for payload in CLIENT_CASES:
        ref_bytes, ref_evt = ref.evaluate_client_request(payload)
        opt_bytes, opt_evt = opt.evaluate_client_request(payload)
        assert opt_bytes == ref_bytes, f"Mismatch bytes for {payload!r}"
        assert _norm_event(opt_evt) == _norm_event(ref_evt), f"Mismatch event for {payload!r}"


@pytest.mark.parametrize("enforce", [False, True])
@pytest.mark.parametrize("fail_mode", ["fail-closed", "fail-open"])
@pytest.mark.parametrize("redact", [False, True])
@pytest.mark.parametrize("use_canary", [False, True])
def test_differential_filter_server_response(enforce: bool, fail_mode: str, redact: bool, use_canary: bool):
    lock = _make_lock()
    canaries = [_SYNTH_CANARY] if use_canary else []
    ref = _ReferencePolicyEnforcer(
        "s1", "diff_srv", server_lock=lock, enforce=enforce, fail_mode=fail_mode,
        redact=redact, canary_mgr=CanaryManager(initial_canaries=canaries),
    )
    opt = PolicyEnforcer(
        "s1", "diff_srv", server_lock=lock, enforce=enforce, fail_mode=fail_mode,
        redact=redact, canary_mgr=CanaryManager(initial_canaries=canaries),
    )

    for payload in SERVER_CASES:
        ref_bytes, ref_evts = ref.filter_server_response(payload)
        opt_bytes, opt_evts = opt.filter_server_response(payload)
        assert opt_bytes == ref_bytes, f"Mismatch bytes for {payload!r}"
        assert [_norm_event(e) for e in opt_evts] == [_norm_event(e) for e in ref_evts], (
            f"Mismatch events for {payload!r}"
        )


import random
from mcp_behave.enforce import _may_contain_secret, _rule_may_match


UNICODE_CASE_AND_EQUIV_CASES: List[bytes] = [
    # Long s (U+017F), Kelvin sign (U+212A), dotted I (U+0130), dotless i (U+0131)
    ('{"jsonrpc":"2.0","id":101,"result":{"s":"\\u017fecret_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}}').encode("utf-8") + b"\n",
    ('{"jsonrpc":"2.0","id":102,"result":{"s":"\u017fecret_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}}').encode("utf-8") + b"\n",
    ('{"jsonrpc":"2.0","id":103,"result":{"s":"api_\u212aey=AbCdEfGhIjKlMnOpQrStUvWxYz123456"}}').encode("utf-8") + b"\n",
    ('{"jsonrpc":"2.0","id":104,"result":{"s":"ap\u0130_key=AbCdEfGhIjKlMnOpQrStUvWxYz123456"}}').encode("utf-8") + b"\n",
    ('{"jsonrpc":"2.0","id":105,"result":{"s":"ap\u0131_key=AbCdEfGhIjKlMnOpQrStUvWxYz123456"}}').encode("utf-8") + b"\n",
    ('{"jsonrpc":"2.0","id":106,"result":{"s":"client_\u017fecret=AbCdEfGhIjKlMnOpQrStUvWxYz123456"}}').encode("utf-8") + b"\n",
    # Duplicate keys (first shadowed by second)
    b'{"jsonrpc":"2.0","id":107,"result":{"secret_key":"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY","secret_key":"clean"}}\n',
    # Unusual whitespace, alternate numbers, non-ASCII, JSON key containing secret
    '{"jsonrpc":"2.0",\t"id":108,\t"result":{"num":1e5,"neg":-0.0,"café":"\\u0041KIAIOSFODNN7EXAMPLE","AKIAIOSFODNN7EXAMPLE":"val"}}\n'.encode("utf-8"),
    # BOMs (UTF-8, UTF-16LE, UTF-16BE)
    b"\xef\xbb\xbf" + b'{"jsonrpc":"2.0","id":109,"result":{"ok":true}}\n',
    b"\xff\xfe" + '{"jsonrpc":"2.0","id":110,"result":{"ok":true}}\n'.encode("utf-16-le"),
    b"\xfe\xff" + '{"jsonrpc":"2.0","id":111,"result":{"ok":true}}\n'.encode("utf-16-be"),
]

UNICODE_CLIENT_BOMS: List[bytes] = [
    b"\xef\xbb\xbf" + b'{"jsonrpc":"2.0","id":112,"method":"tools/call","params":{"name":"blocked_tool"}}\n',
    b"\xff\xfe" + '{"jsonrpc":"2.0","id":113,"method":"tools/call","params":{"name":"blocked_tool"}}\n'.encode("utf-16-le"),
    b"\xfe\xff" + '{"jsonrpc":"2.0","id":114,"method":"tools/call","params":{"name":"allowed_tool"}}\n'.encode("utf-16-be"),
]


@pytest.mark.parametrize("enforce", [False, True])
@pytest.mark.parametrize("fail_mode", ["fail-closed", "fail-open"])
@pytest.mark.parametrize("redact", [False, True])
def test_differential_unicode_equiv_and_boms(enforce: bool, fail_mode: str, redact: bool):
    lock = _make_lock()
    ref = _ReferencePolicyEnforcer("s1", "diff_srv", server_lock=lock, enforce=enforce, fail_mode=fail_mode, redact=redact)
    opt = PolicyEnforcer("s1", "diff_srv", server_lock=lock, enforce=enforce, fail_mode=fail_mode, redact=redact)

    for payload in UNICODE_CLIENT_BOMS:
        rb, re_evt = ref.evaluate_client_request(payload)
        ob, oe_evt = opt.evaluate_client_request(payload)
        assert ob == rb, f"Client BOM mismatch for {payload!r}"
        assert _norm_event(oe_evt) == _norm_event(re_evt)

    for payload in UNICODE_CASE_AND_EQUIV_CASES:
        rb, re_evts = ref.filter_server_response(payload)
        ob, oe_evts = opt.filter_server_response(payload)
        # Optimized .casefold() + substring gate catches raw U+017F ('ſ') and U+0130 ('İ')
        # even when the original COMBINED_TEXT_PREFILTER.search(line_str.lower()) missed them.
        if redact and not (enforce and fail_mode == "fail-closed"):
            if b"\xc5\xbfecret_key=" in payload:
                assert b"[REDACTED: aws_secret_access_key]" in ob
                assert len(oe_evts) == 1
                continue
            if b"ap\xc4\xb0_key=" in payload or b"ap\xc4\xb1_key=" in payload or b"client_\xc5\xbfecret=" in payload:
                assert b"[REDACTED: generic_secret_token]" in ob
                assert len(oe_evts) == 1
                continue
        assert ob == rb, f"Server equiv/Unicode mismatch for {payload!r}"
        assert [_norm_event(e) for e in oe_evts] == [_norm_event(e) for e in re_evts]


def test_all_secret_rules_never_bypassed_by_gate():
    """Every SECRET_RULES regex match must pass _may_contain_secret and _rule_may_match."""
    samples = {
        "private_key": "-----BEGIN OPENSSH PRIVATE KEY-----",
        "aws_access_key_id": "ASIA1234567890ABCDEF",
        "aws_secret_access_key": "\u017fecret_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "openai_api_key": "sk-proj-" + ("a1B2c3D4" * 4),
        "anthropic_api_key": "sk-ant-api03-" + ("A1b2C3d4" * 11),
        "github_token": "ghr_" + ("A1b2C3d4" * 4) + "abcd",
        "github_pat": "github_pat_" + ("a1B2" * 5) + "xy_" + ("Z9y8" * 15),
        "slack_token": "xoxp-12345678901-123456789012-" + ("A1b2C3d4" * 3),
        "generic_secret_token": "api_\u212aey=" + ("A1b2C3d4" * 4),
    }
    assert set(samples.keys()) == {name for name, _, _, _ in SECRET_RULES}

    for rule_name, pattern, _, _ in SECRET_RULES:
        text = samples[rule_name]
        assert pattern.search(text) is not None, f"Test sample for {rule_name} did not match regex"
        fold = text.casefold()
        assert _may_contain_secret(text, fold) is True, f"_may_contain_secret skipped {rule_name}"
        assert _rule_may_match(rule_name, text, fold) is True, f"_rule_may_match skipped {rule_name}"


@pytest.mark.parametrize("enforce,redact,fail_mode", [
    (True, False, "fail-closed"),
    (True, True, "fail-closed"),
    (False, True, "fail-open"),
])
def test_differential_randomized_fuzz(enforce: bool, redact: bool, fail_mode: str):
    """Deterministic randomized differential fuzzing (200 client + 200 server payloads)."""
    rng = random.Random(20261125)
    lock = _make_lock()
    canaries = [_SYNTH_CANARY]
    ref = _ReferencePolicyEnforcer(
        "s1", "diff_srv", server_lock=lock, enforce=enforce, fail_mode=fail_mode,
        redact=redact, canary_mgr=CanaryManager(initial_canaries=canaries),
    )
    opt = PolicyEnforcer(
        "s1", "diff_srv", server_lock=lock, enforce=enforce, fail_mode=fail_mode,
        redact=redact, canary_mgr=CanaryManager(initial_canaries=canaries),
    )

    tokens = [
        "clean_text", "secret", "key", "token", "AKIAIOSFODNN7EXAMPLE",
        _SYNTH_OPENAI_KEY, _SYNTH_GH_TOKEN, _SYNTH_SLACK_TOKEN,
        _SYNTH_AWS_SECRET, _SYNTH_PRIV_KEY, _SYNTH_CANARY,
        "\u017fecret_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "api_\u212aey=" + ("A1b2C3d4" * 4),
        "café_résumé", "a/b\\c",
    ]

    for i in range(200):
        kind = i % 5
        if kind == 0:
            c_payload = json.dumps({
                "jsonrpc": "2.0", "id": i,
                "method": rng.choice(["tools/call", "\\u0074ools/call", "tools/list", "ping"]),
                "params": {"name": rng.choice(["allowed_tool", "blocked_tool", ""])},
            }).encode("utf-8") + b"\n"
        elif kind == 1:
            c_payload = b'[{"jsonrpc":"2.0","id":' + str(i).encode() + b',"method":"tools/call"}]\n'
        elif kind == 2:
            c_payload = b"{bad_json_" + str(i).encode() + b"\n"
        elif kind == 3:
            c_payload = b"\xff\xfe" + f'{{"jsonrpc":"2.0","id":{i}}}\n'.encode("utf-16-le")
        else:
            c_payload = json.dumps({"jsonrpc": "2.0", "id": rng.choice([i, f"s-{i}", True, [1]])}).encode("utf-8") + b"\n"

        rb, re_evt = ref.evaluate_client_request(c_payload)
        ob, oe_evt = opt.evaluate_client_request(c_payload)
        assert ob == rb
        assert _norm_event(oe_evt) == _norm_event(re_evt)

        s_kind = i % 6
        if s_kind in (0, 1, 2):
            val: Any = rng.choice(tokens)
            for _ in range(rng.randint(1, 4)):
                val = rng.choice([{"k": val, "extra": rng.choice(tokens)}, [val, "x"]])
            s_payload = json.dumps(
                {"jsonrpc": "2.0", "id": rng.choice([i, f"r-{i}", None, True]), "result": val},
                ensure_ascii=rng.choice([True, False]),
            ).encode("utf-8") + b"\n"
        elif s_kind == 3:
            s_payload = b'{"jsonrpc":"2.0","id":1,"result":{"k":"' + _SYNTH_AWS_KEY.encode() + b'","k":"clean"}}\n'
        elif s_kind == 4:
            s_payload = b'[{"jsonrpc":"2.0","id":1,"result":{}}]\n'
        else:
            s_payload = b"{truncated_" + str(i).encode() + b"\n"

        rb_s, re_evts = ref.filter_server_response(s_payload)
        ob_s, oe_evts = opt.filter_server_response(s_payload)
        assert ob_s == rb_s
        assert [_norm_event(e) for e in oe_evts] == [_norm_event(e) for e in re_evts]


def test_unicode_casefold_security_improvements():
    """Explicit regression assertions for Unicode case-folding improvements over original prefilter."""
    opt = PolicyEnforcer("s1", "diff_srv", enforce=False, fail_mode="fail-open", redact=True)

    # U+017F (long s) in aws_secret_access_key
    p1 = ('{"jsonrpc":"2.0","id":1,"result":{"s":"\u017fecret_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}}').encode("utf-8") + b"\n"
    out1, evts1 = opt.filter_server_response(p1)
    assert b"[REDACTED: aws_secret_access_key]" in out1
    assert len(evts1) == 1 and evts1[0].payload["detector"] == "aws_secret_access_key"

    # U+017F (long s), U+0130 (dotted I), U+0131 (dotless i) in generic_secret_token
    for s in (
        "client_\u017fecret=AbCdEfGhIjKlMnOpQrStUvWxYz123456",
        "ap\u0130_key=AbCdEfGhIjKlMnOpQrStUvWxYz123456",
        "ap\u0131_key=AbCdEfGhIjKlMnOpQrStUvWxYz123456",
    ):
        p = json.dumps({"jsonrpc": "2.0", "id": 2, "result": {"s": s}}, ensure_ascii=False).encode("utf-8") + b"\n"
        out, evts = opt.filter_server_response(p)
        assert b"[REDACTED: generic_secret_token]" in out
        assert len(evts) == 1 and evts[0].payload["detector"] == "generic_secret_token"

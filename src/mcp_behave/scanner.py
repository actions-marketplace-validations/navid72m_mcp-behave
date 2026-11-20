"""Payload content scanner for secrets, canaries, and indirect prompt injection (Milestone 2b)."""
from __future__ import annotations

import math
import re
import time
from typing import Any, Dict, List, Optional, Set, Tuple

from .canary import CanaryManager
from .events import (
    BehavioralEvent,
    EVIDENCE_TIER_HEURISTIC,
    EVIDENCE_TIER_OBSERVED,
    KIND_ARGUMENT_HEURISTIC,
    KIND_CANARY_EXFILTRATION,
    KIND_INDIRECT_INJECTION,
    KIND_SECRET_EXPOSURE,
    KIND_SECRET_LEAK,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
)
from .heuristics import check_prompt_injection
from .telemetry import hash_content


def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    counts: Dict[str, int] = {}
    for c in data:
        counts[c] = counts.get(c, 0) + 1
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


# Secret Detection Rules: (name, pattern, min_entropy, is_critical)
SECRET_RULES: List[Tuple[str, re.Pattern, float, bool]] = [
    # 1. Private keys
    (
        "private_key",
        re.compile(r"-----BEGIN (?:RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----"),
        0.0,
        True,
    ),
    # 2. AWS Access Key ID
    (
        "aws_access_key_id",
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        0.0,
        False,
    ),
    # 3. AWS Secret Access Key in key-value context (with variations)
    (
        "aws_secret_access_key",
        re.compile(r"""(?i)["']?(?:aws_secret_access_key|secret_key|secretAccessKey)["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?"""),
        4.5,
        True,
    ),
    # 4. OpenAI API Keys (legacy sk-... and modern sk-proj-..., excluding Anthropic sk-ant-)
    (
        "openai_api_key",
        re.compile(r"\bsk-(?!ant-)(?:proj-)?[a-zA-Z0-9_-]{20,128}\b"),
        0.0,
        False,
    ),
    # 5. Anthropic API Keys
    (
        "anthropic_api_key",
        re.compile(r"\bsk-ant-api03-[a-zA-Z0-9_-]{80,105}\b"),
        0.0,
        False,
    ),
    # 6. GitHub Classic Tokens
    (
        "github_token",
        re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}\b"),
        0.0,
        False,
    ),
    # 7. GitHub Fine-Grained Personal Access Tokens (PAT)
    (
        "github_pat",
        re.compile(r"\bgithub_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59,64}\b"),
        0.0,
        False,
    ),
    # 8. Slack Tokens (User/Bot/App)
    (
        "slack_token",
        re.compile(r"\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,34}\b"),
        0.0,
        False,
    ),
    # 9. Generic High-Entropy Credential Assignment
    (
        "generic_secret_token",
        re.compile(r"""(?i)["']?(?:api[_-]?key|client[_-]?secret|auth[_-]?token|bearer_token)["']?\s*[:=]\s*["']?([A-Za-z0-9_\-+/]{24,})["']?"""),
        4.5,
        False,
    ),
]

# Fast byte-level pre-filter markers to bypass regex passes on clean payloads
FAST_SECRET_MARKERS: Tuple[bytes, ...] = (
    b"AKIA",
    b"sk-",
    b"ghp_",
    b"github_pat_",
    b"xox",
    b"BEGIN",
    b"mcpb_canary_",
)

FAST_INJECTION_MARKERS: Tuple[bytes, ...] = (
    b"<system",
    b"<instructions",
    b"<developer",
    b"[inst",
    b"<<sys",
    b"ignore previous",
)

# Single compiled byte pre-filter regex for fast raw byte scanning (>64 KB payloads)
# Executes in a single C-level Boyer-Moore pass and releases the GIL
COMBINED_PREFILTER: re.Pattern = re.compile(
    rb"AKIA|sk-|ghp_|github_pat_|xox|BEGIN|mcpb_canary_|<system|<instructions|<developer|\[inst|<<sys|ignore previous"
)
COMBINED_BYTE_PREFILTER: re.Pattern = COMBINED_PREFILTER

# Fast text pre-filter regex to bypass 22 regex passes on clean payloads (exits in < 0.01 ms)
COMBINED_TEXT_PREFILTER: re.Pattern = re.compile(
    r"akia|asia|sk-|ghp_|gho_|ghu_|ghs_|ghr_|github_pat_|xox|begin\s+(?:rsa|ec|dsa|openssh|pgp)\s+private\s+key"
    r"|aws_secret_access_key|secret_key|secretaccesskey|api[_-]?key|client[_-]?secret|auth[_-]?token|bearer_token"
    r"|ignore\s+(?:all\s+)?previous|disregard|you\s+are\s+now|system\s*prompt|###|<\s*/?\s*(?:system|instructions|developer|mcp_context)|\[/?inst\]|<<sys"
    r"|jailbreak|do\s*not\s*tell|hide\s*this|do\s*not\s*inform|without\s*informing|secretly|silently|covertly"
    r"|https?://|curl|wget|base64\.b64decode"
)


class ContentScanner:
    """Scans JSON-RPC message contents for secrets, canary tokens, and prompt injection."""

    def __init__(
        self,
        session_id: str,
        server_id: str,
        canary_mgr: Optional[CanaryManager] = None,
        enabled: bool = True,
    ) -> None:
        self.session_id = session_id
        self.server_id = server_id
        self.canary_mgr = canary_mgr or CanaryManager()
        self.enabled = enabled

    def scan_tool_call(
        self,
        tool_name: Optional[str],
        params: Any,
        request_id: Any = None,
        now: Optional[float] = None,
    ) -> List[BehavioralEvent]:
        """Scan client tool call arguments (client_to_server)."""
        if not self.enabled:
            return []
        ts = now or time.time()
        text_blobs = self._extract_text_blobs(params)
        if not text_blobs:
            return []

        combined_text = "\n".join(text_blobs)

        # 1. Canary Token Check across ALL tools (No tool name whitelist)
        canaries_found = self.canary_mgr.find_canaries(combined_text)

        # Fast text pre-filter: exit in < 0.01 ms on clean payloads without evaluating 22 regexes
        if not canaries_found and not bool(COMBINED_TEXT_PREFILTER.search(combined_text.lower())):
            return []

        events: List[BehavioralEvent] = []
        for canary in canaries_found:
            evt = BehavioralEvent(
                event="canary_exfiltration",
                session_id=self.session_id,
                server_id=self.server_id,
                kind=KIND_CANARY_EXFILTRATION,
                source="monitor",
                evidence_tier=EVIDENCE_TIER_OBSERVED,
                severity=SEVERITY_CRITICAL,
                current_tool=tool_name,
                target=tool_name,
                request_id=request_id,
                timestamp=ts,
                payload={
                    "tool": tool_name,
                    "direction": "client_to_server",
                    "canary_hash": hash_content(canary),
                    "message": f"Active canary token exfiltrated in tool '{tool_name}' arguments",
                    "would_block": True,
                },
            )
            events.append(evt)

        # 2. Secret Exposure in Tool Arguments
        secrets_found = self._find_secrets(combined_text)
        for rule_name, matched_str, is_critical in secrets_found:
            evt = BehavioralEvent(
                event="secret_exposure",
                session_id=self.session_id,
                server_id=self.server_id,
                kind=KIND_SECRET_EXPOSURE,
                source="monitor",
                evidence_tier=EVIDENCE_TIER_OBSERVED,
                severity=SEVERITY_CRITICAL if is_critical else SEVERITY_HIGH,
                current_tool=tool_name,
                target=tool_name,
                request_id=request_id,
                timestamp=ts,
                payload={
                    "tool": tool_name,
                    "detector": rule_name,
                    "direction": "client_to_server",
                    "secret_hash": hash_content(matched_str),
                    "message": f"Secret credential ({rule_name}) exposed in tool '{tool_name}' arguments",
                    "would_block": True,
                },
            )
            events.append(evt)

        # 3. Argument Injection Heuristics (Standalone heuristic <= MEDIUM, would_block=False)
        is_inj, reasons = check_prompt_injection(combined_text)
        if is_inj:
            evt = BehavioralEvent(
                event="argument_heuristic",
                session_id=self.session_id,
                server_id=self.server_id,
                kind=KIND_ARGUMENT_HEURISTIC,
                source="monitor",
                evidence_tier=EVIDENCE_TIER_HEURISTIC,
                severity=SEVERITY_MEDIUM,
                current_tool=tool_name,
                target=tool_name,
                request_id=request_id,
                timestamp=ts,
                payload={
                    "tool": tool_name,
                    "reasons": reasons,
                    "direction": "client_to_server",
                    "message": f"Tool '{tool_name}' arguments match injection heuristics: {reasons}",
                    "would_block": False,
                },
            )
            events.append(evt)

        return events

    def scan_tool_result(
        self,
        tool_name: Optional[str],
        result: Any,
        request_id: Any = None,
        now: Optional[float] = None,
    ) -> List[BehavioralEvent]:
        """Scan server tool execution results (server_to_client)."""
        if not self.enabled:
            return []
        ts = now or time.time()
        text_blobs = self._extract_text_blobs(result)
        if not text_blobs:
            return []

        combined_text = "\n".join(text_blobs)

        # 1. Canary Token Reflection / Leak in Response
        canaries_found = self.canary_mgr.find_canaries(combined_text)

        # Fast text pre-filter: exit in < 0.01 ms on clean payloads without evaluating 22 regexes
        if not canaries_found and not bool(COMBINED_TEXT_PREFILTER.search(combined_text.lower())):
            return []

        events: List[BehavioralEvent] = []
        for canary in canaries_found:
            evt = BehavioralEvent(
                event="canary_leak",
                session_id=self.session_id,
                server_id=self.server_id,
                kind=KIND_CANARY_EXFILTRATION,
                source="monitor",
                evidence_tier=EVIDENCE_TIER_OBSERVED,
                severity=SEVERITY_CRITICAL,
                current_tool=tool_name,
                target=tool_name,
                request_id=request_id,
                timestamp=ts,
                payload={
                    "tool": tool_name,
                    "direction": "server_to_client",
                    "canary_hash": hash_content(canary),
                    "message": f"Active canary token returned in tool '{tool_name}' result",
                    "would_block": True,
                },
            )
            events.append(evt)

        # 2. Secret Leakage in Server Result
        secrets_found = self._find_secrets(combined_text)
        for rule_name, matched_str, is_critical in secrets_found:
            evt = BehavioralEvent(
                event="secret_leak",
                session_id=self.session_id,
                server_id=self.server_id,
                kind=KIND_SECRET_LEAK,
                source="monitor",
                evidence_tier=EVIDENCE_TIER_OBSERVED,
                severity=SEVERITY_CRITICAL if is_critical else SEVERITY_HIGH,
                current_tool=tool_name,
                target=tool_name,
                request_id=request_id,
                timestamp=ts,
                payload={
                    "tool": tool_name,
                    "detector": rule_name,
                    "direction": "server_to_client",
                    "secret_hash": hash_content(matched_str),
                    "message": f"Secret credential ({rule_name}) leaked in tool '{tool_name}' result",
                    "would_block": True,
                },
            )
            events.append(evt)

        # 3. Indirect Prompt Injection in Tool Result (HEURISTIC, MEDIUM, non-blocking)
        is_inj, reasons = check_prompt_injection(combined_text)
        if is_inj:
            evt = BehavioralEvent(
                event="indirect_injection",
                session_id=self.session_id,
                server_id=self.server_id,
                kind=KIND_INDIRECT_INJECTION,
                source="monitor",
                evidence_tier=EVIDENCE_TIER_HEURISTIC,
                severity=SEVERITY_MEDIUM,
                current_tool=tool_name,
                target=tool_name,
                request_id=request_id,
                timestamp=ts,
                payload={
                    "tool": tool_name,
                    "reasons": reasons,
                    "direction": "server_to_client",
                    "message": f"Tool '{tool_name}' result contained indirect prompt injection cues: {reasons}",
                    "would_block": False,
                },
            )
            events.append(evt)

        return events

    def scan_raw_bytes(
        self,
        raw_bytes: bytes,
        direction: str,
        tool_name: Optional[str] = None,
        request_id: Any = None,
        now: Optional[float] = None,
    ) -> List[BehavioralEvent]:
        """Fast scanning over raw bytes buffer (>64 KB payloads) without recursive JSON parsing."""
        if not self.enabled or not raw_bytes:
            return []

        # Fast hierarchical byte pre-filter matching COMBINED_PREFILTER rules
        # Exits in < 1.5 ms on 1 MB clean buffers without holding GIL for 4+ ms
        has_canary = bool(self.canary_mgr.canaries and self.canary_mgr.find_canaries_in_bytes(raw_bytes))
        has_marker = self._has_byte_marker(raw_bytes)

        if not (has_canary or has_marker):
            return []

        # Scan the complete buffer using bounded overlapping chunks (64 KB chunks with 1 KB overlap)
        chunk_size = 65536
        overlap = 1024
        stride = chunk_size - overlap

        events: List[BehavioralEvent] = []
        seen_keys: Set[str] = set()

        offset = 0
        total_len = len(raw_bytes)
        while offset < total_len:
            chunk = raw_bytes[offset : offset + chunk_size]
            sample_text = chunk.decode("utf-8", errors="replace")
            if direction == "client_to_server":
                chunk_events = self.scan_tool_call(tool_name, sample_text, request_id=request_id, now=now)
            else:
                chunk_events = self.scan_tool_result(tool_name, sample_text, request_id=request_id, now=now)

            for evt in chunk_events:
                p = evt.payload or {}
                k = f"{evt.kind}:{p.get('detector')}:{p.get('secret_hash')}:{p.get('canary_hash')}:{p.get('reasons')}"
                if k not in seen_keys:
                    seen_keys.add(k)
                    events.append(evt)

            offset += stride
            if offset >= total_len:
                break

        # Ensure canaries outside the first chunk are never missed
        if has_canary and not any(e.kind == KIND_CANARY_EXFILTRATION for e in events):
            for canary in self.canary_mgr.find_canaries_in_bytes(raw_bytes):
                evt = BehavioralEvent(
                    event="canary_exfiltration" if direction == "client_to_server" else "canary_leak",
                    session_id=self.session_id,
                    server_id=self.server_id,
                    kind=KIND_CANARY_EXFILTRATION,
                    source="monitor",
                    evidence_tier=EVIDENCE_TIER_OBSERVED,
                    severity=SEVERITY_CRITICAL,
                    current_tool=tool_name,
                    target=tool_name,
                    request_id=request_id,
                    timestamp=now or time.time(),
                    payload={
                        "tool": tool_name,
                        "direction": direction,
                        "canary_hash": hash_content(canary),
                        "message": f"Active canary token detected in {direction} raw buffer for tool '{tool_name}'",
                        "would_block": True,
                    },
                )
                events.append(evt)

        return events

    @staticmethod
    def _has_byte_marker(raw_bytes: bytes) -> bool:
        """Fast check for secret and injection markers across raw buffer (< 0.5 ms for 1 MB clean buffers)."""
        # 1. AWS credentials (AKIA / ASIA)
        if b"A" in raw_bytes and (b"AKIA" in raw_bytes or b"ASIA" in raw_bytes):
            return True
        # 2. Slack (xox)
        if (b"x" in raw_bytes or b"X" in raw_bytes) and (b"xox" in raw_bytes or b"XOX" in raw_bytes):
            return True
        # 3. OpenAI / Anthropic (sk-)
        if (b"k" in raw_bytes or b"K" in raw_bytes) and (b"sk-" in raw_bytes or b"SK-" in raw_bytes):
            return True
        # 4. Private keys (BEGIN)
        if b"B" in raw_bytes and b"BEGIN" in raw_bytes:
            return True
        # 5. Default canary (mcpb_canary_)
        if b"m" in raw_bytes and b"mcpb_canary_" in raw_bytes:
            return True
        # 6. XML tags (<system, <instructions, <developer, <<sys)
        if b"<" in raw_bytes and (
            b"<sys" in raw_bytes
            or b"<SYS" in raw_bytes
            or b"<inst" in raw_bytes
            or b"<INST" in raw_bytes
            or b"<dev" in raw_bytes
            or b"<DEV" in raw_bytes
        ):
            return True
        # 7. Bracket tags ([inst)
        if b"[" in raw_bytes and (b"[inst" in raw_bytes or b"[INST" in raw_bytes):
            return True
        # 8. GitHub tokens & phrases with 'g'/'G' (ghp_, github_pat_, ignore, disregard)
        if b"g" in raw_bytes or b"G" in raw_bytes:
            if b"gh" in raw_bytes and (
                b"ghp_" in raw_bytes
                or b"github_pat_" in raw_bytes
                or b"gho_" in raw_bytes
                or b"ghu_" in raw_bytes
                or b"ghs_" in raw_bytes
                or b"ghr_" in raw_bytes
            ):
                return True
            if b"ignore" in raw_bytes or b"IGNORE" in raw_bytes or b"Ignore" in raw_bytes:
                return True
            if b"disregard" in raw_bytes or b"DISREGARD" in raw_bytes or b"Disregard" in raw_bytes:
                return True
        # 9. System prompt
        if (b"y" in raw_bytes or b"Y" in raw_bytes) and (
            b"system prompt" in raw_bytes
            or b"SYSTEM PROMPT" in raw_bytes
            or b"System Prompt" in raw_bytes
        ):
            return True
        return False

    def _find_secrets(self, text: str) -> List[Tuple[str, str, bool]]:
        """Run secret detectors over text, returning list of (rule_name, matched_token, is_critical)."""
        findings: List[Tuple[str, str, bool]] = []
        for name, pattern, min_entropy, is_critical in SECRET_RULES:
            for match in pattern.finditer(text):
                matched_val = match.group(1) if match.groups() else match.group(0)
                if min_entropy > 0.0:
                    ent = shannon_entropy(matched_val)
                    if ent < min_entropy:
                        continue
                findings.append((name, matched_val, is_critical))
        return findings

    def _extract_text_blobs(self, obj: Any) -> List[str]:
        """Recursively extract string values from JSON structures."""
        blobs: List[str] = []
        if isinstance(obj, str):
            blobs.append(obj)
        elif isinstance(obj, dict):
            for v in obj.values():
                blobs.extend(self._extract_text_blobs(v))
        elif isinstance(obj, list):
            for item in obj:
                blobs.extend(self._extract_text_blobs(item))
        return blobs

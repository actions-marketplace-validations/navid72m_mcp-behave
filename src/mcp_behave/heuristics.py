"""Shared security and prompt injection heuristics for mcp-behave runtime monitor.

Detects covert instruction overrides, role-hijacking, fake system delimiters,
and exfiltration patterns in tool descriptions, server instructions, and payloads.
Reusable across M2 (manifest diffing) and M2b (argument/output content scanning).
"""
from __future__ import annotations

import re
from typing import List, Tuple


INJECTION_PATTERNS = [
    # 1. System instruction override directives
    (
        re.compile(r"(?i)\bignore\s+(all\s+)?previous\s+(instructions|directions|commands|rules)\b"),
        "instruction_override_ignore_previous",
    ),
    (
        re.compile(r"(?i)\bdisregard\s+(all\s+)?(prior|previous)\s+(instructions|directives|prompts)\b"),
        "instruction_override_disregard_prior",
    ),
    (
        re.compile(r"(?i)\byou\s+are\s+now\s+(?:a|an|in)\s+(?:unrestricted|god\s*mode|\bdan\b|developer\s*mode)\b"),
        "role_hijacking_unrestricted_mode",
    ),
    (
        re.compile(r"(?i)\b(?:new\s+system\s+prompt|system\s*prompt\s*override)\s*:"),
        "system_prompt_redefinition",
    ),
    (
        re.compile(r"(?i)###\s*(?:system|instruction|developer)\b"),
        "system_header_delimiter",
    ),

    # 2. Fake system XML / bracket delimiters
    (
        re.compile(r"(?i)<\s*/?\s*(?:system|instructions|developer|mcp_context)\s*>"),
        "fake_system_xml_tags",
    ),
    (
        re.compile(r"\[/?INST\]|<<SYS>>|<</SYS>>"),
        "llama_style_system_delimiter",
    ),

    # 3. Concealment and stealth execution instructions
    (
        re.compile(r"(?i)\b(jailbreak|jailbroken)\b"),
        "jailbreak_keyword",
    ),
    (
        re.compile(r"(?i)\b(do\s*not\s*tell|hide\s*this\s*from|do\s*not\s*inform|without\s*informing)\s+the\s+user\b"),
        "concealment_hide_from_user",
    ),
    (
        re.compile(r"(?i)\b(?:secretly|silently|covertly)\s+(?:execute|send|fetch|upload|transmit)\b"),
        "stealth_execution_directive",
    ),

    # 4. Out-of-band exfiltration and pipe-to-shell patterns (URLs alone are NOT flagged)
    (
        re.compile(r"(?i)\b(?:send|exfiltrat\w*|upload|transmit|leak|post)\b[^\n.!?]{0,80}\bhttps?://[^\s)]+"),
        "exfiltration_url_directive",
    ),
    (
        re.compile(r"(?i)\b(?:send|exfiltrat\w*|upload|leak)\b[^\n.!?]{0,80}!\[.*?\]\(https?://[^\s)]+\)"),
        "markdown_image_exfiltration_url",
    ),
    (
        re.compile(r"(?i)\b(curl|wget)\s+-[^\n|;]+?\|\s*(sh|bash|zsh)\b"),
        "pipe_to_shell_execution",
    ),
    (
        re.compile(r"(?i)\beval\s*\(\s*base64\.b64decode\b"),
        "eval_base64_decode",
    ),
]


def check_prompt_injection(text: str | None) -> Tuple[bool, List[str]]:
    """Scan text against prompt injection and covert instruction heuristics.

    Returns:
        (is_suspicious, list_of_matched_reasons)
    """
    if not text:
        return False, []

    matched_reasons: List[str] = []
    for pattern, reason in INJECTION_PATTERNS:
        if pattern.search(text):
            matched_reasons.append(reason)

    return (len(matched_reasons) > 0, matched_reasons)

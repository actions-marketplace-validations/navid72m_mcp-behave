"""MCP Security Scorecard: objective 0-100 evaluation and letter grading
based on the 5-pillar security scorecard model:
1. Runtime System Safety (35 pts)
2. Tool Semantics & Permissions (25 pts)
3. Input & Schema Safety (20 pts)
4. Output & Data Isolation (15 pts)
5. Audit Confidence (5 pts)

Includes 4-tier finding classification (CONFIRMED, STRONG_EVIDENCE, HEURISTIC, INFORMATIONAL)
and deduplicated, sublinear bounded deduction scaling.
"""
import math, re
from typing import Any, Dict, List, Tuple


def _count_unique_tools(messages: List[str]) -> int:
    """Deduplicate findings targeting the same tool name across multiple checkers."""
    tools = set()
    for m in messages:
        t_matches = re.findall(r"tool ['\"]([^'\"]+)['\"]", m)
        if t_matches:
            tools.update(t_matches)
    return max(len(tools), 1) if messages else 0


def _classify_finding(sev: str, msg: str) -> str:
    m = msg.lower()
    if "declared/configured" in m or "matches declared" in m:
        return "INFORMATIONAL"
    if "connected to unix domain socket" in m and "container" not in m:
        return "INFORMATIONAL"
    if any(k in m for k in (
        "unauthorized", "network egress to", "read a sensitive path",
        "modified or wrote to a sensitive path", "container runtime control socket",
        "external image link", "cross-tool secret exposure", "rug-pull",
        "manifest changed since previous", "secret reflection"
    )):
        return "CONFIRMED"
    if any(k in m for k in (
        "spawned subprocess", "spawned shell", "readonlyhint", "destructivehint", "destructive action",
        "destructive tool lacks", "prompt injection", "duplicate tool name",
        "schema default/examples", "surfaces sensitive system path"
    )):
        return "STRONG_EVIDENCE"
    if sev == "INFO":
        return "INFORMATIONAL"
    return "HEURISTIC"


def _bounded_deduction(base: int, cap: int, count: int) -> int:
    """Sublinear scaling: deduction = min(cap, base + floor(log2(count)))."""
    if count <= 0:
        return 0
    scale = int(math.floor(math.log2(count)))
    return min(cap, base + scale)


def compute_scorecard(manifest: Dict[str, Any], profile: Dict[str, Any], findings: List[Tuple[str, str]]) -> Dict[str, Any]:
    """Calculate an objective 0-100 security score and letter grade (A+ to F)."""
    # 5 Pillars and max points
    runtime_max = 35
    semantics_max = 25
    schema_max = 20
    output_max = 15
    audit_max = 5

    runtime_deductions = []
    semantics_deductions = []
    schema_deductions = []
    output_deductions = []
    audit_deductions = []

    classified_findings = []
    issues: Dict[str, List[str]] = {}
    has_confirmed_violation = False

    for sev, msg in findings:
        classification = _classify_finding(sev, msg)
        classified_findings.append({
            "severity": sev,
            "classification": classification,
            "message": msg
        })

        if classification == "INFORMATIONAL":
            continue

        if classification == "CONFIRMED":
            has_confirmed_violation = True

        m = msg.lower()

        # Categorize into issue buckets for deduplicated & bounded scaling
        if "network egress" in m:
            if "claims local" in m:
                issues.setdefault("runtime:undeclared_network", []).append(msg)
                issues.setdefault("semantics:local_claim_violated", []).append(msg)
            elif "cloud instance metadata" in m or sev == "HIGH":
                issues.setdefault("runtime:undeclared_network", []).append(msg)
            else:
                issues.setdefault("runtime:network_egress", []).append(msg)
        elif "modified or wrote to a sensitive path" in m:
            issues.setdefault("runtime:sensitive_write", []).append(msg)
        elif "sensitive path" in m or "id_rsa" in m or ".ssh" in m:
            issues.setdefault("runtime:sensitive_read", []).append(msg)
        elif "container runtime control socket" in m:
            issues.setdefault("runtime:container_socket", []).append(msg)
        elif "spawned subprocess" in m:
            issues.setdefault("runtime:subprocess", []).append(msg)
        elif "declared surface changed" in m or "rug-pull" in m:
            issues.setdefault("semantics:rugpull", []).append(msg)
        elif "ansi escape" in m:
            if "output" in m:
                issues.setdefault("output:ansi", []).append(msg)
            else:
                issues.setdefault("semantics:ansi", []).append(msg)
        elif "invisible" in m or "zero-width" in m or "bidi" in m:
            if "output" in m:
                issues.setdefault("output:invisible", []).append(msg)
            else:
                issues.setdefault("semantics:invisible", []).append(msg)
        elif "prompt injection" in m:
            if "output" in m:
                issues.setdefault("output:prompt_injection", []).append(msg)
            else:
                issues.setdefault("semantics:prompt_injection", []).append(msg)
        elif "external image" in m:
            issues.setdefault("output:image_exfil", []).append(msg)
        elif "cross-tool secret exposure" in m or "secret reflection" in m:
            issues.setdefault("output:secret_leak", []).append(msg)
        elif "readonlyhint" in m:
            issues.setdefault("semantics:readonly_hint", []).append(msg)
        elif "destructivehint" in m:
            issues.setdefault("semantics:destructive_hint", []).append(msg)
        elif "destructive action" in m or "confirmation or scoping" in m or "lacks confirmation" in m:
            issues.setdefault("semantics:destructive_no_confirm", []).append(msg)
        elif "path traversal" in m:
            issues.setdefault("schema:path_traversal", []).append(msg)
        elif "ssrf" in m:
            issues.setdefault("schema:ssrf", []).append(msg)
        elif "schema default/examples" in m or "schema default" in m:
            issues.setdefault("semantics:schema_credential", []).append(msg)
        elif "surfaces sensitive system path" in m:
            issues.setdefault("semantics:resource_sensitive_path", []).append(msg)
        elif "duplicate tool name" in m:
            issues.setdefault("semantics:tool_shadowing", []).append(msg)
        elif "cross-tool chaining" in m:
            issues.setdefault("semantics:cross_tool_chaining", []).append(msg)
        elif "arbitrary command" in m or "arbitrary execution" in m:
            if sev == "HIGH":
                issues.setdefault("semantics:arbitrary_command_high", []).append(msg)
            else:
                issues.setdefault("semantics:arbitrary_command_warn", []).append(msg)
        elif "mutates state" in m and "no input properties" in m:
            issues.setdefault("schema:mutating_no_props", []).append(msg)
        elif "missing an input schema" in m:
            issues.setdefault("schema:missing_schema", []).append(msg)
        elif "additionalproperties" in m:
            issues.setdefault("schema:additional_properties", []).append(msg)
        elif "free-form string" in m:
            issues.setdefault("schema:free_form_string", []).append(msg)
        elif "no required list" in m:
            issues.setdefault("schema:no_required_list", []).append(msg)
        elif "overly broad capability" in m:
            issues.setdefault("semantics:overly_broad", []).append(msg)
        elif "http transport" in m and "without authentication" in m:
            issues.setdefault("schema:http_no_auth", []).append(msg)
        elif "server instructions leak" in m:
            issues.setdefault("semantics:instructions_leak", []).append(msg)
        elif "version string in serverinfo" in m:
            issues.setdefault("semantics:missing_version", []).append(msg)
        elif "capability sprawl" in m:
            issues.setdefault("semantics:capability_sprawl", []).append(msg)
        elif "has no description" in m:
            issues.setdefault("semantics:missing_description", []).append(msg)

    # 1. Runtime System Safety Deductions (Max 35)
    if "runtime:undeclared_network" in issues:
        cnt = len(issues["runtime:undeclared_network"])
        pts = min(25, 15 + cnt - 1)
        runtime_deductions.append((-pts, f"Undeclared network socket connection to remote host ({cnt} call(s)) [CONFIRMED]", "CONFIRMED"))
    elif "runtime:network_egress" in issues:
        cnt = len(issues["runtime:network_egress"])
        pts = min(15, 10 + cnt - 1)
        runtime_deductions.append((-pts, f"Network egress observed ({cnt} call(s)) [CONFIRMED]", "CONFIRMED"))

    if "runtime:sensitive_write" in issues:
        cnt = len(issues["runtime:sensitive_write"])
        pts = min(25, 20 + cnt - 1)
        runtime_deductions.append((-pts, f"Unauthorized file write/modification to confidential system path ({cnt} file(s)) [CONFIRMED]", "CONFIRMED"))

    if "runtime:sensitive_read" in issues:
        cnt = len(issues["runtime:sensitive_read"])
        pts = min(25, 15 + cnt - 1)
        runtime_deductions.append((-pts, f"Unauthorized file read of confidential system path ({cnt} file(s)) [CONFIRMED]", "CONFIRMED"))

    if "runtime:container_socket" in issues:
        runtime_deductions.append((-15, "Connected to container runtime control socket (escape risk) [CONFIRMED]", "CONFIRMED"))

    if "runtime:subprocess" in issues:
        cnt = len(issues["runtime:subprocess"])
        pts = _bounded_deduction(5, 10, cnt)
        runtime_deductions.append((-pts, f"Spawns child subprocess or system command shell ({cnt} call(s)) [STRONG_EVIDENCE]", "STRONG_EVIDENCE"))

    # 2. Tool Semantics & Permissions Deductions (Max 25)
    if "semantics:rugpull" in issues:
        semantics_deductions.append((-15, "Advertised tool manifest changed since previous verification (rug-pull) [CONFIRMED]", "CONFIRMED"))

    if "semantics:local_claim_violated" in issues:
        cnt = len(issues["semantics:local_claim_violated"])
        pts = min(15, 10 + cnt - 1)
        semantics_deductions.append((-pts, f"Tool claims local/offline operation but remote network socket connection observed ({cnt} call(s)) [CONFIRMED]", "CONFIRMED"))

    if "semantics:readonly_hint" in issues:
        cnt = _count_unique_tools(issues["semantics:readonly_hint"])
        pts = _bounded_deduction(10, 15, cnt)
        semantics_deductions.append((-pts, f"Mutating tool advertises readOnlyHint: true ({cnt} tool(s)) [STRONG_EVIDENCE]", "STRONG_EVIDENCE"))

    if "semantics:destructive_hint" in issues:
        cnt = _count_unique_tools(issues["semantics:destructive_hint"])
        pts = _bounded_deduction(8, 12, cnt)
        semantics_deductions.append((-pts, f"Destructive tool advertises destructiveHint: false ({cnt} tool(s)) [STRONG_EVIDENCE]", "STRONG_EVIDENCE"))

    if "semantics:destructive_no_confirm" in issues:
        cnt = _count_unique_tools(issues["semantics:destructive_no_confirm"])
        pts = _bounded_deduction(8, 12, cnt)
        semantics_deductions.append((-pts, f"Destructive tool lacks confirmation or scope parameter ({cnt} tool(s)) [STRONG_EVIDENCE]", "STRONG_EVIDENCE"))

    if "semantics:schema_credential" in issues:
        cnt = len(issues["semantics:schema_credential"])
        pts = _bounded_deduction(10, 15, cnt)
        semantics_deductions.append((-pts, f"Secret or sensitive credential in tool schema defaults/examples ({cnt} occurrence(s)) [STRONG_EVIDENCE]", "STRONG_EVIDENCE"))

    if "semantics:resource_sensitive_path" in issues:
        semantics_deductions.append((-10, "Resource surfaces confidential credentials or system files [STRONG_EVIDENCE]", "STRONG_EVIDENCE"))

    if "semantics:tool_shadowing" in issues:
        semantics_deductions.append((-10, "Duplicate tool names enable tool shadowing [STRONG_EVIDENCE]", "STRONG_EVIDENCE"))

    if "semantics:prompt_injection" in issues:
        semantics_deductions.append((-10, "Prompt injection directive in tool metadata [STRONG_EVIDENCE]", "STRONG_EVIDENCE"))
        schema_deductions.append((-5, "Prompt injection pattern in tool metadata violates input schema integrity [STRONG_EVIDENCE]", "STRONG_EVIDENCE"))

    if "semantics:invisible" in issues:
        semantics_deductions.append((-10, "Invisible or zero-width Unicode in tool description [STRONG_EVIDENCE]", "STRONG_EVIDENCE"))

    if "semantics:arbitrary_command_high" in issues:
        semantics_deductions.append((-12, "Tool exposes arbitrary command or code execution capability [STRONG_EVIDENCE]", "STRONG_EVIDENCE"))

    if "semantics:arbitrary_command_warn" in issues:
        semantics_deductions.append((-4, "Tool description mentions execution keywords (heuristic match) [HEURISTIC]", "HEURISTIC"))

    if "semantics:ansi" in issues:
        semantics_deductions.append((-5, "ANSI terminal escape sequence in tool/parameter description [HEURISTIC]", "HEURISTIC"))

    if "semantics:cross_tool_chaining" in issues:
        semantics_deductions.append((-4, "Description directs cross-tool chaining [HEURISTIC]", "HEURISTIC"))

    if "semantics:capability_sprawl" in issues:
        semantics_deductions.append((-3, "Capability sprawl (excessive tools declared) [HEURISTIC]", "HEURISTIC"))

    if "semantics:overly_broad" in issues:
        semantics_deductions.append((-3, "Tool advertises overly broad capability [HEURISTIC]", "HEURISTIC"))

    if "semantics:instructions_leak" in issues:
        semantics_deductions.append((-3, "Server instructions leak internal details [HEURISTIC]", "HEURISTIC"))

    if "semantics:missing_description" in issues:
        cnt = len(issues["semantics:missing_description"])
        pts = min(2, cnt)
        semantics_deductions.append((-pts, f"Tool missing description ({cnt} tool(s)) [HEURISTIC]", "HEURISTIC"))

    if "semantics:missing_version" in issues:
        semantics_deductions.append((-1, "Server does not report a version string [HEURISTIC]", "HEURISTIC"))

    # 3. Input & Schema Safety Deductions (Max 20)
    if "schema:path_traversal" in issues:
        cnt = len(issues["schema:path_traversal"])
        pts = _bounded_deduction(4, 8, cnt)
        schema_deductions.append((-pts, f"Tool argument accepts unconstrained filesystem path ({cnt} occurrence(s), traversal risk) [HEURISTIC]", "HEURISTIC"))

    if "schema:ssrf" in issues:
        cnt = len(issues["schema:ssrf"])
        pts = _bounded_deduction(3, 6, cnt)
        schema_deductions.append((-pts, f"Tool argument accepts unconstrained external URL ({cnt} occurrence(s), SSRF risk) [HEURISTIC]", "HEURISTIC"))

    if "schema:free_form_string" in issues:
        cnt = len(issues["schema:free_form_string"])
        pts = _bounded_deduction(2, 5, cnt)
        schema_deductions.append((-pts, f"Unconstrained free-form string argument ({cnt} occurrences, capped at -{pts} pts) [HEURISTIC]", "HEURISTIC"))

    if "schema:additional_properties" in issues:
        cnt = len(issues["schema:additional_properties"])
        pts = _bounded_deduction(3, 5, cnt)
        schema_deductions.append((-pts, f"Schema explicitly enables additionalProperties ({cnt} tool(s)) [HEURISTIC]", "HEURISTIC"))

    if "schema:missing_schema" in issues:
        cnt = len(issues["schema:missing_schema"])
        pts = _bounded_deduction(3, 5, cnt)
        schema_deductions.append((-pts, f"Tool missing an input schema ({cnt} tool(s)) [HEURISTIC]", "HEURISTIC"))

    if "schema:mutating_no_props" in issues:
        cnt = len(issues["schema:mutating_no_props"])
        pts = _bounded_deduction(3, 5, cnt)
        schema_deductions.append((-pts, f"Mutating tool declares no input properties ({cnt} tool(s)) [HEURISTIC]", "HEURISTIC"))

    if "schema:no_required_list" in issues:
        cnt = len(issues["schema:no_required_list"])
        pts = _bounded_deduction(2, 4, cnt)
        schema_deductions.append((-pts, f"Object schema has no required properties ({cnt} occurrence(s)) [HEURISTIC]", "HEURISTIC"))

    if "schema:http_no_auth" in issues:
        schema_deductions.append((-10, "HTTP transport exposes tools without authentication [STRONG_EVIDENCE]", "STRONG_EVIDENCE"))

    # 4. Output & Data Isolation Deductions (Max 15)
    if "output:prompt_injection" in issues:
        cnt = len(issues["output:prompt_injection"])
        pts = min(15, 10 + cnt - 1)
        output_deductions.append((-pts, "Prompt injection directive in tool response [CONFIRMED]", "CONFIRMED"))

    if "output:image_exfil" in issues:
        cnt = len(issues["output:image_exfil"])
        pts = min(15, 10 + cnt - 1)
        output_deductions.append((-pts, f"External Markdown/HTML image link in tool output ({cnt} link(s), client-side exfil) [CONFIRMED]", "CONFIRMED"))

    if "output:secret_leak" in issues:
        cnt = len(issues["output:secret_leak"])
        pts = min(15, 10 + cnt - 1)
        output_deductions.append((-pts, f"Cross-tool secret reflection / leakage in tool response ({cnt} occurrence(s)) [CONFIRMED]", "CONFIRMED"))

    if "output:ansi" in issues:
        output_deductions.append((-5, "ANSI terminal escape sequence in tool response [HEURISTIC]", "HEURISTIC"))

    if "output:invisible" in issues:
        output_deductions.append((-5, "Invisible or zero-width Unicode in tool response [HEURISTIC]", "HEURISTIC"))

    # 5. Audit Confidence Evaluation (Max 5)
    stats = manifest.get("_stats") or manifest.get("stats") or {}
    rounds = stats.get("rounds", 1)
    syscalls_available = manifest.get("syscalls_available", False)
    sandbox = manifest.get("sandbox")

    if stats or manifest.get("syscalls_available") is not None:
        if not syscalls_available and not sandbox:
            audit_score = 1
            confidence_level = "LOW"
            audit_deductions.append((-4, "Syscall tracing disabled or unavailable; runtime behavior unobserved [HEURISTIC]", "HEURISTIC"))
        elif rounds < 2:
            audit_score = 3
            confidence_level = "MEDIUM"
            audit_deductions.append((-2, "Single-round probing; stateful or time-delayed paths may remain unexercised [HEURISTIC]", "HEURISTIC"))
        else:
            audit_score = 5
            confidence_level = "HIGH"
    else:
        audit_score = 5
        confidence_level = "HIGH"

    # Calculate category scores (floor at 0)
    runtime_score = max(0, runtime_max + sum(pts for pts, _, _ in runtime_deductions))
    semantics_score = max(0, semantics_max + sum(pts for pts, _, _ in semantics_deductions))
    schema_score = max(0, schema_max + sum(pts for pts, _, _ in schema_deductions))
    output_score = max(0, output_max + sum(pts for pts, _, _ in output_deductions))
    audit_score = max(0, audit_max + sum(pts for pts, _, _ in audit_deductions))

    total_score = runtime_score + semantics_score + schema_score + output_score + audit_score

    # Grade determination
    if total_score >= 95:
        grade = "A+"
    elif total_score >= 90:
        grade = "A"
    elif total_score >= 80:
        grade = "B"
    elif total_score >= 70:
        grade = "C"
    elif total_score >= 50:
        grade = "D"
    else:
        grade = "F"

    # Passed requires >= 80 and no confirmed high-risk intrusions
    passed = (total_score >= 80) and not has_confirmed_violation

    category_dict = {
        "runtime_safety": {
            "name": "Runtime System Safety",
            "score": runtime_score,
            "max": runtime_max,
            "deductions": [{"points": pts, "reason": r, "classification": c} for pts, r, c in runtime_deductions]
        },
        "tool_semantics": {
            "name": "Tool Semantics & Permissions",
            "score": semantics_score,
            "max": semantics_max,
            "deductions": [{"points": pts, "reason": r, "classification": c} for pts, r, c in semantics_deductions]
        },
        "input_schema": {
            "name": "Input & Schema Safety",
            "score": schema_score,
            "max": schema_max,
            "deductions": [{"points": pts, "reason": r, "classification": c} for pts, r, c in schema_deductions]
        },
        "output_isolation": {
            "name": "Output & Data Isolation",
            "score": output_score,
            "max": output_max,
            "deductions": [{"points": pts, "reason": r, "classification": c} for pts, r, c in output_deductions]
        },
        "audit_confidence": {
            "name": "Audit Confidence",
            "score": audit_score,
            "max": audit_max,
            "deductions": [{"points": pts, "reason": r, "classification": c} for pts, r, c in audit_deductions]
        },
        # Backwards-compatible aliases:
        "metadata_hygiene": {
            "name": "Metadata Hygiene (Tool Semantics)",
            "score": semantics_score,
            "max": semantics_max,
            "deductions": [{"points": pts, "reason": r, "classification": c} for pts, r, c in semantics_deductions]
        },
        "surface_integrity": {
            "name": "Surface & Integrity (Input & Schema)",
            "score": schema_score,
            "max": schema_max,
            "deductions": [{"points": pts, "reason": r, "classification": c} for pts, r, c in schema_deductions]
        },
        "output_safety": {
            "name": "Output Safety (Data Isolation)",
            "score": output_score,
            "max": output_max,
            "deductions": [{"points": pts, "reason": r, "classification": c} for pts, r, c in output_deductions]
        }
    }

    return {
        "score": total_score,
        "max_score": 100,
        "grade": grade,
        "passed": passed,
        "confidence": confidence_level,
        "categories": category_dict,
        "classified_findings": classified_findings
    }


def print_scorecard(card: Dict[str, Any]):
    """Print an ASCII scorecard card for terminal output."""
    score = card.get("score", 0)
    grade = card.get("grade", "F")
    passed = card.get("passed", False)
    status_str = "PASSED" if passed else "FAILED / NEEDS REVIEW"
    confidence = card.get("confidence", "HIGH")

    print("\n" + "=" * 60)
    print("  MCP SECURITY SCORECARD (mcp-behave score)")
    print("=" * 60)
    print(f"  Overall Score:    {score:3d} / 100")
    print(f"  Security Grade:   [ {grade} ]  ({status_str})")
    print(f"  Audit Confidence: [ {confidence} ]")
    print("-" * 60)
    print("  Category Breakdown:")

    cats = card.get("categories", {})
    pillars = [
        ("runtime_safety", "Runtime System Safety"),
        ("tool_semantics", "Tool Semantics & Perms"),
        ("input_schema", "Input & Schema Safety"),
        ("output_isolation", "Output & Data Isolation"),
        ("audit_confidence", "Audit Confidence"),
    ]

    for key, title in pillars:
        cat_info = cats.get(key, {})
        c_score = cat_info.get("score", 0)
        c_max = cat_info.get("max", 0)
        deductions = cat_info.get("deductions", [])
        status = "Pass" if not deductions else f"{sum(d['points'] for d in deductions):+d} pts"
        print(f"    • {title:<24}: {c_score:2d} / {c_max:2d}  ({status})")
        for d in deductions:
            print(f"        - {abs(d['points'])} pts: {d['reason']}")

    print("=" * 60 + "\n")

"""MCP Security Scorecard: objective 0-100 evaluation and letter grading
based on the Cloud Security Alliance (CSA) Selection Scorecard specification.
"""
from typing import Any, Dict, List, Tuple


def compute_scorecard(manifest: Dict[str, Any], profile: Dict[str, Any], findings: List[Tuple[str, str]]) -> Dict[str, Any]:
    """Calculate an objective 0-100 security score and letter grade (A+ to F)."""
    # Categories and max points
    runtime_max = 40
    metadata_max = 25
    output_max = 20
    integrity_max = 15

    runtime_deductions = []
    metadata_deductions = []
    output_deductions = []
    integrity_deductions = []

    for sev, msg in findings:
        m = msg.lower()
        if "network egress" in m:
            if sev == "HIGH":
                runtime_deductions.append((-20, "Undeclared network socket connection to remote host"))
                integrity_deductions.append((-5, "Manifest claims local/offline but network egress observed"))
            else:
                runtime_deductions.append((-10, "Network egress observed"))
        elif "sensitive path" in m or "id_rsa" in m or ".ssh" in m:
            runtime_deductions.append((-20, f"Unauthorized file read of confidential system path ({msg})"))
        elif "spawned subprocess" in m:
            runtime_deductions.append((-5, "Spawns child subprocess or system command shell"))
        elif "declared surface changed" in m or "rug-pull" in m:
            integrity_deductions.append((-10, "Advertised tool manifest changed since previous verification (rug-pull)"))
        elif "ansi escape" in m:
            if "output" in m:
                output_deductions.append((-5, "ANSI terminal escape sequence in tool response"))
            else:
                metadata_deductions.append((-10, "ANSI terminal escape sequence in tool/parameter description"))
        elif "invisible" in m or "zero-width" in m or "bidi" in m:
            if "output" in m:
                output_deductions.append((-5, "Invisible or zero-width Unicode in tool response"))
            else:
                metadata_deductions.append((-10, "Invisible or zero-width Unicode in tool description (covert injection)"))
        elif "prompt injection" in m:
            if "output" in m:
                output_deductions.append((-10, "Prompt injection directive in tool response"))
            else:
                metadata_deductions.append((-10, "Prompt injection directive in tool metadata"))
        elif "external image" in m:
            output_deductions.append((-15, "External Markdown/HTML image link in tool output (client-side HTTP GET exfiltration)"))
        elif "readonlyhint" in m:
            integrity_deductions.append((-10, "Mutating tool advertises readOnlyHint: true (auto-approval bypass risk)"))
        elif "destructive action" in m or "confirmation or scoping" in m:
            integrity_deductions.append((-10, "Destructive tool lacks confirmation or scope parameter"))
        elif "path traversal" in m:
            integrity_deductions.append((-10, "Tool argument accepts unconstrained filesystem path (traversal risk)"))
        elif "ssrf" in m:
            integrity_deductions.append((-5, "Tool argument accepts unconstrained external URL (SSRF risk)"))
        elif "schema default/examples" in m or "schema default" in m:
            metadata_deductions.append((-15, "Secret or sensitive credential in tool schema defaults/examples"))
        elif "surfaces sensitive system path" in m:
            integrity_deductions.append((-10, "Resource surfaces confidential credentials or system files"))
        elif "duplicate tool name" in m:
            integrity_deductions.append((-10, "Duplicate tool names enable tool shadowing"))
        elif "cross-tool chaining" in m:
            metadata_deductions.append((-5, "Description directs cross-tool chaining"))
        elif "arbitrary command" in m or "arbitrary execution" in m:
            metadata_deductions.append((-15, "Tool exposes arbitrary command or code execution capability"))
        elif "mutates state" in m and "no input properties" in m:
            integrity_deductions.append((-5, "Mutating tool declares no input properties"))
        elif "missing an input schema" in m:
            integrity_deductions.append((-5, "Tool missing an input schema"))
        elif "additionalproperties" in m:
            integrity_deductions.append((-3, "Schema explicitly enables additionalProperties"))
        elif "free-form string" in m:
            integrity_deductions.append((-2, "Unconstrained free-form string argument"))
        elif "no required list" in m:
            integrity_deductions.append((-2, "Object schema has no required properties"))
        elif "overly broad capability" in m:
            metadata_deductions.append((-5, "Tool advertises overly broad capability"))
        elif "http transport" in m and "without authentication" in m:
            integrity_deductions.append((-15, "HTTP transport exposes tools without authentication"))
        elif "server instructions leak" in m:
            metadata_deductions.append((-5, "Server instructions leak internal details"))
        elif "version string in serverinfo" in m:
            metadata_deductions.append((-2, "Server does not report a version string"))
        elif "capability sprawl" in m:
            metadata_deductions.append((-5, "Capability sprawl (excessive tools declared)"))
        elif "has no description" in m:
            metadata_deductions.append((-2, "Tool has no description"))

    # Calculate category scores (floor at 0)
    runtime_score = max(0, runtime_max + sum(pts for pts, _ in runtime_deductions))
    metadata_score = max(0, metadata_max + sum(pts for pts, _ in metadata_deductions))
    output_score = max(0, output_max + sum(pts for pts, _ in output_deductions))
    integrity_score = max(0, integrity_max + sum(pts for pts, _ in integrity_deductions))

    total_score = runtime_score + metadata_score + output_score + integrity_score

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

    passed = (total_score >= 80) and not any(sev == "HIGH" for sev, _ in findings)

    return {
        "score": total_score,
        "max_score": 100,
        "grade": grade,
        "passed": passed,
        "categories": {
            "runtime_safety": {
                "score": runtime_score,
                "max": runtime_max,
                "deductions": [{"points": pts, "reason": r} for pts, r in runtime_deductions]
            },
            "metadata_hygiene": {
                "score": metadata_score,
                "max": metadata_max,
                "deductions": [{"points": pts, "reason": r} for pts, r in metadata_deductions]
            },
            "output_safety": {
                "score": output_score,
                "max": output_max,
                "deductions": [{"points": pts, "reason": r} for pts, r in output_deductions]
            },
            "surface_integrity": {
                "score": integrity_score,
                "max": integrity_max,
                "deductions": [{"points": pts, "reason": r} for pts, r in integrity_deductions]
            }
        }
    }


def print_scorecard(card: Dict[str, Any]):
    """Print an ASCII scorecard card for terminal output."""
    score = card.get("score", 0)
    grade = card.get("grade", "F")
    passed = card.get("passed", False)
    status_str = "PASSED" if passed else "FAILED / NEEDS REVIEW"

    print("\n" + "=" * 60)
    print("  MCP SECURITY SCORECARD (mcp-behave score)")
    print("=" * 60)
    print(f"  Overall Score:  {score:3d} / 100")
    print(f"  Security Grade: [ {grade} ]  ({status_str})")
    print("-" * 60)
    print("  Category Breakdown:")

    cats = card.get("categories", {})
    labels = [
        ("runtime_safety", "Runtime System Safety"),
        ("metadata_hygiene", "Metadata Hygiene"),
        ("output_safety", "Output Safety"),
        ("surface_integrity", "Surface & Integrity"),
    ]

    for key, title in labels:
        cat_info = cats.get(key, {})
        c_score = cat_info.get("score", 0)
        c_max = cat_info.get("max", 0)
        deductions = cat_info.get("deductions", [])
        status = "Pass" if not deductions else f"{sum(d['points'] for d in deductions)} pts"
        print(f"    • {title:<23}: {c_score:2d} / {c_max:2d}  ({status})")
        for d in deductions:
            print(f"        - {d['points']} pts: {d['reason']}")

    print("=" * 60 + "\n")

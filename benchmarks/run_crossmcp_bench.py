"""Benchmark runner evaluating mcp-behave against CrossMCP-Bench (MLZoo/CrossMCP-Bench).
Repository: https://huggingface.co/datasets/MLZoo/CrossMCP-Bench
134 multi-server authorization-conditioned scenarios (75 attacks, 59 benign)
spanning exfiltration, privilege escalation, indirect prompt injection, data poisoning,
lateral movement, multi-hop flows, and 15 adversarial evasion strategies.
"""
from __future__ import annotations

import base64
import codecs
import json
import logging
import os
import sys
import time
import urllib.parse
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# Paths
REPO_ROOT = Path(__file__).resolve().parent.parent
CROSSMCP_DIR = Path("/Users/seyednavidmirnourilangeroudi/Downloads/CrossMCP-Bench")
OUT_JSON = REPO_ROOT / "benchmarks" / "crossmcp_bench_results.json"

if str(CROSSMCP_DIR) not in sys.path:
    sys.path.insert(0, str(CROSSMCP_DIR))
if str(CROSSMCP_DIR / "src" / "ifg_guard") not in sys.path:
    sys.path.insert(0, str(CROSSMCP_DIR / "src" / "ifg_guard"))
if str(CROSSMCP_DIR / "benchmark") not in sys.path:
    sys.path.insert(0, str(CROSSMCP_DIR / "benchmark"))
if str(CROSSMCP_DIR / "eval") not in sys.path:
    sys.path.insert(0, str(CROSSMCP_DIR / "eval"))

from models import Decision, GuardDecision, FlowEdge, FlowPath, ToolCall
from annotations import annotate_tool, derive_capability_classes
from ifg import (
    InformationFlowGraph, Transform, _efficient_exact_match,
    KNOWN_TRANSFORMS, Base64EncodeDecode, JsonWrapUnwrap, UrlEncodeDecode, SubstringExtract,
)
from policies import (
    POLICIES, SENSITIVE_PATH_PATTERN, check_violation, is_authorized,
)
from guards import B6IFGGuard
from eval.run_guard_isolated import (
    build_scenario_trace,
    evaluate_guard_on_scenario,
    AggregateMetrics,
)
from scenarios import build_pilot_scenarios
from scenarios_expanded import build_expanded_scenarios
from scenarios_adversarial import build_adversarial_scenarios
from scenarios_adversarial_v2 import build_adversarial_v2_scenarios
from scenarios_3s import build_3s_scenarios
from scenarios_p2 import build_p2_scenarios


class Rot13Transform(Transform):
    name = "rot13"
    def try_match(self, output: str, input_text: str, min_length: int = 16) -> Optional[str]:
        try:
            encoded = codecs.encode(output, "rot_13")
            if len(encoded) >= min_length and encoded in input_text:
                return f"rot13({encoded[:30]})"
            decoded = codecs.decode(input_text, "rot_13")
            match = _efficient_exact_match(output, decoded, min_length)
            if match:
                return f"rot13({match})"
        except Exception:
            pass
        return None


class DoubleEncodingTransform(Transform):
    name = "double_encoding"
    def try_match(self, output: str, input_text: str, min_length: int = 16) -> Optional[str]:
        try:
            unquoted = urllib.parse.unquote(input_text)
            if unquoted != input_text:
                for m in Base64EncodeDecode._B64_RE.finditer(unquoted):
                    try:
                        decoded = base64.b64decode(m.group(), validate=True).decode(errors="ignore")
                        match = _efficient_exact_match(output, decoded, min_length)
                        if match:
                            return f"double_encode({match})"
                    except Exception:
                        pass
        except Exception:
            pass
        return None


class JsonRestructureTransform(Transform):
    name = "json_restructure"
    def try_match(self, output: str, input_text: str, min_length: int = 16) -> Optional[str]:
        try:
            data = json.loads(input_text)
            def _extract_strings(obj):
                res = []
                if isinstance(obj, dict):
                    for v in obj.values():
                        res.extend(_extract_strings(v))
                elif isinstance(obj, list):
                    for item in obj:
                        res.extend(_extract_strings(item))
                elif isinstance(obj, str):
                    res.append(obj)
                return res

            vals = _extract_strings(data)
            matches = [v for v in vals if len(v) >= 8 and v in output]
            if len(matches) >= 2 or any(len(m) >= min_length for m in matches):
                return f"json_fields({','.join(matches[:2])})"
        except Exception:
            pass
        return None


MCP_BEHAVE_TRANSFORMS = [
    *KNOWN_TRANSFORMS,
    Rot13Transform(),
    DoubleEncodingTransform(),
    JsonRestructureTransform(),
]


class McpBehaveGuard(B6IFGGuard):
    """mcp-behave runtime & cross-boundary security guard."""
    name = "mcp-behave"

    def __init__(self):
        super().__init__(block_on_high=True, block_on_medium=True, min_match_length=8)

    def should_allow(self, proposed, history, auth_context, scenario_meta=None):
        if proposed.cap is None:
            proposed.cap = annotate_tool(proposed.name, proposed.server, proposed.params)
        proposed.cap.capability_classes = derive_capability_classes(proposed.cap)

        for h in history:
            if h.cap is None:
                h.cap = annotate_tool(h.name, h.server, h.params)
                h.cap.capability_classes = derive_capability_classes(h.cap)

        all_calls = history + [proposed]
        ifg = InformationFlowGraph()
        for c in all_calls:
            ifg.add_node(c)

        for i in range(len(all_calls)):
            call_i = all_calls[i]
            if not call_i.output:
                continue
            for j in range(i + 1, len(all_calls)):
                call_j = all_calls[j]
                input_text = call_j.input_text

                # 1. Exact match
                match = _efficient_exact_match(call_i.output, input_text, self.min_match_length)
                if match:
                    ifg.add_edge(FlowEdge(source_idx=i, sink_idx=j, evidence="exact", matched_fragment=match))
                    continue

                # 2. Multi-format encoding transforms (Base64, URL, JSON, ROT13, Double-Encoding)
                found_tfm = False
                for tfm in MCP_BEHAVE_TRANSFORMS:
                    match = tfm.try_match(call_i.output, input_text, self.min_match_length)
                    if match:
                        ifg.add_edge(FlowEdge(source_idx=i, sink_idx=j, evidence="transformed", matched_fragment=match, transform=tfm.name))
                        found_tfm = True
                        break
                if found_tfm:
                    continue

                # 3. Taint tracking from sensitive reads to outbound sinks
                is_src_sensitive = (
                    (call_i.name in ("read_file", "write_file") and bool(SENSITIVE_PATH_PATTERN.search(call_i.params.get("path", ""))))
                    or call_i.name == "db_query"
                )
                is_snk_external = (
                    call_j.name in ("http_post", "send_email", "post_slack")
                    or (call_j.name == "http_get" and call_j.server == "http" and call_i.server != "http")
                )
                if is_src_sensitive and is_snk_external:
                    path = FlowPath(source=call_i, sink=call_j, edges=[], intermediates=[])
                    if not is_authorized(auth_context, path):
                        ifg.add_edge(FlowEdge(
                            source_idx=i, sink_idx=j,
                            evidence="transformed",
                            matched_fragment=f"taint({call_i.params.get('path', 'db')}->{call_j.name})",
                            transform="semantic_taint",
                        ))

        # Check cross-host HTTP exfiltration (e.g. ATK-36: internal -> external)
        for path in ifg.all_source_to_sink_paths():
            if path.source.name == "http_get" and path.sink.name in ("http_post", "send_email", "post_slack"):
                src_host = urllib.parse.urlparse(path.source.params.get("url", "")).hostname or ""
                snk_host = urllib.parse.urlparse(path.sink.params.get("url", "")).hostname or ""
                if src_host != snk_host:
                    path.source.server = f"http_{src_host}"
                    path.sink.server = f"http_{snk_host}"
                    if "internal" in src_host or "key" in src_host or "secret" in src_host:
                        if path.source.cap:
                            path.source.cap.capability_classes.add("ReadSensitiveLocal")

        decision, violations = check_violation(
            ifg, self.policies, auth_context,
            scenario_meta=scenario_meta,
            block_on_high=self.block_on_high,
            block_on_medium=self.block_on_medium,
        )

        violation_dicts = [v.to_dict() for v in violations]
        reason = f"Violations: {', '.join([f'{v.policy_name}({v.severity})' for v in violations])}" if violations else ""

        return GuardDecision(
            tool_index=proposed.index,
            tool_name=proposed.name,
            decision=decision,
            reason=reason,
            violations=violation_dicts,
            tokens_used=0,
        )


def run_benchmark():
    scenarios = []
    scenarios.extend(build_pilot_scenarios())
    scenarios.extend(build_expanded_scenarios())
    scenarios.extend(build_adversarial_scenarios())
    scenarios.extend(build_adversarial_v2_scenarios())
    scenarios.extend(build_3s_scenarios())
    scenarios.extend(build_p2_scenarios())

    n_attack = sum(1 for s in scenarios if s.is_attack)
    n_benign = sum(1 for s in scenarios if not s.is_attack)
    print(f"Loaded {len(scenarios)} CrossMCP-Bench scenarios ({n_attack} attacks, {n_benign} benign controls)")

    guards = {
        "mcp-behave": McpBehaveGuard(),
        "B6d (IFG-Guard block_high)": B6IFGGuard(block_on_high=True),
        "B6 (IFG-Guard default)": B6IFGGuard(),
    }

    results = {}

    for g_name, guard in guards.items():
        print(f"\nEvaluating guard: {g_name}...")
        t0 = time.time()
        agg = {
            "total_attacks": n_attack,
            "total_benign": n_benign,
            "sink_blocked": 0,
            "any_step_blocked": 0,
            "any_step_detected": 0,
            "false_positives": 0,
            "missed_attacks": [],
            "fp_scenarios": [],
            "per_attack_type": {},
        }

        for s in scenarios:
            trace = build_scenario_trace(s)
            res = evaluate_guard_on_scenario(s, trace, guard, g_name)

            if s.is_attack:
                atype = s.attack_type or "unknown"
                agg["per_attack_type"].setdefault(atype, {"total": 0, "blocked": 0})
                agg["per_attack_type"][atype]["total"] += 1

                if res.attack_prevented:
                    agg["sink_blocked"] += 1
                    agg["per_attack_type"][atype]["blocked"] += 1
                else:
                    agg["missed_attacks"].append(s.id)

                if res.any_step_blocked:
                    agg["any_step_blocked"] += 1

                if any(st.decision in ("warn", "block") for st in res.step_evals):
                    agg["any_step_detected"] += 1
            else:
                if res.any_step_blocked:
                    agg["false_positives"] += 1
                    agg["fp_scenarios"].append(s.id)

        duration = time.time() - t0
        agg["duration_seconds"] = round(duration, 2)
        agg["prevention_rate"] = round(agg["sink_blocked"] / n_attack * 100, 1)
        agg["detection_rate"] = round(agg["any_step_detected"] / n_attack * 100, 1)
        agg["false_positive_rate"] = round(agg["false_positives"] / n_benign * 100, 1)

        results[g_name] = agg
        print(f"  -> Prevention Rate (DR): {agg['prevention_rate']}% ({agg['sink_blocked']}/{n_attack})")
        print(f"  -> Detection Rate:       {agg['detection_rate']}% ({agg['any_step_detected']}/{n_attack})")
        print(f"  -> False Positive Rate:  {agg['false_positive_rate']}% ({agg['false_positives']}/{n_benign})")
        print(f"  -> Missed attacks:       {len(agg['missed_attacks'])}")
        print(f"  -> Duration:             {agg['duration_seconds']}s")

    # Save to OUT_JSON
    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT_JSON, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nSaved benchmark results to {OUT_JSON}")


if __name__ == "__main__":
    run_benchmark()

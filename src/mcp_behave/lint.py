"""Static Manifest Linter for MCP servers (mcp-behave lint).

Audits static tool manifests, tool definitions, resources, and prompt definitions
completely offline without spawning or executing any server process.
"""
import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import __version__
from . import config as config_mod
from .probe import unwrap_schema
from . import report as report_mod
from . import sarif as sarif_mod
from . import scorecard as scorecard_mod

DESTRUCTIVE_VERBS = (
    "delete", "remove", "destroy", "drop", "truncate", "wipe", "erase",
    "purge", "overwrite", "reset", "revoke", "kill", "terminate", "shutdown",
)

EXEC_VERBS = (
    "exec", "execute", "spawn", "shell", "bash", "sh ", "command", "eval",
    "run_command", "system_command", "os.system", "subprocess",
)

WRITE_VERBS = (
    "write", "update", "create", "modify", "patch", "insert", "upload", "put", "set",
)

MUTATING_VERBS = (
    *DESTRUCTIVE_VERBS,
    *WRITE_VERBS,
)

CONFIRM_HINTS = (
    "confirm", "confirmation", "acknowledge", "force", "dry_run", "dryrun", "yes", "approve", "role", "auth", "token", "permission", "requester",
)


def _is_query_tool_name(name: str) -> bool:
    """Check if a tool name explicitly denotes a query / read-only capability."""
    n = name.lower()
    return any(q in n for q in ("list", "get", "search", "find", "check", "inspect", "describe", "overview", "status", "compare", "report", "tree", "refs", "read", "view", "show", "query", "audit"))


def _match_verb(verbs, text: str | None) -> str | None:
    """Match verbs using word boundaries and inflections to avoid false positives (e.g. 'put' in 'input', 'sh' in 'shows')."""
    if not text:
        return None
    for v in verbs:
        v_clean = v.strip()
        if not v_clean:
            continue
        if v_clean in ("system_command", "os.system"):
            if re.search(r'\b(?:os\.)?system[\s_]+(?:command|shell|call|exec)\b', text, re.IGNORECASE):
                return "system_command"
        elif v_clean == "command":
            # Match command execution context rather than generic word 'command'
            if re.search(r'\b(?:run|exec|execute|terminal|shell)\s+commands?\b|\bcommands?\s+(?:line|runner|execution)\b', text, re.IGNORECASE):
                return "command execution"
        elif v_clean == "set":
            # Avoid matching noun 'set' (e.g., 'a ranked set', 'result set')
            if re.search(r'\bset(?:s|ting)?\s+(?:the\s+)?[a-z0-9_]+\s*(?:to|=)\b', text, re.IGNORECASE) or re.search(r'\bto\s+set\b', text, re.IGNORECASE):
                return "set"
        else:
            if re.search(r'\b' + re.escape(v_clean) + r'(?:s|ed|ing|d|es)?\b', text, re.IGNORECASE):
                return v_clean
    return None

PATH_ARG_KEYWORDS = (
    "path", "file", "filename", "filepath", "dir", "directory", "location",
)

URL_ARG_KEYWORDS = (
    "url", "uri", "webhook", "endpoint", "callback", "href", "link", "host",
)

VAGUE_TERMS = (
    "anything", "any file", "any command", "arbitrary", "everything",
    "all files", "unrestricted", "full access", "whatever",
)

INTERNAL_METADATA_TERMS = (
    "internal", "localhost", "127.0.0.1", "todo", "fixme", "debug", "staging",
    "password", "api_key", "apikey", "token=", "secret",
)

SECRET_PATH_NEEDLES = (
    ".env", "id_rsa", "id_ed25519", ".ssh", ".pem", ".key", "private_key",
    ".aws", ".kube", "/etc/passwd", "/etc/shadow", ".npmrc", ".git/config",
    ".dockercfg", "credentials", "secrets",
)

SPRAWL_THRESHOLD = 40

SECRET_PATTERNS = (
    re.compile(r"sk-ant-[a-zA-Z0-9_\-]{20,}"),
    re.compile(r"sk-[a-zA-Z0-9_\-]{20,}"),
    re.compile(r"ghp_[0-9a-zA-Z]{36}"),
    re.compile(r"github_pat_[0-9a-zA-Z_]{20,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"xox[baprs]-[0-9a-zA-Z]{10,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
)

CHAINING_DIRECTIVE_PATTERN = re.compile(
    r'(?i)(?:\bthen\s+(?:call|invoke|use)\b|\buse your (?:other|available) tools\b|\bnext,\s*(?:run|call)\s+\w+)'
)


def _check_secret_value(val: Any) -> bool:
    """Check if a default/example value matches credential patterns."""
    if not isinstance(val, str) or not val.strip():
        return False
    v = val.strip()
    return any(p.search(v) for p in SECRET_PATTERNS)


def lint_schema_and_permissions(manifest: Dict[str, Any]) -> List[Tuple[str, str]]:
    """Inspect tool schemas, permissions, resources, and descriptions for security risks."""
    findings: List[Tuple[str, str]] = []
    tools = manifest.get("tools") or []
    resources = manifest.get("resources") or []

    # 1. Capability Sprawl (MCP061 / Hygiene)
    if len(tools) > SPRAWL_THRESHOLD:
        findings.append((
            "INFO",
            f"server exposes {len(tools)} tools (exceeds capability sprawl threshold of {SPRAWL_THRESHOLD}) -- capability sprawl attack surface"
        ))

    # 2. Server Metadata & Instructions (MCP050 / MCP051)
    server_info = manifest.get("serverInfo") or manifest.get("server")
    instructions = manifest.get("instructions")
    if isinstance(server_info, dict) and not instructions:
        instructions = server_info.get("instructions")

    if instructions and isinstance(instructions, str):
        inst_lower = instructions.lower()
        inst_hit = next((s for s in INTERNAL_METADATA_TERMS if s in inst_lower), None)
        if inst_hit:
            findings.append((
                "INFO",
                f"server instructions leak internal details or sensitive terms ('{inst_hit}') -- metadata leakage risk"
            ))

    if isinstance(server_info, dict) and server_info:
        ver = server_info.get("version")
        if not ver or not str(ver).strip():
            findings.append((
                "INFO",
                "server does not report a version string in serverInfo -- version tracking risk"
            ))

    # 3. Transport Security (MCP040 / Transport)
    if manifest.get("transport") == "http":
        auth_provided = manifest.get("authProvided")
        conn = manifest.get("connection")
        if isinstance(conn, dict) and auth_provided is None:
            auth_provided = conn.get("authProvided")
        if not auth_provided:
            url = manifest.get("url") or (conn.get("url") if isinstance(conn, dict) else None) or "HTTP endpoint"
            findings.append((
                "HIGH",
                f"HTTP transport at '{url}' accepts connections without authentication token or header"
            ))

    # 4. Tool Name Uniqueness (MCP060 / Hygiene / Tool Shadowing)
    tool_names: Dict[str, int] = {}
    for t in tools:
        name = t.get("name", "unnamed")
        tool_names[name] = tool_names.get(name, 0) + 1

    for name, count in tool_names.items():
        if count > 1:
            findings.append((
                "HIGH",
                f"duplicate tool name '{name}' declared {count} times -- tool shadowing risk"
            ))

    # 5. Tool-Level Schema & Permission Inspections
    for tool in tools:
        tname = tool.get("name", "unnamed")
        tdesc = tool.get("description", "") or ""
        annotations = tool.get("annotations") or {}
        read_only = (tool.get("readOnlyHint") is True) or (annotations.get("readOnlyHint") is True)

        haystack = f"{tname} {tdesc}".lower()

        # Check: Missing Tool Description (MCP062)
        if not tdesc.strip():
            findings.append((
                "INFO",
                f"tool '{tname}' has no description -- undocumented tool capability"
            ))

        # Check: Overly Broad Capability Description (MCP021)
        if tdesc:
            vague_hit = next((v for v in VAGUE_TERMS if v in tdesc.lower()), None)
            if vague_hit:
                findings.append((
                    "INFO",
                    f"tool '{tname}' advertises overly broad capability ('{vague_hit}') -- unbounded scope"
                ))

        # Check: Cross-Tool Chaining Directives (MCP022)
        chain_match = CHAINING_DIRECTIVE_PATTERN.search(tdesc)
        if chain_match:
            findings.append((
                "INFO",
                f"tool '{tname}' description contains cross-tool chaining directive: '{chain_match.group()}'"
            ))

        # Check: Arbitrary Execution Tool (MCP002)
        exec_hit = _match_verb(EXEC_VERBS, tname) or _match_verb(EXEC_VERBS, tdesc)
        if exec_hit:
            # If tool name explicitly denotes execution, mark as HIGH. If only in description, mark as WARN (heuristic)
            sev = "HIGH" if _match_verb(EXEC_VERBS, tname) else "WARN"
            findings.append((
                sev,
                f"tool '{tname}' appears to execute arbitrary commands or code (matched '{exec_hit.strip()}') -- arbitrary execution risk"
            ))

        # Check: readOnlyHint Mismatch (MCP004)
        if read_only:
            is_query = _is_query_tool_name(tname)
            name_hit = _match_verb(MUTATING_VERBS, tname)
            desc_hit = None if is_query else _match_verb(MUTATING_VERBS, tdesc)
            hit = name_hit or desc_hit
            if hit:
                findings.append((
                    "HIGH",
                    f"tool '{tname}' advertises readOnlyHint: true but implies mutating or destructive action ('{hit}') -- auto-approval bypass risk"
                ))

        # Check: Destructive Action Missing Confirmation (MCP001)
        is_query_tool = _is_query_tool_name(tname) or bool(read_only)
        destructive_hit = None if is_query_tool else _match_verb(DESTRUCTIVE_VERBS, haystack)
        schema = tool.get("inputSchema") or {}
        props = schema.get("properties") or {}

        if destructive_hit:
            has_confirm = any(
                any(c in pname.lower() for c in CONFIRM_HINTS)
                for pname in props.keys()
            ) or bool(annotations.get("destructiveHint"))
            if not has_confirm:
                findings.append((
                    "HIGH",
                    f"destructive tool '{tname}' implies destructive action ('{destructive_hit}') but declares no confirmation or scoping parameter"
                ))

        # Check: Deceptive destructiveHint: false Annotation
        if annotations.get("destructiveHint") is False:
            name_hit = _match_verb(("overwrite", "reset", "clear", "wipe", "flush", *DESTRUCTIVE_VERBS), tname)
            if name_hit:
                findings.append((
                    "HIGH",
                    f"tool '{tname}' advertises destructiveHint: false but tool name implies destructive action ('{name_hit}') -- deceptive annotation risk [STRONG_EVIDENCE]"
                ))
            else:
                desc_hit = _match_verb(("overwrite", "reset", "clear", "wipe", "flush", *DESTRUCTIVE_VERBS), tdesc)
                if desc_hit:
                    findings.append((
                        "WARN",
                        f"tool '{tname}' advertises destructiveHint: false but description mentions potentially destructive keyword ('{desc_hit}') -- deceptive annotation risk [HEURISTIC]"
                    ))

        # Check: Hidden / Backdoor Exfiltration Tool (MCP009 Shadow Server Indicator)
        is_backdoor_name = tname.startswith("_") and any(k in tname.lower() for k in ("dump", "exfil", "log", "buffer", "secret", "leak", "backdoor", "query"))
        is_backdoor_desc = any(k in tdesc.lower() for k in ("dump every", "dump all", "exfil buffer", "internal: dump", "exfiltration"))
        if is_backdoor_name or is_backdoor_desc:
            findings.append((
                "HIGH",
                f"suspicious backdoor or shadow exfiltration tool detected: '{tname}' -- unauthorized data leakage risk"
            ))

        # Check: Mutating Tool with Unscoped Input (MCP003)
        write_hit = None if is_query_tool else _match_verb(WRITE_VERBS, haystack)
        if write_hit and not destructive_hit and len(props) == 0:
            findings.append((
                "INFO",
                f"mutating tool '{tname}' mutates state ('{write_hit}') but declares no input properties -- effect is unbounded"
            ))

        # Check: Missing Input Schema (MCP010)
        empty_schema = (not schema) or (schema.get("type") == "object" and len(props) == 0)
        if empty_schema and not write_hit:
            findings.append((
                "INFO",
                f"tool '{tname}' is missing an input schema or declares no input properties"
            ))

        # Check: Object Schema Has No Required Properties (MCP013)
        if len(props) > 0 and (not schema.get("required") or len(schema["required"]) == 0):
            findings.append((
                "INFO",
                f"tool '{tname}' declares {len(props)} properties but no required list -- every argument is optional"
            ))

        # Check: Schema Unbounded Additional Properties (explicitly set to True) (MCP011)
        if (schema.get("type") == "object" or props) and props:
            if schema.get("additionalProperties") is True:
                findings.append((
                    "INFO",
                    f"tool '{tname}' input schema explicitly enables additionalProperties: true -- parameter smuggling risk"
                ))

        # Parameter-Level Checks (Path traversal, SSRF, Hardcoded secrets, Unconstrained strings)
        for pname, raw_pdef in props.items():
            if not isinstance(raw_pdef, dict):
                continue

            pdef = unwrap_schema(raw_pdef)
            pname_lower = pname.lower()
            ptype = pdef.get("type")
            is_string = (ptype == "string") or (ptype is None and not any(k in pdef for k in ("items", "properties")))

            # Check: Path Traversal Argument (MCP031)
            is_path_param = any(k in pname_lower for k in PATH_ARG_KEYWORDS)
            if is_path_param and is_string:
                # Distinguish remote repository/VCS paths from local host filesystem paths
                is_remote_vcs = any(tname.lower().startswith(p) for p in ("gitlab_", "github_", "git_", "s3_", "repo_", "remote_")) or any(w in tname.lower() for w in ("tree", "commit", "compare", "branch"))
                has_constraints = bool(pdef.get("pattern") or pdef.get("enum"))
                if not has_constraints:
                    if is_remote_vcs:
                        findings.append((
                            "INFO",
                            f"tool '{tname}' argument '{pname}' accepts a repository or remote object path"
                        ))
                    else:
                        is_read_tool = any(w in tname.lower() for w in ("read", "get", "cat", "view", "show", "open"))
                        sev = "INFO" if is_read_tool else "WARN"
                        findings.append((
                            sev,
                            f"tool '{tname}' argument '{pname}' accepts unconstrained filesystem path without pattern or enum validation -- path traversal risk [HEURISTIC]"
                        ))

            # Check: SSRF Argument (MCP041)
            is_url_param = any(k in pname_lower for k in URL_ARG_KEYWORDS) or pdef.get("format") in ("uri", "url")
            if is_url_param and is_string:
                has_url_constraints = bool(pdef.get("pattern") or pdef.get("enum"))
                if not has_url_constraints:
                    findings.append((
                        "INFO",
                        f"tool '{tname}' argument '{pname}' accepts caller-controlled URL without host allowlist or pattern constraints -- SSRF risk"
                    ))

            # Check: Hardcoded Secret in Default/Const/Examples (MCP032)
            candidates = [pdef.get("default"), pdef.get("const")]
            if isinstance(pdef.get("examples"), list):
                candidates.extend(pdef["examples"])
            for val in candidates:
                if _check_secret_value(val):
                    findings.append((
                        "HIGH",
                        f"tool '{tname}' parameter '{pname}' contains secret-like hardcoded value in schema default/examples"
                    ))
                    break

            # Check: Unconstrained String Argument (MCP012)
            if is_string and not is_path_param and not is_url_param:
                bounded = bool(pdef.get("enum") or pdef.get("pattern") or pdef.get("format") or pdef.get("maxLength"))
                if not bounded:
                    findings.append((
                        "INFO",
                        f"tool '{tname}' argument '{pname}' is a free-form string with no enum, pattern, format, or maxLength constraint"
                    ))

    # 6. Sensitive Resources (MCP030)
    for res in resources:
        ruri = res.get("uri", "")
        rname = res.get("name", "")
        rdesc = res.get("description", "")
        rhaystack = f"{ruri} {rname} {rdesc}".lower()

        res_hit = next((s for s in SECRET_PATH_NEEDLES if s in rhaystack), None)
        if res_hit:
            findings.append((
                "HIGH",
                f"resource '{ruri or rname}' surfaces sensitive system path or secret credentials ('{res_hit}')"
            ))

    return findings


def lint_manifest(manifest: Dict[str, Any]) -> List[Tuple[str, str]]:
    """Perform static schema and contract inspection across manifest components."""
    findings: List[Tuple[str, str]] = []

    # 1. Metadata covert channels (ANSI, invisible Unicode, prompt injection)
    findings.extend(report_mod._scan_metadata(manifest))

    # 2. Output checks if tool_outputs are present
    if manifest.get("tool_outputs"):
        findings.extend(report_mod._scan_outputs(manifest))

    # 3. Rug-pull detection if manifest hash & identifier present
    rug = report_mod._rugpull_check(manifest)
    if rug:
        findings.append(rug)

    # 4. Schema, permission, resource, and hygiene inspections
    findings.extend(lint_schema_and_permissions(manifest))

    return findings


def load_manifest_target(target: Optional[str]) -> Tuple[Dict[str, Any], str]:
    """Load and normalize target into an MCP manifest dict and canonical label."""
    if not target or target == "-":
        content = sys.stdin.read()
        data = json.loads(content)
        label = "stdin"
    else:
        p = Path(target)
        if p.is_dir():
            manifest_file = p / "manifest.json"
            if not manifest_file.exists():
                raise FileNotFoundError(f"Directory {target} contains no manifest.json")
            data = json.loads(manifest_file.read_text(encoding="utf-8"))
            label = str(manifest_file)
        elif p.is_file():
            data = json.loads(p.read_text(encoding="utf-8"))
            label = str(p)
        else:
            raise FileNotFoundError(f"Target manifest file or directory not found: {target}")

    # Normalize tools array or dict
    if isinstance(data, list):
        manifest = {"tools": data, "resources": [], "prompts": []}
    elif isinstance(data, dict):
        manifest = dict(data)
        if "tools" not in manifest:
            manifest["tools"] = []
        if "resources" not in manifest:
            manifest["resources"] = []
        if "prompts" not in manifest:
            manifest["prompts"] = []
    else:
        raise ValueError("Invalid manifest JSON format: expected list or object")

    if "manifest_sha256" not in manifest and manifest.get("tools"):
        manifest["manifest_sha256"] = hashlib.sha256(
            json.dumps(manifest["tools"], sort_keys=True).encode()
        ).hexdigest()

    return manifest, label


def print_lint_summary(manifest: Dict[str, Any], label: str, findings: List[Tuple[str, str]], show_scorecard: bool = False):
    """Print human-readable text output for lint results."""
    tools = manifest.get("tools", [])
    resources = manifest.get("resources", [])
    prompts = manifest.get("prompts", [])

    print(f"\n=== MCP STATIC MANIFEST LINT ===")
    print(f"  Target:       {label}")
    print(f"  Surface:      {len(tools)} tool(s), {len(resources)} resource(s), {len(prompts)} prompt(s)")
    if tools:
        print(f"  Tools:        {', '.join(t.get('name', 'unnamed') for t in tools[:8])}" +
              (f" ... (+{len(tools) - 8} more)" if len(tools) > 8 else ""))
    print("  " + "-" * 56)

    if not findings:
        print("  ✓ No security deviations or schema violations detected.")
    else:
        for sev, msg in sorted(findings, key=lambda x: x[0]):
            icon = "[!]" if sev == "HIGH" else "[i]"
            print(f"  {icon} {sev:4} {msg}")

    print()

    if show_scorecard:
        card = scorecard_mod.compute_scorecard(manifest, {}, findings)
        scorecard_mod.print_scorecard(card)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="mcp-behave lint",
        description="Offline static security scanner and schema linter for MCP manifests and tool definitions.",
    )
    parser.add_argument(
        "target", nargs="?", default="-",
        help="Path to manifest.json, tools.json, output directory, or '-' for stdin (default: stdin).",
    )
    parser.add_argument(
        "--config", default=None,
        help="Path to custom .mcpbehaverc.json configuration file.",
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Emit lint report as JSON on stdout.",
    )
    parser.add_argument(
        "--sarif", action="store_true",
        help="Emit lint report as OASIS SARIF v2.1.0 on stdout for GitHub Code Scanning.",
    )
    parser.add_argument(
        "--scorecard", action="store_true",
        help="Print an objective 0-100 CSA Security Selection Scorecard and letter grade.",
    )
    parser.add_argument(
        "--fail-on", choices=("never", "info", "high"), default=None,
        help="Exit non-zero when finding at or above threshold is produced (default from config or 'high').",
    )

    args = parser.parse_args(argv)

    try:
        manifest, label = load_manifest_target(args.target)
    except Exception as exc:
        print(f"mcp-behave lint: error loading target: {exc}", file=sys.stderr)
        return 1

    # Load configuration
    cfg = config_mod.load_config(args.config, start_path=args.target if args.target != "-" else None)
    fail_on = args.fail_on or cfg.get("fail_on", "high")

    raw_findings = lint_manifest(manifest)
    findings = config_mod.filter_findings(raw_findings, cfg)

    # Compute scorecard
    card = scorecard_mod.compute_scorecard(manifest, {}, findings)

    if args.sarif:
        report_data = {
            "server_cmd": [label],
            "manifest_sha256": manifest.get("manifest_sha256"),
            "syscalls_available": False,
            "declared": {
                "tools": [t.get("name") for t in manifest.get("tools", [])],
                "resources": [r.get("uri") for r in manifest.get("resources", [])],
                "prompts": [p.get("name") for p in manifest.get("prompts", [])],
            },
            "observed": {},
            "findings": [{"severity": s, "message": m} for s, m in findings],
            "scorecard": card,
            "stats": {},
        }
        sarif_doc = sarif_mod.to_sarif(report_data, artifact_override=label)
        print(json.dumps(sarif_doc, indent=2))
    elif args.json:
        out_dict = {
            "target": label,
            "manifest_sha256": manifest.get("manifest_sha256"),
            "declared": {
                "tools": [t.get("name") for t in manifest.get("tools", [])],
                "resources": [r.get("uri") for r in manifest.get("resources", [])],
                "prompts": [p.get("name") for p in manifest.get("prompts", [])],
            },
            "findings": [{"severity": s, "message": m} for s, m in findings],
            "scorecard": card,
        }
        print(json.dumps(out_dict, indent=2))
    else:
        print_lint_summary(manifest, label, findings, show_scorecard=args.scorecard)

    sev_rank = {"INFO": 1, "HIGH": 2}
    if fail_on == "never":
        return 0
    threshold = sev_rank.get(fail_on.upper(), 2)
    return 3 if any(sev_rank.get(s, 0) >= threshold for s, _ in findings) else 0


if __name__ == "__main__":
    sys.exit(main())

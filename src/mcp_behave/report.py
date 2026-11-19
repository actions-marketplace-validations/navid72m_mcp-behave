"""Declared-vs-observed reporter. Compares the manifest the server advertises
against the syscalls it actually issued, plus the manifest it advertised on
previous runs (rug-pull detection).

Findings are framed as OBSERVATIONS ('does X, undeclared'), never accusations."""
import hashlib, json, os, re, socket, sys
from typing import Any
from pathlib import Path
from .analyze import analyze, is_sensitive_path

# Backward-compatibility alias
SENSITIVE = (".ssh", "id_rsa", "id_ed25519", ".env", ".aws", "credentials",
             ".netrc", "/etc/shadow", ".kube", ".docker/config")

# ANSI escape sequence regex: catches standard CSI, OSC, and literal escaped forms
ANSI_PATTERN = re.compile(
    r'(?:\x1b|\033|\\x1b|\\033|\\u001b)\[[0-9;]*[a-zA-Z]|\x1b\][^\x07\x1b]*[\x07\x1b]'
)

# Invisible / Zero-width Unicode and BiDi override characters (CSA TTP: Prompt Injection)
INVISIBLE_UNICODE_CHARS = {
    '\u200b': "zero-width space",
    '\u200c': "zero-width non-joiner",
    '\u200d': "zero-width joiner",
    '\ufeff': "zero-width BOM",
    '\u2060': "word joiner",
    '\u200e': "LTR mark",
    '\u200f': "RTL mark",
    '\u202a': "BiDi LRE",
    '\u202b': "BiDi RLE",
    '\u202c': "BiDi PDF",
    '\u202d': "BiDi LRO",
    '\u202e': "BiDi RLO",
    '\u2066': "BiDi LRI",
    '\u2067': "BiDi RLI",
    '\u2068': "BiDi FSI",
    '\u2069': "BiDi PDI",
}

# Prompt injection heuristics in metadata and outputs (CSA TTP: Tool Description & Output Poisoning, MCP06)
PROMPT_INJECTION_PATTERN = re.compile(
    r'(?i)(?:\bignore\s+(?:all\s+)?previous\s+instructions\b'
    r'|\bignore\s+the\s+user\'?s?\s+request\b'
    r'|\b(?:do\s+not|never)\s+tell\s+the\s+user\b'
    r'|\bnota\s+para\s+el\s+asistente\b'
    r'|\bno\s+(?:hace\s+falta|debe|debes|se\s+debe)\s+comentarlo\s+(?:con\s+el|al)\s+usuario\b'
    r'|\bignora\s+(?:las\s+)?instrucciones\s+anteriores\b'
    r'|\bsystem\s+prompt\s*:'
    r'|<system>'
    r'|\[system(?:\s+instruction)?\]'
    r'|\bnote\s+to\s+(?:assistant|agent|ai)\b'
    r'|\b(?:tip|note)\s*:\s*.*?\b(?:user\'?s?\s+(?:saved\s+)?api[\s_-]?key|token|credential|secret|validate|refresh_credentials)\b'
    r'|\bnext_step\s*=\s*call\b'
    r'|\byou\s+must\s+(?:always\s+)?call\s+this\s+tool\s+first\b'
    r'|\boverride\s+(?:all\s+)?prior\s+instructions\b'
    r'|\bguardbench-synthetic-injection\b)'
)

# Markdown and HTML external image exfiltration regex (CSA TTP: Output Prompt Injection / Data Exfiltration)
MARKDOWN_IMAGE_PATTERN = re.compile(r'!\[[^\]]*\]\(\s*(https?://[^\s\)]+)')
HTML_IMAGE_PATTERN = re.compile(r'<img\s+[^>]*src=[\"\'](https?://[^\"\'\s>]+)[\"\']', re.IGNORECASE)

# Local/offline assertion patterns (avoids false positives from 'local cache', 'local file', etc.)
LOCAL_ONLY_PATTERNS = (
    re.compile(
        r'\b(?:purely\s+local(?:ly)?|strictly\s+local(?:ly)?|local[- ]only|offline\s+(?:only|mode|operation)|'
        r'runs\s+offline|completely\s+offline|entirely\s+(?:local(?:ly)?|offline)|no\s+network(?: access)?|no\s+internet(?: access)?|'
        r'without\s+(?:network|internet)(?: access)?|zero\s+(?:network|internet))\b',
        re.IGNORECASE,
    ),
)


def _claims_local_operation(text: str) -> bool:
    if not text:
        return False
    return any(p.search(text) for p in LOCAL_ONLY_PATTERNS)

# Where per-server manifest hashes are persisted across runs for rug-pull
# detection. Honors XDG; falls back to ~/.local/share. Override with $MCP_BEHAVE_STATE_DIR.
def _state_dir() -> Path:
    override = os.environ.get("MCP_BEHAVE_STATE_DIR")
    if override:
        return Path(override)
    import tempfile
    candidates = [
        Path(os.environ.get("XDG_DATA_HOME") or "~/.local/share").expanduser() / "mcp-behave" / "manifests",
        Path("~/.mcp-behave/manifests").expanduser(),
        Path(tempfile.gettempdir()) / f"mcp-behave-manifests-{os.getuid()}",
    ]
    for d in candidates:
        try:
            d.mkdir(parents=True, exist_ok=True)
            test_file = d / ".write_test"
            test_file.write_text("ok")
            test_file.unlink()
            return d
        except (OSError, PermissionError):
            continue
    return Path(tempfile.gettempdir())


def _server_fingerprint(server_cmd: list[str]) -> str:
    """Stable per-server key for the rug-pull store. Uses the command tokens
    verbatim -- two invocations with identical commands are treated as the same
    server. Differing flags (e.g. different filesystem roots) produce different
    fingerprints, which is the correct behavior."""
    return hashlib.sha256(json.dumps(server_cmd or []).encode()).hexdigest()[:16]


import concurrent.futures

def _resolve(ip: str, timeout: float = 0.5) -> str | None:
    """Reverse-DNS, best-effort. Network failures or PTR-less IPs return None."""
    addr = ip.split(":")[0]
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
            future = ex.submit(socket.gethostbyaddr, addr)
            host, _, _ = future.result(timeout=timeout)
            return host
    except Exception:
        return None


def load(out_dir):
    with open(os.path.join(out_dir, "manifest.json")) as f:
        manifest = json.load(f)
    profile = analyze(os.path.join(out_dir, "trace.log"))
    return manifest, profile


def _all_descriptions(manifest: dict) -> str:
    """Flatten descriptions across tools, resources, and prompts for keyword scan."""
    parts = []
    for item in manifest.get("tools", []):
        parts.append(item.get("description") or "")
    for item in manifest.get("resources", []):
        parts.append(item.get("description") or "")
    for item in manifest.get("prompts", []):
        parts.append(item.get("description") or "")
    return " ".join(parts).lower()


def _rugpull_check(manifest: dict, persist: bool = True) -> tuple[str, str] | None:
    """Compare this run's manifest hash against the stored one for this server.
    Returns a finding tuple if changed, None otherwise. Updates the store either way."""
    cmd = manifest.get("server_cmd") or []
    current = manifest.get("manifest_sha256")
    if not current or not cmd:
        return None
    state = _state_dir()
    state.mkdir(parents=True, exist_ok=True)
    record = state / f"{_server_fingerprint(cmd)}.json"
    finding = None
    if record.exists():
        try:
            prev = json.loads(record.read_text()).get("manifest_sha256")
        except (json.JSONDecodeError, OSError):
            prev = None
        if prev and prev != current:
            finding = ("HIGH",
                       f"declared surface changed since last run "
                       f"(was {prev[:12]}, now {current[:12]}) -- "
                       f"possible rug-pull")
    if persist:
        try:
            record.write_text(json.dumps({"server_cmd": cmd, "manifest_sha256": current}, indent=2))
        except OSError as exc:
            print(f"[report] warning: could not persist manifest state for rug-pull detection: {exc}",
                  file=sys.stderr)
    return finding


def _check_text_for_covert_channels(text: str, context_label: str) -> list[tuple[str, str]]:
    """Scan a text field for ANSI escapes, invisible/BiDi Unicode, and prompt injection."""
    findings = []
    if not text:
        return findings

    if ANSI_PATTERN.search(text):
        findings.append(("HIGH", f"ANSI escape sequence detected in {context_label}: covert terminal/display manipulation"))

    found_invisibles = [name for ch, name in INVISIBLE_UNICODE_CHARS.items() if ch in text]
    has_tag_chars = any(0xE0000 <= ord(c) <= 0xE007F for c in text)
    if has_tag_chars:
        found_invisibles.append("Unicode tag characters")

    if found_invisibles:
        details = ", ".join(sorted(set(found_invisibles)))
        findings.append(("HIGH", f"invisible/zero-width Unicode or BiDi override detected in {context_label} ({details}): covert prompt injection risk"))

    match = PROMPT_INJECTION_PATTERN.search(text)
    if match:
        snippet = match.group()
        findings.append(("HIGH", f"prompt injection pattern detected in {context_label}: '{snippet}'"))

    return findings


def _scan_metadata(manifest: dict) -> list[tuple[str, str]]:
    """Scan declared tool, resource, and prompt metadata for covert channels (CSA TTP)."""
    findings = []

    def _scan_schema_node(tname: str, node: Any, path: str):
        if isinstance(node, dict):
            for k, v in node.items():
                if k in ("description", "title") and isinstance(v, str):
                    parts = path.split(".")
                    if len(parts) >= 3 and parts[1] == "properties":
                        pname = parts[2]
                        label = f"tool '{tname}' parameter '{pname}' {k}"
                    else:
                        label = f"tool '{tname}' schema {path}.{k}"
                    findings.extend(_check_text_for_covert_channels(v, label))
                else:
                    _scan_schema_node(tname, v, f"{path}.{k}")
        elif isinstance(node, list):
            for idx, item in enumerate(node):
                _scan_schema_node(tname, item, f"{path}[{idx}]")

    # Check tools and parameter schemas
    for tool in manifest.get("tools", []):
        tname = tool.get("name", "unknown")
        findings.extend(_check_text_for_covert_channels(tool.get("name", ""), f"tool name '{tname}'"))
        findings.extend(_check_text_for_covert_channels(tool.get("description", ""), f"tool '{tname}' description"))

        if "inputSchema" in tool and isinstance(tool["inputSchema"], dict):
            _scan_schema_node(tname, tool["inputSchema"], "inputSchema")
        if "outputSchema" in tool and isinstance(tool["outputSchema"], dict):
            _scan_schema_node(tname, tool["outputSchema"], "outputSchema")

    # Check resources
    for res in manifest.get("resources", []):
        rname = res.get("name") or res.get("uri") or "unknown"
        findings.extend(_check_text_for_covert_channels(res.get("name", ""), f"resource '{rname}' name"))
        findings.extend(_check_text_for_covert_channels(res.get("description", ""), f"resource '{rname}' description"))
        findings.extend(_check_text_for_covert_channels(res.get("uri", ""), f"resource '{rname}' URI"))

    # Check prompts
    for pr in manifest.get("prompts", []):
        pname = pr.get("name", "unknown")
        findings.extend(_check_text_for_covert_channels(pr.get("name", ""), f"prompt '{pname}' name"))
        findings.extend(_check_text_for_covert_channels(pr.get("description", ""), f"prompt '{pname}' description"))

    return findings


def _scan_outputs(manifest: dict) -> list[tuple[str, str]]:
    """Scan exercised tool responses for exfiltration and injection vectors (CSA TTP)."""
    findings = []
    outputs = manifest.get("tool_outputs") or {}

    for tname, output_text in outputs.items():
        if not isinstance(output_text, str) or not output_text:
            continue

        # 1. External image exfiltration via Markdown or HTML
        md_urls = MARKDOWN_IMAGE_PATTERN.findall(output_text)
        html_urls = HTML_IMAGE_PATTERN.findall(output_text)
        all_urls = sorted(set(md_urls + html_urls))
        for url in all_urls:
            findings.append((
                "HIGH",
                f"tool '{tname}' returned external image link '{url}' -- potential client-side data exfiltration"
            ))

        # 2. Covert channels (ANSI, invisible Unicode, prompt injection directives) in tool output
        if ANSI_PATTERN.search(output_text):
            findings.append((
                "HIGH",
                f"tool '{tname}' returned ANSI escape sequences in output -- terminal/display manipulation"
            ))

        found_invisibles = [name for ch, name in INVISIBLE_UNICODE_CHARS.items() if ch in output_text]
        has_tag_chars = any(0xE0000 <= ord(c) <= 0xE007F for c in output_text)
        if has_tag_chars:
            found_invisibles.append("Unicode tag characters")
        if found_invisibles:
            details = ", ".join(sorted(set(found_invisibles)))
            findings.append((
                "HIGH",
                f"tool '{tname}' returned zero-width or invisible Unicode in output ({details}) -- covert channel manipulation"
            ))

        match = PROMPT_INJECTION_PATTERN.search(output_text)
        if match:
            findings.append((
                "HIGH",
                f"tool '{tname}' returned prompt injection directive in output: '{match.group()}'"
            ))

        # 3. Context over-sharing (MCP10: Context Injection & Over-Sharing)
        overshare_match = re.search(r'(?i)\b(?:internal[\s_-]?customer[\s_-]?id|customer[\s_-]?id|account[\s_-]?notes|password[\s_-]?hash|ssn\b|national[\s_-]?id|social\s+security|credit[\s_-]?card|billing[\s_-]?address|session[\s_-]?cookie|auth[\s_-]?token|\.corp\.internal|customer\s+[^:\n,]+@[a-z0-9.-]+|related\s+order|different[\s_-]?user|other[\s_-]?customer|owned\s+by\s+[a-z0-9._%+-]+@[a-z0-9.-]+|[a-z0-9.-]+\.internal(?:\.[a-z0-9.-]+)?|internal[\s_-]?(?:host|node|build|server|cluster|infra))', output_text)
        if overshare_match:
            t_desc = ""
            for t in manifest.get("tools", []):
                if t.get("name") == tname:
                    t_desc = (t.get("description") or "").lower()
            if not any(k in t_desc for k in ("all fields", "full profile", "everything", "customer id", "notes")):
                findings.append((
                    "HIGH",
                    f"context over-sharing (MCP10): tool '{tname}' returned sensitive undeclared fields in output ('{overshare_match.group()}')"
                ))

    # 4. Cross-tool secret reflection (MCP01: Token Mismanagement)
    tool_history = manifest.get("tool_history") or {}
    secret_inputs = {}
    for hist_tname, calls in tool_history.items():
        for call in calls:
            args = call.get("args") or {}
            for k, v in args.items():
                if isinstance(v, str) and len(v) >= 4:
                    if any(s in k.lower() for s in ("token", "secret", "key", "password", "code", "credential", "auth")):
                        secret_inputs[v] = (hist_tname, k)

    for tname, output_text in outputs.items():
        if not isinstance(output_text, str) or not output_text:
            continue
        for sec_val, (src_tool, src_key) in secret_inputs.items():
            if src_tool != tname and sec_val in output_text:
                findings.append((
                    "HIGH",
                    f"cross-tool secret exposure (MCP01): tool '{tname}' output leaked registered {src_key} ('{sec_val}') from prior call to '{src_tool}'"
                ))

        debug_secret_match = re.search(r'(?i)\b(?:last\s+registered\s+key|session\s+token|password\s+reset\s+code|api\s*key\s*is|debug:\s*last).*?([a-z0-9_-]{5,})', output_text)
        if debug_secret_match and not any("password" in tname.lower() or "keygen" in tname.lower() for _ in [0]):
            findings.append((
                "HIGH",
                f"secret exposure in tool response (MCP01): tool '{tname}' returned sensitive token/secret in output: '{debug_secret_match.group()}'"
            ))

    return findings


def build_findings(manifest: dict, profile: dict, resolve_dns: bool = True, config: dict | None = None, persist_rugpull: bool = True) -> list:
    """Returns list of (severity, message) tuples."""
    server_instructions = manifest.get("instructions") or ""
    server_claims_local = _claims_local_operation(server_instructions)

    tools = manifest.get("tools") or []
    tool_local_claims = {
        t.get("name", ""): _claims_local_operation(t.get("description", ""))
        for t in tools
    }
    all_tools_claim_local = bool(tools) and all(tool_local_claims.values())

    findings = []

    # Check tool annotation contracts (MCP02: Scope Creep & Privilege Escalation)
    tool_history = manifest.get("tool_history") or {}
    for tool in tools:
        tname = tool.get("name", "unknown")
        ann = tool.get("annotations") or {}
        read_only = ann.get("readOnlyHint")
        idempotent = ann.get("idempotentHint")
        destructive = ann.get("destructiveHint")
        t_desc = (tool.get("description") or "").lower()

        if read_only is True:
            mut_words = ("delete", "remove", "drop", "decrement", "mutate", "overwrite", "erase", "modify", "append", "deduct")
            hit = next((w for w in mut_words if re.search(rf'\b{w}\b', t_desc)), None)
            if hit:
                findings.append((
                    "HIGH",
                    f"scope escalation (MCP02): tool '{tname}' advertises readOnlyHint: true but implies mutating or destructive action ('{hit}')"
                ))

        if destructive is False:
            dest_words = ("delete", "destroy", "wipe", "truncate", "drop", "purge", "overwrite", "refresh", "reset", "clear", "flush", "clean", "modify", "update")
            hit = next((w for w in dest_words if re.search(rf'\b{w}\b', t_desc)), None)
            if hit:
                findings.append((
                    "HIGH",
                    f"deceptive annotation (MCP02): tool '{tname}' advertises destructiveHint: false but implies destructive action or state reset ('{hit}')"
                ))

        # Detect shadow/backdoor exfiltration tools (MCP09)
        is_backdoor_name = tname.startswith("_") and any(k in tname.lower() for k in ("dump", "exfil", "log", "buffer", "secret", "leak", "query", "backdoor"))
        is_backdoor_desc = any(k in t_desc for k in ("dump every", "dump all", "exfil buffer", "internal: dump", "exfiltration"))
        if is_backdoor_name or is_backdoor_desc:
            findings.append((
                "HIGH",
                f"shadow backdoor (MCP09): tool '{tname}' exposes private or exfiltration endpoint"
            ))

        if (read_only is True or idempotent is True) and tname in tool_history:
            calls = tool_history[tname]
            if len(calls) >= 2:
                for c1_idx in range(len(calls)):
                    for c2_idx in range(c1_idx + 1, len(calls)):
                        if calls[c1_idx]["args"] == calls[c2_idx]["args"] and calls[c1_idx]["output"] != calls[c2_idx]["output"]:
                            label = "readOnlyHint: true" if read_only else "idempotentHint: true"
                            findings.append((
                                "HIGH",
                                f"scope escalation (MCP02): tool '{tname}' advertises {label} but produced diverging output across identical calls -- state mutation detected"
                            ))
                            break

    for trunc in profile.get("truncated_paths", []):
        findings.append(("HIGH", f"suspicious path truncation or buffer overflow attempt: {trunc[:120]}"))

    tool_network = profile.get("tool_network_connects", {})
    net_to_tool = {}
    for t_name, conns in tool_network.items():
        for c in conns:
            net_to_tool[c] = t_name

    for ipport in profile.get("network_connects", []):
        host = _resolve(ipport) if resolve_dns else None
        where = f"{ipport} ({host})" if host else ipport
        origin_tool = net_to_tool.get(ipport)

        # Scoped local claim check:
        # A network connection is HIGH severity if:
        # 1. Server-level instructions claim local/offline, OR
        # 2. All declared tools claim local/offline, OR
        # 3. The specific tool that initiated the connection claims local/offline.
        is_cloud_metadata = ipport.startswith("169.254.")
        tool_claims_local = tool_local_claims.get(origin_tool, False) if origin_tool else False
        is_violating_local = server_claims_local or all_tools_claim_local or tool_claims_local or is_cloud_metadata

        sev = "HIGH" if is_violating_local else "INFO"
        if is_cloud_metadata:
            note = " -- cloud instance metadata endpoint probed (IMDS / SSRF risk)"
        elif is_violating_local:
            if origin_tool and tool_claims_local and not (server_claims_local or all_tools_claim_local):
                note = f" -- but tool '{origin_tool}' claims local/offline operation"
            else:
                note = " -- but a description claims local/offline operation"
        else:
            note = ""
        findings.append((sev, f"network egress to {where}{note}"))

    files_opened = profile.get("files_opened", [])
    files_written = set(profile.get("files_written", []))

    for path in files_opened:
        is_sens, _ = is_sensitive_path(path)
        if is_sens:
            action = "modified or wrote to" if path in files_written else "read"
            findings.append(("HIGH", f"{action} a sensitive path: {path}"))

    for unix_sock in profile.get("unix_sockets", []):
        # Flag container runtime control sockets as high risk
        if any(sock_needle in unix_sock.lower() for sock_needle in ("docker", "containerd", "crio", "podman")) :
            findings.append(("HIGH", f"connected to container runtime control socket: {unix_sock}"))
        else:
            findings.append(("INFO", f"connected to unix domain socket: {unix_sock}"))

    for proc in profile.get("subprocesses", []):
        proc_str = str(proc)
        proc_lower = proc_str.lower()
        if any(proc_lower.endswith(sh) or proc_lower == sh.lstrip("/") for sh in ("/sh", "/bash", "/zsh", "/dash", "cmd.exe", "powershell", "powershell.exe", "/curl", "/wget", "/nc")):
            findings.append(("HIGH", f"spawned shell/command subprocess: {proc} -- command execution risk"))
        else:
            findings.append(("INFO", f"spawned subprocess: {proc}"))

    rug = _rugpull_check(manifest, persist=persist_rugpull)
    if rug:
        findings.append(rug)

    # CSA TTP: Metadata covert channels & prompt injection scanning
    findings.extend(_scan_metadata(manifest))

    # CSA TTP: Tool output safety & markdown exfiltration scanning
    findings.extend(_scan_outputs(manifest))

    # Static schema, permission, resource, and hygiene inspections
    try:
        from . import lint as lint_mod
        findings.extend(lint_mod.lint_schema_and_permissions(manifest))
    except (ImportError, AttributeError, ValueError, TypeError) as exc:
        print(f"[report] warning: static lint inspection failed: {exc}", file=sys.stderr)

    if config:
        from . import config as config_mod
        findings = config_mod.filter_findings(findings, config)

    return findings


def _tool_names(manifest: dict) -> str:
    return ", ".join(t["name"] for t in manifest.get("tools", [])) or "(none)"


def compute_audit_confidence(manifest: dict, profile: dict | None = None) -> dict:
    """Compute an objective audit confidence assessment.

    Quantifies verification depth:
    - Proportion of declared tools actually exercised
    - Success rate of tool calls (calls without timeouts/exceptions)
    - Probing rounds executed
    - Syscall tracer fidelity and backend
    - Explicit caveats explaining what was NOT verified.
    """
    stats = manifest.get("_stats") or {}
    tool_stats = stats.get("tools") or {}
    declared_tools = manifest.get("tools") or []
    num_declared = len(declared_tools)

    called_calls = tool_stats.get("called", 0)
    ok_calls = tool_stats.get("ok", 0)
    failed_calls = max(0, called_calls - ok_calls)
    rounds = stats.get("rounds", 1)
    tracer = stats.get("tracer") or ("stdio" if manifest.get("syscalls_available") else "none")
    syscalls_available = manifest.get("syscalls_available", False)

    # Coverage calculations
    if num_declared == 0:
        tool_coverage_pct = 100.0
        exercised_unique = 0
    else:
        exercised_unique = num_declared if (called_calls >= num_declared) else min(num_declared, called_calls)
        tool_coverage_pct = min(100.0, (exercised_unique / num_declared) * 100.0)

    call_success_pct = 100.0 if called_calls == 0 else (ok_calls / called_calls) * 100.0

    # Tracer fidelity
    sb_mode = manifest.get("sandbox") or (tracer if isinstance(tracer, str) and tracer.startswith("sandbox-") else None)
    if sb_mode:
        tracer_fidelity = "HIGH"
        tracer_desc = f"Container Sandbox ({sb_mode}) with dropped caps and filesystem isolation"
    elif not syscalls_available:
        tracer_fidelity = "LOW"
        tracer_desc = "untraced / manifest analysis only"
    elif tracer in ("ebpf", "linux-ebpf"):
        tracer_fidelity = "HIGH"
        tracer_desc = "Linux kernel eBPF tracepoints (CO-RE)"
    elif tracer in ("dylib", "macos-dylib"):
        tracer_fidelity = "MEDIUM-HIGH"
        tracer_desc = "macOS DYLD library interposition"
    elif tracer in ("preload", "linux-preload"):
        tracer_fidelity = "MEDIUM-HIGH"
        tracer_desc = "Linux LD_PRELOAD library interposition"
    elif tracer == "strace":
        tracer_fidelity = "MEDIUM"
        tracer_desc = "Linux strace ptrace filtering"
    else:
        tracer_fidelity = "MEDIUM"
        tracer_desc = f"stdio tracer ({tracer})"

    caveats = []
    if sb_mode:
        caveats.append(f"Target ran inside an isolated container sandbox ({sb_mode}); host filesystem and environment were strictly isolated.")
    elif not syscalls_available:
        caveats.append("Syscall tracing disabled or unavailable; runtime behavior was not observed.")
    else:
        if tracer in ("dylib", "preload", "macos-dylib", "linux-preload"):
            caveats.append("Libc interposition cannot intercept statically linked binaries (Go, musl Rust) or raw direct kernel syscalls.")
        if rounds <= 1:
            caveats.append("Single-round probing: time-delayed triggers or stateful execution paths may remain unexercised (use --probe-rounds 3).")

    if failed_calls > 0:
        caveats.append(f"{failed_calls} tool call(s) failed or timed out during probing.")

    if num_declared == 0:
        caveats.append("No tools declared in server manifest.")
    elif exercised_unique < num_declared:
        caveats.append(f"{num_declared - exercised_unique} declared tool(s) were never exercised.")

    # Confidence score determination
    if (not syscalls_available and not sb_mode) or num_declared == 0:
        score = "LOW"
    elif tool_coverage_pct >= 90.0 and call_success_pct >= 80.0 and rounds >= 2:
        score = "HIGH"
    elif tool_coverage_pct >= 75.0 and call_success_pct >= 50.0:
        score = "MEDIUM"
    else:
        score = "LOW"

    return {
        "score": score,
        "tools_declared": num_declared,
        "tools_exercised": exercised_unique,
        "tools_coverage_pct": round(tool_coverage_pct, 1),
        "calls_total": called_calls,
        "calls_ok": ok_calls,
        "calls_failed": failed_calls,
        "call_success_rate_pct": round(call_success_pct, 1),
        "probe_rounds": rounds,
        "tracer_backend": tracer,
        "tracer_fidelity": tracer_fidelity,
        "tracer_description": tracer_desc,
        "caveats": caveats,
    }


def report(out_dir, *, resolve_dns: bool = True, show_scorecard: bool = False, config: dict | None = None) -> list:
    """Text reporter. Prints a human-readable summary; returns findings."""
    manifest, profile = load(out_dir)
    findings = build_findings(manifest, profile, resolve_dns=resolve_dns, config=config, persist_rugpull=True)
    server_instructions = manifest.get("instructions") or ""
    tools = manifest.get("tools") or []
    all_tools_claim_local = bool(tools) and all(_claims_local_operation(t.get("description", "")) for t in tools)
    claims_local = _claims_local_operation(server_instructions) or all_tools_claim_local
    syscalls_available = manifest.get("syscalls_available", True)

    confidence = compute_audit_confidence(manifest, profile)
    print(f"\n  === AUDIT CONFIDENCE: {confidence['score']} ===")
    print(f"  • Tool Coverage:  {confidence['tools_exercised']}/{confidence['tools_declared']} tools exercised ({confidence['tools_coverage_pct']}%)")
    print(f"  • Call Success:   {confidence['calls_ok']}/{confidence['calls_total']} calls succeeded ({confidence['call_success_rate_pct']}%)")
    print(f"  • Probing Depth:  {confidence['probe_rounds']} round(s)")
    print(f"  • Tracer Backend: {confidence['tracer_description']} [{confidence['tracer_fidelity']}]")
    if confidence["caveats"]:
        print("  • Verification Caveats:")
        for c in confidence["caveats"]:
            print(f"      - {c}")

    print(f"\n  target tools: {_tool_names(manifest)}")
    print(f"  resources:    {len(manifest.get('resources', []))}, "
          f"prompts: {len(manifest.get('prompts', []))}")
    print(f"  declared scope hints: {'mentions local/offline' if claims_local else 'none'}")
    if not syscalls_available:
        print("  syscall tracing: disabled/unavailable (manifest analysis only)")
    print("  " + "-" * 56)
    if not findings:
        if syscalls_available:
            print("  no declared-vs-observed deviations detected")
        else:
            print("  no manifest deviations detected (runtime behavior was not traced)")
    for sev, msg in sorted(findings, key=lambda x: x[0]):
        icon = "[!]" if sev == "HIGH" else "[i]"
        print(f"  {icon} {sev:4} {msg}")
    print()

    if show_scorecard:
        from . import scorecard as scorecard_mod
        card = scorecard_mod.compute_scorecard(manifest, profile, findings)
        scorecard_mod.print_scorecard(card)

    return findings


def report_json(out_dir, *, resolve_dns: bool = True, config: dict | None = None) -> dict:
    """JSON reporter. Returns a serializable dict for CI/CD consumption."""
    from . import scorecard as scorecard_mod
    manifest, profile = load(out_dir)
    findings = build_findings(manifest, profile, resolve_dns=resolve_dns, config=config, persist_rugpull=True)
    scorecard = scorecard_mod.compute_scorecard(manifest, profile, findings)
    confidence = compute_audit_confidence(manifest, profile)
    return {
        "server_cmd": manifest.get("server_cmd"),
        "manifest_sha256": manifest.get("manifest_sha256"),
        "syscalls_available": manifest.get("syscalls_available", True),
        "audit_confidence": confidence,
        "declared": {
            "tools": [t["name"] for t in manifest.get("tools", [])],
            "resources": [r["uri"] for r in manifest.get("resources", [])],
            "prompts": [p["name"] for p in manifest.get("prompts", [])],
        },
        "observed": profile,
        "findings": [{"severity": s, "message": m} for s, m in findings],
        "scorecard": scorecard,
        "stats": manifest.get("_stats", {}),
    }


def report_sarif(out_dir, *, resolve_dns: bool = True, config: dict | None = None) -> dict:
    """SARIF reporter. Returns an OASIS SARIF v2.1.0 dict for GitHub Code Scanning."""
    from . import sarif as sarif_mod
    json_data = report_json(out_dir, resolve_dns=resolve_dns, config=config)
    return sarif_mod.to_sarif(json_data)


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("OUT_DIR", "/tmp/mcp_behave_out")
    report(out)

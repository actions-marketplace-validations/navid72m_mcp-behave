"""Declared-vs-observed reporter. Compares the manifest the server advertises
against the syscalls it actually issued, plus the manifest it advertised on
previous runs (rug-pull detection).

Findings are framed as OBSERVATIONS ('does X, undeclared'), never accusations."""
import hashlib, json, os, re, socket, sys
from pathlib import Path
from .analyze import analyze

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

# Prompt injection heuristics in metadata and outputs (CSA TTP: Tool Description & Output Poisoning)
PROMPT_INJECTION_PATTERN = re.compile(
    r'(?i)(?:\bignore\s+(?:all\s+)?previous\s+instructions\b'
    r'|\bsystem\s+prompt\s*:'
    r'|<system>'
    r'|\[system\s+instruction\]'
    r'|\byou\s+must\s+(?:always\s+)?call\s+this\s+tool\s+first\b'
    r'|\boverride\s+(?:all\s+)?prior\s+instructions\b)'
)

# Markdown and HTML external image exfiltration regex (CSA TTP: Output Prompt Injection / Data Exfiltration)
MARKDOWN_IMAGE_PATTERN = re.compile(r'!\[[^\]]*\]\(\s*(https?://[^\s\)]+)')
HTML_IMAGE_PATTERN = re.compile(r'<img\s+[^>]*src=[\"\'](https?://[^\"\'\s>]+)[\"\']', re.IGNORECASE)

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


def _rugpull_check(manifest: dict) -> tuple[str, str] | None:
    """Compare this run's manifest hash against the stored one for this server.
    Returns a finding tuple if changed, None otherwise. Updates the store either way."""
    cmd = manifest.get("server_cmd") or []
    current = manifest.get("manifest_sha256")
    if not current:
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
    try:
        record.write_text(json.dumps({"server_cmd": cmd,
                                       "manifest_sha256": current}, indent=2))
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

    # Check tools and parameter schemas
    for tool in manifest.get("tools", []):
        tname = tool.get("name", "unknown")
        findings.extend(_check_text_for_covert_channels(tool.get("name", ""), f"tool name '{tname}'"))
        findings.extend(_check_text_for_covert_channels(tool.get("description", ""), f"tool '{tname}' description"))

        schema = tool.get("inputSchema") or {}
        props = schema.get("properties") or {}
        for pname, pdef in props.items():
            if isinstance(pdef, dict):
                pdesc = pdef.get("description", "")
                findings.extend(_check_text_for_covert_channels(pdesc, f"tool '{tname}' parameter '{pname}' description"))

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

    return findings


def build_findings(manifest: dict, profile: dict, resolve_dns: bool = True) -> list:
    """Returns list of (severity, message) tuples. Pure function -- no I/O
    except optional reverse-DNS lookups."""
    descs = _all_descriptions(manifest)
    claims_local = any(w in descs for w in ("local", "offline", "no network"))
    findings = []

    for ipport in profile.get("network_connects", []):
        host = _resolve(ipport) if resolve_dns else None
        where = f"{ipport} ({host})" if host else ipport
        sev = "HIGH" if claims_local else "INFO"
        note = " -- but a description claims local/offline operation" if claims_local else ""
        findings.append((sev, f"network egress to {where}{note}"))

    for path in profile.get("files_opened", []):
        if any(s in path for s in SENSITIVE):
            findings.append(("HIGH", f"read a sensitive path: {path}"))

    for proc in profile.get("subprocesses", []):
        findings.append(("INFO", f"spawned subprocess: {proc}"))

    rug = _rugpull_check(manifest)
    if rug:
        findings.append(rug)

    # CSA TTP: Metadata covert channels & prompt injection scanning
    findings.extend(_scan_metadata(manifest))

    # CSA TTP: Tool output safety & markdown exfiltration scanning
    findings.extend(_scan_outputs(manifest))

    return findings


def _tool_names(manifest: dict) -> str:
    return ", ".join(t["name"] for t in manifest.get("tools", [])) or "(none)"


def report(out_dir, *, resolve_dns: bool = True, show_scorecard: bool = False) -> list:
    """Text reporter. Prints a human-readable summary; returns findings."""
    manifest, profile = load(out_dir)
    findings = build_findings(manifest, profile, resolve_dns=resolve_dns)
    descs = _all_descriptions(manifest)
    claims_local = any(w in descs for w in ("local", "offline", "no network"))
    syscalls_available = manifest.get("syscalls_available", True)

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


def report_json(out_dir, *, resolve_dns: bool = True) -> dict:
    """JSON reporter. Returns a serializable dict for CI/CD consumption."""
    from . import scorecard as scorecard_mod
    manifest, profile = load(out_dir)
    findings = build_findings(manifest, profile, resolve_dns=resolve_dns)
    scorecard = scorecard_mod.compute_scorecard(manifest, profile, findings)
    return {
        "server_cmd": manifest.get("server_cmd"),
        "manifest_sha256": manifest.get("manifest_sha256"),
        "syscalls_available": manifest.get("syscalls_available", True),
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


def report_sarif(out_dir, *, resolve_dns: bool = True) -> dict:
    """SARIF reporter. Returns an OASIS SARIF v2.1.0 dict for GitHub Code Scanning."""
    from . import sarif as sarif_mod
    json_data = report_json(out_dir, resolve_dns=resolve_dns)
    return sarif_mod.to_sarif(json_data)


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("OUT_DIR", "/tmp/mcp_behave_out")
    report(out)

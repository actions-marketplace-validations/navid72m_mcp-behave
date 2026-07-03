"""Run an MCP server under strace, exercise every capability (tools, resources,
prompts) with synthesized inputs, and record both the server's self-declared
manifest and the raw syscall trace of what it actually did.

No judgements here -- that's report.py."""
import asyncio, hashlib, json, os, platform, shutil, sys
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

OUT_DIR    = os.environ.get("OUT_DIR", "/tmp/mcp_behave_out")
TRACE_FILE = os.path.join(OUT_DIR, "trace.log")
MANIFEST   = os.path.join(OUT_DIR, "manifest.json")
# openat: file reads. connect: outbound network. execve: subprocesses.
# (sendto was traced before but never parsed -- removed to keep the log lean.)
SYSCALLS   = "openat,connect,execve"
# Per-call timeout. A hanging tool used to hang the whole probe.
DEFAULT_CALL_TIMEOUT = float(os.environ.get("MCP_BEHAVE_CALL_TIMEOUT", "15"))


def _macos_tracer_dylib() -> str | None:
    """Compile (once, cached) the DYLD interposition dylib and return its path.

    We ship the .c source in the package and build it locally so the dylib
    always matches the host arch. Returns None if we can't build it (no cc),
    letting the caller fall back to untraced manifest-only mode with a hint.
    """
    src = os.path.join(os.path.dirname(__file__), "macos_tracer.c")
    if not os.path.exists(src):
        return None
    cache = os.path.join(
        os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache"),
        "mcp-behave")
    os.makedirs(cache, exist_ok=True)
    dylib = os.path.join(cache, "libmcpbehave_trace.dylib")
    # Rebuild if missing or older than the source (e.g. after a package update).
    if os.path.exists(dylib) and os.path.getmtime(dylib) >= os.path.getmtime(src):
        return dylib
    cc = shutil.which("cc") or shutil.which("clang")
    if not cc:
        return None
    import subprocess
    # Build UNIVERSAL2 (arm64 + x86_64). The target interpreter's arch may
    # differ from ours -- e.g. an x86_64 conda python (under Rosetta) on an
    # Apple Silicon host. A single-arch dylib whose slice doesn't match the
    # target makes dyld ABORT the injected process (surfaces as "connection
    # closed"). A fat dylib loads into either. Fall back to native-only if the
    # universal build fails (e.g. a missing SDK slice).
    last = ""
    for arch_flags in (["-arch", "arm64", "-arch", "x86_64"],
                       ["-arch", platform.machine()]):
        try:
            subprocess.run([cc, *arch_flags, "-dynamiclib", "-O2",
                            "-o", dylib, src],
                           check=True, capture_output=True, text=True, timeout=90)
            return dylib
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            last = getattr(exc, "stderr", str(exc))
    print(f"[probe] failed to build macOS tracer: {last}", file=sys.stderr)
    return None


def _target_is_hardened(exe: str) -> bool | None:
    """Does `exe` carry the hardened-runtime flag? A hardened process refuses
    DYLD_INSERT_LIBRARIES for ad-hoc-signed dylibs (like ours) and dyld ABORTS
    it on load -- which surfaces to us as "connection closed", not a clean skip.

    Returns True/False, or None if we can't tell (no codesign, unsigned, etc.).
    The hardened flag lives in the CodeDirectory flags, NOT in entitlements --
    so we read `codesign -d --verbose` and look for the 'runtime' flag.
    """
    cs = shutil.which("codesign")
    if not cs:
        return None
    path = shutil.which(exe) or exe
    import subprocess
    try:
        # codesign writes its report to stderr.
        out = subprocess.run([cs, "-d", "--verbose=4", path],
                             capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return None
    import re
    for line in (out.stdout + out.stderr).splitlines():
        # codesign prints e.g. "CodeDirectory v=... flags=0x10000(runtime) ..."
        # -- the flags token is mid-line, not at the start.
        m = re.search(r"flags=(\S+)", line)
        if m:
            return "runtime" in m.group(1)
    return None


def _tracer_setup(server_cmd: list[str], trace_file: str
                  ) -> tuple[list[str], str, dict]:
    """Pick the platform's tracer.

    Returns (argv, tracer_name, env_overlay). tracer_name is "" if no tracer
    is available (caller falls back to untraced). On macOS the server argv is
    UNCHANGED -- tracing is done by injecting a dylib via env, so the server
    runs as the normal user (no root, unlike the old dtruss path).
    """
    if platform.system() == "Darwin":
        dylib = _macos_tracer_dylib()
        if not dylib:
            return server_cmd, "", {}
        # Warn BEFORE launch: if the target interpreter is hardened, dyld will
        # abort it on inject and the failure looks like "connection closed".
        # Catching it here turns a cryptic abort into an actionable message.
        if server_cmd and _target_is_hardened(server_cmd[0]):
            resolved = shutil.which(server_cmd[0]) or server_cmd[0]
            print(f"[probe] WARNING: '{resolved}' has the hardened runtime; it "
                  "will reject the injected tracer and likely abort on launch.\n"
                  "[probe] Run the target under a NON-hardened interpreter "
                  "(Homebrew/uv/pyenv), e.g.:\n"
                  f"[probe]     mcp-behave \"$(brew --prefix)/bin/python3\" "
                  "<your-server-args>", file=sys.stderr)
        # DYLD_INSERT_LIBRARIES injects our interposers; the tracer writes
        # records to MCP_BEHAVE_TRACE_FILE (never to stdout -- that carries
        # the JSON-RPC protocol). Env propagates to posix_spawn children too.
        return server_cmd, "dylib", {
            "DYLD_INSERT_LIBRARIES": dylib,
            "MCP_BEHAVE_TRACE_FILE": trace_file,
        }

    if shutil.which("strace"):
        return (["strace", "-f", "-qq", "-e", f"trace={SYSCALLS}",
                 "-o", trace_file, *server_cmd], "strace", {})
    return server_cmd, "", {}


def synth_args(schema: dict) -> dict:
    """Synthesize ONE plausible-and-valid input per field from a JSON schema.

    Strategy (first match wins, per property):
      1. JSON Schema `format` (uri, email, ipv4, date-time, ...) -- standards-based.
      2. Key-name heuristics (url, path, query, ...) -- pragmatic; many MCP tools
         don't set `format` but name fields obviously.
      3. Type-based default -- safety net.

    Goal is NOT coverage or fuzzing -- just inputs realistic enough that the tool
    actually runs (e.g. a `url` field gets a real URL) so we can observe behavior.
    A constrained `enum` is honored when present (first value).
    """
    # RFC 2606 / 5737 / 3849 reserved ranges -- keeps the probe's own traffic honest.
    FORMAT_VALUES = {
        "uri": "http://example.com/",
        "url": "http://example.com/",
        "iri": "http://example.com/",
        "email": "probe@example.com",
        "idn-email": "probe@example.com",
        "hostname": "example.com",
        "ipv4": "192.0.2.1",
        "ipv6": "2001:db8::1",
        "date-time": "2026-01-01T00:00:00Z",
        "date": "2026-01-01",
        "time": "00:00:00Z",
        "uuid": "00000000-0000-0000-0000-000000000000",
    }
    KEYNAME_HINTS = (
        ("url", "http://example.com/"),
        ("uri", "http://example.com/"),
        ("link", "http://example.com/"),
        ("href", "http://example.com/"),
        ("endpoint", "http://example.com/"),
        ("path", "/tmp/probe-canary.txt"),
        ("file", "/tmp/probe-canary.txt"),
        ("dir", "/tmp"),
        ("email", "probe@example.com"),
        ("host", "example.com"),
        ("query", "probe-canary"),
        ("search", "probe-canary"),
        ("text", "probe-canary"),
        ("name", "probe-canary"),
    )
    TYPE_DEFAULTS = {"string": "canary-input", "integer": 1, "number": 1.0,
                     "boolean": True, "array": [], "object": {}}

    def synth_one(key: str, spec: dict):
        spec = spec or {}
        if isinstance(spec.get("enum"), list) and spec["enum"]:
            return spec["enum"][0]
        fmt = spec.get("format")
        if fmt in FORMAT_VALUES:
            return FORMAT_VALUES[fmt]
        if spec.get("type", "string") == "string":
            k = key.lower()
            for needle, value in KEYNAME_HINTS:
                if needle in k:
                    return value
        return TYPE_DEFAULTS.get(spec.get("type", "string"), "canary-input")

    return {key: synth_one(key, spec)
            for key, spec in (schema or {}).get("properties", {}).items()}


async def _list_safely(coro, label: str):
    """Some servers don't implement resources/ or prompts/. Tolerate that."""
    try:
        return await coro
    except Exception as exc:
        print(f"[probe]   {label} not supported: {exc}")
        return None


async def _call_with_timeout(coro, label: str, timeout: float):
    try:
        await asyncio.wait_for(coro, timeout=timeout)
        return True
    except asyncio.TimeoutError:
        print(f"[probe]   {label} timed out after {timeout}s")
        return False
    except Exception as exc:
        print(f"[probe]   {label} raised: {exc}")
        return False


async def _exercise(session: ClientSession, call_timeout: float):
    """Shared logic: discover + exercise tools, resources, prompts on a live session."""
    tools_meta, resources_meta, prompts_meta = [], [], []
    stats = {"tools": {"called": 0, "ok": 0}, "resources": {"called": 0, "ok": 0},
             "prompts": {"called": 0, "ok": 0}}

    await session.initialize()

    tools_result = await _list_safely(session.list_tools(), "tools/list")
    tools = getattr(tools_result, "tools", []) if tools_result else []
    tools_meta = [{"name": t.name, "description": t.description,
                   "inputSchema": t.inputSchema} for t in tools]
    print(f"[probe] discovered {len(tools)} tool(s)")
    for t in tools:
        args = synth_args(t.inputSchema)
        print(f"[probe] calling tool {t.name}({json.dumps(args)})")
        stats["tools"]["called"] += 1
        if await _call_with_timeout(
            session.call_tool(t.name, args), f"tool {t.name}", call_timeout):
            stats["tools"]["ok"] += 1

    res_result = await _list_safely(session.list_resources(), "resources/list")
    resources = getattr(res_result, "resources", []) if res_result else []
    resources_meta = [{"uri": str(r.uri), "name": r.name,
                       "description": r.description,
                       "mimeType": r.mimeType} for r in resources]
    print(f"[probe] discovered {len(resources)} resource(s)")
    for r in resources:
        print(f"[probe] reading resource {r.uri}")
        stats["resources"]["called"] += 1
        if await _call_with_timeout(
            session.read_resource(r.uri), f"resource {r.uri}", call_timeout):
            stats["resources"]["ok"] += 1

    pr_result = await _list_safely(session.list_prompts(), "prompts/list")
    prompts = getattr(pr_result, "prompts", []) if pr_result else []
    prompts_meta = [{"name": p.name, "description": p.description,
                     "arguments": [{"name": a.name, "required": a.required}
                                   for a in (p.arguments or [])]}
                    for p in prompts]
    print(f"[probe] discovered {len(prompts)} prompt(s)")
    for p in prompts:
        args = {a.name: "canary-input" for a in (p.arguments or [])
                if a.required}
        print(f"[probe] getting prompt {p.name}({json.dumps(args)})")
        stats["prompts"]["called"] += 1
        if await _call_with_timeout(
            session.get_prompt(p.name, args), f"prompt {p.name}", call_timeout):
            stats["prompts"]["ok"] += 1

    return tools_meta, resources_meta, prompts_meta, stats


def _write_manifest(server_cmd, tools_meta, resources_meta, prompts_meta, stats,
                    *, transport: str, syscalls_available: bool):
    manifest = {
        "server_cmd": list(server_cmd) if server_cmd else None,
        "transport": transport,
        "syscalls_available": syscalls_available,
        "tools": tools_meta,
        "resources": resources_meta,
        "prompts": prompts_meta,
        "manifest_sha256": hashlib.sha256(
            json.dumps({"tools": tools_meta, "resources": resources_meta,
                        "prompts": prompts_meta}, sort_keys=True).encode()
        ).hexdigest(),
        "_stats": stats,
    }
    with open(MANIFEST, "w") as f:
        json.dump(manifest, f, indent=2)
    print(f"[probe] manifest -> {MANIFEST}")
    if syscalls_available:
        print(f"[probe] trace    -> {TRACE_FILE}")


async def run(server_cmd: list[str], call_timeout: float = DEFAULT_CALL_TIMEOUT):
    """Stdio transport: wrap the server in the platform's syscall tracer
    (strace on Linux, an injected dylib on macOS) and connect via stdio."""
    os.makedirs(OUT_DIR, exist_ok=True)
    trace_cmd, tracer, env_overlay = _tracer_setup(server_cmd, TRACE_FILE)
    syscalls_available = bool(tracer)
    # Truncate/create the trace file up front: the macOS tracer opens it
    # O_APPEND, and analyze() needs a readable file even if the server exits
    # before any interesting syscall fires.
    open(TRACE_FILE, "w").close()

    if syscalls_available:
        params = StdioServerParameters(command=trace_cmd[0], args=trace_cmd[1:],
                                       env={**os.environ, **env_overlay})
    else:
        print(f"[probe] no syscall tracer available on {platform.system()}; "
              "running server untraced (manifest analysis only)",
              file=sys.stderr)
        params = StdioServerParameters(command=server_cmd[0], args=server_cmd[1:],
                                       env={**os.environ})

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            tools_meta, resources_meta, prompts_meta, stats = await _exercise(
                session, call_timeout)
    _write_manifest(server_cmd, tools_meta, resources_meta, prompts_meta, stats,
                    transport="stdio", syscalls_available=syscalls_available)


async def run_remote(url: str, *, transport: str,
                     call_timeout: float = DEFAULT_CALL_TIMEOUT):
    """Remote transport (sse/streamable-http): connect to an already-running
    server. Syscall ground-truth is NOT available -- we can only verify the
    declared surface and detect rug-pulls. analyze.py is a no-op in this mode."""
    os.makedirs(OUT_DIR, exist_ok=True)
    # Write an empty trace so analyze() doesn't crash.
    open(TRACE_FILE, "w").close()

    if transport == "sse":
        from mcp.client.sse import sse_client
        ctx = sse_client(url)
    elif transport == "streamable-http":
        from mcp.client.streamable_http import streamablehttp_client
        ctx = streamablehttp_client(url)
    else:
        raise ValueError(f"unknown remote transport: {transport}")

    async with ctx as conn:
        # streamable_http returns (read, write, _); sse returns (read, write)
        read, write = conn[0], conn[1]
        async with ClientSession(read, write) as session:
            tools_meta, resources_meta, prompts_meta, stats = await _exercise(
                session, call_timeout)
    _write_manifest([url], tools_meta, resources_meta, prompts_meta, stats,
                    transport=transport, syscalls_available=False)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: probe.py <server-command> [args...]"); sys.exit(2)
    asyncio.run(run(sys.argv[1:]))
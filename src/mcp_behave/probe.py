"""Run an MCP server under a runtime syscall tracer (or untraced), exercise every capability (tools, resources,
prompts) with synthesized inputs, and record both the server's self-declared
manifest and the raw syscall trace of what it actually did.

No judgements here -- that's report.py."""
import asyncio, hashlib, json, os, platform, re, shutil, signal, sys, tempfile
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator, Optional, Tuple
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

OUT_DIR    = os.environ.get("OUT_DIR", "/tmp/mcp_behave_out")
TRACE_FILE = os.path.join(OUT_DIR, "trace.log")
MANIFEST   = os.path.join(OUT_DIR, "manifest.json")


# Sentinel values for audit_status recorded in manifest.json
AUDIT_STATUS_COMPLETE = "complete"
AUDIT_STATUS_PARTIAL  = "partial"
AUDIT_STATUS_FAILED   = "failed"


@asynccontextmanager
async def supervised_stdio_client(
    server_cmd: list[str],
    env: dict | None = None,
    grace_period: float = 3.0,
) -> AsyncGenerator[Tuple[asyncio.StreamReader, asyncio.StreamWriter, int], None]:
    """Launch an MCP server subprocess in its own process group and yield
    (stdout_reader, stdin_writer, pid).  On exit (normal, exception, or
    cancellation) the entire process group is terminated safely.

    This provides equivalent lifecycle guarantees to the ``wrap`` path:
    - ``start_new_session=True`` creates a dedicated process group.
    - ``terminate_process_group_by_pid`` cleans up surviving descendants
      even when the root server has already crashed.
    - stdin / stdout are piped; stderr inherits from the parent.

    Unlike the MCP SDK's ``stdio_client`` context manager this implementation
    exposes the process handle so callers can detect premature exit, capture
    the exit code, and guarantee that no grandchild process survives audit
    cleanup.
    """
    if not server_cmd:
        raise ValueError("supervised_stdio_client: empty server command")

    child_env = dict(os.environ)
    if env:
        child_env.update(env)

    proc = await asyncio.create_subprocess_exec(
        *server_cmd,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=None,            # inherit parent stderr (matches wrap behaviour)
        start_new_session=True, # own process group for clean descendant reaping
        env=child_env,
    )

    # Adapt raw asyncio StreamWriter/Reader to the objects expected by
    # mcp.ClientSession (which accepts any object with read/write interfaces).
    stdout_reader: asyncio.StreamReader = proc.stdout  # type: ignore[assignment]
    stdin_writer: asyncio.StreamWriter  = proc.stdin   # type: ignore[assignment]
    pid: int = proc.pid

    try:
        yield stdout_reader, stdin_writer, pid
    finally:
        await _terminate_process_group_by_pid(proc, grace_period=grace_period)


async def _terminate_process_group_by_pid(
    proc: asyncio.subprocess.Process,
    grace_period: float = 3.0,
) -> int:
    """Terminate the process group identified by proc.pid.

    Safe when the root has already exited.  Always returns the root's
    original exit code, never a cleanup sentinel.
    """
    original_exit_code: Optional[int] = proc.returncode
    pid = proc.pid

    # Close stdin only while root is still alive
    if proc.stdin and original_exit_code is None:
        try:
            proc.stdin.close()
            await proc.stdin.wait_closed()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass

    # Give root a grace period to exit on its own
    if original_exit_code is None:
        try:
            await asyncio.wait_for(proc.wait(), timeout=grace_period)
            original_exit_code = proc.returncode
        except asyncio.TimeoutError:
            pass

    # SIGTERM the whole process group regardless of root status
    try:
        os.killpg(pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError, OSError):
        pass

    if original_exit_code is None:
        try:
            await asyncio.wait_for(proc.wait(), timeout=1.0)
            original_exit_code = proc.returncode
        except asyncio.TimeoutError:
            pass
    else:
        await asyncio.sleep(0.05)

    # SIGKILL as final backstop
    try:
        os.killpg(pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        pass

    if original_exit_code is None:
        try:
            await asyncio.wait_for(proc.wait(), timeout=1.0)
            original_exit_code = proc.returncode
        except asyncio.TimeoutError:
            pass

    return original_exit_code if original_exit_code is not None else 137


def set_out_dir(path: str):
    global OUT_DIR, TRACE_FILE, MANIFEST
    OUT_DIR = path
    TRACE_FILE = os.path.join(OUT_DIR, "trace.log")
    MANIFEST = os.path.join(OUT_DIR, "manifest.json")


# Syscalls to capture:
# - open, openat, creat: filesystem reads, modifications, and overwrites
# - connect, sendto, sendmsg, sendmmsg: TCP/UDP network connections, DNS, AF_UNIX
# - execve, execveat: subprocess invocations and system commands
SYSCALLS = "open,openat,creat,connect,sendto,sendmsg,sendmmsg,execve,execveat"
# Per-call timeout. A hanging tool used to hang the whole probe.
DEFAULT_CALL_TIMEOUT = float(os.environ.get("MCP_BEHAVE_CALL_TIMEOUT", "15"))


SENSITIVE_ENV_PREFIXES = (
    "AWS_", "GITHUB_", "GH_", "NPM_", "PYPI_", "SLACK_", "OPENAI_",
    "ANTHROPIC_", "GEMINI_", "AZURE_", "GOOGLE_", "CLOUDFLARE_",
    "SSH_", "GNUPG",
)
SENSITIVE_ENV_PATTERN = re.compile(
    r"(?i)(?:api[_-]?key|access[_-]?token|auth[_-]?token|secret|password|passwd|private[_-]?key|credential)"
)


def _build_isolated_env(env_overlay: dict, unsafe_host: bool = False) -> tuple[dict, str | None]:
    """Build an isolated execution environment for the target server.

    Unless unsafe_host=True:
    1. Creates a temporary canary directory as $HOME, seeded with dummy canary files
       (.ssh/id_rsa, .aws/credentials, .env, .netrc) so credential probes trip detection
       without exposing the user's host files.
    2. Scrubs sensitive environment variables (API keys, cloud tokens, secrets).
    3. Sets $HOME, $USERPROFILE, $XDG_CONFIG_HOME, $XDG_DATA_HOME to the canary directory.

    Returns (env_dict, canary_dir_path_or_none).
    """
    if unsafe_host or os.environ.get("MCP_BEHAVE_UNSAFE_HOST") == "1":
        print("[probe] WARNING: Running with --unsafe-host. Target subprocess inherits "
              "host $HOME and credentials without sandbox redirection!", file=sys.stderr)
        return {**os.environ, **env_overlay}, None

    canary_dir = tempfile.mkdtemp(prefix="mcp_behave_canary_home_")

    try:
        # Seed canary targets
        ssh_dir = os.path.join(canary_dir, ".ssh")
        os.makedirs(ssh_dir, exist_ok=True)
        with open(os.path.join(ssh_dir, "id_rsa"), "w") as f:
            f.write("-----BEGIN OPENSSH PRIVATE KEY-----\nCANARY_DUMMY_KEY_FOR_PROBING\n-----END OPENSSH PRIVATE KEY-----\n")

        aws_dir = os.path.join(canary_dir, ".aws")
        os.makedirs(aws_dir, exist_ok=True)
        with open(os.path.join(aws_dir, "credentials"), "w") as f:
            f.write("[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n")

        with open(os.path.join(canary_dir, ".env"), "w") as f:
            f.write("CANARY_PROBE_SECRET=dummy_value_for_probing\n")

        with open(os.path.join(canary_dir, ".netrc"), "w") as f:
            f.write("machine test.local login canary password canarypass\n")

        # Scrub sensitive host environment variables
        cleaned_env = {}
        for k, v in os.environ.items():
            k_upper = k.upper()
            if any(k_upper.startswith(pfx) for pfx in SENSITIVE_ENV_PREFIXES):
                continue
            if SENSITIVE_ENV_PATTERN.search(k):
                continue
            cleaned_env[k] = v

        cleaned_env["HOME"] = canary_dir
        cleaned_env["USERPROFILE"] = canary_dir
        cleaned_env["XDG_CONFIG_HOME"] = os.path.join(canary_dir, ".config")
        cleaned_env["XDG_DATA_HOME"] = os.path.join(canary_dir, ".local", "share")
        cleaned_env.update(env_overlay)

        return cleaned_env, canary_dir
    except Exception as exc:
        shutil.rmtree(canary_dir, ignore_errors=True)
        raise exc


def _tracer_cache_dir() -> str:
    """Find a writable directory for cached tracer dylib/so artifacts.
    Falls back gracefully if ~/.cache is root-owned or unwritable.
    """
    candidates = []
    xdg = os.environ.get("XDG_CACHE_HOME")
    if xdg:
        candidates.append(os.path.join(xdg, "mcp-behave"))
    candidates.append(os.path.expanduser("~/.cache/mcp-behave"))
    candidates.append(os.path.expanduser("~/.mcp-behave/cache"))
    import tempfile
    candidates.append(os.path.join(tempfile.gettempdir(), f"mcp-behave-cache-{os.getuid()}"))

    for d in candidates:
        try:
            os.makedirs(d, exist_ok=True)
            test_file = os.path.join(d, ".write_test")
            with open(test_file, "w") as f:
                f.write("ok")
            os.remove(test_file)
            return d
        except (OSError, PermissionError):
            continue
    return tempfile.gettempdir()


def _macos_tracer_dylib() -> str | None:
    """Compile (once, cached) the DYLD interposition dylib and return its path.

    We ship the .c source in the package and build it locally so the dylib
    always matches the host arch. Returns None if we can't build it (no cc),
    letting the caller fall back to untraced manifest-only mode with a hint.
    """
    src = os.path.join(os.path.dirname(__file__), "macos_tracer.c")
    if not os.path.exists(src):
        return None
    cache = _tracer_cache_dir()
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


def _linux_tracer_so() -> str | None:
    """Compile (once, cached) the LD_PRELOAD shared library and return its path.

    We ship the .c source in the package and build it locally so the shared object
    always matches the host architecture and libc. Returns None if we can't build
    it (no cc), letting the caller fall back to strace or untraced mode.
    """
    src = os.path.join(os.path.dirname(__file__), "linux_tracer.c")
    if not os.path.exists(src):
        return None
    cache = _tracer_cache_dir()
    so = os.path.join(cache, "libmcpbehave_trace.so")
    if os.path.exists(so) and os.path.getmtime(so) >= os.path.getmtime(src):
        return so
    cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if not cc:
        return None
    import subprocess
    try:
        subprocess.run([cc, "-shared", "-fPIC", "-O2", "-o", so, src, "-ldl"],
                       check=True, capture_output=True, text=True, timeout=90)
        return so
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        err = getattr(exc, "stderr", str(exc))
        print(f"[probe] failed to build Linux preload tracer: {err}", file=sys.stderr)
        return None


def detect_tracer(tracer_override: str | None = None) -> str:
    """Detect which tracer backend would be selected ('dylib', 'preload', 'strace', or '')."""
    _, tracer_name, _ = _tracer_setup([], "", tracer_override)
    return tracer_name


def _tracer_setup(server_cmd: list[str], trace_file: str,
                  tracer_override: str | None = None
                  ) -> tuple[list[str], str, dict]:
    """Pick the platform's tracer.

    Returns (argv, tracer_name, env_overlay). tracer_name is "" if no tracer
    is available or tracing is disabled (caller falls back to untraced).
    On macOS/Linux native tracers the server argv is UNCHANGED -- tracing is done
    by injecting a library via env, so the server runs as the normal user
    without root or SYS_PTRACE.
    """
    if tracer_override in ("none", "untraced", "off"):
        return server_cmd, "", {}

    if tracer_override == "ebpf":
        from .ebpf import is_ebpf_supported
        supported, reason = is_ebpf_supported()
        if not supported and os.environ.get("MCP_BEHAVE_MOCK_EBPF") != "1":
            raise RuntimeError(
                f"Requested tracer 'ebpf' is unavailable: {reason}. "
                "Use --tracer auto or --no-trace."
            )
        return server_cmd, "ebpf", {
            "MCP_BEHAVE_TRACE_FILE": trace_file,
            "MCP_BEHAVE_TRACER": "ebpf",
        }

    if platform.system() == "Darwin":
        if tracer_override and tracer_override not in ("dylib", "native", "auto"):
            raise RuntimeError(
                f"Requested tracer '{tracer_override}' is not supported on macOS. "
                "Use --tracer auto, --tracer dylib, or --no-trace."
            )
        dylib = _macos_tracer_dylib()
        if not dylib:
            if tracer_override in ("dylib", "native"):
                raise RuntimeError(
                    "Requested tracer 'dylib' is unavailable (could not build macOS interposer; "
                    "ensure a C compiler is installed)."
                )
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

    if platform.system() == "Linux":
        if tracer_override == "dylib":
            raise RuntimeError(
                "Requested tracer 'dylib' is not supported on Linux. "
                "Use --tracer auto, --tracer preload, --tracer strace, or --no-trace."
            )
        # 1. Try LD_PRELOAD native tracer first (no root / SYS_PTRACE / strace needed)
        if tracer_override in (None, "auto", "preload", "native"):
            so = _linux_tracer_so()
            if so:
                return server_cmd, "preload", {
                    "LD_PRELOAD": so,
                    "MCP_BEHAVE_TRACE_FILE": trace_file,
                }
            if tracer_override in ("preload", "native"):
                raise RuntimeError(
                    "Requested tracer 'preload' is unavailable (could not build Linux interposer; "
                    "ensure a C compiler is installed)."
                )

        # 2. Fall back to strace if available or requested
        if tracer_override in (None, "auto", "strace"):
            if shutil.which("strace"):
                return (["strace", "-f", "-qq", "-e", f"trace={SYSCALLS}",
                         "-o", trace_file, *server_cmd], "strace", {})
            if tracer_override == "strace":
                raise RuntimeError(
                    "Requested tracer 'strace' is unavailable (strace not found on PATH)."
                )

    if tracer_override and tracer_override not in ("auto",):
        raise RuntimeError(
            f"Requested tracer '{tracer_override}' is not supported on {platform.system()}."
        )

    return server_cmd, "", {}


def unwrap_schema(spec: dict | None) -> dict:
    """Unwrap anyOf / oneOf / allOf schemas (e.g. FastMCP / Pydantic v2 Optional types).
    Selects the first non-null branch and merges its properties with outer spec.
    """
    if not isinstance(spec, dict):
        return {}
    unwrapped = dict(spec)
    for branch_key in ("anyOf", "oneOf", "allOf"):
        branches = unwrapped.get(branch_key)
        if isinstance(branches, list) and branches:
            non_null_branches = [
                b for b in branches
                if isinstance(b, dict) and b.get("type") != "null"
            ]
            if non_null_branches:
                target = non_null_branches[0]
                target_unwrapped = unwrap_schema(target)
                merged = dict(target_unwrapped)
                merged.update({k: v for k, v in unwrapped.items() if k not in ("anyOf", "oneOf", "allOf") and v is not None})
                unwrapped = merged
                break
    t_type = unwrapped.get("type")
    if isinstance(t_type, list):
        non_null = [t for t in t_type if t != "null"]
        unwrapped["type"] = non_null[0] if non_null else ("string" if not non_null else non_null[0])
    return unwrapped


def synth_args(schema: dict | None, round_idx: int = 0, harvested_pool: dict[str, list[Any]] | None = None) -> dict:
    """Synthesize valid arguments from a tool's JSON Schema.

    Goal is NOT coverage or fuzzing -- just inputs realistic enough that the tool
    actually runs (e.g. a `url` field gets a real URL) so we can observe behavior.
    Uses realistic, diversified payloads across probe rounds to resist canary detection.
    A constrained `enum` is honored when present.
    Supports seeding from a harvested pool of real read-only entities (services, databases, projects, etc.).
    """
    # RFC 2606 / 5737 / 3849 reserved ranges -- keeps the probe's own traffic honest.
    FORMAT_VALUES = {
        "uri": ["https://example.com/", "https://example.org/", "https://example.net/"],
        "url": ["https://example.com/", "https://example.org/", "https://example.net/"],
        "iri": ["https://example.com/", "https://example.org/", "https://example.net/"],
        "email": ["admin@example.com", "service@example.org", "contact@example.net"],
        "idn-email": ["admin@example.com", "service@example.org", "contact@example.net"],
        "hostname": ["example.com", "example.org", "example.net"],
        "ipv4": ["192.0.2.1", "198.51.100.1"],
        "ipv6": ["2001:db8::1", "2001:db8::2"],
        "date-time": ["2026-01-01T00:00:00Z", "2026-06-15T12:00:00Z"],
        "date": ["2026-01-01", "2026-06-15"],
        "time": ["00:00:00Z", "12:00:00Z"],
        "uuid": ["00000000-0000-0000-0000-000000000000", "123e4567-e89b-12d3-a456-426614174000"],
    }
    KEYNAME_HINTS = (
        ("url", ["https://example.com/", "https://example.org/", "https://example.net/"]),
        ("uri", ["https://example.com/", "https://example.org/", "https://example.net/"]),
        ("link", ["https://example.com/", "https://example.org/"]),
        ("href", ["https://example.com/", "https://example.org/"]),
        ("endpoint", ["https://example.com/api", "https://example.org/api"]),
        ("path", ["/tmp/sample_file.txt", "/tmp/audit_test.dat", "/tmp/local_document.json"]),
        ("file", ["/tmp/sample_file.txt", "/tmp/audit_test.dat", "/tmp/local_document.json"]),
        ("dir", ["/tmp", "/var/tmp"]),
        ("email", ["admin@example.com", "service@example.org"]),
        ("token", ["mcp-probe-token-sec-99", "mcp-probe-token-sec-88"]),
        ("secret", ["mcp-probe-secret-8877", "mcp-probe-secret-6655"]),
        ("key", ["mcp-probe-key-12345", "mcp-probe-key-67890"]),
        ("password", ["mcp-probe-pass-4321", "mcp-probe-pass-8765"]),
        ("account", ["acct-1"]),
        ("acct", ["acct-1"]),
        ("user", ["user-1"]),
        ("sku", ["widget-1"]),
        ("product", ["widget-1"]),
        ("widget", ["widget-1"]),
        ("host", ["example.com", "example.org"]),
        ("query", ["system status overview", "service health check", "operational metrics"]),
        ("search", ["system status overview", "service health check", "operational metrics"]),
        ("text", ["sample input text", "verified operational data", "standard test request"]),
        ("time", ["12:00", "14:30", "09:15", "00:00"]),
        ("timezone", ["UTC", "America/New_York", "Europe/London"]),
        ("tz", ["UTC", "America/New_York", "Europe/London"]),
        ("name", ["primary_test_item", "worker_node", "default_cluster"]),
        ("id", ["item-101", "node-402", "task-803"]),
    )
    TYPE_DEFAULTS = {
        "string": ["valid-input", "standard-value", "test-parameter"],
        "integer": [1, 2, 5],
        "number": [1.0, 2.5, 10.0],
        "boolean": [False, True],
        "array": [[]],
        "object": [{}]
    }

    def _pick(choices, idx: int):
        if isinstance(choices, list) and choices:
            return choices[idx % len(choices)]
        return choices

    def synth_one(key: str, raw_spec: dict):
        spec = unwrap_schema(raw_spec)
        k = key.lower()

        # If enum is explicitly specified, pick from enum first
        if isinstance(spec.get("enum"), list) and spec["enum"]:
            return _pick(spec["enum"], round_idx)

        t_type = spec.get("type", "string")
        if isinstance(t_type, list):
            non_null = [t for t in t_type if t != "null"]
            t_type = non_null[0] if non_null else (t_type[0] if t_type else "string")

        # Type-aware boolean safety overrides
        if t_type == "boolean":
            # Confirmation / mutating boolean flags must ALWAYS default to False to prevent live mutations
            CONFIRM_TOKENS = {"confirm", "force", "apply", "execute", "delete_data", "destructive", "yes", "commit"}
            k_tokens = set(re.split(r'[_.\-]', k))
            is_confirm = bool(k_tokens & CONFIRM_TOKENS) or any(c in k for c in ("confirm", "delete_data", "destructive"))
            if is_confirm:
                return False

            # Preview / dry run boolean parameters default to True
            if any(c in k for c in ("dry_run", "dryrun", "preview", "simulate")):
                return True

            if "default" in spec and spec["default"] is not None:
                return bool(spec["default"]) if round_idx == 0 else not bool(spec["default"])
            return False if round_idx == 0 else True

        if t_type == "string":
            # Seed from harvested pool if available (e.g. real service names, database names, project IDs)
            if harvested_pool and isinstance(harvested_pool, dict):
                val_list = harvested_pool.get(k)
                if not val_list:
                    aliases = {
                        "service": ["service", "service_name", "services", "name"],
                        "db": ["db", "database", "databases", "db_name", "name"],
                        "database": ["database", "db", "databases", "name"],
                        "project": ["project", "project_id", "projects", "id"],
                        "job": ["job", "job_id", "jobs", "id"],
                        "target": ["target", "target_id", "targets", "name"],
                        "report": ["report", "report_id", "reports", "id"],
                        "table": ["table", "table_name", "tables", "name"],
                        "repo": ["repo", "repository", "repo_path", "path", "dir", "directory"],
                        "repository": ["repository", "repo", "repo_path", "path", "dir", "directory"],
                        "path": ["path", "file", "allowed_directories", "directory", "dir", "repo_path", "repo"],
                        "file": ["file", "path", "filename", "filepath"],
                        "dir": ["dir", "directory", "allowed_directories", "path", "repo_path", "repo"],
                        "directory": ["directory", "dir", "allowed_directories", "path", "repo_path", "repo"],
                        "id": ["id", "name"],
                    }
                    for entity_type, cand_keys in aliases.items():
                        if entity_type in k:
                            for ck in cand_keys:
                                if ck in harvested_pool and harvested_pool[ck]:
                                    val_list = harvested_pool[ck]
                                    break
                            if val_list:
                                break
                if val_list:
                    offset = 1 if (k.endswith("2") or "second" in k) and len(val_list) > 1 else 0
                    return _pick(val_list, round_idx + offset)

            if "default" in spec and spec["default"] is not None and round_idx == 0:
                return spec["default"]
            fmt = spec.get("format")
            if fmt in FORMAT_VALUES:
                return _pick(FORMAT_VALUES[fmt], round_idx)
            for needle, val_list in KEYNAME_HINTS:
                if needle in k:
                    return _pick(val_list, round_idx)

        if t_type in ("integer", "number"):
            if harvested_pool and isinstance(harvested_pool, dict) and any(needle in k for needle in ("id", "project", "job", "pipeline")):
                for cand in (k, "id", "project", "job", "pipeline"):
                    if cand in harvested_pool:
                        for v in harvested_pool[cand]:
                            try:
                                return int(v) if t_type == "integer" else float(v)
                            except (ValueError, TypeError):
                                continue
            if "default" in spec and spec["default"] is not None and round_idx == 0:
                return spec["default"]
            val = _pick(TYPE_DEFAULTS.get(t_type, [1]), round_idx)
            if "minimum" in spec and val < spec["minimum"]:
                val = spec["minimum"]
            return val

        val = _pick(TYPE_DEFAULTS.get(t_type, ["valid-input"]), round_idx)
        if isinstance(val, (int, float)) and "minimum" in spec and val < spec["minimum"]:
            val = spec["minimum"]
        return val

    props = (schema or {}).get("properties", {})
    has_required_field = "required" in (schema or {})
    required = set((schema or {}).get("required") or [])

    # Round 0: if required fields are declared in schema, send required-only payload to avoid
    # tripping over optional filter/timestamp validators (e.g. since, until, tags).
    # If required is empty ([]), send {} so default query execution path is taken.
    if round_idx == 0 and has_required_field:
        target_keys = [k for k in props if k in required]
    else:
        target_keys = list(props.keys())

    return {key: synth_one(key, props[key]) for key in target_keys}


def synth_fuzz_args(schema: dict | None) -> list[dict]:
    """Generate adversarial boundary and fuzzing arguments for a tool's JSON Schema (Idea 3).
    Tests for path traversal, command injection, format string injection, and boundary overflow."""
    if not schema or not isinstance(schema, dict):
        return []
    props = schema.get("properties", {})
    if not props:
        return []

    # Adversarial payloads categorized by target vulnerability
    FUZZ_VECTORS = [
        ("../../../../../../../../etc/passwd", -1),
        ("..\\..\\..\\..\\windows\\win.ini", 0),
        ("; id; whoami", 2147483647),
        ("`id`", 0),
        ("| whoami", -1),
        ("%s%s%s%s%n", 1),
        ("' OR '1'='1' --", 1),
        ("A" * 1000, 9999999),
        ("", 0),
    ]

    base_args = synth_args(schema, round_idx=1)
    fuzz_variations = []

    for str_payload, num_payload in FUZZ_VECTORS:
        variant = dict(base_args)
        for key, raw_spec in props.items():
            if not isinstance(raw_spec, dict):
                continue
            spec = unwrap_schema(raw_spec)
            t = spec.get("type", "string")
            if isinstance(t, list):
                non_null = [item for item in t if item != "null"]
                t = non_null[0] if non_null else (t[0] if t else "string")
            if t == "string":
                if not spec.get("enum"):
                    variant[key] = str_payload
            elif t in ("integer", "number"):
                variant[key] = num_payload
        if variant != base_args and variant not in fuzz_variations:
            fuzz_variations.append(variant)

    return fuzz_variations


async def _list_safely(coro, label: str):
    """Some servers don't implement resources/ or prompts/. Tolerate that."""
    try:
        return await coro
    except Exception as exc:
        print(f"[probe]   {label} not supported: {exc}")
        return None


async def _call_with_timeout(coro, label: str, timeout: float):
    try:
        res = await asyncio.wait_for(coro, timeout=timeout)
        return True, res
    except asyncio.TimeoutError:
        print(f"[probe]   {label} timed out after {timeout}s")
        return False, None
    except Exception as exc:
        print(f"[probe]   {label} raised: {exc}")
        return False, None


def _extract_text_content(res) -> str:
    """Extract concatenated string content from an MCP call result."""
    if res is None:
        return ""
    content = getattr(res, "content", None)
    if content is None and isinstance(res, dict):
        content = res.get("content", [])
    if not isinstance(content, list):
        return ""
    texts = []
    for item in content:
        if hasattr(item, "text"):
            texts.append(str(item.text))
        elif isinstance(item, dict) and "text" in item:
            texts.append(str(item["text"]))
    return "\n".join(texts)


async def _discover_manifest(session: ClientSession):
    """Discover tools, resources, and prompts declared by the server."""
    await session.initialize()

    tools_result = await _list_safely(session.list_tools(), "tools/list")
    tools = getattr(tools_result, "tools", []) if tools_result else []
    tools_meta = []
    for t in tools:
        t_meta = {
            "name": t.name,
            "description": t.description,
            "inputSchema": t.inputSchema,
        }
        if hasattr(t, "annotations") and t.annotations:
            ann = t.annotations
            if hasattr(ann, "model_dump"):
                t_meta["annotations"] = ann.model_dump(exclude_none=True)
            elif isinstance(ann, dict):
                t_meta["annotations"] = ann
            else:
                t_meta["annotations"] = {
                    k: getattr(ann, k)
                    for k in ("readOnlyHint", "idempotentHint", "destructiveHint")
                    if hasattr(ann, k) and getattr(ann, k) is not None
                }
        tools_meta.append(t_meta)

    res_result = await _list_safely(session.list_resources(), "resources/list")
    resources = getattr(res_result, "resources", []) if res_result else []
    resources_meta = [{"uri": str(r.uri), "name": r.name,
                       "description": r.description,
                       "mimeType": r.mimeType} for r in resources]

    pr_result = await _list_safely(session.list_prompts(), "prompts/list")
    prompts = getattr(pr_result, "prompts", []) if pr_result else []
    prompts_meta = [{"name": p.name, "description": p.description,
                     "arguments": [{"name": a.name, "required": a.required}
                                   for a in (p.arguments or [])]}
                    for p in prompts]

    return tools_meta, resources_meta, prompts_meta


def _harvest_entities_from_output(text: str, pool: dict[str, list[Any]], tname: str = "") -> None:
    """Parse JSON or structured plain text output from a read query to harvest entity names.
    Populates candidate identifiers (services, databases, projects, jobs, targets, tables, IDs)
    to seed downstream read-only tool calls without mutating state.
    """
    if not text or not isinstance(text, str):
        return
    text = text.strip()

    data = None
    try:
        data = json.loads(text)
    except Exception:
        match = re.search(r'(\[.*\]|\{.*\})', text, re.DOTALL)
        if match:
            try:
                data = json.loads(match.group(1))
            except Exception:
                data = None

    def _add_entity(key: str, val: Any):
        if not isinstance(val, (str, int)) or isinstance(val, bool):
            return
        sval = str(val).strip()
        if not sval or len(sval) > 128:
            return
        # Skip generic synthetic placeholders
        if sval in ("valid-input", "standard-value", "item-101", "test-parameter", "null", "none"):
            return
        k = key.lower().strip()
        pool.setdefault(k, [])
        if sval not in pool[k]:
            pool[k].append(sval)

    # Derive entity hint from tool name (e.g., list_services -> service, db_list -> db, list_allowed_directories -> path)
    tool_entity_hint = ""
    if "director" in tname.lower():
        tool_entity_hint = "path"
    else:
        for prefix in ("list_", "get_", "db_", "gitlab_", "deploy_"):
            if tname.startswith(prefix):
                raw_suffix = tname[len(prefix):]
                tool_entity_hint = raw_suffix[:-1] if raw_suffix.endswith("s") else raw_suffix
                break

    def _walk(obj, parent_key: str = ""):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, (str, int)) and not isinstance(v, bool):
                    _add_entity(k, v)
                    if parent_key:
                        _add_entity(f"{parent_key}_{k}", v)
                elif isinstance(v, (dict, list)):
                    _walk(v, k)
        elif isinstance(obj, list):
            for item in obj:
                if isinstance(item, (str, int)) and not isinstance(item, bool):
                    target_key = parent_key or tool_entity_hint or "id"
                    _add_entity(target_key, item)
                    if "director" in target_key or target_key in ("path", "dir"):
                        _add_entity("path", item)
                        _add_entity("dir", item)
                        _add_entity("directory", item)
                else:
                    _walk(item, parent_key or tool_entity_hint)

    if data is not None:
        _walk(data)
    else:
        # Fallback regex extraction for common key-value or table patterns in plain text
        for match in re.finditer(r'\b(service|name|db|database|job|project|target|id|host|table|path|dir|directory)\b\s*[:=]\s*([a-zA-Z0-9_\-\./]+)', text, re.IGNORECASE):
            _add_entity(match.group(1), match.group(2))

        # Extract any explicit filesystem paths in plain text output
        for line in text.splitlines():
            line_clean = line.strip().strip("'\"- ")
            if line_clean.startswith("/") and len(line_clean) < 256:
                if not line_clean.startswith(("/usr", "/bin", "/sbin", "/lib")):
                    _add_entity("path", line_clean)
                    _add_entity("dir", line_clean)
                    _add_entity("directory", line_clean)
                    _add_entity("file", f"{line_clean.rstrip('/')}/test.txt")


def _seed_pool_from_cmd(server_cmd: list[str] | None, pool: dict[str, list[Any]]):
    """Extract candidate filesystem paths or repository targets from CLI command arguments to seed entity pool."""
    if not server_cmd:
        return
    for i, arg in enumerate(server_cmd):
        val = None
        key = None
        if arg in ("--repository", "--repo", "-r") and i + 1 < len(server_cmd):
            val = server_cmd[i + 1]
            key = "repo"
        elif arg.startswith(("--repository=", "--repo=")):
            val = arg.split("=", 1)[1]
            key = "repo"
        elif arg in ("--path", "--dir", "--directory", "--folder", "--workspace", "--root") and i + 1 < len(server_cmd):
            val = server_cmd[i + 1]
            key = "path"
        elif any(arg.startswith(f"{k}=") for k in ("--path", "--dir", "--directory", "--folder", "--workspace", "--root")):
            val = arg.split("=", 1)[1]
            key = "path"
        elif arg.startswith("/") and len(arg) < 256:
            # Check if this positional arg is a directory or path and not an executable / script
            if i > 0 and not arg.endswith((".js", ".py", ".sh", ".ts", ".mjs", ".cjs", ".bin")):
                val = arg
                key = "path"

        if val:
            val_clean = val.strip().strip("'\"")
            keys_to_seed = (
                ["repo", "repository", "repo_path", "path", "dir", "directory"]
                if key == "repo"
                else ["path", "dir", "directory", "folder", "workspace", "repo_path", "repo"]
            )
            for k in keys_to_seed:
                pool.setdefault(k, [])
                if val_clean not in pool[k]:
                    pool[k].append(val_clean)
            pool.setdefault("file", [])
            test_file = f"{val_clean.rstrip('/')}/test.txt"
            if test_file not in pool["file"]:
                pool["file"].append(test_file)


def _emit_trace_marker(trace_file: str | None, tag: str, val: str = ""):
    if not trace_file:
        return
    try:
        with open(trace_file, "a") as f:
            f.write(f"M {tag} {val}\n")
    except OSError:
        pass


async def _exercise(session: ClientSession, call_timeout: float, fuzz: bool = False,
                    trace_file: str | None = None, rounds: int = 1,
                    server_cmd: list[str] | None = None):
    """Shared logic: discover + exercise tools, resources, prompts on a live session."""
    stats = {
        "tools": {
            "called": 0,
            "transport_ok": 0,
            "executed_ok": 0,
            "validation_rejected": 0,
            "tool_error": 0,
            "ok": 0,
            "tools_executed_count": 0,
            "tools_executed_names": [],
        },
        "resources": {"called": 0, "ok": 0},
        "prompts": {"called": 0, "ok": 0}
    }
    tool_outputs = {}
    tool_history = {}
    executed_tools = set()
    harvested_pool: dict[str, list[Any]] = {}
    _seed_pool_from_cmd(server_cmd, harvested_pool)

    def _eval_tool_call(ok: bool, res: Any, tname: str = "") -> tuple[bool, str]:
        if not ok or res is None:
            stats["tools"]["tool_error"] += 1
            return False, ""
        stats["tools"]["transport_ok"] += 1
        is_err = getattr(res, "isError", False)
        text = _extract_text_content(res)
        lower_text = text.lower() if text else ""
        SCHEMA_REJECTION_PATTERNS = (
            "rejected arguments:",
            "validation error for ",
            "extra inputs are not permitted",
            "missing required argument",
            "schema validation failed",
            "value is not a valid",
            "input should be a valid",
        )
        is_val_rej = any(pat in lower_text for pat in SCHEMA_REJECTION_PATTERNS)

        if not is_err and not is_val_rej:
            stats["tools"]["executed_ok"] += 1
            stats["tools"]["ok"] += 1
            if tname:
                executed_tools.add(tname)
            return True, text
        elif is_val_rej:
            stats["tools"]["validation_rejected"] += 1
            return False, text
        else:
            stats["tools"]["tool_error"] += 1
            return False, text

    tools_meta, resources_meta, prompts_meta = await _discover_manifest(session)

    print(f"[probe] discovered {len(tools_meta)} tool(s)")

    def _is_tool_read_only(tool_meta: dict) -> bool:
        ann = tool_meta.get("annotations") or {}
        if ann.get("readOnlyHint") is True or tool_meta.get("readOnlyHint") is True:
            return True
        tname = tool_meta.get("name", "").lower()
        if any(m in tname for m in ("delete", "remove", "drop", "create", "write", "update", "set_", "restart", "start", "stop", "deploy", "rollback", "rehearse", "cancel", "run")):
            return False
        return any(q in tname for q in ("list_", "get_", "db_", "status", "overview", "_projects", "_targets", "_list", "read_"))

    def _tool_priority(t: dict) -> int:
        is_ro = _is_tool_read_only(t)
        schema = t.get("inputSchema") or {}
        req = schema.get("required") or []
        if is_ro and len(req) == 0:
            return 0  # Phase 1: Zero-arg / all-optional read discovery tools
        elif is_ro:
            return 1  # Phase 2: Read-only query tools with required parameters
        else:
            return 2  # Mutating / stateful tools

    ordered_tools = sorted(tools_meta, key=_tool_priority)

    rounds = max(1, rounds)
    for round_idx in range(rounds):
        if rounds > 1:
            print(f"[probe] --- probe round {round_idx + 1}/{rounds} ---")
        for t in ordered_tools:
            tname = t.get("name", "")
            # Skip re-registering setup/init tools in subsequent rounds so downstream state accumulation can be observed
            if round_idx > 0 and len(tools_meta) > 1 and tname.startswith(("register_", "init_")):
                continue
            ann = t.get("annotations") or {}
            is_ro = _is_tool_read_only(t)
            # If tool claims to be idempotent, repeat round 0 arguments across all rounds
            r_idx = 0 if ann.get("idempotentHint") else round_idx

            # CRITICAL SAFETY CONSTRAINT: Harvested live asset names are strictly passed
            # to read-only query tools. Mutating tools NEVER receive harvested entities!
            active_pool = harvested_pool if is_ro else None
            args = synth_args(t.get("inputSchema"), round_idx=r_idx, harvested_pool=active_pool)
            print(f"[probe] calling tool {t['name']}({json.dumps(args)})")
            stats["tools"]["called"] += 1
            _emit_trace_marker(trace_file, "CALL_START", t["name"])
            ok, res = await _call_with_timeout(
                session.call_tool(t["name"], args), f"tool {t['name']}", call_timeout)
            _emit_trace_marker(trace_file, "CALL_END", t["name"])
            exec_ok, text = _eval_tool_call(ok, res, tname)
            if text:
                tool_outputs[t["name"]] = text
                tool_history.setdefault(t["name"], []).append({"args": args, "output": text, "round": round_idx, "executed_ok": exec_ok})
                # If call succeeded and tool is read-only, harvest candidate entities for downstream tools
                if exec_ok and is_ro:
                    _harvest_entities_from_output(text, harvested_pool, tname)

            # In round 0, call mutating/collection tools a second time to populate multiple test entries
            if round_idx == 0 and tname.startswith(("add_", "insert_", "append_")):
                args2 = synth_args(t.get("inputSchema"), round_idx=1)
                stats["tools"]["called"] += 1
                ok2, res2 = await _call_with_timeout(
                    session.call_tool(t["name"], args2), f"tool {t['name']} (seed)", call_timeout)
                _eval_tool_call(ok2, res2, tname)

            if fuzz and round_idx == 0:
                fuzz_arg_sets = synth_fuzz_args(t.get("inputSchema"))
                if fuzz_arg_sets:
                    stats.setdefault("fuzz", {"attempted": 0, "ok": 0, "failed": 0})
                    print(f"[probe] fuzzing tool {t['name']} with {len(fuzz_arg_sets)} vector(s)")
                    for f_args in fuzz_arg_sets:
                        stats["tools"]["called"] += 1
                        stats["fuzz"]["attempted"] += 1
                        f_ok, f_res = await _call_with_timeout(
                            session.call_tool(t["name"], f_args), f"fuzz tool {t['name']}", call_timeout)
                        f_exec_ok, f_text = _eval_tool_call(f_ok, f_res, tname)
                        if f_ok:
                            stats["fuzz"]["ok"] += 1
                            if f_text and t["name"] not in tool_outputs:
                                tool_outputs[t["name"]] = f_text
                        else:
                            stats["fuzz"]["failed"] += 1

    stats["tools"]["tools_executed_count"] = len(executed_tools)
    stats["tools"]["tools_executed_names"] = sorted(list(executed_tools))

    print(f"[probe] discovered {len(resources_meta)} resource(s)")
    for r in resources_meta:
        print(f"[probe] reading resource {r['uri']}")
        stats["resources"]["called"] += 1
        _emit_trace_marker(trace_file, "RES_START", r["uri"])
        ok, _ = await _call_with_timeout(
            session.read_resource(r["uri"]), f"resource {r['uri']}", call_timeout)
        _emit_trace_marker(trace_file, "RES_END", r["uri"])
        if ok:
            stats["resources"]["ok"] += 1

    print(f"[probe] discovered {len(prompts_meta)} prompt(s)")
    for p in prompts_meta:
        args = {}
        for a in (p.get("arguments") or []):
            if a.get("required"):
                aname = a.get("name", "")
                val = None
                if harvested_pool:
                    val_list = harvested_pool.get(aname)
                    if not val_list:
                        for ek, cks in (("repo", ["repo", "repo_path", "path"]), ("path", ["path", "dir", "repo_path"])):
                            if ek in aname:
                                for ck in cks:
                                    if ck in harvested_pool and harvested_pool[ck]:
                                        val_list = harvested_pool[ck]
                                        break
                                if val_list:
                                    break
                    if val_list:
                        val = val_list[0]
                args[aname] = val or "valid-input"
        print(f"[probe] getting prompt {p['name']}({json.dumps(args)})")
        stats["prompts"]["called"] += 1
        _emit_trace_marker(trace_file, "PR_START", p["name"])
        ok, _ = await _call_with_timeout(
            session.get_prompt(p["name"], args), f"prompt {p['name']}", call_timeout)
        _emit_trace_marker(trace_file, "PR_END", p["name"])
        if ok:
            stats["prompts"]["ok"] += 1

    return tools_meta, resources_meta, prompts_meta, stats, tool_outputs, tool_history


def _write_manifest(server_cmd, tools_meta, resources_meta, prompts_meta, stats,
                    tool_outputs: dict | None = None,
                    *, transport: str, syscalls_available: bool,
                    manifest_file: str | None = None, trace_file: str | None = None,
                    sandbox: str | None = None, tool_history: dict | None = None,
                    audit_status: str = AUDIT_STATUS_COMPLETE,
                    failure_reason: str | None = None):
    """Write the manifest JSON to disk.

    audit_status must be one of AUDIT_STATUS_COMPLETE, AUDIT_STATUS_PARTIAL,
    or AUDIT_STATUS_FAILED.  Only AUDIT_STATUS_COMPLETE manifests may be used
    to update a trusted behavioral lockfile.
    """
    m_file = manifest_file or MANIFEST
    t_file = trace_file or TRACE_FILE
    manifest = {
        "server_cmd": list(server_cmd) if server_cmd else None,
        "transport": transport,
        "syscalls_available": syscalls_available,
        "sandbox": sandbox,
        "audit_status": audit_status,
        "failure_reason": failure_reason,
        "tools": tools_meta,
        "resources": resources_meta,
        "prompts": prompts_meta,
        "tool_outputs": tool_outputs or {},
        "tool_history": tool_history or {},
        "manifest_sha256": hashlib.sha256(
            json.dumps({"tools": tools_meta, "resources": resources_meta,
                        "prompts": prompts_meta}, sort_keys=True).encode()
        ).hexdigest(),
        "_stats": stats,
    }
    with open(m_file, "w") as f:
        json.dump(manifest, f, indent=2)
    print(f"[probe] manifest -> {m_file}")
    if syscalls_available:
        print(f"[probe] trace    -> {t_file}")


async def run(server_cmd: list[str], call_timeout: float = DEFAULT_CALL_TIMEOUT,
              tracer: str | None = None, out_dir: str | None = None,
              fuzz: bool = False, rounds: int = 1, unsafe_host: bool = False,
              sandbox: str | None = None, sandbox_image: str | None = None,
              sandbox_network: str = "none"):
    """Stdio transport: wrap the server in the platform's syscall tracer
    (an injected dylib on macOS, LD_PRELOAD or strace on Linux) or container sandbox
    (Docker/Podman) and connect via stdio.
    By default runs in an isolated canary environment to protect host files and credentials."""
    target_out_dir = out_dir or OUT_DIR
    target_trace_file = os.path.join(target_out_dir, "trace.log")
    target_manifest_file = os.path.join(target_out_dir, "manifest.json")
    os.makedirs(target_out_dir, exist_ok=True)
    if os.path.exists(target_manifest_file):
        try:
            os.remove(target_manifest_file)
        except OSError:
            pass

    active_sandbox = None
    if sandbox and sandbox != "none":
        from . import sandbox as sandbox_mod
        runtime = sandbox_mod.detect_container_runtime() if sandbox == "auto" else sandbox
        if sandbox != "auto" and not runtime:
            raise RuntimeError(f"Requested container sandbox '{sandbox}' but runtime is not available or responsive.")
        active_sandbox = runtime

    if active_sandbox:
        trace_cmd, tracer_name, env_overlay = server_cmd, f"sandbox-{active_sandbox}", {}
        syscalls_available = False
    else:
        trace_cmd, tracer_name, env_overlay = _tracer_setup(server_cmd, target_trace_file, tracer)
        syscalls_available = bool(tracer_name)
    # Truncate/create the trace file up front: native tracers open it
    # O_APPEND, and analyze() needs a readable file even if the server exits
    # before any interesting syscall fires.
    open(target_trace_file, "w").close()

    cleaned_env, canary_dir = _build_isolated_env(env_overlay if syscalls_available else {}, unsafe_host=unsafe_host)

    try:
        if active_sandbox:
            from . import sandbox as sandbox_mod
            sandbox_cmd = sandbox_mod.build_sandbox_command(
                server_cmd,
                runtime=active_sandbox,
                canary_dir=canary_dir,
                network=sandbox_network,
                image=sandbox_image,
            )
            print(f"[probe] running server inside container sandbox ({active_sandbox})", file=sys.stderr)
            params = StdioServerParameters(command=sandbox_cmd[0], args=sandbox_cmd[1:],
                                           env=cleaned_env)
            syscalls_available = False
            tracer_name = f"sandbox-{active_sandbox}"
        elif syscalls_available:
            params = StdioServerParameters(command=trace_cmd[0], args=trace_cmd[1:],
                                           env=cleaned_env)
        else:
            print(f"[probe] running server untraced on {platform.system()} "
                  "(manifest analysis only)",
                  file=sys.stderr)
            params = StdioServerParameters(command=server_cmd[0], args=server_cmd[1:],
                                           env=cleaned_env)

        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                tools_meta, resources_meta, prompts_meta, stats, tool_outputs, tool_history = await _exercise(
                    session, call_timeout, fuzz=fuzz, trace_file=target_trace_file, rounds=rounds,
                    server_cmd=server_cmd)

        stats["rounds"] = rounds
        stats["tracer"] = tracer_name or ("stdio" if syscalls_available else "none")

        _write_manifest(server_cmd, tools_meta, resources_meta, prompts_meta, stats,
                        tool_outputs=tool_outputs,
                        transport="stdio", syscalls_available=syscalls_available,
                        manifest_file=target_manifest_file, trace_file=target_trace_file,
                        sandbox=active_sandbox, tool_history=tool_history)
    finally:
        if canary_dir and os.path.exists(canary_dir):
            try:
                shutil.rmtree(canary_dir, ignore_errors=True)
            except OSError:
                pass


async def run_remote(url: str, *, transport: str,
                     call_timeout: float = DEFAULT_CALL_TIMEOUT,
                     out_dir: str | None = None,
                     fuzz: bool = False,
                     rounds: int = 1):
    """Remote transport (sse/streamable-http): connect to an already-running
    server. Syscall ground-truth is NOT available -- we can only verify the
    declared surface and detect rug-pulls. analyze.py is a no-op in this mode."""
    target_out_dir = out_dir or OUT_DIR
    target_trace_file = os.path.join(target_out_dir, "trace.log")
    target_manifest_file = os.path.join(target_out_dir, "manifest.json")
    os.makedirs(target_out_dir, exist_ok=True)
    if os.path.exists(target_manifest_file):
        try:
            os.remove(target_manifest_file)
        except OSError:
            pass
    # Write an empty trace so analyze() doesn't crash.
    open(target_trace_file, "w").close()

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
            tools_meta, resources_meta, prompts_meta, stats, tool_outputs, tool_history = await _exercise(
                session, call_timeout, fuzz=fuzz, trace_file=target_trace_file, rounds=rounds)
    stats["rounds"] = rounds
    stats["tracer"] = "remote"
    _write_manifest([url], tools_meta, resources_meta, prompts_meta, stats,
                    tool_outputs=tool_outputs,
                    transport=transport, syscalls_available=False,
                    manifest_file=target_manifest_file, trace_file=target_trace_file,
                    tool_history=tool_history)


async def fetch_manifest(server_cmd: list[str], *, transport: str = "stdio",
                         call_timeout: float = DEFAULT_CALL_TIMEOUT,
                         unsafe_host: bool = False) -> dict:
    """Connect to a server and fetch declared tools, resources, and prompts
    without exercising tools or tracing syscalls."""
    if transport == "stdio":
        cleaned_env, canary_dir = _build_isolated_env({}, unsafe_host=unsafe_host)
        try:
            params = StdioServerParameters(command=server_cmd[0], args=server_cmd[1:],
                                           env=cleaned_env)
            async with stdio_client(params) as (read, write):
                async with ClientSession(read, write) as session:
                    tools_meta, resources_meta, prompts_meta = await _discover_manifest(session)
        finally:
            if canary_dir and os.path.exists(canary_dir):
                try:
                    shutil.rmtree(canary_dir, ignore_errors=True)
                except OSError:
                    pass
    elif transport in ("sse", "streamable-http"):
        if transport == "sse":
            from mcp.client.sse import sse_client
            ctx = sse_client(server_cmd[0])
        else:
            from mcp.client.streamable_http import streamablehttp_client
            ctx = streamablehttp_client(server_cmd[0])
        async with ctx as conn:
            read, write = conn[0], conn[1]
            async with ClientSession(read, write) as session:
                tools_meta, resources_meta, prompts_meta = await _discover_manifest(session)
    else:
        raise ValueError(f"unknown remote transport: {transport}")

    return {
        "server_cmd": list(server_cmd) if server_cmd else None,
        "transport": transport,
        "syscalls_available": False,
        "tools": tools_meta,
        "resources": resources_meta,
        "prompts": prompts_meta,
        "manifest_sha256": hashlib.sha256(
            json.dumps({"tools": tools_meta, "resources": resources_meta,
                        "prompts": prompts_meta}, sort_keys=True).encode()
        ).hexdigest(),
        "_stats": {"tools": {"called": 0, "ok": 0},
                   "resources": {"called": 0, "ok": 0},
                   "prompts": {"called": 0, "ok": 0}},
    }


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: probe.py <server-command> [args...]"); sys.exit(2)
    asyncio.run(run(sys.argv[1:]))
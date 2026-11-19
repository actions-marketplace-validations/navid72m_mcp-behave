"""mcp-behave CLI: orchestrates probe → report.

Thin orchestrator. Does NOT reimplement probe/analyze/report -- it calls them.
"""
import argparse, asyncio, json, os, platform, sys

from . import __version__
from . import probe as probe_mod
from . import report as report_mod

PTRACE_HINT = """
mcp-behave couldn't trace the target server on Linux.

Options:
1. Native LD_PRELOAD tracer (default, no ptrace/root needed): ensure a C compiler
   (gcc or clang) is installed so mcp-behave can build the interposer:
       apt-get install -y gcc
2. strace tracer: if using --tracer strace in Docker, add the ptrace capability:
       --cap-add=SYS_PTRACE
3. Untraced mode: if your environment prohibits tracing, run manifest analysis only:
       mcp-behave --no-trace <server-command>
"""

DTRACE_HINT = """
mcp-behave ran the target on macOS but captured no syscalls.

macOS tracing works by injecting a small library (DYLD_INSERT_LIBRARIES) into
the server. This runs as YOU -- no sudo needed. Two things can prevent it:

1. Hardened-runtime interpreters reject injection (dyld ABORTS the process,
   which looks like "connection closed"). Anaconda/conda python, python.org's
   signed builds, and /usr/bin/python3 are hardened; Homebrew, uv, and pyenv
   Python are not. Check yours (look for 'runtime' in the flags):
       codesign -d --verbose=4 "$(which python3)" 2>&1 | grep -o 'flags=[^ ]*'
   If it shows 'runtime', run your server under a non-hardened interpreter:
       mcp-behave "$(brew --prefix)/bin/python3" <your-server-args>
       mcp-behave uv run <your-server-args>

2. No C compiler. The tracer is built on first use with `cc`. If missing:
       xcode-select --install
"""

# Severity ranking for --fail-on comparisons.
SEV_RANK = {"INFO": 1, "HIGH": 2}


def _looks_like_ptrace_failure(exc: BaseException) -> bool:
    text = repr(exc).lower() + str(exc).lower()
    return any(s in text for s in
               ("connection closed", "permission denied", "ptrace", "exec",
                "dtrace", "requires additional privileges"))


def _build_parser():
    p = argparse.ArgumentParser(
        prog="mcp-behave",
        description="Runtime behavioral auditor for MCP servers. "
                    "Observes server runtime behavior (files, network, subprocesses) "
                    "and compares what it DECLARED against what it actually DID.\n\n"
                    "Subcommands:\n"
                    "  `mcp-behave init` generates a committed baseline behavior lockfile (mcp-behave.lock)\n"
                    "  `mcp-behave check` diffs live server behavior against mcp-behave.lock in CI\n"
                    "  `mcp-behave lint` statically audits a manifest.json or tools file without execution\n"
                    "  `mcp-behave scan-configs` scans local AI client configs (Claude Desktop, Cursor, etc.)\n"
                    "  `mcp-behave audit-configs` scans and runs behavioral audits on all configured servers\n"
                    "  `mcp-behave inspect` displays correlated live JSON-RPC traffic and OS syscall stream\n"
                    "  `mcp-behave serve` runs mcp-behave as an MCP server\n"
                    "  `mcp-behave push` uploads an audit result to an mcp-behave dashboard",
    )
    p.add_argument("--version", action="version", version=f"mcp-behave {__version__}")
    p.add_argument(
        "--config", default=None,
        help="Path to custom .mcpbehaverc.json configuration file.",
    )
    p.add_argument(
        "--out-dir", default=os.environ.get("OUT_DIR", "/tmp/mcp_behave_out"),
        help="Where to write manifest.json and trace.log (default: %(default)s).",
    )
    p.add_argument(
        "--json", action="store_true",
        help="Emit findings as JSON on stdout instead of human-readable text. "
             "Useful for CI pipelines.",
    )
    p.add_argument(
        "--sarif", action="store_true",
        help="Emit findings as OASIS SARIF v2.1.0 on stdout for GitHub Code Scanning / CI.",
    )
    p.add_argument(
        "--fuzz", action="store_true",
        help="Run adversarial input fuzzing against tool schemas (path traversal, command injection, buffer stress).",
    )
    p.add_argument(
        "--probe-rounds", type=int, default=1,
        help="Number of probing rounds to execute with varied realistic inputs (default: 1).",
    )
    p.add_argument(
        "--scorecard", action="store_true",
        help="Print an objective 0-100 CSA Security Selection Scorecard and letter grade (A+ to F).",
    )
    p.add_argument(
        "--fail-on", choices=("never", "info", "high"), default="high",
        help="Exit non-zero when a finding at or above this severity is "
             "produced (default: %(default)s).",
    )
    p.add_argument(
        "--no-dns", action="store_true",
        help="Skip reverse-DNS lookups for IPs in findings (faster, offline-safe).",
    )
    p.add_argument(
        "--no-trace", action="store_true",
        help="Skip syscall tracing and perform manifest analysis only (no tracer/root needed).",
    )
    p.add_argument(
        "--tracer", choices=("auto", "ebpf", "preload", "dylib", "strace", "none"), default="auto",
        help="Syscall tracer backend (default: auto). 'ebpf' uses Linux kernel eBPF tracepoints (experimental), "
             "'preload' uses Linux LD_PRELOAD, 'dylib' uses macOS DYLD interposition, 'strace' uses strace, 'none' runs untraced.",
    )
    p.add_argument(
        "--unsafe-host", action="store_true",
        help="Disable temporary canary $HOME redirection and run against the real host environment.",
    )
    p.add_argument(
        "--sandbox", choices=("auto", "docker", "podman", "none"), default="none",
        help="Run target inside an ephemeral container sandbox (default: none). 'auto' detects docker or podman.",
    )
    p.add_argument(
        "--sandbox-image", default=None,
        help="Container image to use when running with --sandbox (default: python:3.12-slim or node:20-slim).",
    )
    p.add_argument(
        "--sandbox-network", choices=("none", "bridge", "host"), default="none",
        help="Network namespace isolation mode for --sandbox (default: none).",
    )
    p.add_argument(
        "--timeout", type=float, default=probe_mod.DEFAULT_CALL_TIMEOUT,
        help="Seconds to wait per tool/resource/prompt call "
             "(default: %(default)s).",
    )
    p.add_argument(
        "--transport", choices=("stdio", "sse", "streamable-http"), default="stdio",
        help="Transport used to reach the MCP server. 'stdio' spawns the "
             "server under a behavioral tracer (dylib on macOS, LD_PRELOAD or strace "
             "on Linux) and provides full behavioral ground-truth. "
             "'sse' and 'streamable-http' connect to an already-running remote "
             "server -- syscall tracing is NOT available in those modes, so "
             "only manifest analysis and rug-pull detection run.",
    )
    p.add_argument(
        "server_command", nargs=argparse.REMAINDER,
        help="For --transport stdio: the command to spawn (e.g. "
             "`python -m mcp_server_fetch`). For --transport sse/"
             "streamable-http: a single URL.",
    )
    return p


def _exit_code(findings: list, fail_on: str) -> int:
    if fail_on == "never":
        return 0
    threshold = SEV_RANK[fail_on.upper()]
    return 3 if any(SEV_RANK.get(s, 0) >= threshold for s, _ in findings) else 0


SUBCOMMANDS = {"init", "check", "push", "serve", "scan-configs", "audit-configs", "inspect", "lint"}


def main(argv=None):
    raw_argv = sys.argv[1:] if argv is None else list(argv)
    # Strip leading binary name if passed by container entrypoints/wrappers
    if raw_argv and raw_argv[0] in ("mcp-behave", "mcp_behave"):
        raw_argv = raw_argv[1:]

    if raw_argv and raw_argv[0] == "audit":
        raw_argv = raw_argv[1:]

    if not raw_argv:
        # Default with no arguments: start the FastMCP server
        from . import server as server_mod
        return server_mod.main([])

    if raw_argv and raw_argv[0] in SUBCOMMANDS:
        sub = raw_argv[0]
        rest = raw_argv[1:]
        if sub == "init":
            from . import lockfile as lockfile_mod
            return lockfile_mod.main_init(rest)
        elif sub == "check":
            from . import lockfile as lockfile_mod
            return lockfile_mod.main_check(rest)
        elif sub == "push":
            from . import push as push_mod
            return push_mod.main(rest)
        elif sub == "serve":
            from . import server as server_mod
            return server_mod.main(rest)
        elif sub in ("scan-configs", "audit-configs"):
            from . import config_scanner
            return config_scanner.main(rest, default_audit=(sub == "audit-configs"))
        elif sub == "inspect":
            from . import inspect as inspect_mod
            return inspect_mod.main(rest)
        elif sub == "lint":
            from . import lint as lint_mod
            return lint_mod.main(rest)

    parser = _build_parser()
    args = parser.parse_args(raw_argv)

    if args.server_command and args.server_command[0] == "--":
        args.server_command = args.server_command[1:]

    if not args.server_command:
        parser.error("no server command given. "
                     "Example: mcp-behave python -m mcp_server_fetch")

    # In --json or --sarif mode, suppress the human-readable banners so stdout stays
    # machine-parseable. We can't easily silence probe.py's progress prints
    # without rewiring it, so they go to stderr by setting stdout=/dev/null
    # for the probe call would be wrong (we'd lose real errors). Instead,
    # accept that probe progress lines mingle with stderr in JSON/SARIF mode.
    quiet = args.json or args.sarif

    os.environ["OUT_DIR"] = args.out_dir  # probe/report read this

    tracer_choice = "none" if args.no_trace else args.tracer
    if args.transport == "stdio":
        if args.sandbox and args.sandbox != "none":
            tracer_label = f"sandbox ({args.sandbox})"
        else:
            active_tracer = probe_mod.detect_tracer(tracer_choice)
            tracer_label = {
                "ebpf": "linux-ebpf",
                "dylib": "macos-dylib",
                "preload": "linux-preload",
                "strace": "strace",
            }.get(active_tracer, "untraced")
        if not quiet:
            print(f"=== STEP 1: observe ({tracer_label}) ===")
        coro = probe_mod.run(args.server_command, out_dir=args.out_dir,
                             call_timeout=args.timeout,
                             tracer=tracer_choice, fuzz=args.fuzz,
                             rounds=args.probe_rounds,
                             unsafe_host=args.unsafe_host,
                             sandbox=args.sandbox,
                             sandbox_image=args.sandbox_image,
                             sandbox_network=args.sandbox_network)
    else:
        if len(args.server_command) != 1:
            parser.error(f"--transport {args.transport} expects exactly one URL argument")
        if not quiet:
            print(f"=== STEP 1: connect ({args.transport}) ===")
            print("  note: remote transports cannot trace syscalls; "
                  "only manifest analysis runs.", file=sys.stderr)
        coro = probe_mod.run_remote(args.server_command[0],
                                    out_dir=args.out_dir,
                                    transport=args.transport,
                                    call_timeout=args.timeout,
                                    fuzz=args.fuzz,
                                    rounds=args.probe_rounds)

    try:
        asyncio.run(coro)
    except SystemExit:
        raise
    except BaseException as exc:
        import traceback
        # ALWAYS surface the real error. The macOS hint is only a *possible*
        # cause, appended below -- it must never replace the actual exception
        # (a benign stdio-shutdown error must not masquerade as "no syscalls").
        print(f"\nmcp-behave: probe failed: {exc!r}", file=sys.stderr)
        if os.environ.get("MCP_BEHAVE_DEBUG"):
            traceback.print_exc()
        # If a manifest was still written, the probe likely succeeded and this
        # was a teardown race -- report from what we have instead of bailing.
        manifest = os.path.join(args.out_dir, "manifest.json")
        if args.transport == "stdio" and os.path.exists(manifest):
            print("[note] a manifest was written; the error above is likely a "
                  "post-probe teardown race. Reporting anyway.\n", file=sys.stderr)
        elif args.transport == "stdio" and _looks_like_ptrace_failure(exc):
            print("\nIf this looks trace/injection-related, this may help:",
                  file=sys.stderr)
            print(DTRACE_HINT if platform.system() == "Darwin" else PTRACE_HINT,
                  file=sys.stderr)
            return 2
        else:
            return 1

    from . import config as config_mod
    cfg = config_mod.load_config(args.config)
    fail_on = args.fail_on if ("--fail-on" in raw_argv) else (cfg.get("fail_on") or args.fail_on)

    if args.sarif:
        result = report_mod.report_sarif(args.out_dir, resolve_dns=not args.no_dns, config=cfg)
        print(json.dumps(result, indent=2))
        raw_json = report_mod.report_json(args.out_dir, resolve_dns=not args.no_dns, config=cfg)
        findings = [(f["severity"], f["message"]) for f in raw_json["findings"]]
    elif args.json:
        result = report_mod.report_json(args.out_dir, resolve_dns=not args.no_dns, config=cfg)
        print(json.dumps(result, indent=2))
        findings = [(f["severity"], f["message"]) for f in result["findings"]]
    else:
        print("=== STEP 2: declared-vs-observed diff ===")
        findings = report_mod.report(args.out_dir, resolve_dns=not args.no_dns, show_scorecard=args.scorecard, config=cfg)

    return _exit_code(findings, fail_on)


if __name__ == "__main__":
    sys.exit(main())
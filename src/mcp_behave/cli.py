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
                    "Subcommands: `mcp-behave serve` runs mcp-behave as an MCP "
                    "server; `mcp-behave push` uploads a JSON audit "
                    "result to an mcp-behave dashboard.",
    )
    p.add_argument("--version", action="version", version=f"mcp-behave {__version__}")
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
        "--tracer", choices=("auto", "preload", "dylib", "strace", "none"), default="auto",
        help="Syscall tracer backend (default: auto). 'preload' uses Linux LD_PRELOAD, "
             "'dylib' uses macOS DYLD interposition, 'strace' uses strace, 'none' runs untraced.",
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


SUBCOMMANDS = {"push", "serve"}


def main(argv=None):
    raw_argv = sys.argv[1:] if argv is None else list(argv)
    if raw_argv and raw_argv[0] in SUBCOMMANDS:
        sub = raw_argv[0]
        rest = raw_argv[1:]
        if sub == "push":
            from . import push as push_mod
            return push_mod.main(rest)
        elif sub == "serve":
            from . import server as server_mod
            return server_mod.main(rest)

    parser = _build_parser()
    args = parser.parse_args(argv)

    if not args.server_command:
        parser.error("no server command given. "
                     "Example: mcp-behave python -m mcp_server_fetch")

    # In --json mode, suppress the human-readable banners so stdout stays
    # machine-parseable. We can't easily silence probe.py's progress prints
    # without rewiring it, so they go to stderr by setting stdout=/dev/null
    # for the probe call would be wrong (we'd lose real errors). Instead,
    # accept that probe progress lines mingle with stderr in JSON mode.
    quiet = args.json

    os.environ["OUT_DIR"] = args.out_dir  # probe/report read this

    tracer_choice = "none" if args.no_trace else args.tracer
    if args.transport == "stdio":
        active_tracer = probe_mod.detect_tracer(tracer_choice)
        tracer_label = {
            "dylib": "macos-dylib",
            "preload": "linux-preload",
            "strace": "strace",
        }.get(active_tracer, "untraced")
        if not quiet:
            print(f"=== STEP 1: observe ({tracer_label}) ===")
        coro = probe_mod.run(args.server_command, call_timeout=args.timeout,
                             tracer=tracer_choice)
    else:
        if len(args.server_command) != 1:
            parser.error(f"--transport {args.transport} expects exactly one URL argument")
        if not quiet:
            print(f"=== STEP 1: connect ({args.transport}) ===")
            print("  note: remote transports cannot trace syscalls; "
                  "only manifest analysis runs.", file=sys.stderr)
        coro = probe_mod.run_remote(args.server_command[0],
                                    transport=args.transport,
                                    call_timeout=args.timeout)

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

    if args.json:
        result = report_mod.report_json(args.out_dir, resolve_dns=not args.no_dns)
        print(json.dumps(result, indent=2))
        findings = [(f["severity"], f["message"]) for f in result["findings"]]
    else:
        print("=== STEP 2: declared-vs-observed diff ===")
        findings = report_mod.report(args.out_dir, resolve_dns=not args.no_dns)

    return _exit_code(findings, args.fail_on)


if __name__ == "__main__":
    sys.exit(main())
"""mcp-behave wrap: inline transparent stdio monitor for Model Context Protocol servers.

Sits between MCP client (Claude Desktop, Cursor) and target server, proxying JSON-RPC
traffic byte-for-byte, enforcing behavioral policies, and recording telemetry without
blocking or corrupting stdio transport.
"""
from __future__ import annotations

import argparse
import asyncio
import os
import signal
import sys
import time
import uuid
from pathlib import Path
from typing import Any, List, Optional

from .bus import EventBus
from .attribution import AttributionEngine
from .canary import CanaryManager
from .events import (
    BehavioralEvent,
    KIND_OS_TRACING,
    KIND_SESSION_END,
    KIND_SESSION_START,
)
from .identity import resolve_package_identity
from .launcher import (
    derive_server_id,
    get_tracer_environment,
    resolve_server_executable,
    spawn_child_server,
    terminate_process_group,
)
from .lockfile import Lockfile, ServerLock, load_lockfile
from .protocol import ProtocolMonitor, StreamingFramer
from .telemetry import TelemetryStore
from .tracer_server import TracerServer


def send_macos_notification(title: str, message: str) -> None:
    """Send an urgent desktop alert via osascript on macOS (off by default)."""
    if sys.platform != "darwin":
        return
    try:
        clean_title = title.replace('"', '\\"')
        clean_msg = message.replace('"', '\\"')
        script = f'display notification "{clean_msg}" with title "{clean_title}"'
        # Run asynchronously in background, never blocking proxy
        import subprocess
        subprocess.Popen(["osascript", "-e", script], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass


async def child_stdin_writer(
    queue: asyncio.Queue[Optional[bytes]],
    writer: asyncio.StreamWriter,
) -> None:
    """Single serialized writer for child stdin.

    All client messages and proxy probes flow through this queue,
    ensuring whole complete lines are written atomically with zero splicing or tearing.
    """
    try:
        while True:
            line_bytes = await queue.get()
            if line_bytes is None:
                queue.task_done()
                break
            try:
                writer.write(line_bytes)
                await writer.drain()
            except (BrokenPipeError, ConnectionResetError, OSError):
                queue.task_done()
                break
            queue.task_done()
    except asyncio.CancelledError:
        pass


async def client_to_server_pump(
    reader: asyncio.StreamReader,
    stdin_queue: asyncio.Queue[Optional[bytes]],
    monitor: ProtocolMonitor,
    stop_event: asyncio.Event,
) -> None:
    """Stream NDJSON lines from client stdin into child server stdin queue."""
    framer = StreamingFramer(reader)
    try:
        async for line_bytes, is_eof in framer:
            if stop_event.is_set():
                break

            # 1. Hot path: Forward complete line to serialized child stdin writer queue
            await stdin_queue.put(line_bytes)

            # 2. Off hot path: Parse, correlate, and record telemetry
            monitor.enqueue_line(line_bytes, "client_to_server")
    except Exception:
        stop_event.set()


async def server_to_client_pump(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    monitor: ProtocolMonitor,
    stop_event: asyncio.Event,
) -> None:
    """Stream NDJSON lines from child server stdout to client stdout."""
    framer = StreamingFramer(reader)
    try:
        async for line_bytes, is_eof in framer:
            if stop_event.is_set() and not line_bytes:
                break

            # Check if this line is a response to an active proxy synthetic probe
            if monitor.is_synthetic_probe_response(line_bytes):
                # Never forward synthetic probe responses to client stdout
                monitor.enqueue_line(line_bytes, "server_to_client")
                continue

            # 1. Hot path: Forward immediately to client stdout
            try:
                writer.write(line_bytes)
                await writer.drain()
            except (BrokenPipeError, ConnectionResetError, OSError):
                break

            # 2. Off hot path: Parse, correlate, and record telemetry
            monitor.enqueue_line(line_bytes, "server_to_client")
    finally:
        stop_event.set()


async def run_proxy(
    server_cmd: List[str],
    server_id: Optional[str] = None,
    state_dir: Optional[str] = None,
    log_content: bool = False,
    notify: bool = False,
    grace_period: float = 3.0,
    augment_path: bool = False,
    retention_days: int = 14,
    reverify_interval: int = 20,
    reverify_period: float = 300.0,
    enable_reverify: bool = True,
    canaries: Optional[List[str]] = None,
    canary_file: Optional[str] = None,
    enable_content_scan: bool = True,
    lockfile_path: Optional[str] = None,
    enforce: bool = False,
    enable_trace: bool = True,
    stdin_reader_override: Optional[asyncio.StreamReader] = None,
    stdout_writer_override: Optional[asyncio.StreamWriter] = None,
) -> int:
    """Run the transparent proxy event loop."""
    loop = asyncio.get_running_loop()

    session_id = uuid.uuid4().hex
    eff_server_id = server_id or derive_server_id(server_cmd)

    bus = EventBus()
    telemetry = TelemetryStore(
        session_id=session_id,
        server_id=eff_server_id,
        state_dir=state_dir,
        log_content=log_content,
        retention_days=retention_days,
    )

    stdin_queue: asyncio.Queue[Optional[bytes]] = asyncio.Queue()

    async def send_probe_fn(probe_bytes: bytes) -> None:
        await stdin_queue.put(probe_bytes)

    # Initialize canary manager
    canary_mgr = CanaryManager(initial_canaries=canaries)
    if canary_file:
        canary_mgr.load_from_file(canary_file)

    # Offline package identity resolution and lockfile discovery (Milestone 3)
    live_identity = resolve_package_identity(server_cmd, augment_path=augment_path, allow_network=False)
    lockfile = load_lockfile(lockfile_path)
    server_lock: Optional[ServerLock] = None
    if isinstance(lockfile, Lockfile):
        server_lock = lockfile.get_server(eff_server_id)

    # Attribution Engine (Milestone 4)
    attribution_engine = AttributionEngine(
        server_id=eff_server_id,
        server_lock=server_lock,
        enforce=enforce,
    )

    monitor = ProtocolMonitor(
        session_id=session_id,
        server_id=eff_server_id,
        bus=bus,
        telemetry=telemetry,
        log_content=log_content,
        send_probe_fn=send_probe_fn,
        reverify_interval=reverify_interval,
        reverify_period=reverify_period,
        enable_reverify=enable_reverify,
        notify=notify,
        loop=loop,
        canary_mgr=canary_mgr,
        enable_content_scan=enable_content_scan,
        server_lock=server_lock,
        enforce=enforce,
        live_identity=live_identity,
        attribution_engine=attribution_engine,
    )

    # OS Syscall Interposition Tracer (Milestone 4)
    tracer_server: Optional[TracerServer] = None
    tracer_child_env: Dict[str, str] = {}
    tracing_status = "disabled"
    tracing_reason = None

    def on_os_event(evt: BehavioralEvent) -> None:
        attributed_evt, violations = attribution_engine.attribute_os_event(evt)
        bus.publish_sync(attributed_evt)
        telemetry.record(attributed_evt)
        for v in violations:
            bus.publish_sync(v)
            telemetry.record(v)
            monitor._emit_alert(v)

    resolved_binary, _ = resolve_server_executable(server_cmd[0])

    if enable_trace:
        interposer_env, disabled_reason = get_tracer_environment(resolved_binary, enable_trace=True)
        if not disabled_reason and interposer_env:
            tracer_server = TracerServer(session_id=session_id, on_event_fn=on_os_event, loop=loop)
            trace_sock_env = tracer_server.start()
            tracer_child_env.update(trace_sock_env)
            tracer_child_env.update(interposer_env)
            tracing_status = "active"
        else:
            tracing_status = "disabled"
            tracing_reason = disabled_reason or "tracer_unavailable"
    else:
        tracing_status = "disabled"
        tracing_reason = "disabled_by_config"

    # Spawn child server process in its own process group with tracer environment
    child_proc, resolved_cmd0, resolved_sha256 = await spawn_child_server(
        server_cmd, env=tracer_child_env, augment_path=augment_path
    )

    # Emit session start event with resolved binary and checksum
    start_event = BehavioralEvent(
        event="session_start",
        session_id=session_id,
        server_id=eff_server_id,
        kind=KIND_SESSION_START,
        timestamp=time.time(),
        source="monitor",
        evidence_tier="observed",
        payload={
            "server_cmd": server_cmd,
            "server_id": eff_server_id,
            "session_id": session_id,
            "resolved_command": resolved_cmd0,
            "resolved_command_sha256": resolved_sha256,
            "augmented_path": augment_path,
            "package_identity": live_identity,
            "locked_server": server_lock.server_id if server_lock else None,
        },
    )
    await bus.publish(start_event)
    telemetry.record(start_event)

    # Emit OS tracing status event (Milestone 4)
    os_event = BehavioralEvent(
        event="os_tracing_status",
        session_id=session_id,
        server_id=eff_server_id,
        kind=KIND_OS_TRACING,
        timestamp=time.time(),
        source="monitor",
        evidence_tier="observed",
        payload={
            "status": tracing_status,
            "reason": tracing_reason,
            "backend": "interposition" if tracing_status == "active" else None,
        },
    )
    await bus.publish(os_event)
    telemetry.record(os_event)

    # Connect client stdin / stdout pipes
    if stdin_reader_override:
        client_reader = stdin_reader_override
    else:
        client_reader = asyncio.StreamReader()
        reader_proto = asyncio.StreamReaderProtocol(client_reader)
        await loop.connect_read_pipe(lambda: reader_proto, sys.stdin.buffer)

    if stdout_writer_override:
        client_writer = stdout_writer_override
    else:
        w_transport, w_protocol = await loop.connect_write_pipe(
            asyncio.streams.FlowControlMixin, sys.stdout.buffer
        )
        client_writer = asyncio.StreamWriter(w_transport, w_protocol, None, loop)

    stop_event = asyncio.Event()

    # Trap signals for process group termination
    sig_received = None

    def _sig_handler(sig):
        nonlocal sig_received
        sig_received = sig
        stop_event.set()
        if child_proc and child_proc.pid:
            try:
                os.killpg(child_proc.pid, sig)
            except Exception:
                pass

    for s in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(s, lambda s=s: _sig_handler(s))
        except (NotImplementedError, ValueError):
            pass

    # Start single serialized child stdin writer
    writer_task = asyncio.create_task(
        child_stdin_writer(stdin_queue, child_proc.stdin)
    )

    # Start bi-directional pumps
    c2s_task = asyncio.create_task(
        client_to_server_pump(client_reader, stdin_queue, monitor, stop_event)
    )
    s2c_task = asyncio.create_task(
        server_to_client_pump(child_proc.stdout, client_writer, monitor, stop_event)
    )

    # Wait until either pump finishes or stop_event is set
    done, pending = await asyncio.wait(
        [c2s_task, s2c_task],
        return_when=asyncio.FIRST_COMPLETED,
    )

    # If client stdin closed (c2s finished), flush queue then close child stdin so server can gracefully exit
    if c2s_task in done:
        try:
            await stdin_queue.join()
            await stdin_queue.put(None)
            await asyncio.wait_for(writer_task, timeout=1.0)
        except Exception:
            pass
        if child_proc.stdin:
            try:
                child_proc.stdin.close()
                await child_proc.stdin.wait_closed()
            except Exception:
                pass

    # Allow a brief window for server_to_client to finish flushing responses if it was still active
    if s2c_task in pending:
        try:
            await asyncio.wait_for(s2c_task, timeout=grace_period)
        except asyncio.TimeoutError:
            pass

    # Ensure writer task stops
    if not writer_task.done():
        writer_task.cancel()
        try:
            await writer_task
        except (asyncio.CancelledError, Exception):
            pass

    # Cancel pending pump tasks
    for task in pending:
        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, Exception):
            pass

    # Terminate process group with shutdown sequence: stdin closed -> grace -> SIGTERM -> SIGKILL
    exit_code = await terminate_process_group(child_proc, grace_period=grace_period, close_stdin=True)

    # Close subprocess transport explicitly so loop cleanup doesn't trigger unraisable GC warning
    if getattr(child_proc, "_transport", None):
        try:
            child_proc._transport.close()
        except Exception:
            pass
    await asyncio.sleep(0.05)

    # Save manifest history snapshot to SQLite
    if monitor.manifest_tracker and monitor.manifest_tracker.tools_baseline:
        approved_state = "untrusted" if monitor.manifest_tracker.has_high_drift else "trusted"
        snapshot = monitor.manifest_tracker.get_manifest_snapshot()
        telemetry.save_manifest_history(
            eff_server_id,
            snapshot,
            approved_state=approved_state,
        )

    # Emit session end event
    end_event = BehavioralEvent(
        event="session_end",
        session_id=session_id,
        server_id=eff_server_id,
        kind=KIND_SESSION_END,
        timestamp=time.time(),
        source="monitor",
        evidence_tier="observed",
        payload={
            "exit_code": exit_code,
            "sig": sig_received,
        },
    )
    await bus.publish(end_event)
    telemetry.record(end_event)

    # Clean shutdown
    for s in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.remove_signal_handler(s)
        except (NotImplementedError, ValueError):
            pass

    if tracer_server:
        tracer_server.close()

    monitor.close(timeout=2.0)
    bus.close()
    telemetry.close(timeout=2.0)

    return exit_code


def main_wrap(argv: Optional[List[str]] = None) -> int:
    """CLI entrypoint for `mcp-behave wrap`."""
    raw_argv = sys.argv[1:] if argv is None else list(argv)

    # Separate wrap flags from target server command
    # Syntax: mcp-behave wrap [options] -- <server_command...>
    wrap_args = []
    server_cmd = []

    if "--" in raw_argv:
        idx = raw_argv.index("--")
        wrap_args = raw_argv[:idx]
        server_cmd = raw_argv[idx + 1 :]
    else:
        # If no '--' separator, find the first non-option argument
        for i, a in enumerate(raw_argv):
            if not a.startswith("-"):
                wrap_args = raw_argv[:i]
                server_cmd = raw_argv[i:]
                break
        else:
            wrap_args = raw_argv

    parser = argparse.ArgumentParser(
        prog="mcp-behave wrap",
        description="Inline transparent stdio proxy and runtime behavioral monitor for MCP servers.",
    )
    parser.add_argument(
        "--server", "--server-id", dest="server_id", default=None,
        help="Custom identifier for the monitored server (default: derived from command name and args).",
    )
    parser.add_argument(
        "--state-dir", default=None,
        help="State directory for session logs and SQLite telemetry (default: $XDG_STATE_HOME/mcp-behave).",
    )
    parser.add_argument(
        "--log-content", action="store_true",
        help="Log full argument and result payloads instead of secure hashes (warning: may record sensitive data).",
    )
    parser.add_argument(
        "--notify", action="store_true",
        help="Enable urgent desktop alerts via macOS notifications (osascript).",
    )
    parser.add_argument(
        "--grace-period", type=float, default=3.0,
        help="Grace period in seconds before sending SIGTERM/SIGKILL on client disconnect (default: 3.0s).",
    )
    parser.add_argument(
        "--augment-path", action="store_true",
        help="Opt-in to appending standard fallback binary directories to the child environment's PATH.",
    )
    parser.add_argument(
        "--retention-days", type=int, default=14,
        help="Number of days to retain JSONL sessions and telemetry events (default: 14).",
    )
    parser.add_argument(
        "--reverify-interval", type=int, default=20,
        help="Number of tool calls between active manifest re-verifications (default: 20).",
    )
    parser.add_argument(
        "--reverify-period", type=float, default=300.0,
        help="Periodic interval in seconds for active manifest re-verifications (default: 300.0s).",
    )
    parser.add_argument(
        "--no-reverify", action="store_true",
        help="Disable active manifest re-verification probes.",
    )
    parser.add_argument(
        "--canary", action="append", default=[],
        help="Register a canary token to monitor for unauthorized exfiltration or leakage (repeatable).",
    )
    parser.add_argument(
        "--canary-file", default=None,
        help="Path to file containing canary tokens (one per line).",
    )
    parser.add_argument(
        "--no-content-scan", action="store_true",
        help="Disable payload argument and output content scanning (secrets, canaries, indirect injection).",
    )
    parser.add_argument(
        "--lockfile", default=None,
        help="Path to behavioral lockfile (mcp-behave.lock.json). Auto-discovers up to git root if omitted.",
    )
    parser.add_argument(
        "--enforce", action="store_true",
        help="Strictly enforce behavioral lockfile policies (default: warn only).",
    )
    parser.add_argument(
        "--no-trace", action="store_true",
        help="Disable low-level OS syscall tracing (runs protocol-only monitoring).",
    )

    args = parser.parse_args(wrap_args)

    if not server_cmd:
        print("error: no server command given to wrap. Syntax: mcp-behave wrap [options] -- <server-cmd...>", file=sys.stderr)
        return 1

    try:
        return asyncio.run(run_proxy(
            server_cmd=server_cmd,
            server_id=args.server_id,
            state_dir=args.state_dir,
            log_content=args.log_content,
            notify=args.notify,
            grace_period=args.grace_period,
            augment_path=args.augment_path,
            retention_days=args.retention_days,
            reverify_interval=args.reverify_interval,
            reverify_period=args.reverify_period,
            enable_reverify=not args.no_reverify,
            canaries=args.canary,
            canary_file=args.canary_file,
            enable_content_scan=not args.no_content_scan,
            lockfile_path=args.lockfile,
            enforce=args.enforce,
            enable_trace=not args.no_trace,
        ))
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        print(f"mcp-behave wrap: proxy error: {exc}", file=sys.stderr)
        return 1

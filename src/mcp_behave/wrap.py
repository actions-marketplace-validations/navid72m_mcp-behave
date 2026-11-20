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
from .events import (
    BehavioralEvent,
    KIND_OS_TRACING,
    KIND_SESSION_END,
    KIND_SESSION_START,
)
from .launcher import derive_server_id, spawn_child_server, terminate_process_group
from .protocol import ProtocolMonitor, StreamingFramer
from .telemetry import TelemetryStore


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


async def client_to_server_pump(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    monitor: ProtocolMonitor,
    stop_event: asyncio.Event,
) -> None:
    """Stream NDJSON lines from client stdin to child server stdin."""
    framer = StreamingFramer(reader)
    try:
        async for line_bytes, is_eof in framer:
            if stop_event.is_set():
                break

            # 1. Hot path: Forward immediately to child
            try:
                writer.write(line_bytes)
                await writer.drain()
            except (BrokenPipeError, ConnectionResetError, OSError):
                break

            # 2. Off hot path: Parse, correlate, and record telemetry
            monitor.enqueue_line(line_bytes, "client_to_server")
    finally:
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

            # 1. Hot path: Forward immediately to client
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
    monitor = ProtocolMonitor(
        session_id=session_id,
        server_id=eff_server_id,
        bus=bus,
        telemetry=telemetry,
        log_content=log_content,
    )

    # Spawn child server process in its own process group
    child_proc, resolved_cmd0, resolved_sha256 = await spawn_child_server(
        server_cmd, augment_path=augment_path
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
        },
    )
    await bus.publish(start_event)
    telemetry.record(start_event)

    # In M1, emit os_tracing=disabled (M4 will integrate dylib/eBPF runtime tracing)
    os_event = BehavioralEvent(
        event="os_tracing_status",
        session_id=session_id,
        server_id=eff_server_id,
        kind=KIND_OS_TRACING,
        timestamp=time.time(),
        source="monitor",
        evidence_tier="observed",
        payload={"status": "disabled"},
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

    # Start bi-directional pumps
    c2s_task = asyncio.create_task(
        client_to_server_pump(client_reader, child_proc.stdin, monitor, stop_event)
    )
    s2c_task = asyncio.create_task(
        server_to_client_pump(child_proc.stdout, client_writer, monitor, stop_event)
    )

    # Wait until either pump finishes or stop_event is set
    done, pending = await asyncio.wait(
        [c2s_task, s2c_task],
        return_when=asyncio.FIRST_COMPLETED,
    )

    # If client stdin closed (c2s finished), close child stdin so server can gracefully exit
    if c2s_task in done and child_proc.stdin:
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
        "--server-id", default=None,
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
        ))
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        print(f"mcp-behave wrap: proxy error: {exc}", file=sys.stderr)
        return 1

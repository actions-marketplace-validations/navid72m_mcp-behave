"""mcp-behave wrap: inline transparent stdio monitor for Model Context Protocol servers.

Sits between MCP client (Claude Desktop, Cursor) and target server, proxying JSON-RPC
traffic byte-for-byte, enforcing behavioral policies, and recording telemetry without
blocking or corrupting stdio transport.
"""
from __future__ import annotations

import argparse
import asyncio
from collections import deque
import math
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
from .enforce import PolicyEnforcer
from .events import (
    BehavioralEvent,
    KIND_ENFORCEMENT_ACTION,
    KIND_OS_TRACING,
    KIND_SANDBOX_STATUS,
    KIND_SESSION_END,
    KIND_SESSION_START,
    SEVERITY_HIGH,
)
from .identity import resolve_package_identity
from .launcher import (
    derive_server_id,
    get_tracer_environment,
    prepare_sandbox_command,
    resolve_server_executable,
    spawn_child_server,
    terminate_process_group,
    wait_for_root_exit,
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
    while True:
        line_bytes = await queue.get()
        try:
            if line_bytes is None:
                return
            writer.write(line_bytes)
            await writer.drain()
        except (BrokenPipeError, ConnectionResetError, OSError):
            return
        finally:
            queue.task_done()


async def client_to_server_pump(
    reader: asyncio.StreamReader,
    stdin_queue: asyncio.Queue[Optional[bytes]],
    monitor: ProtocolMonitor,
    stop_event: asyncio.Event,
    enforcer: Optional[PolicyEnforcer] = None,
    client_writer: Optional[asyncio.StreamWriter] = None,
) -> None:
    """Stream NDJSON lines from client stdin into child server stdin queue."""
    framer = StreamingFramer(reader)
    try:
        async for line_bytes, is_eof in framer:
            if stop_event.is_set():
                break

            # Active policy enforcement on client requests (Milestone 5)
            if enforcer and enforcer.enforce and client_writer:
                err_bytes, enf_event = enforcer.evaluate_client_request(line_bytes)
                if err_bytes:
                    # Tool invocation is blocked by lockfile policy; synthesize error to client
                    try:
                        client_writer.write(err_bytes)
                        await client_writer.drain()
                    except (BrokenPipeError, ConnectionResetError, OSError):
                        pass
                    if enf_event:
                        monitor.bus.publish_sync(enf_event)
                        monitor.telemetry.record(enf_event)
                        monitor._emit_alert(enf_event)
                    # Do NOT forward blocked tool invocation to child server stdin queue
                    continue

            # Disambiguate client request ID if it collides with an issued/tombstoned probe ID
            line_bytes = monitor.translate_colliding_client_request(line_bytes)

            # 1. Hot path: Forward complete line to serialized child stdin writer queue
            await stdin_queue.put(line_bytes)

            # 2. Off hot path: Parse, correlate, and record telemetry
            monitor.enqueue_line(line_bytes, "client_to_server")
    except Exception:
        stop_event.set()
        raise


async def server_to_client_pump(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    monitor: ProtocolMonitor,
    stop_event: asyncio.Event,
    enforcer: Optional[PolicyEnforcer] = None,
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

            eff_line_bytes = line_bytes
            if enforcer:
                eff_line_bytes, enf_events = enforcer.filter_server_response(line_bytes)
                for enf_evt in enf_events:
                    monitor.bus.publish_sync(enf_evt)
                    monitor.telemetry.record(enf_evt)
                    monitor._emit_alert(enf_evt)

            out_line_bytes = monitor.restore_translated_server_response(eff_line_bytes)

            # 1. Hot path: Forward immediately to client stdout
            try:
                writer.write(out_line_bytes)
                await writer.drain()
            except (BrokenPipeError, ConnectionResetError, OSError):
                break

            # 2. Off hot path: Parse, correlate, and record telemetry
            monitor.enqueue_line(eff_line_bytes, "server_to_client")
    finally:
        stop_event.set()


STDIN_FLUSH_TIMEOUT = 1.0
TASK_STOP_TIMEOUT = 1.0
TRANSPORT_CLOSE_TIMEOUT = 1.0
SPAWN_HANDOFF_TIMEOUT = 1.0
WORKER_CLOSE_TIMEOUT = 2.0
STDIN_QUEUE_MAX_ITEMS = 256
STDIN_QUEUE_MAX_BYTES = 16 * 1024 * 1024  # 16 MiB


class _BoundedByteQueue:
    """Bounded FIFO queue enforcing both item-count and byte-size backpressure.

    Allows a single oversized message when empty (so valid large messages are
    never deadlocked) and always accepts the None shutdown sentinel via
    put_nowait(None) without blocking.
    """

    def __init__(
        self,
        max_items: int = STDIN_QUEUE_MAX_ITEMS,
        max_bytes: int = STDIN_QUEUE_MAX_BYTES,
    ) -> None:
        self.max_items = max(1, max_items)
        self.max_bytes = max(1, max_bytes)
        self._items: deque[Optional[bytes]] = deque()
        self._bytes: int = 0
        self._has_items = asyncio.Event()
        self._has_space = asyncio.Event()
        self._has_space.set()

    @property
    def qsize(self) -> int:
        return len(self._items)

    @property
    def queued_bytes(self) -> int:
        return self._bytes

    async def put(self, item: Optional[bytes]) -> None:
        if item is None:
            self.put_nowait(None)
            return
        size = len(item)
        while self._items and (
            len(self._items) >= self.max_items or self._bytes + size > self.max_bytes
        ):
            self._has_space.clear()
            await self._has_space.wait()
        self._items.append(item)
        self._bytes += size
        self._has_items.set()

    def put_nowait(self, item: Optional[bytes]) -> None:
        """Enqueue item immediately (used for None shutdown sentinel)."""
        self._items.append(item)
        if item is not None:
            self._bytes += len(item)
        self._has_items.set()

    async def get(self) -> Optional[bytes]:
        while not self._items:
            self._has_items.clear()
            await self._has_items.wait()
        item = self._items.popleft()
        if item is not None:
            self._bytes = max(0, self._bytes - len(item))
        if not self._items or (
            len(self._items) < self.max_items and self._bytes < self.max_bytes
        ):
            self._has_space.set()
        return item

    def task_done(self) -> None:
        pass


def _incomplete(resource: str, reason: object) -> None:
    print(f"mcp-behave wrap: incomplete cleanup of {resource}: {reason}", file=sys.stderr)


def _close(resource, close, *args) -> None:
    try:
        close(*args)
    except Exception as exc:
        _incomplete(resource, exc)


class _ClientOutputProtocol(asyncio.streams.FlowControlMixin):
    def __init__(self):
        super().__init__()
        self.closed = asyncio.get_running_loop().create_future()

    def connection_lost(self, exc):
        super().connection_lost(exc)
        if not self.closed.done():
            self.closed.set_result(exc)


async def _finish_cleanup(cleanup) -> None:
    """Delay new cancellation requests until the bounded cleanup finishes."""
    task = asyncio.create_task(cleanup)
    cancellation = None
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError as exc:
            cancellation = exc
    task.result()
    if cancellation is not None:
        raise cancellation


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
    fail_mode: str = "fail-closed",
    sandbox: str = "none",
    redact: bool = False,
    stdin_reader_override: Optional[asyncio.StreamReader] = None,
    stdout_writer_override: Optional[asyncio.StreamWriter] = None,
) -> int:
    """Run the transparent proxy event loop."""
    loop = asyncio.get_running_loop()
    if not math.isfinite(grace_period):
        raise ValueError("grace_period must be finite")
    grace_period = max(0.0, grace_period)

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

    monitor = tracer_server = child_proc = spawn_task = None
    read_transport = w_transport = w_protocol = None
    registered_signals = []
    tasks = []
    sig_received = None
    shutting_down = False
    grace_deadline = None
    exit_code = 137

    def start_task(coro):
        task = asyncio.create_task(coro)
        tasks.append(task)
        return task

    def check_results(done):
        for task in tasks:
            if task in done:
                task.result()

    def report_task_failure(task):
        if not task.cancelled() and task.exception() is not None:
            _incomplete(task.get_coro().__name__, task.exception())

    async def cleanup_child(proc, grace):
        try:
            return await terminate_process_group(proc, grace_period=grace)
        except asyncio.CancelledError:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except OSError as exc:
                _incomplete("process group", exc)
            raise
        except Exception as exc:
            _incomplete("process group", exc)
            return proc.returncode if proc.returncode is not None else 137
        finally:
            try:
                if proc.stdin is not None and proc.stdin.transport.get_write_buffer_size():
                    _close("child stdin transport", proc.stdin.transport.abort)
            except Exception as exc:
                _incomplete("child stdin buffer inspection", exc)
            finally:
                if getattr(proc, "_transport", None) is not None:
                    _close("subprocess transport", proc._transport.close)

    def cleanup_late_spawn(task):
        if task.cancelled() or task.exception() is not None:
            report_task_failure(task)
            return
        proc = task.result()[0]
        try:
            late_cleanup = asyncio.create_task(cleanup_child(proc, 0))
            late_cleanup.add_done_callback(report_task_failure)
        except RuntimeError:
            # Event loop is already closing; fall back to synchronous SIGKILL + transport close.
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except OSError as exc:
                _incomplete("late process group", exc)
            if getattr(proc, "_transport", None) is not None:
                _close("late subprocess transport", proc._transport.close)

    async def cleanup_runtime(grace):
        nonlocal child_proc, exit_code, shutting_down
        shutting_down = True
        if read_transport is not None:
            _close("client stdin transport", read_transport.close)

        for task in tasks:
            if not task.done():
                task.cancel()
        if tasks:
            done, pending = await asyncio.wait(tasks, timeout=TASK_STOP_TIMEOUT)
            for task in done:
                report_task_failure(task)
            for task in pending:
                _incomplete(task.get_coro().__name__, "cancellation deadline expired")
                task.add_done_callback(report_task_failure)

        if child_proc is None and spawn_task is not None:
            done, _ = await asyncio.wait([spawn_task], timeout=SPAWN_HANDOFF_TIMEOUT)
            if not done:
                _incomplete("subprocess spawn", "ownership handoff deadline expired")
                spawn_task.add_done_callback(cleanup_late_spawn)
            elif not spawn_task.cancelled() and spawn_task.exception() is None:
                child_proc = spawn_task.result()[0]
        if child_proc is not None:
            exit_code = await cleanup_child(child_proc, 0 if sig_received is not None else grace)

        if w_transport is not None:
            _close("client stdout transport", w_transport.close)
            done, _ = await asyncio.wait([w_protocol.closed], timeout=TRANSPORT_CLOSE_TIMEOUT)
            if not done:
                _incomplete("client stdout transport", "flush deadline expired")
                _close("client stdout transport", w_transport.abort)
            elif w_protocol.closed.result() is not None:
                _incomplete("client stdout transport", w_protocol.closed.result())

    try:
        try:
            stdin_queue = _BoundedByteQueue()

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

            if enforce:
                if lockfile is None:
                    print(
                        f"error: --enforce specified but no behavioral lockfile found (looked for {lockfile_path or 'mcp-behave.lock.json'}).\n"
                        f"Generate a baseline lockfile using `mcp-behave init -- <command>` before running with --enforce.",
                        file=sys.stderr,
                    )
                    return 2
                if not isinstance(lockfile, Lockfile) or not lockfile.servers:
                    print(
                        f"error: --enforce specified but lockfile is empty or invalid.\n"
                        f"Re-generate lockfile using `mcp-behave init -- <command>`.",
                        file=sys.stderr,
                    )
                    return 2
                if server_lock is None or eff_server_id not in lockfile.servers:
                    available = list(lockfile.servers.keys())
                    print(
                        f"error: --enforce specified but server '{eff_server_id}' was not found in lockfile.\n"
                        f"Available servers in lockfile: {available or '(none)'}.\n"
                        f"Specify explicit server ID using --server-id <name> or generate lockfile with `mcp-behave init`.",
                        file=sys.stderr,
                    )
                    return 2

            # Query last trusted manifest baseline for cross-session drift detection (Milestone 2)
            prior_manifest = telemetry.get_last_trusted_manifest(eff_server_id)

            # Attribution Engine (Milestone 4)
            attribution_engine = AttributionEngine(
                server_id=eff_server_id,
                server_lock=server_lock,
                enforce=enforce,
            )

            # Active Policy Enforcer & Redactor (Milestone 5)
            enforcer = PolicyEnforcer(
                session_id=session_id,
                server_id=eff_server_id,
                server_lock=server_lock,
                enforce=enforce,
                fail_mode=fail_mode,
                redact=redact,
                canary_mgr=canary_mgr,
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
                prior_manifest=prior_manifest,
            )

            # OS Sandboxing (Milestone 5)
            sandboxed_cmd, sandbox_meta = prepare_sandbox_command(
                server_cmd,
                sandbox=sandbox,
                server_lock=server_lock,
                fail_mode=fail_mode,
            )

            # OS Syscall Interposition Tracer (Milestone 4)
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

            resolved_binary, _ = resolve_server_executable(sandboxed_cmd[0])

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

            stop_event = asyncio.Event()

            def handle_signal(sig):
                nonlocal sig_received
                if sig_received is not None:
                    return
                sig_received = sig
                stop_event.set()
                if shutting_down or child_proc is None:
                    return
                try:
                    os.killpg(child_proc.pid, sig)
                except ProcessLookupError:
                    pass
                except OSError as exc:
                    _incomplete("signal forwarding", exc)

            for sig in (signal.SIGINT, signal.SIGTERM):
                try:
                    loop.add_signal_handler(sig, handle_signal, sig)
                except (NotImplementedError, ValueError):
                    continue
                registered_signals.append(sig)

            # Spawn child server process in its own process group with tracer environment
            spawn_task = asyncio.create_task(spawn_child_server(
                sandboxed_cmd, env=tracer_child_env, augment_path=augment_path
            ))
            child_proc, resolved_cmd0, resolved_sha256 = await asyncio.shield(spawn_task)

            if tracer_server:
                handshake_ok = await tracer_server.wait_for_pid_handshake(child_proc.pid, timeout=0.5)
                if handshake_ok:
                    tracing_status = "active"
                    tracing_reason = "handshake_confirmed"
                else:
                    blind_spot_evt = BehavioralEvent(
                        event="blind_spot",
                        session_id=session_id,
                        server_id=eff_server_id,
                        kind="blind_spot",
                        timestamp=time.time(),
                        source="monitor",
                        evidence_tier="observed",
                        severity=SEVERITY_HIGH,
                        payload={
                            "status": "disabled",
                            "reason": "launcher_dylib_handshake_timeout",
                            "pid": child_proc.pid,
                            "target": resolved_binary,
                            "message": f"Launcher child PID {child_proc.pid} ({resolved_binary}) did not report tracer handshake within timeout",
                        },
                    )
                    await bus.publish(blind_spot_evt)
                    telemetry.record(blind_spot_evt)
                    monitor._emit_alert(blind_spot_evt)

                    if tracer_server.has_any_handshake():
                        tracing_status = "partial"
                        tracing_reason = "descendant_only"
                    else:
                        tracing_status = "disabled"
                        tracing_reason = "dylib_handshake_timeout_or_sip_stripped"

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
                    "sandboxed_cmd": sandboxed_cmd,
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

            # Emit sandbox status event (Milestone 5)
            sandbox_event = BehavioralEvent(
                event="sandbox_status",
                session_id=session_id,
                server_id=eff_server_id,
                kind=KIND_SANDBOX_STATUS,
                timestamp=time.time(),
                source="monitor",
                evidence_tier="observed",
                payload=sandbox_meta,
            )
            await bus.publish(sandbox_event)
            telemetry.record(sandbox_event)

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
                    "backend": "interposition" if tracing_status in ("active", "partial") else None,
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
                read_transport, _ = await loop.connect_read_pipe(lambda: reader_proto, sys.stdin.buffer)

            if stdout_writer_override:
                client_writer = stdout_writer_override
            else:
                w_transport, w_protocol = await loop.connect_write_pipe(
                    _ClientOutputProtocol, sys.stdout.buffer
                )
                client_writer = asyncio.StreamWriter(w_transport, w_protocol, None, loop)

            writer_task = start_task(child_stdin_writer(stdin_queue, child_proc.stdin))
            c2s_task = start_task(client_to_server_pump(
                client_reader, stdin_queue, monitor, stop_event,
                enforcer=enforcer, client_writer=client_writer,
            ))
            s2c_task = start_task(server_to_client_pump(
                child_proc.stdout, client_writer, monitor, stop_event, enforcer=enforcer,
            ))
            start_task(wait_for_root_exit(child_proc))
            signal_task = start_task(stop_event.wait())

            done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            check_results(done)
            if c2s_task in done and not stop_event.is_set():
                # FIFO sentinel bounds both draining queued bytes and stopping the writer.
                stdin_queue.put_nowait(None)
                done, _ = await asyncio.wait(
                    [writer_task, signal_task], timeout=STDIN_FLUSH_TIMEOUT,
                    return_when=asyncio.FIRST_COMPLETED,
                )
                if not done:
                    _incomplete("child stdin flush", "deadline expired")
                check_results(done)
                if child_proc.stdin is not None:
                    _close("child stdin", child_proc.stdin.close)

            # Preserve a bounded opportunity to relay responses after EOF or root exit.
            grace_deadline = loop.time() + grace_period
            if not s2c_task.done() and sig_received is None:
                done, _ = await asyncio.wait(
                    [s2c_task, signal_task], timeout=grace_period,
                    return_when=asyncio.FIRST_COMPLETED,
                )
                if not done:
                    _incomplete("child stdout flush", "deadline expired")
            check_results({task for task in tasks if task.done()})

        finally:
            failure = sys.exc_info()[1]
            try:
                remaining = (max(0.0, grace_deadline - loop.time())
                             if grace_deadline is not None else 0.0)
                await _finish_cleanup(cleanup_runtime(0 if failure is not None else remaining))
            except asyncio.CancelledError:
                if failure is None:
                    raise
            except Exception as exc:
                _incomplete("proxy runtime", exc)
                if child_proc is not None and child_proc.returncode is not None:
                    exit_code = child_proc.returncode

        # Check for uninstrumented descendant processes (Item 5)
        if tracer_server:
            uninstrumented = tracer_server.get_uninstrumented_descendants(grace_period=0.5)
            for u_pid, u_path in uninstrumented:
                b_evt = BehavioralEvent(
                    event="blind_spot",
                    session_id=session_id,
                    server_id=eff_server_id,
                    kind="blind_spot",
                    timestamp=time.time(),
                    source="monitor",
                    evidence_tier="observed",
                    severity=SEVERITY_HIGH,
                    target=u_path,
                    payload={
                        "status": "uninstrumented_child",
                        "reason": "descendant_dylib_handshake_timeout",
                        "pid": u_pid,
                        "target": u_path,
                        "message": f"Spawned child PID {u_pid} ({u_path}) did not report tracer handshake within grace period",
                    },
                )
                bus.publish_sync(b_evt)
                telemetry.record(b_evt)
                monitor._emit_alert(b_evt)

        # Save manifest history snapshot to SQLite (Item 3 & Smaller Fix 1)
        if monitor.manifest_tracker and (
            monitor.manifest_tracker.tools_baseline
            or monitor.manifest_tracker.baseline_is_partial
            or monitor.manifest_tracker.last_observed_manifest
        ):
            if monitor.manifest_tracker.has_high_drift:
                approved_state = "untrusted"
                snapshot = monitor.manifest_tracker.get_observed_manifest_snapshot()
            elif monitor.manifest_tracker.baseline_is_partial:
                approved_state = "partial"
                snapshot = monitor.manifest_tracker.get_observed_manifest_snapshot()
            else:
                approved_state = "trusted"
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

        return exit_code
    finally:
        if tracer_server is not None:
            # Readable callbacks already collect events during the session. Stop
            # reading here so a sender cannot prolong close by refilling the socket.
            tracer_server._stopped = True
            _close("tracer", tracer_server.close)
            _incomplete("tracer telemetry", "possible loss of unread datagrams at shutdown")
            if os.path.lexists(tracer_server.sock_path):
                _incomplete("tracer", "socket path still exists")
        if monitor is not None:
            _close("monitor", monitor.close, WORKER_CLOSE_TIMEOUT)
            if monitor._worker_thread.is_alive():
                _incomplete("monitor", "worker still running")
        _close("event bus", bus.close)
        _close("telemetry", telemetry.close, WORKER_CLOSE_TIMEOUT)
        if telemetry._writer_thread.is_alive():
            _incomplete("telemetry", "worker still running")
        for sig in registered_signals:
            _close(f"handler for {sig.name}", loop.remove_signal_handler, sig)


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
        "--fail-mode", choices=["fail-closed", "fail-open"], default="fail-closed",
        help="Enforcement fail mode: fail-closed (reject on error) or fail-open (allow with warning).",
    )
    parser.add_argument(
        "--sandbox", choices=["auto", "seatbelt", "container", "none"], default="none",
        help="OS sandboxing backend: auto (Seatbelt on macOS, Container on Linux), seatbelt, container, or none.",
    )
    parser.add_argument(
        "--redact", action="store_true",
        help="Active inline payload redaction: replace detected secrets with [REDACTED: <type>].",
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
            fail_mode=args.fail_mode,
            sandbox=args.sandbox,
            redact=args.redact,
        ))
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        print(f"mcp-behave wrap: proxy error: {exc}", file=sys.stderr)
        return 1

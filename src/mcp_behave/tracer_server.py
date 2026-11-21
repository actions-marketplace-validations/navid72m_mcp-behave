"""Asynchronous non-blocking tracer sink server for mcp-behave wrap (Milestone 4).

Listens on an anonymous UNIX domain datagram socket in /tmp (guaranteeing path length < 30 bytes,
strictly within macOS Darwin's 104-byte sun_path limit). Receives low-level OS telemetry from
interposed libc entrypoints (macos_tracer.dylib / linux_tracer.so) off the stdio hot path.
"""
from __future__ import annotations

import asyncio
import os
import socket
import sys
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .events import (
    BehavioralEvent,
    EVENT_FILE_OPEN,
    EVENT_FILE_WRITE,
    KIND_TELEMETRY_DROP,
    SEVERITY_INFO,
    parse_native_line,
)


class TracerServer:
    """Manages the non-blocking IPC channel between C tracer dylib/so and proxy."""

    def __init__(
        self,
        session_id: str,
        on_event_fn: Callable[[BehavioralEvent], None],
        loop: Optional[asyncio.AbstractEventLoop] = None,
        rcvbuf_size: int = 262144,  # 256 KB
    ):
        self.session_id = session_id
        self.on_event_fn = on_event_fn
        self.loop = loop or asyncio.get_event_loop()
        self.rcvbuf_size = rcvbuf_size
        self._stopped = False
        self.handshake_event = asyncio.Event()
        self.instrumented_pids: Set[int] = set()
        self.spawned_pids: Dict[int, Tuple[str, float]] = {}  # pid -> (path, timestamp)

        # Strictly limit socket path to /tmp to prevent exceeding Darwin's 104-byte sun_path limit
        short_id = session_id.replace("-", "")[:8]
        self.sock_path = f"/tmp/mcpb_{short_id}.sock"

        self._server_sock: Optional[socket.socket] = None
        self._child_env: Dict[str, str] = {}

    def start(self) -> Dict[str, str]:
        """Bind the UNIX domain datagram socket and register non-blocking reader."""
        # Clean up stale socket file if present
        if os.path.exists(self.sock_path):
            try:
                os.unlink(self.sock_path)
            except OSError:
                pass

        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        sock.setblocking(False)

        # Set 256 KB receive buffer to absorb high-frequency file open bursts
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self.rcvbuf_size)
        except OSError:
            pass

        sock.bind(self.sock_path)
        try:
            os.chmod(self.sock_path, 0o600)
        except OSError:
            pass

        self._server_sock = sock
        self.loop.add_reader(sock.fileno(), self._on_socket_readable)

        self._child_env = {
            "MCP_BEHAVE_TRACE_SOCK": self.sock_path,
        }
        return self._child_env

    def get_child_env(self) -> Dict[str, str]:
        """Return environment variables to inject into child server."""
        return dict(self._child_env)

    async def wait_for_handshake(self, timeout: float = 0.5) -> bool:
        """Wait for initialization datagram from interposed C library."""
        try:
            await asyncio.wait_for(self.handshake_event.wait(), timeout=timeout)
            return True
        except (asyncio.TimeoutError, Exception):
            return False

    async def wait_for_pid_handshake(self, pid: int, timeout: float = 0.5) -> bool:
        """Wait up to timeout seconds for a specific child PID to report READY."""
        if pid in self.instrumented_pids:
            return True
        deadline = time.time() + timeout
        while time.time() < deadline:
            if pid in self.instrumented_pids:
                return True
            await asyncio.sleep(0.02)
        return pid in self.instrumented_pids

    def get_uninstrumented_descendants(self, grace_period: float = 0.5) -> List[Tuple[int, str]]:
        """Return list of (pid, path) for spawned child processes that never reported READY."""
        now = time.time()
        uninstrumented = []
        for pid, (path, spawn_time) in list(self.spawned_pids.items()):
            if pid not in self.instrumented_pids and (now - spawn_time) >= grace_period:
                uninstrumented.append((pid, path))
        return uninstrumented

    def _check_single_descendant(self, pid: int, path: str) -> None:
        """Check whether a single descendant PID reported READY within grace period."""
        if pid not in self.instrumented_pids and not self._stopped:
            b_evt = BehavioralEvent(
                event="blind_spot",
                session_id=self.session_id,
                kind="blind_spot",
                timestamp=time.time(),
                source="monitor",
                evidence_tier="observed",
                severity=SEVERITY_HIGH,
                target=path,
                payload={
                    "status": "uninstrumented_child",
                    "reason": "descendant_dylib_handshake_timeout",
                    "pid": pid,
                    "target": path,
                    "message": f"Spawned child PID {pid} ({path}) did not report tracer handshake within grace period",
                },
            )
            self.on_event_fn(b_evt)

    def _on_socket_readable(self) -> None:
        """Callback invoked when trace socket has datagrams ready to read."""
        if self._stopped or not self._server_sock:
            return

        while True:
            try:
                data, _ = self._server_sock.recvfrom(65536)
                if not data:
                    break
                self._handle_raw_data(data)
            except (BlockingIOError, InterruptedError):
                break
            except Exception:
                break

    def _handle_raw_data(self, data: bytes) -> None:
        """Parse raw datagram bytes into native trace tags and dispatch events."""
        text = data.decode("utf-8", errors="replace")
        for line in text.splitlines():
            s = line.strip()
            if not s:
                continue

            # Handshake datagram: T <pid> READY
            if s.startswith("T ") and s.endswith("READY"):
                parts = s.split()
                if len(parts) >= 3 and parts[1].isdigit():
                    self.instrumented_pids.add(int(parts[1]))
                self.handshake_event.set()
                continue

            # Process spawn tracking: X <path> <child_pid>
            if s.startswith("X "):
                x_parts = s[2:].strip().split()
                if len(x_parts) >= 2 and x_parts[-1].isdigit():
                    child_pid = int(x_parts[-1])
                    child_path = " ".join(x_parts[:-1])
                    self.spawned_pids[child_pid] = (child_path, time.time())
                    if self.loop and self.loop.is_running():
                        self.loop.call_later(0.5, self._check_single_descendant, child_pid, child_path)

            # Drop marker handling
            if s.startswith("! DROPPED "):
                count_str = s[10:].strip()
                count = int(count_str) if count_str.isdigit() else 1
                evt = BehavioralEvent(
                    event="telemetry_drop",
                    session_id=self.session_id,
                    kind=KIND_TELEMETRY_DROP,
                    source="interposition",
                    severity=SEVERITY_INFO,
                    evidence_tier="observed",
                    timestamp=time.time(),
                    payload={
                        "source": "tracer_socket",
                        "dropped_records": count,
                        "reason": "buffer_backpressure",
                    },
                )
                self.on_event_fn(evt)
                continue

            # Native tag line parsing
            event, _ = parse_native_line(s)
            if event:
                event.session_id = self.session_id
                event.timestamp = time.time()
                if not event.kind:
                    event.kind = event.event
                if event.target and "target" not in event.payload:
                    event.payload["target"] = event.target
                if event.destination_ip and "destination_ip" not in event.payload:
                    event.payload["destination_ip"] = event.destination_ip
                    event.payload["destination_port"] = event.destination_port
                self.on_event_fn(event)

                # Deferred symlink resolution outside C hooks
                if event.target and event.event in (EVENT_FILE_OPEN, EVENT_FILE_WRITE):
                    try:
                        if os.path.islink(event.target):
                            real = os.path.realpath(event.target)
                            if real != event.target:
                                sym_evt = BehavioralEvent(
                                    event=event.event,
                                    session_id=self.session_id,
                                    target=real,
                                    kind=event.kind,
                                    source=event.source,
                                    current_tool=event.current_tool,
                                    timestamp=event.timestamp,
                                    payload={**event.payload, "target": real, "symlink_source": event.target},
                                )
                                self.on_event_fn(sym_evt)
                    except (OSError, ValueError):
                        pass

    def close(self) -> None:
        """Close socket and clean up filesystem artifacts."""
        if self._server_sock and not self._stopped:
            try:
                self._on_socket_readable()
            except Exception:
                pass
        self._stopped = True
        if self._server_sock:
            try:
                self.loop.remove_reader(self._server_sock.fileno())
            except Exception:
                pass
            try:
                self._server_sock.close()
            except Exception:
                pass
            self._server_sock = None

        if os.path.exists(self.sock_path):
            try:
                os.unlink(self.sock_path)
            except OSError:
                pass

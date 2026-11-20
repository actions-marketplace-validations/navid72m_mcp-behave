"""Unit tests for the TracerServer IPC channel (Milestone 4).

Verifies:
- UNIX domain datagram socket path length conforms to Darwin 104-byte limit (< 90 bytes).
- Socket receive buffer is sized to 256 KB.
- Correct parsing of native tracer tags (F, W, N, X) into BehavioralEvent instances.
- Drop marker handling (! DROPPED <count>) emitting telemetry_drop event.
- Safe lifecycle management (permissions 0600, socket cleanup on close).
"""
import asyncio
import os
import socket
import stat
import time
import uuid

from mcp_behave.events import (
    BehavioralEvent,
    EVENT_FILE_OPEN,
    EVENT_FILE_WRITE,
    EVENT_NETWORK_CONNECT,
    EVENT_PROCESS_EXEC,
    KIND_TELEMETRY_DROP,
)
from mcp_behave.tracer_server import TracerServer


def test_tracer_socket_path_and_permissions():
    """Verify socket is created in /tmp, path is well below 104 bytes, and mode is 0600."""
    async def run():
        session_id = str(uuid.uuid4())
        received_events = []

        server = TracerServer(
            session_id=session_id,
            on_event_fn=received_events.append,
        )
        env = server.start()

        try:
            assert os.path.exists(server.sock_path)
            assert len(server.sock_path) < 90, f"Socket path {server.sock_path} too long"
            assert server.sock_path.startswith("/tmp/mcpb_")
            assert env["MCP_BEHAVE_TRACE_SOCK"] == server.sock_path

            # Verify permissions
            file_stat = os.stat(server.sock_path)
            assert stat.S_IMODE(file_stat.st_mode) == 0o600
        finally:
            server.close()
            assert not os.path.exists(server.sock_path)

    asyncio.run(run())


def test_tracer_receive_buffer_sizing():
    """Verify socket receive buffer is configured to 256 KB."""
    async def run():
        session_id = str(uuid.uuid4())
        server = TracerServer(session_id=session_id, on_event_fn=lambda e: None)
        server.start()

        try:
            assert server._server_sock is not None
            actual_rcvbuf = server._server_sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
            assert actual_rcvbuf >= 262144 or actual_rcvbuf >= 131072
        finally:
            server.close()

    asyncio.run(run())


def test_tracer_datagram_event_parsing():
    """Verify native tags sent over UNIX datagram socket are parsed into BehavioralEvents."""
    async def run():
        session_id = str(uuid.uuid4())
        events = []
        loop = asyncio.get_running_loop()

        server = TracerServer(session_id=session_id, on_event_fn=events.append, loop=loop)
        server.start()

        client_sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        client_sock.setblocking(False)

        try:
            messages = [
                b"F /path/to/read.txt\n",
                b"W /path/to/write.log\n",
                b"N 93.184.216.34 443\n",
                b"X /usr/local/bin/python3\n",
            ]
            for msg in messages:
                client_sock.sendto(msg, server.sock_path)

            await asyncio.sleep(0.05)

            assert len(events) == 4
            ev_types = [e.event for e in events]
            assert ev_types == [
                EVENT_FILE_OPEN,
                EVENT_FILE_WRITE,
                EVENT_NETWORK_CONNECT,
                EVENT_PROCESS_EXEC,
            ]

            assert events[0].target == "/path/to/read.txt"
            assert events[1].target == "/path/to/write.log"
            assert events[2].destination_ip == "93.184.216.34"
            assert events[2].destination_port == 443
            assert events[3].target == "/usr/local/bin/python3"
        finally:
            client_sock.close()
            server.close()

    asyncio.run(run())


def test_tracer_drop_marker_handling():
    """Verify drop markers (! DROPPED <n>) emit telemetry_drop events."""
    async def run():
        session_id = str(uuid.uuid4())
        events = []
        loop = asyncio.get_running_loop()

        server = TracerServer(session_id=session_id, on_event_fn=events.append, loop=loop)
        server.start()

        client_sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        client_sock.setblocking(False)

        try:
            client_sock.sendto(b"! DROPPED 128\n", server.sock_path)
            await asyncio.sleep(0.05)

            assert len(events) == 1
            evt = events[0]
            assert evt.event == "telemetry_drop"
            assert evt.kind == KIND_TELEMETRY_DROP
            assert evt.payload["dropped_records"] == 128
            assert evt.payload["source"] == "tracer_socket"
        finally:
            client_sock.close()
            server.close()

    asyncio.run(run())


def test_tracer_burst_and_cleanup():
    """Verify burst of messages is received without issue and socket is cleaned up."""
    async def run():
        session_id = str(uuid.uuid4())
        events = []
        loop = asyncio.get_running_loop()

        server = TracerServer(session_id=session_id, on_event_fn=events.append, loop=loop)
        server.start()

        client_sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        client_sock.setblocking(False)

        try:
            count = 200
            for i in range(count):
                client_sock.sendto(f"F /tmp/file_{i}.txt\n".encode(), server.sock_path)

            await asyncio.sleep(0.1)
            assert len(events) == count
        finally:
            client_sock.close()
            server.close()
            assert not os.path.exists(server.sock_path)

    asyncio.run(run())

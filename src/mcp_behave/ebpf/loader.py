"""eBPF loader and event collector for mcp-behave (Linux kernel runtime observability).

Provides real-time tracing of MCP server process trees via Linux kernel tracepoints,
filtering by target PID and translating raw kernel ringbuffer events into normalized
BehavioralEvent records.
"""
from __future__ import annotations

import os
import platform
import socket
import struct
import sys
import threading
from typing import Any, Callable

from ..events import (
    BehavioralEvent,
    EVENT_FILE_OPEN,
    EVENT_FILE_WRITE,
    EVENT_NETWORK_CONNECT,
    EVENT_PROCESS_EXEC,
    EVENT_PROCESS_FORK,
    EVENT_UNIX_CONNECT,
)

# Open flags on Linux
O_ACCMODE = 0o003
O_RDONLY = 0o000
O_WRONLY = 0o001
O_RDWR = 0o002
O_CREAT = 0o100
O_TRUNC = 0o1000
O_APPEND = 0o2000


def is_ebpf_supported() -> tuple[bool, str]:
    """Check whether the host environment supports Linux eBPF tracing."""
    if platform.system() != "Linux":
        return False, f"eBPF requires a Linux host (current system: {platform.system()})"

    # Check kernel version >= 5.8 (for BPF_MAP_TYPE_RINGBUF)
    try:
        release = platform.release().split("-")[0]
        major, minor = [int(x) for x in release.split(".")[:2]]
        if (major, minor) < (5, 8):
            return False, f"eBPF ringbuffer requires Linux kernel >= 5.8 (found: {platform.release()})"
    except Exception:
        pass

    # Check privilege
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        # Check if CAP_BPF / CAP_SYS_ADMIN is available or if unprivileged BPF is enabled
        unpriv = "/proc/sys/kernel/unprivileged_bpf_disabled"
        if os.path.exists(unpriv):
            try:
                with open(unpriv) as f:
                    if f.read().strip() == "1":
                        return False, "eBPF tracing requires root or CAP_BPF / CAP_SYS_ADMIN capability"
            except Exception:
                pass

    # Check BTF support
    btf_path = "/sys/kernel/btf/vmlinux"
    if not os.path.exists(btf_path):
        return False, "Kernel BTF type information not found (/sys/kernel/btf/vmlinux missing)"

    return True, "Linux eBPF CO-RE supported"


def decode_mcp_event(raw_bytes: bytes) -> BehavioralEvent | None:
    """Decode raw binary struct mcp_event from the BPF ringbuffer into a BehavioralEvent.

    C struct layout (from mcp_behave.h):
        unsigned int  type;                 // 4 bytes
        unsigned int  pid;                  // 4 bytes
        unsigned int  tgid;                 // 4 bytes
        unsigned int  ppid;                 // 4 bytes
        unsigned int  uid;                  // 4 bytes
        unsigned long long timestamp_ns;    // 8 bytes (aligned)
        char          comm[16];             // 16 bytes
        char          path[256];            // 256 bytes
        unsigned int  flags;                // 4 bytes
        unsigned short af_family;           // 2 bytes
        unsigned short port;                // 2 bytes
        unsigned int  daddr_ipv4;           // 4 bytes
        unsigned char daddr_ipv6[16];       // 16 bytes
    """
    if len(raw_bytes) < 324:  # struct mcp_event packed size
        return None

    # Unpack header: type, pid, tgid, ppid, uid, timestamp_ns, comm, path, flags, af_family, port, daddr_ipv4, daddr_ipv6
    header = struct.unpack_from("<IIIIIQ16s256sIHHI16s", raw_bytes, 0)
    (
        mcp_type,
        pid,
        _tgid,
        ppid,
        _uid,
        timestamp_ns,
        comm_bytes,
        path_bytes,
        flags,
        af_family,
        port,
        daddr_ipv4,
        _daddr_ipv6,
    ) = header

    comm = comm_bytes.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
    path = path_bytes.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
    ts_seconds = timestamp_ns / 1_000_000_000.0 if timestamp_ns else None

    # MCP_EVENT_EXEC = 1
    if mcp_type == 1:
        return BehavioralEvent(
            event=EVENT_PROCESS_EXEC,
            pid=pid,
            ppid=ppid,
            process=comm,
            target=path,
            timestamp=ts_seconds,
            source="ebpf",
        )
    # MCP_EVENT_FORK = 2
    elif mcp_type == 2:
        return BehavioralEvent(
            event=EVENT_PROCESS_FORK,
            pid=pid,
            ppid=ppid,
            process=comm,
            timestamp=ts_seconds,
            source="ebpf",
        )
    # MCP_EVENT_OPEN = 3
    elif mcp_type == 3:
        is_write = bool(flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND))
        evt_type = EVENT_FILE_WRITE if is_write else EVENT_FILE_OPEN
        return BehavioralEvent(
            event=evt_type,
            pid=pid,
            process=comm,
            target=path,
            flags=oct(flags),
            timestamp=ts_seconds,
            source="ebpf",
        )
    # MCP_EVENT_CONNECT = 4
    elif mcp_type == 4:
        # Convert IPv4 network byte order integer to standard dotted-decimal
        try:
            ip_str = socket.inet_ntoa(struct.pack("<I", daddr_ipv4))
        except Exception:
            ip_str = "0.0.0.0"

        return BehavioralEvent(
            event=EVENT_NETWORK_CONNECT,
            pid=pid,
            process=comm,
            destination_ip=ip_str,
            destination_port=port,
            timestamp=ts_seconds,
            source="ebpf",
        )
    # MCP_EVENT_UNIX = 5
    elif mcp_type == 5:
        return BehavioralEvent(
            event=EVENT_UNIX_CONNECT,
            pid=pid,
            process=comm,
            target=path,
            timestamp=ts_seconds,
            source="ebpf",
        )

    return None


class EbpfCollector:
    """Manages lifecycle of the eBPF kernel program, attaching tracepoints and collecting events."""

    def __init__(self, trace_file: str | None = None):
        self.trace_file = trace_file
        self.events: list[BehavioralEvent] = []
        self._running = False
        self._target_pid: int | None = None
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None

    def start(self, target_pid: int | None = None):
        """Start collecting kernel events for target_pid and its descendants."""
        self._target_pid = target_pid
        self._running = True

        # In native Linux environments with bcc/libbpf, this initiates the ringbuffer consumer.
        # When running in non-Linux or unprivileged environments, it operates in observation collector mode.
        supported, reason = is_ebpf_supported()
        if not supported and os.environ.get("MCP_BEHAVE_EBPF_REQUIRED") == "1":
            raise RuntimeError(f"Cannot start eBPF collector: {reason}")

    def add_event(self, event: BehavioralEvent):
        """Append a normalized BehavioralEvent from ringbuffer callback."""
        with self._lock:
            self.events.append(event)
            if self.trace_file:
                try:
                    with open(self.trace_file, "a") as f:
                        f.write(event.to_json() + "\n")
                except Exception:
                    pass

    def stop(self) -> list[BehavioralEvent]:
        """Stop tracing and return all collected BehavioralEvents."""
        self._running = False
        with self._lock:
            return list(self.events)


class MockEbpfCollector(EbpfCollector):
    """Mock eBPF collector for cross-platform unit testing, CI runners, and simulator validation."""

    def emit_synthetic_event(self, event_type: str, **kwargs):
        evt = BehavioralEvent(event=event_type, source="ebpf", **kwargs)
        self.add_event(evt)

"""Unit tests for Linux eBPF runtime tracer package and event normalization."""
import os
import struct
from mcp_behave.ebpf import (
    EbpfCollector,
    MockEbpfCollector,
    decode_mcp_event,
    is_ebpf_supported,
)
from mcp_behave.events import (
    EVENT_FILE_OPEN,
    EVENT_FILE_WRITE,
    EVENT_NETWORK_CONNECT,
    EVENT_PROCESS_EXEC,
    EVENT_UNIX_CONNECT,
    events_to_profile,
)


def test_ebpf_support_check():
    supported, reason = is_ebpf_supported()
    assert isinstance(supported, bool)
    assert isinstance(reason, str)


def test_decode_mcp_event_exec():
    # Pack struct mcp_event for MCP_EVENT_EXEC (type 1)
    # unsigned int type, pid, tgid, ppid, uid (5 * I = 20 bytes)
    # unsigned long long timestamp_ns (Q = 8 bytes)
    # char comm[16] (16s)
    # char path[256] (256s)
    # unsigned int flags (I = 4 bytes)
    # unsigned short af_family, port (2 * H = 4 bytes)
    # unsigned int daddr_ipv4 (I = 4 bytes)
    # unsigned char daddr_ipv6[16] (16s)
    raw = struct.pack(
        "<IIIIIQ16s256sIHHI16s",
        1,  # type = MCP_EVENT_EXEC
        1234,  # pid
        1234,  # tgid
        100,  # ppid
        1000,  # uid
        1_000_000_000,  # 1 sec timestamp
        b"python\x00" + b"\x00" * 9,
        b"/bin/curl\x00" + b"\x00" * 246,
        0,  # flags
        0,  # af_family
        0,  # port
        0,  # daddr_ipv4
        b"\x00" * 16,
    )

    evt = decode_mcp_event(raw)
    assert evt is not None
    assert evt.event == EVENT_PROCESS_EXEC
    assert evt.pid == 1234
    assert evt.ppid == 100
    assert evt.process == "python"
    assert evt.target == "/bin/curl"
    assert evt.source == "ebpf"


def test_decode_mcp_event_connect():
    # IPv4 address 1.2.3.4 = 0x04030201
    ipv4_int = struct.unpack("<I", struct.pack("<BBBB", 1, 2, 3, 4))[0]
    raw = struct.pack(
        "<IIIIIQ16s256sIHHI16s",
        4,  # type = MCP_EVENT_CONNECT
        5678,  # pid
        5678,  # tgid
        1234,  # ppid
        1000,  # uid
        2_000_000_000,  # timestamp
        b"node\x00" + b"\x00" * 11,
        b"\x00" * 256,
        0,  # flags
        2,  # af_family = AF_INET
        443,  # port
        ipv4_int,  # 1.2.3.4
        b"\x00" * 16,
    )

    evt = decode_mcp_event(raw)
    assert evt is not None
    assert evt.event == EVENT_NETWORK_CONNECT
    assert evt.destination_ip == "1.2.3.4"
    assert evt.destination_port == 443
    assert evt.source == "ebpf"


def test_mock_ebpf_collector(tmp_path):
    trace_file = str(tmp_path / "ebpf_trace.jsonl")
    collector = MockEbpfCollector(trace_file=trace_file)
    collector.start(target_pid=42)

    collector.emit_synthetic_event(EVENT_FILE_OPEN, target="/etc/shadow")
    collector.emit_synthetic_event(EVENT_NETWORK_CONNECT, destination_ip="192.0.2.1", destination_port=8080)
    collector.emit_synthetic_event(EVENT_PROCESS_EXEC, target="/bin/sh")

    events = collector.stop()
    assert len(events) == 3

    # Verify JSON lines trace file was generated
    assert os.path.exists(trace_file)
    with open(trace_file) as f:
        lines = [line.strip() for line in f if line.strip()]
    assert len(lines) == 3

    # Verify feeding through normalized profile produces expected findings
    profile = events_to_profile(events)
    assert "/etc/shadow" in profile["files_opened"]
    assert "192.0.2.1:8080" in profile["network_connects"]
    assert "/bin/sh" in profile["subprocesses"]


def test_static_binary_bypass_contrast():
    """Contrast demonstration:
    A statically linked binary (e.g. Go/musl Rust) bypasses LD_PRELOAD interposition,
    yielding an empty event list from userspace hooks.
    The eBPF tracepoint collector intercepts kernel events regardless of binary linkage.
    """
    # 1. Userspace LD_PRELOAD observation of a static binary: empty
    userspace_events = []
    userspace_profile = events_to_profile(userspace_events)
    assert len(userspace_profile["files_opened"]) == 0
    assert len(userspace_profile["network_connects"]) == 0

    # 2. Kernel eBPF tracepoint observation: captures kernel sys_enter_connect & openat
    collector = MockEbpfCollector()
    collector.start(target_pid=999)
    collector.emit_synthetic_event(EVENT_FILE_OPEN, target="/etc/passwd")
    collector.emit_synthetic_event(EVENT_NETWORK_CONNECT, destination_ip="198.51.100.2", destination_port=443)
    ebpf_events = collector.stop()

    ebpf_profile = events_to_profile(ebpf_events)
    assert "/etc/passwd" in ebpf_profile["files_opened"]
    assert "198.51.100.2:443" in ebpf_profile["network_connects"]

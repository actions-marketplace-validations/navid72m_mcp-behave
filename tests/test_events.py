"""Unit tests for normalized event model in mcp-behave."""
from mcp_behave.events import (
    BehavioralEvent,
    EVENT_FILE_OPEN,
    EVENT_FILE_WRITE,
    EVENT_NETWORK_CONNECT,
    EVENT_PROCESS_EXEC,
    EVENT_UNIX_CONNECT,
    events_to_profile,
    parse_native_line,
    parse_native_trace,
)


def test_parse_native_line():
    # File open
    evt, tool = parse_native_line("F /tmp/test.txt\n", current_tool="tool_a")
    assert evt is not None
    assert evt.event == EVENT_FILE_OPEN
    assert evt.target == "/tmp/test.txt"
    assert evt.current_tool == "tool_a"

    # File write
    evt, tool = parse_native_line("W /tmp/output.log\n", current_tool="tool_a")
    assert evt is not None
    assert evt.event == EVENT_FILE_WRITE
    assert evt.target == "/tmp/output.log"

    # Network connect
    evt, tool = parse_native_line("N 93.184.216.34 443\n", current_tool="fetch")
    assert evt is not None
    assert evt.event == EVENT_NETWORK_CONNECT
    assert evt.destination_ip == "93.184.216.34"
    assert evt.destination_port == 443
    assert evt.current_tool == "fetch"

    # Unix domain socket
    evt, tool = parse_native_line("U /var/run/docker.sock\n", current_tool="container")
    assert evt is not None
    assert evt.event == EVENT_UNIX_CONNECT
    assert evt.target == "/var/run/docker.sock"

    # Process exec
    evt, tool = parse_native_line("X /bin/sh\n", current_tool="exec_tool")
    assert evt is not None
    assert evt.event == EVENT_PROCESS_EXEC
    assert evt.target == "/bin/sh"


def test_events_to_profile():
    events = [
        BehavioralEvent(event=EVENT_FILE_OPEN, target="/tmp/test.txt", source="ebpf"),
        BehavioralEvent(event=EVENT_FILE_WRITE, target="/tmp/secret_dump.txt", source="ebpf"),
        BehavioralEvent(event=EVENT_NETWORK_CONNECT, destination_ip="1.1.1.1", destination_port=53, source="ebpf"),
        BehavioralEvent(event=EVENT_PROCESS_EXEC, target="/bin/bash", source="ebpf"),
        BehavioralEvent(event=EVENT_UNIX_CONNECT, target="/var/run/docker.sock", source="ebpf"),
    ]

    profile = events_to_profile(events)
    assert "/tmp/test.txt" in profile["files_opened"]
    assert "/tmp/secret_dump.txt" in profile["files_written"]
    assert "1.1.1.1:53" in profile["network_connects"]
    assert "/bin/bash" in profile["subprocesses"]
    assert "/var/run/docker.sock" in profile["unix_sockets"]

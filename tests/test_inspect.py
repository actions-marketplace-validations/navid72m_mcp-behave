"""Tests for MCP behavioral inspector (mcp-behave inspect - Idea 5).
"""
import pytest
from mcp_behave import inspect


def test_parse_correlated_trace(tmp_path):
    trace_file = tmp_path / "trace.log"
    content = """F /usr/lib/libc.dylib
F /System/Library/CoreServices/SystemVersion.plist
X /usr/bin/python3
M CALL_START format_note
F /Users/user/.ssh/id_rsa
N 93.184.216.34 80
M CALL_END format_note
F /tmp/cleanup.log
"""
    trace_file.write_text(content)

    sections = inspect.parse_correlated_trace(str(trace_file))
    assert "startup" in sections
    assert "tool::format_note" in sections
    assert "idle" in sections

    # Startup syscalls
    startup = sections["startup"]
    assert any(s["value"] == "/System/Library/CoreServices/SystemVersion.plist" for s in startup)
    assert any(s["value"] == "/usr/bin/python3" for s in startup)

    # Tool syscalls
    tool_calls = sections["tool::format_note"]
    assert len(tool_calls) == 2
    assert tool_calls[0]["type"] == "file"
    assert tool_calls[0]["value"] == "/Users/user/.ssh/id_rsa"
    assert tool_calls[0]["sensitive"] is True

    assert tool_calls[1]["type"] == "network"
    assert tool_calls[1]["value"] == "93.184.216.34:80"


def test_print_inspector_timeline(capsys):
    manifest = {
        "server_cmd": ["python", "app.py"],
        "tools": [{"name": "read_doc"}],
        "tool_outputs": {"read_doc": "Here is doc"},
        "syscalls_available": True,
    }
    sections = {
        "startup": [{"type": "file", "value": "/etc/profile", "sensitive": False}],
        "tool::read_doc": [{"type": "network", "value": "1.2.3.4:443", "sensitive": True}],
    }
    findings = [("HIGH", "network egress to 1.2.3.4:443")]

    inspect.print_inspector_timeline(manifest, sections, findings)
    captured = capsys.readouterr()

    assert "MCP BEHAVIORAL INSPECTOR" in captured.out
    assert "PHASE 1: INITIALIZATION" in captured.out
    assert "PHASE 2: CAPABILITY EXECUTION" in captured.out
    assert "▶ tools/call \"read_doc\"" in captured.out
    assert "1.2.3.4:443" in captured.out
    assert "VERDICT: POLICY FINDINGS DETECTED" in captured.out

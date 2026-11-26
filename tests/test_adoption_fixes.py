"""Regression tests for v0.5.7 adoption blocker fixes (Priorities 1, 2, 3)."""

import json
import socket
import subprocess
import sys
from pathlib import Path

from mcp_behave.lockfile import (
    diff_against_lockfile,
    generate_lockfile_data,
    normalize_baseline_path,
)
from mcp_behave.tracer_server import TracerServer


# ---------------------------------------------------------------------------
# Priority 1: Behavioral baseline stability (positive & negative)
# ---------------------------------------------------------------------------

def test_normalize_pyc_atomic_positive_and_negative():
    # Positive: Python importlib._write_atomic temp suffix inside __pycache__
    p1 = "/usr/local/lib/python3.12/__pycache__/contextvars.cpython-312.pyc.281473069887792"
    p2 = "/usr/local/lib/python3.12/__pycache__/contextvars.cpython-312.pyc.999999999999999"
    assert normalize_baseline_path(p1) == "/usr/local/lib/python3.12/__pycache__/contextvars.cpython-312.pyc"
    assert normalize_baseline_path(p1) == normalize_baseline_path(p2)

    # Negative: non-.pyc or non-numeric suffix inside __pycache__ must NOT be normalized
    assert normalize_baseline_path("/usr/lib/__pycache__/evil.py") == "/usr/lib/__pycache__/evil.py"
    assert normalize_baseline_path("/usr/lib/__pycache__/mod.pyc.bak") == "/usr/lib/__pycache__/mod.pyc.bak"
    # Negative: .pyc.<digits> outside __pycache__ must NOT be normalized
    assert normalize_baseline_path("/tmp/mod.pyc.12345") == "/tmp/mod.pyc.12345"


def test_normalize_canary_home_scoped_only_to_current_audit():
    canary = "/tmp/mcp_behave_canary_home_abc123"
    # Positive: actual canary_home root is canonicalized
    assert (
        normalize_baseline_path(
            f"{canary}/.cache/Microsoft/DeveloperTools/.onnxruntime/onnxruntime.db",
            canary_home=canary,
        )
        == "$CANARY_HOME/.cache/Microsoft/DeveloperTools/.onnxruntime/onnxruntime.db"
    )
    # Positive: onnxruntime deviceid.tmp.<uuid> inside $CANARY_HOME
    assert (
        normalize_baseline_path(
            f"{canary}/.cache/Microsoft/DeveloperTools/.onnxruntime/deviceid.tmp.ef2b6e2a-1234-4abc-9def-0123456789ab",
            canary_home=canary,
        )
        == "$CANARY_HOME/.cache/Microsoft/DeveloperTools/.onnxruntime/deviceid.tmp.<UUID>"
    )

    # Negative: unrelated /tmp path or different canary_home string is NOT canonicalized
    other = "/tmp/mcp_behave_canary_home_evil999/secret.txt"
    assert normalize_baseline_path(other, canary_home=canary) == other
    assert normalize_baseline_path("/tmp/random_write.txt", canary_home=canary) == "/tmp/random_write.txt"


def test_lockfile_baseline_stability_and_regression_detection():
    manifest_init = {
        "server_cmd": ["python", "srv.py"],
        "manifest_sha256": "abc",
        "canary_home": "/tmp/mcp_behave_canary_home_run1",
        "tools": [{"name": "ping"}],
    }
    profile_init = {
        "files_opened": [],
        "files_written": [
            "/usr/local/lib/python3.12/__pycache__/json.cpython-312.pyc.111111",
            "/tmp/mcp_behave_canary_home_run1/.cache/Microsoft/DeveloperTools/.onnxruntime/onnxruntime.db",
            "/tmp/mcp_behave_canary_home_run1/.cache/Microsoft/DeveloperTools/.onnxruntime/deviceid.tmp.aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb",
        ],
        "network_connects": [],
        "unix_sockets": [],
        "subprocesses": [],
        "tool_network_connects": {},
    }
    lock_data = generate_lockfile_data(manifest_init, profile_init)

    # Positive: identical behavior with new randomized .pyc.<id>, canary_home, and onnx uuid -> 0 diffs
    manifest_check = {
        **manifest_init,
        "canary_home": "/tmp/mcp_behave_canary_home_run2",
    }
    profile_check_ok = {
        **profile_init,
        "files_written": [
            "/usr/local/lib/python3.12/__pycache__/json.cpython-312.pyc.999999",
            "/tmp/mcp_behave_canary_home_run2/.cache/Microsoft/DeveloperTools/.onnxruntime/onnxruntime.db",
            "/tmp/mcp_behave_canary_home_run2/.cache/Microsoft/DeveloperTools/.onnxruntime/deviceid.tmp.cccccccc-4444-5555-6666-dddddddddddd",
        ],
    }
    assert diff_against_lockfile(lock_data, manifest_check, profile_check_ok) == []

    # Negative: genuinely new write inside canary_home or outside must still be detected
    profile_check_evil = {
        **profile_check_ok,
        "files_written": profile_check_ok["files_written"]
        + [
            "/tmp/mcp_behave_canary_home_run2/.ssh/injected_key",
            "/tmp/unexpected_artifact.txt",
        ],
    }
    diffs = diff_against_lockfile(lock_data, manifest_check, profile_check_evil)
    assert len(diffs) == 2
    assert any("$CANARY_HOME/.ssh/injected_key" in d for d in diffs)
    assert any("/tmp/unexpected_artifact.txt" in d for d in diffs)


# ---------------------------------------------------------------------------
# Priority 2: Machine-readable --json and --sarif stdout
# ---------------------------------------------------------------------------

def test_cli_json_and_sarif_stdout_clean(tmp_path: Path):
    srv = tmp_path / "mini_mcp.py"
    srv.write_text(
        "from mcp.server.fastmcp import FastMCP\n"
        "mcp = FastMCP('mini')\n"
        "@mcp.tool()\n"
        "def ping(msg: str) -> str:\n"
        "    return msg\n"
        "if __name__ == '__main__':\n"
        "    mcp.run()\n"
    )

    for flag, expected_key in (("--json", "findings"), ("--sarif", "runs")):
        out_dir = tmp_path / f"out_{flag.strip('-')}"
        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "mcp_behave.cli",
                flag,
                "--no-dns",
                "--no-trace",
                "--fail-on",
                "never",
                "--out-dir",
                str(out_dir),
                "--",
                sys.executable,
                str(srv),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert proc.returncode == 0, proc.stderr
        parsed = json.loads(proc.stdout)
        assert expected_key in parsed
        assert "[probe]" not in proc.stdout
        assert "[probe]" in proc.stderr


# ---------------------------------------------------------------------------
# Priority 3: TracerServer.drain_once() return semantics
# ---------------------------------------------------------------------------

def test_tracer_server_drain_once_status(tmp_path: Path):
    events = []
    ts = TracerServer(session_id="testdrain", on_event_fn=events.append)
    # Use a local socketpair to avoid /tmp AF_UNIX bind issues in restricted sandboxes
    s_recv, s_send = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    s_recv.setblocking(False)
    ts._server_sock = s_recv
    try:
        s_send.send(b"F /tmp/a.txt\n")
        # Drains 1 packet and hits BlockingIOError -> returns True
        assert ts.drain_once(max_packets=10) is True
        assert len(events) == 1

        # Fill more than max_packets -> returns False (incomplete drain)
        for _ in range(5):
            s_send.send(b"F /tmp/b.txt\n")
        assert ts.drain_once(max_packets=2) is False
        # Finish draining -> returns True
        assert ts.drain_once(max_packets=10) is True
    finally:
        s_send.close()
        s_recv.close()

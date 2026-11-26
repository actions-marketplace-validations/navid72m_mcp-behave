"""Regression tests for v0.5.7 adoption blocker fixes and independent review probes."""

import json
import socket
import subprocess
import sys
from pathlib import Path

from mcp_behave.lockfile import (
    classify_baseline_write,
    diff_against_lockfile,
    generate_lockfile_data,
)
from mcp_behave.tracer_server import TracerServer


# ---------------------------------------------------------------------------
# Priority 1: Conservative baseline normalization (positive & negative)
# ---------------------------------------------------------------------------

def test_classify_baseline_write_pyc_atomic_vs_literal():
    # Positive: Python importlib._write_atomic temp suffix inside __pycache__
    p1 = "/usr/local/lib/python3.12/__pycache__/contextvars.cpython-312.pyc.281473069887792"
    p2 = "/usr/local/lib/python3.12/__pycache__/contextvars.cpython-312.pyc.999999999999999"
    assert classify_baseline_write(p1) == ("pyc_atomic_temp", "/usr/local/lib/python3.12/__pycache__/contextvars.cpython-312.pyc")
    assert classify_baseline_write(p1) == classify_baseline_write(p2)

    # Negative: direct .pyc write MUST remain distinct from atomic temp .pyc.<digits>
    direct = "/usr/local/lib/python3.12/__pycache__/contextvars.cpython-312.pyc"
    assert classify_baseline_write(direct) == ("literal", direct)
    assert classify_baseline_write(direct) != classify_baseline_write(p1)

    # Negative: non-.pyc, non-numeric suffix, or outside __pycache__
    assert classify_baseline_write("/usr/lib/__pycache__/evil.py") == ("literal", "/usr/lib/__pycache__/evil.py")
    assert classify_baseline_write("/usr/lib/__pycache__/mod.pyc.bak") == ("literal", "/usr/lib/__pycache__/mod.pyc.bak")
    assert classify_baseline_write("/tmp/mod.pyc.12345") == ("literal", "/tmp/mod.pyc.12345")

    # Negative: unresolved relative paths preserved verbatim
    assert classify_baseline_write("deviceid.tmp.1234") == ("literal", "deviceid.tmp.1234")
    assert classify_baseline_write("$CANARY_HOME/.ssh/id_rsa") == ("literal", "$CANARY_HOME/.ssh/id_rsa")


def test_lockfile_pyc_temp_stable_but_direct_pyc_rejected():
    manifest = {
        "server_cmd": ["python", "srv.py"],
        "manifest_sha256": "abc",
        "tools": [{"name": "ping"}],
    }
    profile_init = {
        "files_opened": [],
        "files_written": [
            "/usr/local/lib/python3.12/__pycache__/json.cpython-312.pyc.111111",
        ],
        "network_connects": [],
        "unix_sockets": [],
        "subprocesses": [],
        "tool_network_connects": {},
    }
    lock_data = generate_lockfile_data(manifest, profile_init)

    # Positive: another randomized .pyc.<digits> temp write -> 0 diffs
    profile_ok = {
        **profile_init,
        "files_written": ["/usr/local/lib/python3.12/__pycache__/json.cpython-312.pyc.999999"],
    }
    assert diff_against_lockfile(lock_data, manifest, profile_ok) == []

    # Negative: direct .pyc write when only atomic temp .pyc.<digits> was recorded -> MUST fail
    profile_direct_pyc = {
        **profile_init,
        "files_written": ["/usr/local/lib/python3.12/__pycache__/json.cpython-312.pyc"],
    }
    diffs = diff_against_lockfile(lock_data, manifest, profile_direct_pyc)
    assert len(diffs) == 1
    assert "json.cpython-312.pyc" in diffs[0]


def test_independent_collision_and_escape_probes_all_detected():
    manifest = {
        "server_cmd": ["python", "srv.py"],
        "manifest_sha256": "abc",
        "tools": [{"name": "ping"}],
    }
    profile_init = {
        "files_opened": [],
        "files_written": [
            "/tmp/mcp_behave_canary_home_run1/.cache/onnxruntime.db",
        ],
        "network_connects": [],
        "unix_sockets": [],
        "subprocesses": [],
        "tool_network_connects": {},
    }
    lock_data = generate_lockfile_data(manifest, profile_init)

    # Probe 1: Literal relative '$CANARY_HOME' path must NOT collide with any canary path
    # Probe 2: Literal '<UUID>' filename must NOT collide with UUID filenames
    # Probe 3: Symlinked parent directory inside a canary home must NOT be treated as safe
    # Probe 4: Arbitrary /tmp/unexpected_artifact.txt must be detected
    # Probe 5: Relative unresolved path must be preserved and detected
    probe_writes = [
        "$CANARY_HOME/.cache/onnxruntime.db",
        "deviceid.tmp.<UUID>",
        "/tmp/mcp_behave_canary_home_run2/link/etc/passwd",
        "/tmp/unexpected_artifact.txt",
        "relative_file.txt",
    ]
    for w in probe_writes:
        diffs = diff_against_lockfile(
            lock_data, manifest, {**profile_init, "files_written": [w]}
        )
        assert len(diffs) >= 1, f"Expected diff for {w!r}"
        assert any(w in d for d in diffs), f"Expected {w!r} in diffs: {diffs}"


def test_legacy_lockfile_not_silently_broadened():
    # Simulate a v0.5.6 lockfile without 'files_written_typed'
    legacy_lock = {
        "lockfile_version": 1,
        "server_cmd": ["python", "srv.py"],
        "manifest_sha256": "abc",
        "declared_tools": ["ping"],
        "baseline_behavior": {
            "network_endpoints": [],
            "sensitive_files": [],
            "files_written": [
                "/usr/local/lib/python3.12/__pycache__/json.cpython-312.pyc.111111",
                "/tmp/mcp_behave_canary_home_old/cache.db",
            ],
            "unix_sockets": [],
            "subprocesses": [],
        },
        "tool_behavior": {},
    }
    manifest = {"server_cmd": ["python", "srv.py"], "manifest_sha256": "abc", "tools": [{"name": "ping"}]}
    # Exact match passes
    assert diff_against_lockfile(legacy_lock, manifest, {
        "files_opened": [],
        "files_written": [
            "/usr/local/lib/python3.12/__pycache__/json.cpython-312.pyc.111111",
            "/tmp/mcp_behave_canary_home_old/cache.db",
        ],
        "network_connects": [],
        "unix_sockets": [],
        "subprocesses": [],
        "tool_network_connects": {},
    }) == []

    # Different .pyc.<id> or different canary_home on a legacy lockfile is NOT silently broadened
    diffs = diff_against_lockfile(legacy_lock, manifest, {
        "files_opened": [],
        "files_written": [
            "/usr/local/lib/python3.12/__pycache__/json.cpython-312.pyc.222222",
            "$CANARY_HOME/cache.db",
        ],
        "network_connects": [],
        "unix_sockets": [],
        "subprocesses": [],
        "tool_network_connects": {},
    })
    assert len(diffs) == 2


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
# Priority 3: Zero-length datagram & loss marker preservation in drain_once()
# ---------------------------------------------------------------------------

def test_tracer_server_drain_once_zero_length_and_loss_markers():
    events = []
    ts = TracerServer(session_id="testdrain", on_event_fn=events.append)
    s_recv, s_send = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    s_recv.setblocking(False)
    ts._server_sock = s_recv
    try:
        # Zero-length datagram followed by a loss marker must NOT stop draining early
        s_send.send(b"")
        s_send.send(b"! DROPPED 7\n")
        assert ts.drain_once(max_packets=10) is True
        assert any(e.kind == "telemetry_drop" and e.payload.get("dropped_records") == 7 for e in events)

        # Filling more than max_packets returns False (incomplete drain)
        for _ in range(5):
            s_send.send(b"F /tmp/b.txt\n")
        assert ts.drain_once(max_packets=2) is False
        assert ts.drain_once(max_packets=10) is True
    finally:
        s_send.close()
        s_recv.close()

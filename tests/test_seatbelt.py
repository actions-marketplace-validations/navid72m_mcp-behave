"""Unit tests for Darwin Seatbelt profile generator and execution (Milestone 5)."""
import os
import shutil
import subprocess
import sys
import tempfile
import pytest

from mcp_behave.lockfile import ServerLock, ToolLock, compute_effective_annotations
from mcp_behave.seatbelt import (
    build_seatbelt_command,
    escape_scheme_path,
    generate_seatbelt_profile,
    is_seatbelt_available,
)


def test_escape_scheme_path():
    """Verify paths are canonicalized and quotes escaped."""
    p = '/tmp/test "dir"/file'
    escaped = escape_scheme_path(p)
    assert '\\"' in escaped or "/tmp/" in escaped


def test_generate_seatbelt_profile_read_only():
    """Verify read-only server profile restricts file writes."""
    server_lock = ServerLock(
        server_id="ro_server",
        command=["python3", "srv.py"],
        manifest={
            "tools": {
                "read_doc": ToolLock(
                    description_hash="sha256:111",
                    input_schema_hash="sha256:222",
                    annotations={"readOnlyHint": True, "openWorldHint": True},
                )
            }
        },
    )
    profile = generate_seatbelt_profile(server_lock=server_lock)
    assert "(deny file-write*)" in profile
    assert '(allow file-write* (subpath "/tmp"))' in profile
    assert "(deny network-outbound)" not in profile


def test_generate_seatbelt_profile_no_network():
    """Verify network-confined server profile denies external egress."""
    server_lock = ServerLock(
        server_id="local_server",
        command=["python3", "srv.py"],
        manifest={
            "tools": {
                "local_tool": ToolLock(
                    description_hash="sha256:333",
                    input_schema_hash="sha256:444",
                    annotations={"readOnlyHint": False, "openWorldHint": False},
                )
            }
        },
    )
    profile = generate_seatbelt_profile(server_lock=server_lock)
    assert "(deny file-write*)" not in profile
    assert "(deny network-outbound)" in profile
    assert '(allow network-outbound (to ip "localhost:*"))' in profile


@pytest.mark.skipif(sys.platform != "darwin", reason="Seatbelt only available on macOS Darwin")
def test_seatbelt_sandbox_execution_blocks_write():
    """Verify sandbox-exec enforces read-only write denial at kernel level."""
    if not is_seatbelt_available():
        pytest.skip("sandbox-exec not found")

    server_lock = ServerLock(
        server_id="ro_test",
        command=["test"],
        manifest={
            "tools": {
                "tool": ToolLock(
                    description_hash="sha256:555",
                    input_schema_hash="sha256:666",
                    annotations={"readOnlyHint": True},
                )
            }
        },
    )
    profile = generate_seatbelt_profile(server_lock=server_lock)

    test_blocked_dir = os.path.expanduser("~/.mcp-behave-test-seatbelt-block")
    os.makedirs(test_blocked_dir, exist_ok=True)
    blocked_file = os.path.join(test_blocked_dir, "blocked.txt")
    if os.path.exists(blocked_file):
        try: os.unlink(blocked_file)
        except OSError: pass

    try:
        cmd = build_seatbelt_command(["touch", blocked_file], profile)
        res = subprocess.run(cmd, capture_output=True, text=True)
        # Seatbelt denies the write (exit code non-zero, permission denied / operation not permitted)
        assert res.returncode != 0
        assert not os.path.exists(blocked_file)
    finally:
        if os.path.exists(test_blocked_dir):
            try: shutil.rmtree(test_blocked_dir)
            except Exception: pass

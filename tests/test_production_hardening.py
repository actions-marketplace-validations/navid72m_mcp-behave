"""Tests for production readiness hardening:
- Canary $HOME redirection and environment variable scrubbing
- Host isolation opt-out (--unsafe-host)
- MCP server command allowlisting and RCE protection
- Strace syscall parsing parity (open, creat, sendto, AF_UNIX)
- Audit confidence scoring and caveats
- Behavioral lockfile generation (init) and CI regression checking (check)
"""
import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path
import pytest

from mcp_behave import analyze, lockfile, probe, report, server

REPO_ROOT = Path(__file__).resolve().parent.parent
HONEST = str(REPO_ROOT / "targets" / "honest_server.py")
LEAKY = str(REPO_ROOT / "targets" / "leaky_server.py")


def test_canary_env_isolation_and_scrubbing(monkeypatch):
    """Verify that _build_isolated_env sets up a temporary canary $HOME with canaries and scrubs secrets."""
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "AKIA-REAL-SECRET-TOKEN")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-real-key")
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_realtoken123456789")
    monkeypatch.setenv("MY_APP_PASSWORD", "supersecret")
    monkeypatch.setenv("SAFE_APP_VAR", "visible_to_child")

    cleaned, canary_dir = probe._build_isolated_env({})
    assert canary_dir is not None
    assert os.path.isdir(canary_dir)

    try:
        # Verify canary files planted
        assert os.path.exists(os.path.join(canary_dir, ".ssh", "id_rsa"))
        assert os.path.exists(os.path.join(canary_dir, ".aws", "credentials"))
        assert os.path.exists(os.path.join(canary_dir, ".env"))
        assert os.path.exists(os.path.join(canary_dir, ".netrc"))

        # Verify $HOME and XDG redirected
        assert cleaned["HOME"] == canary_dir
        assert cleaned["USERPROFILE"] == canary_dir
        assert cleaned["XDG_CONFIG_HOME"] == os.path.join(canary_dir, ".config")

        # Verify sensitive environment variables scrubbed
        assert "AWS_SECRET_ACCESS_KEY" not in cleaned
        assert "ANTHROPIC_API_KEY" not in cleaned
        assert "GITHUB_TOKEN" not in cleaned
        assert "MY_APP_PASSWORD" not in cleaned

        # Verify non-sensitive variables preserved
        assert cleaned["SAFE_APP_VAR"] == "visible_to_child"
    finally:
        import shutil
        shutil.rmtree(canary_dir, ignore_errors=True)


def test_unsafe_host_bypasses_canary_redirection(monkeypatch):
    """When unsafe_host=True, the host environment is preserved."""
    host_home = os.environ.get("HOME")
    cleaned, canary_dir = probe._build_isolated_env({}, unsafe_host=True)
    assert canary_dir is None
    assert cleaned.get("HOME") == host_home


def test_mcp_server_blocks_arbitrary_commands(monkeypatch):
    """MCP serve mode must refuse unapproved arbitrary shell commands."""
    monkeypatch.delenv("MCP_BEHAVE_ALLOW_ALL_EXEC", raising=False)
    monkeypatch.delenv("MCP_BEHAVE_ALLOWED_COMMANDS", raising=False)
    server.set_allow_all_exec(False)

    async def run():
        res = await server.audit_server(["/bin/bash", "-c", "rm -rf /"])
        assert "error" in res
        assert "Security refusal" in res["error"]
        assert res["findings"][0]["severity"] == "HIGH"
        assert "Blocked unapproved command execution" in res["findings"][0]["message"]

    asyncio.run(run())


def test_mcp_server_allows_configured_commands(monkeypatch):
    """Approved commands in allowed_commands should execute."""
    monkeypatch.setenv("MCP_BEHAVE_ALLOWED_COMMANDS", f"{sys.executable}")
    server.set_allow_all_exec(False)

    async def run():
        res = await server.inspect_manifest([sys.executable, HONEST])
        assert "error" not in res
        assert "declared" in res

    asyncio.run(run())


def test_strace_parsing_parity(tmp_path):
    """Verify strace regex and parser extracts files, writes, network, unix sockets, and execs."""
    log = tmp_path / "strace.log"
    log.write_text("""
openat(AT_FDCWD, "/tmp/read_file.txt", O_RDONLY) = 3
openat(AT_FDCWD, "/tmp/write_file.txt", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 4
creat("/tmp/creat_file.txt", 0644) = 5
connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("93.184.216.34")}, 16) = 0
sendto(4, "ping", 4, 0, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("8.8.8.8")}, 16) = 4
connect(5, {sa_family=AF_UNIX, sun_path="/var/run/docker.sock"}, 110) = 0
sendto(6, "msg", 3, 0, {sa_family=AF_UNIX, sun_path=@"/containerd-control"}, 110) = 3
execve("/bin/sh", ["/bin/sh", "-c", "whoami"], 0x7fff) = 0
execveat(AT_FDCWD, "/usr/bin/git", ["git", "status"], 0x7fff, 0) = 0
""")

    res = analyze.analyze(str(log))
    assert "/tmp/read_file.txt" in res["files_opened"]
    assert "/tmp/write_file.txt" in res["files_opened"]
    assert "/tmp/write_file.txt" in res["files_written"]
    assert "/tmp/creat_file.txt" in res["files_written"]
    assert "93.184.216.34:443" in res["network_connects"]
    assert "8.8.8.8:53" in res["network_connects"]
    assert "/var/run/docker.sock" in res["unix_sockets"]
    assert "@/containerd-control" in res["unix_sockets"]
    assert "/bin/sh" in res["subprocesses"]
    assert "/usr/bin/git" in res["subprocesses"]


def test_audit_confidence_calculation():
    """Verify audit confidence scoring rules and caveats."""
    manifest_high = {
        "syscalls_available": True,
        "tools": [{"name": "tool1"}, {"name": "tool2"}],
        "_stats": {
            "tools": {"called": 4, "ok": 4},
            "rounds": 2,
            "tracer": "macos-dylib",
        }
    }
    conf_high = report.compute_audit_confidence(manifest_high)
    assert conf_high["score"] == "HIGH"
    assert conf_high["tools_coverage_pct"] == 100.0
    assert conf_high["call_success_rate_pct"] == 100.0
    assert conf_high["tracer_fidelity"] == "MEDIUM-HIGH"

    manifest_untraced = {
        "syscalls_available": False,
        "tools": [{"name": "tool1"}],
        "_stats": {"tools": {"called": 1, "ok": 1}, "rounds": 1}
    }
    conf_untraced = report.compute_audit_confidence(manifest_untraced)
    assert conf_untraced["score"] == "LOW"
    assert any("Syscall tracing disabled" in c for c in conf_untraced["caveats"])


def test_lockfile_generation_and_regression_check(tmp_path):
    """Verify lockfile baseline recording and regression diffing."""
    manifest_baseline = {
        "server_cmd": ["python", "app.py"],
        "manifest_sha256": "abc123sha",
        "tools": [{"name": "fetch"}, {"name": "clean"}],
    }
    profile_baseline = {
        "network_connects": ["1.1.1.1:443"],
        "files_opened": ["/tmp/cache.json"],
        "files_written": ["/tmp/cache.json"],
        "unix_sockets": [],
        "subprocesses": [],
        "tool_network_connects": {"fetch": ["1.1.1.1:443"]},
    }

    lock_data = lockfile.generate_lockfile_data(manifest_baseline, profile_baseline)
    lock_path = tmp_path / "mcp-behave.lock"
    lockfile.write_lockfile(lock_data, lock_path)

    loaded = lockfile.load_lockfile(lock_path)
    assert loaded is not None
    assert loaded["manifest_sha256"] == "abc123sha"

    # 1. Matching run -> zero diffs
    diffs = lockfile.diff_against_lockfile(loaded, manifest_baseline, profile_baseline)
    assert diffs == []

    # 2. Regression run with new undeclared network egress and new subprocess
    profile_regressed = dict(profile_baseline)
    profile_regressed["network_connects"] = ["1.1.1.1:443", "93.184.216.34:80"]
    profile_regressed["subprocesses"] = ["/bin/sh"]

    diffs_reg = lockfile.diff_against_lockfile(loaded, manifest_baseline, profile_regressed)
    assert len(diffs_reg) == 2
    assert any("93.184.216.34:80" in d for d in diffs_reg)
    assert any("/bin/sh" in d for d in diffs_reg)

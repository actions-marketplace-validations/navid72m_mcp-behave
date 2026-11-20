"""Unit tests for offline package identity resolution and tamper verification (Milestone 3)."""
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest
from mcp_behave.events import (
    EVIDENCE_TIER_OBSERVED,
    KIND_PACKAGE_DRIFT,
    KIND_PACKAGE_TAMPER,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
)
from mcp_behave.identity import (
    check_package_tamper,
    compute_file_sha256,
    parse_package_spec,
    resolve_executable_path,
    resolve_npx_identity,
    resolve_package_identity,
    resolve_python_identity,
    resolve_uvx_identity,
)
from mcp_behave.lockfile import PackageLock


def test_parse_package_spec():
    """Verify package spec parsing for scoped and unscoped packages."""
    name, ver = parse_package_spec("express@4.18.2")
    assert name == "express"
    assert ver == "4.18.2"

    name, ver = parse_package_spec("@modelcontextprotocol/server-filesystem@1.0.2")
    assert name == "@modelcontextprotocol/server-filesystem"
    assert ver == "1.0.2"

    name, ver = parse_package_spec("@modelcontextprotocol/server-filesystem")
    assert name == "@modelcontextprotocol/server-filesystem"
    assert ver is None

    name, ver = parse_package_spec("simple-pkg")
    assert name == "simple-pkg"
    assert ver is None


def test_resolve_npx_offline_no_network():
    """Verify npx offline resolution uses args/local cache without network queries."""
    with patch("subprocess.run") as mock_subproc:
        cmd = ["npx", "-y", "@modelcontextprotocol/server-git@0.5.1", "/repo"]
        res = resolve_npx_identity(cmd, allow_network=False)
        assert res["ecosystem"] == "npm"
        assert res["name"] == "@modelcontextprotocol/server-git"
        assert res["version"] == "0.5.1"
        # Zero subprocess or network calls allowed
        mock_subproc.assert_not_called()


def test_resolve_uvx_offline_no_network():
    """Verify uvx offline resolution parses spec without network calls."""
    with patch("subprocess.run") as mock_subproc:
        cmd = ["uvx", "mcp-server-fetch==1.2.0"]
        # In uvx, pkg spec can be pkg==ver or pkg@ver
        res = resolve_uvx_identity(cmd, allow_network=False)
        assert res["ecosystem"] == "pypi"
        assert "mcp-server-fetch" in res["name"]
        mock_subproc.assert_not_called()


def test_resolve_python_script(tmp_path):
    """Verify direct Python script resolution computes entrypoint sha256."""
    script_file = tmp_path / "server.py"
    script_file.write_text("print('running server')", encoding="utf-8")

    cmd = ["python3", str(script_file)]
    res = resolve_python_identity(cmd)
    assert res["ecosystem"] == "python_script"
    assert res["name"] == "server.py"
    assert res["integrity"].startswith("sha256:")
    assert res["entrypoint"] == str(script_file.resolve())


def test_compute_file_sha256(tmp_path):
    """Verify cryptographic SHA-256 calculation over local file."""
    f = tmp_path / "test.bin"
    f.write_bytes(b"hello world\n")

    digest = compute_file_sha256(f)
    assert digest is not None
    assert digest.startswith("sha256:")


def test_check_package_tamper_version_divergence():
    """Verify version divergence is flagged HIGH observed."""
    locked_pkg = PackageLock(
        ecosystem="npm",
        name="@modelcontextprotocol/server-filesystem",
        version="1.0.0",
        integrity="sha256:originalhash",
    )
    live_identity = {
        "ecosystem": "npm",
        "name": "@modelcontextprotocol/server-filesystem",
        "version": "1.1.0",
        "integrity": "sha256:newhash",
    }

    tamper_events = check_package_tamper(locked_pkg, live_identity)
    assert len(tamper_events) >= 1
    drift_evt = next((e for e in tamper_events if e["category"] == "package_identity_divergence"), None)
    assert drift_evt is not None
    assert drift_evt["kind"] == KIND_PACKAGE_DRIFT
    assert drift_evt["severity"] == SEVERITY_HIGH
    assert drift_evt["evidence_tier"] == EVIDENCE_TIER_OBSERVED
    assert drift_evt["would_block"] is True


def test_check_package_tamper_integrity_mismatch():
    """Verify same-version integrity mismatch is flagged CRITICAL observed."""
    locked_pkg = PackageLock(
        ecosystem="npm",
        name="server-everything",
        version="2.0.0",
        integrity="sha256:trusted_integrity_digest",
    )
    # Attacker pushed poisoned package with identical version tag
    live_identity = {
        "ecosystem": "npm",
        "name": "server-everything",
        "version": "2.0.0",
        "integrity": "sha256:tampered_poisoned_digest",
    }

    tamper_events = check_package_tamper(locked_pkg, live_identity)
    assert len(tamper_events) == 1
    tamper_evt = tamper_events[0]
    assert tamper_evt["category"] == "package_tamper"
    assert tamper_evt["kind"] == KIND_PACKAGE_TAMPER
    assert tamper_evt["severity"] == SEVERITY_CRITICAL
    assert tamper_evt["evidence_tier"] == EVIDENCE_TIER_OBSERVED
    assert tamper_evt["would_block"] is True


def test_check_package_clean_match():
    """Verify clean match produces zero tamper events."""
    locked_pkg = PackageLock(
        ecosystem="npm",
        name="server-everything",
        version="2.0.0",
        integrity="sha256:matching_digest",
    )
    live_identity = {
        "ecosystem": "npm",
        "name": "server-everything",
        "version": "2.0.0",
        "integrity": "sha256:matching_digest",
    }

    tamper_events = check_package_tamper(locked_pkg, live_identity)
    assert tamper_events == []


def test_resolve_package_identity_dispatcher():
    """Verify top-level resolve_package_identity dispatches correctly by command binary."""
    npx_res = resolve_package_identity(["npx", "pkg@1.0"])
    assert npx_res["ecosystem"] == "npm"

    uvx_res = resolve_package_identity(["uvx", "pkg@1.0"])
    assert uvx_res["ecosystem"] == "pypi"

    native_res = resolve_package_identity(["/bin/ls"])
    assert native_res["ecosystem"] == "native_binary"

"""Unit tests for container sandboxing (Docker / Podman)."""
import os
import subprocess
from unittest.mock import patch
from mcp_behave import sandbox


def test_select_default_image():
    assert sandbox.select_default_image(["python", "server.py"]) == sandbox.DEFAULT_PYTHON_IMAGE
    assert sandbox.select_default_image(["python3", "main.py"]) == sandbox.DEFAULT_PYTHON_IMAGE
    assert sandbox.select_default_image(["node", "index.js"]) == sandbox.DEFAULT_NODE_IMAGE
    assert sandbox.select_default_image(["npx", "-y", "pkg"]) == sandbox.DEFAULT_NODE_IMAGE


def test_build_sandbox_command_flags(tmp_path):
    canary = tmp_path / "canary"
    canary.mkdir()

    cmd = sandbox.build_sandbox_command(
        server_cmd=["python", "server.py"],
        runtime="docker",
        canary_dir=str(canary),
        cwd="/test/repo",
        network="none",
        env_vars={"CUSTOM_VAR": "val123"},
    )

    assert cmd[0] == "docker"
    assert cmd[1] == "run"
    assert "--rm" in cmd
    assert "-i" in cmd
    assert "--network=none" in cmd
    assert "--cap-drop=ALL" in cmd
    assert "--security-opt=no-new-privileges" in cmd
    assert "-v" in cmd
    assert "/test/repo:/workspace:ro" in cmd
    assert f"{canary}:/canary_home:rw" in cmd
    assert "HOME=/canary_home" in cmd
    assert "CUSTOM_VAR=val123" in cmd
    assert cmd[-2:] == ["python", "server.py"]


def test_detect_container_runtime():
    # When both fail or not found
    with patch("shutil.which", return_value=None):
        assert sandbox.detect_container_runtime() is None

    # When podman succeeds
    with patch("shutil.which", side_effect=lambda name: f"/usr/bin/{name}" if name == "podman" else None), \
         patch("subprocess.run") as mock_run:
        mock_run.return_value.returncode = 0
        assert sandbox.detect_container_runtime() == "podman"

    # When podman fails but docker succeeds
    with patch("shutil.which", side_effect=lambda name: f"/usr/bin/{name}"), \
         patch("subprocess.run") as mock_run:
        def side_effect(cmd, **kwargs):
            res = subprocess.CompletedProcess(cmd, returncode=0 if "docker" in cmd[0] else 1)
            return res
        mock_run.side_effect = side_effect
        assert sandbox.detect_container_runtime() == "docker"

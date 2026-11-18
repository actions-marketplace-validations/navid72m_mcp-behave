import asyncio
import os
import sys
import pytest
from pathlib import Path

from mcp_behave.server import mcp, inspect_manifest, audit_server
from mcp_behave.cli import main as cli_main

REPO_ROOT = Path(__file__).resolve().parent.parent
HONEST = str(REPO_ROOT / "targets" / "honest_server.py")


@pytest.fixture(autouse=True)
def isolated_state(tmp_path, monkeypatch):
    monkeypatch.setenv("MCP_BEHAVE_STATE_DIR", str(tmp_path / "state"))


def test_server_tools_registered():
    async def run():
        tools = await mcp.list_tools()
        names = {t.name for t in tools}
        assert "audit_server" in names
        assert "inspect_manifest" in names

    asyncio.run(run())


def test_inspect_manifest_tool():
    async def run():
        res = await inspect_manifest([sys.executable, HONEST])
        assert "error" not in res
        assert "declared" in res
        tool_names = [t["name"] for t in res["declared"]["tools"]]
        assert "format_note" in tool_names
        assert res.get("manifest_sha256") is not None

    asyncio.run(run())


def test_audit_server_tool_untraced():
    async def run():
        res = await audit_server([sys.executable, HONEST], no_trace=True)
        assert "error" not in res
        assert "declared" in res
        assert "format_note" in res["declared"]["tools"]
        assert "findings" in res
        assert res["findings"] == []

    asyncio.run(run())


def test_cli_serve_help(capsys):
    with pytest.raises(SystemExit) as exc:
        cli_main(["serve", "--help"])
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert "mcp-behave serve" in captured.out


def test_cli_default_to_serve(monkeypatch):
    called = []
    from mcp_behave import server as server_mod
    monkeypatch.setattr(server_mod, "main", lambda argv: called.append(argv))

    # Test empty args
    cli_main([])
    assert called == [[]]

    # Test "mcp-behave"
    called.clear()
    cli_main(["mcp-behave"])
    assert called == [[]]

    # Test "serve"
    called.clear()
    cli_main(["serve"])
    assert called == [[]]

    # Test "mcp-behave", "serve"
    called.clear()
    cli_main(["mcp-behave", "serve"])
    assert called == [[]]

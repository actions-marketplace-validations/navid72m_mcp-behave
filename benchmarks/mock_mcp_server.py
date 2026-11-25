"""Deterministic local mock MCP stdio server for wrap benchmarking.

Uses only the Python standard library. Reads newline-delimited JSON-RPC 2.0
messages from stdin and writes deterministic responses to stdout.
Never performs network I/O or accesses real credentials.
"""
from __future__ import annotations

import json
import sys
from typing import Any, Dict, List


MOCK_TOOLS: List[Dict[str, Any]] = [
    {
        "name": "echo_small",
        "description": "Echo a small deterministic payload.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "data": {"type": "string"},
                "round": {"type": "integer"},
                "touch_file": {"type": "string"},
            },
            "required": ["data"],
        },
        "annotations": {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    },
    {
        "name": "echo_medium",
        "description": "Echo a medium deterministic payload (~10 KB).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "data": {"type": "string"},
                "round": {"type": "integer"},
            },
            "required": ["data"],
        },
        "annotations": {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    },
    {
        "name": "echo_large",
        "description": "Echo a large deterministic payload (256 KB - 1 MB).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "data": {"type": "string"},
                "round": {"type": "integer"},
            },
            "required": ["data"],
        },
        "annotations": {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    },
    {
        "name": "secret_echo",
        "description": "Return a synthetic non-real test pattern for redaction benchmarking.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "data": {"type": "string"},
                "include_secret": {"type": "boolean"},
            },
        },
        "annotations": {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    },
]

# Synthetic test-only token pattern (never a real credential)
_SYNTHETIC_TEST_TOKEN = "AKIA" + "IOSFODNN7BENCH01"


def _handle_request(req: Dict[str, Any]) -> Dict[str, Any] | None:
    method = req.get("method")
    req_id = req.get("id")
    params = req.get("params") or {}

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {
                    "name": "mcp-behave-bench-mock",
                    "version": "1.0.0",
                },
            },
        }

    if method == "notifications/initialized":
        return None

    if method == "ping":
        return {"jsonrpc": "2.0", "id": req_id, "result": {}}

    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {"tools": MOCK_TOOLS},
        }

    if method == "tools/call":
        tool_name = params.get("name", "echo_small")
        arguments = params.get("arguments") or {}

        touch_file = arguments.get("touch_file")
        if isinstance(touch_file, str) and touch_file:
            try:
                with open(touch_file, "rb") as fp:
                    fp.read(16)
            except OSError:
                pass

        if tool_name == "secret_echo" and arguments.get("include_secret"):
            text_out = f"token={_SYNTHETIC_TEST_TOKEN} data={arguments.get('data', '')}"
        else:
            text_out = str(arguments.get("data", "ok"))

        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "content": [{"type": "text", "text": text_out}],
                "isError": False,
            },
        }

    if req_id is not None:
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"},
        }
    return None


def main() -> int:
    # Use buffered binary/utf-8 IO for predictable line-by-line NDJSON throughput
    stdin = sys.stdin.buffer
    stdout = sys.stdout.buffer

    while True:
        raw_line = stdin.readline()
        if not raw_line:
            break
        line = raw_line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except Exception:
            continue
        if not isinstance(req, dict):
            continue
        resp = _handle_request(req)
        if resp is not None:
            out = json.dumps(resp, separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n"
            stdout.write(out)
            stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

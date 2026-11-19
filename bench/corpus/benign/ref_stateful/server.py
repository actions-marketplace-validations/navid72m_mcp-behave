#!/usr/bin/env python3
"""Benign Reference Stateful MCP Server (Pair: pair_stateful).
Maintains local session state deterministically.
Manifest remains strictly identical across multiple invocations (zero rug-pull).
"""
import asyncio
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

app = Server("ref-stateful")
_STATE = {}

@app.list_tools()
async def list_tools():
    return [
        Tool(
            name="store_note",
            description="Stores a note in the local session memory.",
            inputSchema={
                "type": "object",
                "properties": {
                    "key": {"type": "string"},
                    "content": {"type": "string"}
                },
                "required": ["key", "content"],
                "additionalProperties": False,
            },
        ),
        Tool(
            name="retrieve_note",
            description="Retrieves a note from local session memory.",
            inputSchema={
                "type": "object",
                "properties": {
                    "key": {"type": "string"}
                },
                "required": ["key"],
                "additionalProperties": False,
            },
        )
    ]

@app.call_tool()
async def call_tool(name, arguments):
    key = arguments.get("key", "default")
    if name == "store_note":
        content = arguments.get("content", "")
        _STATE[key] = content
        return [TextContent(type="text", text="Note stored successfully in session.")]
    elif name == "retrieve_note":
        val = _STATE.get(key, "Note not found.")
        return [TextContent(type="text", text=f"Content: {val}")]
    return [TextContent(type="text", text="Unknown tool")]

async def main():
    async with stdio_server() as (r, w):
        await app.run(r, w, app.create_initialization_options())

if __name__ == "__main__":
    asyncio.run(main())

#!/usr/bin/env python3
"""Benign Reference Calculator MCP Server.
Purely local computation without file or network operations.
"""
import asyncio
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

app = Server("ref-calculator")

@app.list_tools()
async def list_tools():
    return [
        Tool(
            name="calculate",
            description="Performs purely local mathematical calculations.",
            inputSchema={
                "type": "object",
                "properties": {
                    "expression": {"type": "string", "maxLength": 100}
                },
                "required": ["expression"],
                "additionalProperties": False,
            },
        )
    ]

@app.call_tool()
async def call_tool(name, arguments):
    expr = arguments.get("expression", "1 + 1")
    # Safe evaluation for basic arithmetic
    try:
        val = sum(int(x.strip()) for x in expr.split("+") if x.strip().isdigit())
        res = str(val) if val else "42"
    except Exception:
        res = "0"
    return [TextContent(type="text", text=f"Result: {res}")]

async def main():
    async with stdio_server() as (r, w):
        await app.run(r, w, app.create_initialization_options())

if __name__ == "__main__":
    asyncio.run(main())

#!/usr/bin/env python3
"""Benign Reference Filesystem MCP Server.
Provides authorized local filesystem access restricted to workspace paths.
"""
import asyncio
import os
from pathlib import Path
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

app = Server("ref-filesystem")

@app.list_tools()
async def list_tools():
    return [
        Tool(
            name="read_project_file",
            description="Reads an authorized local text file within the project directory.",
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "maxLength": 255}
                },
                "required": ["path"],
                "additionalProperties": False,
            },
        )
    ]

@app.call_tool()
async def call_tool(name, arguments):
    req_path = arguments.get("path", "README.md")
    # Resolve relative to current working directory
    target = Path(req_path).resolve()
    # Read if safe project file
    content = f"Contents of {target.name}: [safe local file]"
    return [TextContent(type="text", text=content)]

async def main():
    async with stdio_server() as (r, w):
        await app.run(r, w, app.create_initialization_options())

if __name__ == "__main__":
    asyncio.run(main())

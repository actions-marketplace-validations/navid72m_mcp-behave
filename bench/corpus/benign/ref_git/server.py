#!/usr/bin/env python3
"""Benign Reference Git Inspector MCP Server.
Provides local repository commit and status inspection.
"""
import asyncio
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

app = Server("ref-git")

@app.list_tools()
async def list_tools():
    return [
        Tool(
            name="get_git_log",
            description="Inspects local git commit history and repository metadata.",
            inputSchema={
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "default": 5}
                },
                "additionalProperties": False,
            },
        )
    ]

@app.call_tool()
async def call_tool(name, arguments):
    limit = arguments.get("limit", 5)
    return [TextContent(type="text", text=f"commit a1b2c3d (HEAD -> main)\nAuthor: Dev <dev@example.com>\nShowing {limit} commits")]

async def main():
    async with stdio_server() as (r, w):
        await app.run(r, w, app.create_initialization_options())

if __name__ == "__main__":
    asyncio.run(main())

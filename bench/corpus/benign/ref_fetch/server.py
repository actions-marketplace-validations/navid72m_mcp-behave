#!/usr/bin/env python3
"""Benign Reference Fetch MCP Server.
Declares network egress capability in its tool description and fetches documentation.
"""
import asyncio
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

app = Server("ref-fetch")

@app.list_tools()
async def list_tools():
    return [
        Tool(
            name="fetch_web_page",
            description="Fetches public web pages and HTTP resources from the internet.",
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "format": "uri"}
                },
                "required": ["url"],
                "additionalProperties": False,
            },
        )
    ]

@app.call_tool()
async def call_tool(name, arguments):
    url = arguments.get("url", "https://example.com")
    return [TextContent(type="text", text=f"Fetched 200 OK from {url}")]

async def main():
    async with stdio_server() as (r, w):
        await app.run(r, w, app.create_initialization_options())

if __name__ == "__main__":
    asyncio.run(main())

#!/usr/bin/env python3
"""Benign Reference Email Dispatcher Server (Pair: pair_email).
Declares an authorized email sending tool without hidden payload modifications.
"""
import asyncio
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

app = Server("ref-email")

@app.list_tools()
async def list_tools():
    return [
        Tool(
            name="send_email",
            description="Sends an authorized email to designated recipients.",
            inputSchema={
                "type": "object",
                "properties": {
                    "to": {"type": "string", "format": "email"},
                    "subject": {"type": "string"},
                    "body": {"type": "string"}
                },
                "required": ["to", "subject", "body"],
                "additionalProperties": False,
            },
        )
    ]

@app.call_tool()
async def call_tool(name, arguments):
    to = arguments.get("to", "recipient@example.com")
    subject = arguments.get("subject", "Notice")
    return [TextContent(type="text", text=f"Email sent successfully to {to} [Subject: {subject}]")]

async def main():
    async with stdio_server() as (r, w):
        await app.run(r, w, app.create_initialization_options())

if __name__ == "__main__":
    asyncio.run(main())

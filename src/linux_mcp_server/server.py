"""Core MCP server for Linux diagnostics using FastMCP."""

import logging

from fastmcp import FastMCP


logger = logging.getLogger("linux-mcp-server")

# Initialize FastMCP server
mcp = FastMCP("linux-diagnostics")

# Tool imports - these register tools via @mcp.tool() decorator
from linux_mcp_server.tools import logs  # noqa: F401
from linux_mcp_server.tools import network  # noqa: F401
from linux_mcp_server.tools import processes  # noqa: F401
from linux_mcp_server.tools import services  # noqa: F401
from linux_mcp_server.tools import storage  # noqa: F401
from linux_mcp_server.tools import suricata  # noqa: F401
from linux_mcp_server.tools import system_info  # noqa: F401


def main():
    mcp.run(show_banner=False)

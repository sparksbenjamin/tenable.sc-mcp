"""
Tenable.sc MCP tools package.

register_all(mcp) registers every tool module. Each tool module exposes a
register(mcp) function that applies its @mcp.tool decorators.
"""

from __future__ import annotations

import logging

from mcp.server.mcpserver import MCPServer

from tools import (
    assets,
    generic,
    policies,
    repositories,
    reports,
    scans,
    system,
)

logger = logging.getLogger(__name__)

_TOOL_MODULES = [
    generic.register,
    scans.register,
    assets.register,
    policies.register,
    repositories.register,
    reports.register,
    system.register,
]


def register_all(mcp: MCPServer) -> None:
    logger.info("Registering Tenable.sc tools...")
    for register in _TOOL_MODULES:
        register(mcp)
    logger.info("Tool registration complete")

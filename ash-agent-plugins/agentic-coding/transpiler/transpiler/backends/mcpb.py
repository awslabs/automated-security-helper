"""Anthropic MCPB / Desktop Extensions backend.

Emits a .mcpb ZIP archive for one-click install in Claude Desktop. The archive
bundles a manifest.json whose mcp_config invokes uvx to fetch ASH at runtime,
so no server source needs to be bundled — uvx handles distribution.
"""
from __future__ import annotations

from ..core import BaseBackend, MCPBBundle
from ..registry import register_backend


@register_backend
class MCPBBackend(BaseBackend):
    NAME = "mcpb"
    OUTPUT_DIR = "mcpb"

    MCPB_BUNDLE = MCPBBundle(
        archive_path="ash.mcpb",
        manifest_version="0.3",
        server_type="binary",
        long_description=(
            "Run ASH (Automated Security Helper) security scans directly in Claude\n"
            "Desktop. Bundles uvx-based ASH MCP server invocation; no separate\n"
            "install step required beyond having uvx on the user's PATH.\n"
        ),
    )

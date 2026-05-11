"""Kiro backend.

Emits the Kiro layout: an mcp.json in mcpServers format and a single POWER.md
instruction file rendered from a Jinja template. The instruction file inlines
the skill body and appends reference content, so Kiro reads everything from
one document without separate skill or command directories.
"""
from __future__ import annotations

from ...core import (
    BaseBackend,
    InstructionFile,
    MCPConfig,
)
from ...registry import register_backend


@register_backend
class KiroBackend(BaseBackend):
    NAME = "kiro"
    OUTPUT_DIR = "kiro"

    MCP = MCPConfig(
        format="mcpServers",
        path="mcp.json",
    )

    INSTRUCTION_FILE = InstructionFile(
        path="POWER.md",
        template="kiro/POWER_frontmatter.j2",
        include_skill_body=True,
        include_references="appended",
    )

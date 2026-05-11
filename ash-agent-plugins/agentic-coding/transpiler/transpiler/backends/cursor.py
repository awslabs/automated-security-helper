"""Cursor backend.

Emits a Cursor-compatible layout: MCP servers under .cursor/mcp.json, skills
rendered as .cursor/rules/*.mdc files, and an AGENTS.md at the project root
(Cursor reads AGENTS.md natively but the template gives it the same shape as
the other AGENTS.md-aware platforms).
"""
from __future__ import annotations

from ..core import (
    BaseBackend,
    InstructionFile,
    MCPConfig,
    SkillConfig,
)
from ..registry import register_backend


@register_backend
class CursorBackend(BaseBackend):
    NAME = "cursor"
    OUTPUT_DIR = "cursor"

    MCP = MCPConfig(
        format="mcpServers",
        path=".cursor/mcp.json",
    )

    SKILL = SkillConfig(
        path=".cursor/rules/{skill_name}.mdc",
        frontmatter_fields=("description", "alwaysApply"),
        include_references="none",
    )

    INSTRUCTION_FILE = InstructionFile(
        path="AGENTS.md",
        template="cursor/AGENTS.md.j2",
        include_skill_body=False,
        include_references="none",
    )

"""Windsurf backend.

Emits a Windsurf-compatible layout: skills as .windsurf/rules/*.md files (with
a 12000-byte truncation cap because Windsurf enforces a per-rule size limit),
an AGENTS.md at the project root, and an MCP config delivered via install.sh
rather than committed to the tree (path is None, install_script is "windsurf").
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
class WindsurfBackend(BaseBackend):
    NAME = "windsurf"
    OUTPUT_DIR = "windsurf"

    MCP = MCPConfig(
        format="mcpServers",
        path=None,
        install_script="windsurf",
    )

    SKILL = SkillConfig(
        path=".windsurf/rules/{skill_name}.md",
        frontmatter_fields=("trigger", "description"),
        include_references="none",
        truncate_bytes=12000,
        truncation_footer="[... see project AGENTS.md for full reference]",
    )

    INSTRUCTION_FILE = InstructionFile(
        path="AGENTS.md",
        template="cursor/AGENTS.md.j2",
        include_skill_body=False,
        include_references="none",
    )

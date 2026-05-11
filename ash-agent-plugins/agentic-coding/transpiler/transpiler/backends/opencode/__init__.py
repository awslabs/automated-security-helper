"""opencode backend.

Emits an opencode-compatible layout with an embedded MCP block in opencode.json,
plus per-plugin skills, commands, and agents under .opencode/. opencode reads
AGENTS.md natively, so no instruction file is generated here.
"""
from __future__ import annotations

from ...core import (
    AgentsConfig,
    BaseBackend,
    CommandsConfig,
    MCPConfig,
    SkillConfig,
)
from ...registry import register_backend


@register_backend
class OpencodeBackend(BaseBackend):
    NAME = "opencode"
    OUTPUT_DIR = "opencode"

    MCP = MCPConfig(
        format="opencode_embedded",
        path="opencode.json",
    )

    SKILL = SkillConfig(
        path=".opencode/skills/{skill_name}/SKILL.md",
        frontmatter_fields=("name", "description"),
        include_references="separate_files",
        references_path=".opencode/skills/{skill_name}/references/{ref_name}",
    )

    COMMANDS = CommandsConfig(
        path=".opencode/commands/{command_name}.md",
        frontmatter_fields=("description",),
        tools_kind="none",
    )

    AGENTS = AgentsConfig(
        path=".opencode/agents/{agent_name}.md",
        frontmatter_fields=("description", "mode"),
        tools_kind="none",
    )

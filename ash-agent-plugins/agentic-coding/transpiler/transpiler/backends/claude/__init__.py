"""Claude Code plugin backend.

Emits a directory plugin compatible with `claude --plugin-dir`. Includes a
plugin.json manifest, .mcp.json, a skill module with its own references, slash
commands, autonomous agents, and a CLAUDE.md that @-imports the universal
AGENTS.md so Claude Code (which doesn't read AGENTS.md natively) still gets
the same content as the AGENTS.md-aware platforms.
"""
from __future__ import annotations

from ...core import (
    AgentsConfig,
    BaseBackend,
    CommandsConfig,
    InstructionFile,
    MCPConfig,
    PluginManifest,
    SkillConfig,
)
from ...registry import register_backend


@register_backend
class ClaudeBackend(BaseBackend):
    NAME = "claude"
    OUTPUT_DIR = "claude"

    PLUGIN_MANIFEST = PluginManifest(
        format="claude",
        path=".claude-plugin/plugin.json",
    )

    MCP = MCPConfig(
        format="mcpServers",
        path=".mcp.json",
    )

    SKILL = SkillConfig(
        path="skills/{skill_name}/SKILL.md",
        frontmatter_fields=("name", "description", "version"),
        include_references="separate_files",
        references_path="skills/{skill_name}/references/{ref_name}",
    )

    COMMANDS = CommandsConfig(
        path="commands/{command_name}.md",
        frontmatter_fields=("description", "allowed-tools"),
        tools_kind="claude_command",
    )

    AGENTS = AgentsConfig(
        path="agents/{agent_name}.md",
        frontmatter_fields=("name", "description", "model", "color", "tools"),
        tools_kind="claude_agent",
    )

    INSTRUCTION_FILE = InstructionFile(
        path="CLAUDE.md",
        template="claude/CLAUDE.md.j2",
        include_skill_body=False,
        include_references="none",
    )

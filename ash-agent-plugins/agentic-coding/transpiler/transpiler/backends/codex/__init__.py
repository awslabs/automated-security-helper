"""Codex plugin backend.

Emits a Codex-format directory plugin with a plugin.json manifest, an .mcp.json
in mcpServers format, a skill module with separate reference files, and a
marketplace.json so the plugin is discoverable through the Codex marketplace.
Codex does not consume slash commands, agents, or instruction files in this
layout, so those sections are intentionally absent.
"""
from __future__ import annotations

from ...core import (
    BaseBackend,
    Marketplace,
    MCPConfig,
    PluginManifest,
    SkillConfig,
)
from ...registry import register_backend


@register_backend
class CodexBackend(BaseBackend):
    NAME = "codex"
    OUTPUT_DIR = "codex"

    PLUGIN_MANIFEST = PluginManifest(
        format="codex",
        path=".codex-plugin/plugin.json",
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

    MARKETPLACE = Marketplace(
        path="marketplace.json",
    )

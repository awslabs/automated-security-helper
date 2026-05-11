"""Codex plugin backend.

Emits a Codex-format directory plugin with a plugin.json manifest, an .mcp.json
in mcpServers format, a skill module with separate reference files, and a
marketplace.json so the plugin is discoverable through the Codex marketplace.
Codex does not consume slash commands, agents, or instruction files in this
layout, so those sections are intentionally absent.
"""
from __future__ import annotations

import json

from ...core import (
    BaseBackend,
    BuildContext,
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

    def smoke_test(self, ctx: BuildContext) -> dict | None:
        """Validate plugin.json + marketplace.json parse.

        Codex resolves plugins via marketplace.json. Structural check + an
        optional `codex --version` invocation is the most we can verify
        without auth."""
        marketplace = ctx.out / "marketplace.json"
        manifest = ctx.out / ".codex-plugin" / "plugin.json"

        if not manifest.exists():
            return {"ok": False, "reason": ".codex-plugin/plugin.json missing"}
        try:
            json.loads(manifest.read_text())
        except json.JSONDecodeError as e:
            return {"ok": False, "reason": f"plugin.json invalid JSON: {e}"}

        if not marketplace.exists():
            return {"ok": False, "reason": "marketplace.json missing"}
        try:
            mp = json.loads(marketplace.read_text())
        except json.JSONDecodeError as e:
            return {"ok": False, "reason": f"marketplace.json invalid JSON: {e}"}
        if not mp.get("plugins"):
            return {"ok": False, "reason": "marketplace.json has no plugins entries"}

        return self._invoke_cli(["codex", "--version"])

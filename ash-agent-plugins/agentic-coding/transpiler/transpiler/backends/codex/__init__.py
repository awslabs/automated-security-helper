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
from ...formats import CLAUDE_MARKETPLACE
from ...registry import register_backend


@register_backend
class CodexBackend(BaseBackend):
    NAME = "codex"
    OUTPUT_DIR = "codex"
    FORMAT = CLAUDE_MARKETPLACE

    PLUGIN_MANIFEST = PluginManifest(
        # Codex's plugin loader searches both .codex-plugin/plugin.json AND
        # .claude-plugin/plugin.json (DISCOVERABLE_PLUGIN_MANIFEST_PATHS in
        # codex-rs/utils/plugins/src/plugin_namespace.rs). Emitting at the
        # Claude path lets Codex AND Claude Code both consume the same
        # artifact today, while keeping the codex backend free to switch
        # to .codex-plugin/plugin.json later when divergence is needed.
        format="codex",
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

    MARKETPLACE = Marketplace(
        # Codex requires marketplace.json at one of two canonical paths
        # (per MARKETPLACE_MANIFEST_RELATIVE_PATHS in core-plugins/marketplace.rs).
        # We emit at .claude-plugin/marketplace.json to match the path Claude
        # Code also uses for marketplaces.
        path=".claude-plugin/marketplace.json",
    )

    def smoke_test(self, ctx: BuildContext) -> dict | None:
        """Validate plugin.json + marketplace.json + run `codex plugin marketplace add`.

        Per github.com/openai/codex codex-rs/cli/src/marketplace_cmd.rs,
        Codex has no `validate` verb. The CI lever is `codex plugin
        marketplace add <local-dir>`, which schema-validates marketplace.json
        + plugin.json synchronously before recording metadata. We point
        CODEX_HOME at a tempdir to keep the runner clean.

        Codex requires marketplace.json at `.claude-plugin/marketplace.json`
        (per MARKETPLACE_MANIFEST_RELATIVE_PATHS in core-plugins/marketplace.rs)."""
        marketplace = ctx.out / ".claude-plugin" / "marketplace.json"
        manifest = ctx.out / ".claude-plugin" / "plugin.json"

        if not manifest.exists():
            return {"ok": False, "reason": ".claude-plugin/plugin.json missing"}
        try:
            json.loads(manifest.read_text())
        except json.JSONDecodeError as e:
            return {"ok": False, "reason": f"plugin.json invalid JSON: {e}"}

        if not marketplace.exists():
            return {"ok": False, "reason": ".claude-plugin/marketplace.json missing"}
        try:
            mp = json.loads(marketplace.read_text())
        except json.JSONDecodeError as e:
            return {"ok": False, "reason": f"marketplace.json invalid JSON: {e}"}
        if not mp.get("plugins"):
            return {"ok": False, "reason": "marketplace.json has no plugins entries"}

        pins = self._load_cli_pins(ctx.base_dir)
        if "codex" in pins:
            ver = self._assert_version_pin("codex", ["codex", "--version"], pins["codex"])
            if ver and ver.get("ok") is False:
                return ver
        # Use isolated CODEX_HOME so CI runs are reproducible.
        import tempfile
        with tempfile.TemporaryDirectory() as codex_home:
            env_argv = ["env", f"CODEX_HOME={codex_home}", "codex", "plugin",
                        "marketplace", "add", str(ctx.out.resolve())]
            return self._invoke_validator(env_argv)

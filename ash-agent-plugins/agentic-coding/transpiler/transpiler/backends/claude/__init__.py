"""Claude Code plugin backend.

Emits a directory plugin compatible with `claude --plugin-dir`. Includes a
plugin.json manifest, .mcp.json, a skill module with its own references, slash
commands, autonomous agents, and a CLAUDE.md that @-imports the universal
AGENTS.md so Claude Code (which doesn't read AGENTS.md natively) still gets
the same content as the AGENTS.md-aware platforms.
"""
from __future__ import annotations

import json

from ...core import (
    AgentsConfig,
    BaseBackend,
    BuildContext,
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

    def smoke_test(self, ctx: BuildContext) -> dict | None:
        """Validate plugin.json + .mcp.json parse, then run `claude plugin validate`.

        Per code.claude.com/docs/en/plugins-reference, `claude plugin validate`
        is a no-LLM schema check: parses plugin.json, skill/agent/command
        frontmatter, hooks/hooks.json. Exits non-zero on any malformed file.
        We also assert the CLI version matches the pinned major.minor so
        upstream subcommand-shape changes surface early."""
        manifest = ctx.out / ".claude-plugin" / "plugin.json"
        mcp = ctx.out / ".mcp.json"

        if not manifest.exists():
            return {"ok": False, "reason": ".claude-plugin/plugin.json missing"}
        try:
            m = json.loads(manifest.read_text())
        except json.JSONDecodeError as e:
            return {"ok": False, "reason": f"plugin.json invalid JSON: {e}"}
        if not m.get("name"):
            return {"ok": False, "reason": "plugin.json missing required `name`"}

        if mcp.exists():
            try:
                mcp_cfg = json.loads(mcp.read_text())
            except json.JSONDecodeError as e:
                return {"ok": False, "reason": f".mcp.json invalid JSON: {e}"}
            if not isinstance(mcp_cfg.get("mcpServers"), dict):
                return {"ok": False, "reason": ".mcp.json missing `mcpServers` object"}

        pins = self._load_cli_pins(ctx.base_dir)
        if "claude" in pins:
            ver = self._assert_version_pin("claude", ["claude", "--version"], pins["claude"])
            if ver and ver.get("ok") is False:
                return ver
        return self._invoke_validator(["claude", "plugin", "validate", str(ctx.out.resolve())])

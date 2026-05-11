"""OpenCode backend.

Emits opencode.json + .opencode/ directory of skills, commands, agents.
"""
from __future__ import annotations

import json

from ...core import (
    AgentsConfig,
    BaseBackend,
    BuildContext,
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

    def smoke_test(self, ctx: BuildContext) -> dict | None:
        """Validate opencode.json parses + declares mcp servers."""
        cfg_path = ctx.out / "opencode.json"

        if not cfg_path.exists():
            return {"ok": False, "reason": "opencode.json missing"}
        try:
            cfg = json.loads(cfg_path.read_text())
        except json.JSONDecodeError as e:
            return {"ok": False, "reason": f"opencode.json invalid JSON: {e}"}
        if "mcp" not in cfg:
            return {"ok": False, "reason": "opencode.json missing `mcp` block"}

        return self._invoke_cli(["opencode", "--version"])

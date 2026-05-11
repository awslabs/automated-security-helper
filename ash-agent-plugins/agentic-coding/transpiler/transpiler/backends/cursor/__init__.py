"""Cursor backend."""
from __future__ import annotations

import json

from ...core import (
    BaseBackend,
    BuildContext,
    InstructionFile,
    MCPConfig,
    SkillConfig,
)
from ...formats import CURSOR_RULES
from ...cli_tools import CLI_CURSOR, CLI_SKILLS_REF
from ...registry import register_backend


@register_backend
class CursorBackend(BaseBackend):
    NAME = "cursor"
    OUTPUT_DIR = "cursor"
    FORMAT = CURSOR_RULES
    CLI_TOOLS = (CLI_CURSOR, CLI_SKILLS_REF)

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

    def smoke_test(self, ctx: BuildContext) -> dict | None:
        """Validate .cursor/mcp.json parses + AGENTS.md exists."""
        mcp = ctx.out / ".cursor" / "mcp.json"
        agents = ctx.out / "AGENTS.md"

        if not mcp.exists():
            return {"ok": False, "reason": ".cursor/mcp.json missing"}
        try:
            cfg = json.loads(mcp.read_text())
        except json.JSONDecodeError as e:
            return {"ok": False, "reason": f".cursor/mcp.json invalid JSON: {e}"}
        if "mcpServers" not in cfg:
            return {"ok": False, "reason": ".cursor/mcp.json missing `mcpServers` block"}
        if not agents.exists():
            return {"ok": False, "reason": "AGENTS.md missing"}

        return {"ok": True, "detail": "mcp.json + AGENTS.md valid (Cursor is GUI-only; no CLI)"}

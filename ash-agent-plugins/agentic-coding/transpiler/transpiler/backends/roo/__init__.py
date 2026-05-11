"""Roo Code backend."""
from __future__ import annotations

import json

from ...core import (
    BaseBackend,
    BuildContext,
    CustomModes,
    InstructionFile,
    MCPConfig,
    RulesDir,
)
from ...registry import register_backend


@register_backend
class RooBackend(BaseBackend):
    NAME = "roo"
    OUTPUT_DIR = "roo"

    MCP = MCPConfig(
        format="mcpServers",
        path=".roo/mcp.json",
    )

    RULES_DIR = RulesDir(
        path=".roo/rules-{plugin_name}",
        skill_filename="01-skill.md",
        include_skill_body=True,
        include_references="separate_files",
        reference_filename_prefix="02-",
    )

    CUSTOM_MODES = CustomModes(
        path=".roomodes",
        template="roo/roomodes.j2",
    )

    INSTRUCTION_FILE = InstructionFile(
        path="AGENTS.md",
        template="cursor/AGENTS.md.j2",
        include_skill_body=False,
        include_references="none",
    )

    def smoke_test(self, ctx: BuildContext) -> dict | None:
        """Validate .roo/mcp.json + .roomodes + rules dir."""
        mcp = ctx.out / ".roo" / "mcp.json"
        roomodes = ctx.out / ".roomodes"
        agents = ctx.out / "AGENTS.md"

        if not mcp.exists():
            return {"ok": False, "reason": ".roo/mcp.json missing"}
        try:
            cfg = json.loads(mcp.read_text())
        except json.JSONDecodeError as e:
            return {"ok": False, "reason": f".roo/mcp.json invalid JSON: {e}"}
        if "mcpServers" not in cfg:
            return {"ok": False, "reason": ".roo/mcp.json missing `mcpServers` block"}
        if not roomodes.exists():
            return {"ok": False, "reason": ".roomodes missing"}
        if not agents.exists():
            return {"ok": False, "reason": "AGENTS.md missing"}

        return {"ok": True, "detail": ".roo/mcp.json + .roomodes + AGENTS.md valid (Roo is VS Code-only)"}

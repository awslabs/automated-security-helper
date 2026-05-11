"""Kiro IDE Power backend."""
from __future__ import annotations

import json

from ...core import (
    BaseBackend,
    BuildContext,
    InstructionFile,
    MCPConfig,
)
from ...registry import register_backend


@register_backend
class KiroBackend(BaseBackend):
    NAME = "kiro"
    OUTPUT_DIR = "kiro"

    MCP = MCPConfig(
        format="mcpServers",
        path="mcp.json",
    )

    INSTRUCTION_FILE = InstructionFile(
        path="POWER.md",
        template="kiro/POWER_frontmatter.j2",
        include_skill_body=True,
        include_references="appended",
    )

    def smoke_test(self, ctx: BuildContext) -> dict | None:
        """Validate mcp.json + POWER.md."""
        mcp = ctx.out / "mcp.json"
        power = ctx.out / "POWER.md"

        if not mcp.exists():
            return {"ok": False, "reason": "mcp.json missing"}
        try:
            cfg = json.loads(mcp.read_text())
        except json.JSONDecodeError as e:
            return {"ok": False, "reason": f"mcp.json invalid JSON: {e}"}
        if "mcpServers" not in cfg:
            return {"ok": False, "reason": "mcp.json missing `mcpServers` block"}
        if not power.exists():
            return {"ok": False, "reason": "POWER.md missing"}

        return {"ok": True, "detail": "mcp.json + POWER.md valid (Kiro is GUI-only)"}

"""GitHub Copilot backend.

Emits .vscode/mcp.json (servers format) + .github/copilot-instructions.md +
.github/prompts/*.prompt.md + .github/agents/*.agent.md.
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
)
from ...formats import VSCODE_MCP
from ...cli_tools import CLI_VSCODE
from ...registry import register_backend


@register_backend
class CopilotBackend(BaseBackend):
    NAME = "copilot"
    OUTPUT_DIR = "copilot"
    FORMAT = VSCODE_MCP
    CLI_TOOLS = (CLI_VSCODE,)

    MCP = MCPConfig(
        format="servers",
        path=".vscode/mcp.json",
    )

    INSTRUCTION_FILE = InstructionFile(
        path=".github/copilot-instructions.md",
        template="copilot/copilot-instructions.md.j2",
        include_skill_body=True,
        include_references="none",
        truncate_chars=4000,
        truncation_footer="[... see prompt files for details]",
    )

    COMMANDS = CommandsConfig(
        path=".github/prompts/{command_name}.prompt.md",
        frontmatter_fields=("description", "name", "agent"),
        tools_kind="none",
        single_quote_strings=True,
    )

    AGENTS = AgentsConfig(
        path=".github/agents/{agent_name}.agent.md",
        frontmatter_fields=("name", "description", "target", "model"),
        tools_kind="none",
        single_quote_strings=True,
    )

    def smoke_test(self, ctx: BuildContext) -> dict | None:
        """Validate .vscode/mcp.json + copilot-instructions.md."""
        mcp = ctx.out / ".vscode" / "mcp.json"
        instructions = ctx.out / ".github" / "copilot-instructions.md"

        if not mcp.exists():
            return {"ok": False, "reason": ".vscode/mcp.json missing"}
        try:
            cfg = json.loads(mcp.read_text())
        except json.JSONDecodeError as e:
            return {"ok": False, "reason": f".vscode/mcp.json invalid JSON: {e}"}
        if "servers" not in cfg:
            return {"ok": False, "reason": ".vscode/mcp.json missing `servers` block"}
        if not instructions.exists():
            return {"ok": False, "reason": ".github/copilot-instructions.md missing"}
        char_count = len(instructions.read_text())
        if char_count > 4000:
            return {"ok": False, "reason": f"copilot-instructions.md exceeds 4000-char cap ({char_count} chars)"}

        return {"ok": True, "detail": "mcp.json + copilot-instructions valid (no CLI to invoke)"}

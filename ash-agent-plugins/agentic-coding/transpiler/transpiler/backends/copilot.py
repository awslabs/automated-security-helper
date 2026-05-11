"""GitHub Copilot backend.

Emits the GitHub Copilot layout: a .vscode/mcp.json using the `servers` format,
a .github/copilot-instructions.md rendered from a Jinja template (with the
skill body inlined and truncated at 4000 characters), prompt files under
.github/prompts/, and agent files under .github/agents/. Command and agent
frontmatter is serialized with single-quoted strings to match Copilot's
expected YAML style.
"""
from __future__ import annotations

from ..core import (
    AgentsConfig,
    BaseBackend,
    CommandsConfig,
    InstructionFile,
    MCPConfig,
)
from ..registry import register_backend


@register_backend
class CopilotBackend(BaseBackend):
    NAME = "copilot"
    OUTPUT_DIR = "copilot"

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

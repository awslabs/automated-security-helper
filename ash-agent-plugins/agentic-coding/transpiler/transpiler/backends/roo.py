"""Roo Code plugin backend.

Emits a Roo layout: a per-plugin rules directory under `.roo/rules-{plugin_name}`
that carries the skill body and references, a `.roomodes` file rendered from
the custom-modes template, an `.roo/mcp.json` for MCP servers, and a shared
AGENTS.md instruction file rendered from the cursor template.
"""
from __future__ import annotations

from ..core import (
    BaseBackend,
    CustomModes,
    InstructionFile,
    MCPConfig,
    RulesDir,
)
from ..registry import register_backend


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

"""Cline plugin backend.

Emits a Cline layout: a `.clinerules` directory holding the skill body and
its references as separately-numbered files, an AGENTS.md instruction file
shared with the other AGENTS.md-aware platforms, and an MCP config delivered
via Cline's install script (the MCP file itself is not committed; the
`install_script` hook wires it up at install time).
"""
from __future__ import annotations

from ...core import (
    BaseBackend,
    InstructionFile,
    MCPConfig,
    RulesDir,
)
from ...registry import register_backend


@register_backend
class ClineBackend(BaseBackend):
    NAME = "cline"
    OUTPUT_DIR = "cline"

    MCP = MCPConfig(
        format="mcpServers",
        path=None,
        install_script="cline",
    )

    RULES_DIR = RulesDir(
        path=".clinerules",
        skill_filename="01-skill.md",
        include_skill_body=True,
        include_references="separate_files",
        reference_filename_prefix="02-",
    )

    INSTRUCTION_FILE = InstructionFile(
        path="AGENTS.md",
        template="cursor/AGENTS.md.j2",
        include_skill_body=False,
        include_references="none",
    )

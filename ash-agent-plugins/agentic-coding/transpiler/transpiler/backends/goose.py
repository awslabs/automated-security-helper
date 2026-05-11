"""Goose plugin backend.

Emits a Goose extension layout: a YAML extension manifest rendered from a
template, paired with a .goosehints instruction file that appends the skill
body and references inline (Goose has no separate skill module concept).
The MCP config is the extension.yaml itself; an install script handles
registration with the Goose CLI.
"""
from __future__ import annotations

from ..core import (
    BaseBackend,
    InstructionFile,
    MCPConfig,
)
from ..registry import register_backend


@register_backend
class GooseBackend(BaseBackend):
    NAME = "goose"
    OUTPUT_DIR = "goose"

    MCP = MCPConfig(
        format="goose_yaml",
        path="extension.yaml",
        template="goose/extension.yaml.j2",
        install_script="goose",
    )

    INSTRUCTION_FILE = InstructionFile(
        path=".goosehints",
        template="goose/goosehints.j2",
        include_skill_body=True,
        include_references="appended",
    )

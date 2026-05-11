"""Aider backend.

Emits an Aider-compatible layout consisting of a CONVENTIONS.md instruction
file (with the skill body and references appended) and an .aider.conf.yml
config file. Aider has no MCP support, so no MCP section is declared.
"""
from __future__ import annotations

from ..core import (
    BaseBackend,
    ConfigFile,
    InstructionFile,
)
from ..registry import register_backend


@register_backend
class AiderBackend(BaseBackend):
    NAME = "aider"
    OUTPUT_DIR = "aider"

    INSTRUCTION_FILE = InstructionFile(
        path="CONVENTIONS.md",
        template="aider/CONVENTIONS.md.j2",
        include_skill_body=True,
        include_references="appended",
    )

    CONFIG_FILE = ConfigFile(
        path=".aider.conf.yml",
        template="aider/aider_conf.yml.j2",
    )

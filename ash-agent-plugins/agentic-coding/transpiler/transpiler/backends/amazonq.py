"""Amazon Q Developer CLI plugin backend.

Emits the minimal layout Amazon Q expects: just an agent.json describing the
MCP server. Amazon Q has no skill, command, agent, or instruction-file slots
in this transpiler — the agent.json is the entire deliverable, registered
via an install script.
"""
from __future__ import annotations

from ..core import BaseBackend, MCPConfig
from ..registry import register_backend


@register_backend
class AmazonqBackend(BaseBackend):
    NAME = "amazonq"
    OUTPUT_DIR = "amazonq"

    MCP = MCPConfig(
        format="amazonq",
        path="agent.json",
        install_script="amazonq",
    )

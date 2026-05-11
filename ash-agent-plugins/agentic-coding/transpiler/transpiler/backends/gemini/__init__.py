"""Gemini CLI plugin backend.

Emits a Gemini extension layout: a GEMINI.md instruction file (which appends
skill body and references inline because Gemini has no separate skill module
concept), plus a gemini-extension.json manifest. MCP servers ship via an
install script rather than a committed config file.
"""
from __future__ import annotations

from ...core import (
    BaseBackend,
    ExtensionManifest,
    InstructionFile,
    MCPConfig,
)
from ...registry import register_backend


@register_backend
class GeminiBackend(BaseBackend):
    NAME = "gemini"
    OUTPUT_DIR = "gemini"

    MCP = MCPConfig(
        format="mcpServers",
        path=None,
        install_script="gemini",
    )

    INSTRUCTION_FILE = InstructionFile(
        path="GEMINI.md",
        template="gemini/GEMINI.md.j2",
        include_skill_body=True,
        include_references="appended",
    )

    EXTENSION_MANIFEST = ExtensionManifest(
        format="gemini",
        path="gemini-extension.json",
    )

"""Gemini CLI extension backend.

Emits a Gemini extension with gemini-extension.json manifest + GEMINI.md
instruction file. MCP install is delegated to a generated install.sh that
calls `gemini extensions install` after the user clones the repo.
"""
from __future__ import annotations

import json

from ...core import (
    BaseBackend,
    BuildContext,
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

    def smoke_test(self, ctx: BuildContext) -> dict | None:
        """Validate gemini-extension.json parses + GEMINI.md exists.

        Gemini CLI loads the extension by reading gemini-extension.json. We
        verify the manifest is valid JSON with the required `name` field,
        then invoke `gemini --version` if the CLI is on PATH."""
        manifest = ctx.out / "gemini-extension.json"
        instructions = ctx.out / "GEMINI.md"

        if not manifest.exists():
            return {"ok": False, "reason": "gemini-extension.json missing"}
        try:
            m = json.loads(manifest.read_text())
        except json.JSONDecodeError as e:
            return {"ok": False, "reason": f"gemini-extension.json invalid JSON: {e}"}
        if not m.get("name"):
            return {"ok": False, "reason": "gemini-extension.json missing `name`"}
        if not instructions.exists():
            return {"ok": False, "reason": "GEMINI.md missing"}

        return self._invoke_cli(["gemini", "--version"])

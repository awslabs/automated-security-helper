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
from ...formats import GEMINI_EXTENSION
from ...cli_tools import CLI_GEMINI
from ...registry import register_backend


@register_backend
class GeminiBackend(BaseBackend):
    NAME = "gemini"
    OUTPUT_DIR = "gemini"
    FORMAT = GEMINI_EXTENSION
    CLI_TOOLS = (CLI_GEMINI,)

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
        """Validate gemini-extension.json + run `gemini extensions validate`.

        Per github.com/google-gemini/gemini-cli packages/cli/src/commands/
        extensions/validate.ts: this is a purpose-built no-LLM, no-auth,
        exit-coded validator. It loads through the same ExtensionManager
        the runtime uses, so any drift fails at this gate."""
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

        pins = self._load_cli_pins(ctx.base_dir)
        if "gemini" in pins:
            ver = self._assert_version_pin("gemini", ["gemini", "--version"], pins["gemini"])
            if ver and ver.get("ok") is False:
                return ver
        return self._invoke_validator(["gemini", "extensions", "validate", str(ctx.out.resolve())])

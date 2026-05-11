"""Block Goose extension backend.

Emits a Goose extension with extension.yaml + .goosehints instruction file.
"""
from __future__ import annotations

import yaml

from ...core import (
    BaseBackend,
    BuildContext,
    InstructionFile,
    MCPConfig,
)
from ...formats import GOOSE_CONFIG
from ...registry import register_backend


@register_backend
class GooseBackend(BaseBackend):
    NAME = "goose"
    OUTPUT_DIR = "goose"
    FORMAT = GOOSE_CONFIG

    MCP = MCPConfig(
        format="goose_yaml",
        path="extension.yaml",
        template="goose/extension.yaml.j2",
        install_script="goose",
    )

    INSTRUCTION_FILE = InstructionFile(
        # Goose's default context-file list per goose-docs.ai/docs/guides/
        # context-engineering/using-goosehints is ["AGENTS.md", ".goosehints"].
        # Emitting AGENTS.md aligns with the shared instruction-file format
        # already adopted by Codex, Cursor, Windsurf, Roo, Copilot, Kiro,
        # OpenCode, Aider, and Cline.
        path="AGENTS.md",
        template="goose/goosehints.j2",
        include_skill_body=True,
        include_references="appended",
    )

    def smoke_test(self, ctx: BuildContext) -> dict | None:
        """Validate extension.yaml parses + has the required Goose shape."""
        ext_path = ctx.out / "extension.yaml"
        hints = ctx.out / "AGENTS.md"

        if not ext_path.exists():
            return {"ok": False, "reason": "extension.yaml missing"}
        try:
            ext = yaml.safe_load(ext_path.read_text())
        except yaml.YAMLError as e:
            return {"ok": False, "reason": f"extension.yaml YAML invalid: {e}"}
        if not isinstance(ext, dict) or "extensions" not in ext:
            return {"ok": False, "reason": "extension.yaml missing `extensions` key"}
        if not hints.exists():
            return {"ok": False, "reason": "AGENTS.md missing"}

        return self._invoke_cli(["goose", "--version"])

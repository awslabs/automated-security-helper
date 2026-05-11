"""Cline backend."""
from __future__ import annotations

from ...core import (
    BaseBackend,
    BuildContext,
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

    def smoke_test(self, ctx: BuildContext) -> dict | None:
        """Validate .clinerules/ + install.sh + AGENTS.md exist."""
        rules_dir = ctx.out / ".clinerules"
        agents = ctx.out / "AGENTS.md"
        install = ctx.out / "install.sh"

        if not rules_dir.exists() or not list(rules_dir.iterdir()):
            return {"ok": False, "reason": ".clinerules/ missing or empty"}
        if not (rules_dir / "01-skill.md").exists():
            return {"ok": False, "reason": ".clinerules/01-skill.md missing"}
        if not agents.exists():
            return {"ok": False, "reason": "AGENTS.md missing"}
        if not install.exists():
            return {"ok": False, "reason": "install.sh missing"}

        return {"ok": True, "detail": "rules + AGENTS.md + install.sh valid (Cline is VS Code-only)"}

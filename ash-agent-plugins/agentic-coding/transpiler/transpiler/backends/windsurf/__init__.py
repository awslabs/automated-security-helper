"""Windsurf backend."""
from __future__ import annotations

from ...core import (
    BaseBackend,
    BuildContext,
    InstructionFile,
    MCPConfig,
    SkillConfig,
)
from ...formats import WINDSURF_RULES
from ...cli_tools import CLI_WINDSURF, CLI_SKILLS_REF
from ...registry import register_backend


@register_backend
class WindsurfBackend(BaseBackend):
    NAME = "windsurf"
    OUTPUT_DIR = "windsurf"
    FORMAT = WINDSURF_RULES
    CLI_TOOLS = (CLI_WINDSURF, CLI_SKILLS_REF)

    MCP = MCPConfig(
        format="mcpServers",
        path=None,
        install_script="windsurf",
    )

    SKILL = SkillConfig(
        path=".windsurf/rules/{skill_name}.md",
        frontmatter_fields=("trigger", "description"),
        include_references="none",
        truncate_bytes=12000,
        truncation_footer="[... see project AGENTS.md for full reference]",
    )

    INSTRUCTION_FILE = InstructionFile(
        path="AGENTS.md",
        template="cursor/AGENTS.md.j2",
        include_skill_body=False,
        include_references="none",
    )

    def smoke_test(self, ctx: BuildContext) -> dict | None:
        """Validate .windsurf/rules and AGENTS.md exist; rule file under 12KB cap."""
        rules_dir = ctx.out / ".windsurf" / "rules"
        agents = ctx.out / "AGENTS.md"
        install = ctx.out / "install.sh"

        if not rules_dir.exists() or not list(rules_dir.iterdir()):
            return {"ok": False, "reason": ".windsurf/rules/ missing or empty"}
        for rule in rules_dir.glob("*.md"):
            if rule.stat().st_size > 12000:
                return {"ok": False, "reason": f"{rule.name} exceeds 12000-byte cap"}
        if not agents.exists():
            return {"ok": False, "reason": "AGENTS.md missing"}
        if not install.exists():
            return {"ok": False, "reason": "install.sh missing"}

        return {"ok": True, "detail": "rules + AGENTS.md + install.sh valid (Windsurf is GUI-only)"}

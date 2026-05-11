"""Continue.dev backend."""
from __future__ import annotations

import yaml

from ...core import (
    BaseBackend,
    BuildContext,
    MCPConfig,
    SkillConfig,
)
from ...formats import CONTINUE_CONFIG
from ...registry import register_backend


@register_backend
class ContinueBackend(BaseBackend):
    NAME = "continue"
    OUTPUT_DIR = "continue"
    FORMAT = CONTINUE_CONFIG

    MCP = MCPConfig(
        format="continue_yaml",
        path=".continue/mcpServers/{plugin_name}.yaml",
        template="continue/mcp_servers.yaml.j2",
    )

    SKILL = SkillConfig(
        path=".continue/rules/{skill_name}.md",
        frontmatter_fields=("name", "description"),
        include_references="none",
    )

    def smoke_test(self, ctx: BuildContext) -> dict | None:
        """Validate .continue/mcpServers/*.yaml parses + .continue/rules/ exists."""
        mcp_dir = ctx.out / ".continue" / "mcpServers"
        rules_dir = ctx.out / ".continue" / "rules"

        if not mcp_dir.exists() or not list(mcp_dir.glob("*.yaml")):
            return {"ok": False, "reason": ".continue/mcpServers/*.yaml missing"}
        for yml in mcp_dir.glob("*.yaml"):
            try:
                cfg = yaml.safe_load(yml.read_text())
            except yaml.YAMLError as e:
                return {"ok": False, "reason": f"{yml.name} YAML invalid: {e}"}
            if not isinstance(cfg, dict) or "mcpServers" not in cfg:
                return {"ok": False, "reason": f"{yml.name} missing `mcpServers` key"}

        if not rules_dir.exists() or not list(rules_dir.glob("*.md")):
            return {"ok": False, "reason": ".continue/rules/*.md missing"}

        return {"ok": True, "detail": "mcpServers yaml + rules valid (Continue is VS Code-only)"}

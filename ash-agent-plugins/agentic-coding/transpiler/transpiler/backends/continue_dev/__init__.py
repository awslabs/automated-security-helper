"""Continue.dev plugin backend.

Emits a Continue.dev layout: an MCP server YAML at `.continue/mcpServers/{plugin_name}.yaml`
rendered from a Jinja template (Continue uses its own YAML schema rather than
the standard `mcpServers` JSON), and a skill placed under `.continue/rules/`
with a minimal name+description frontmatter. The module is named `continue_dev`
because `continue` is a Python keyword, but the backend's NAME stays "continue".
"""
from __future__ import annotations

from ...core import (
    BaseBackend,
    MCPConfig,
    SkillConfig,
)
from ...registry import register_backend


@register_backend
class ContinueBackend(BaseBackend):
    NAME = "continue"
    OUTPUT_DIR = "continue"

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

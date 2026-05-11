"""Amazon Q Dev CLI agent backend.

Emits agent.json (Amazon Q agent definition) and an install.sh that copies
it into ~/.aws/amazonq/cli-agents/.
"""
from __future__ import annotations

import json

from ...core import BaseBackend, BuildContext, MCPConfig
from ...registry import register_backend


@register_backend
class AmazonqBackend(BaseBackend):
    NAME = "amazonq"
    OUTPUT_DIR = "amazonq"

    MCP = MCPConfig(
        format="amazonq",
        path="agent.json",
        install_script="amazonq",
    )

    def smoke_test(self, ctx: BuildContext) -> dict | None:
        """Validate agent.json parses + has required Amazon Q shape."""
        agent_path = ctx.out / "agent.json"

        if not agent_path.exists():
            return {"ok": False, "reason": "agent.json missing"}
        try:
            agent = json.loads(agent_path.read_text())
        except json.JSONDecodeError as e:
            return {"ok": False, "reason": f"agent.json invalid JSON: {e}"}
        if not agent.get("name"):
            return {"ok": False, "reason": "agent.json missing `name`"}
        if "mcpServers" not in agent:
            return {"ok": False, "reason": "agent.json missing `mcpServers` block"}

        return self._invoke_cli(["q", "--version"])

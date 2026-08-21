"""MCP config shape variants — dispatched by MCPConfig.format."""
from __future__ import annotations

import json
from pathlib import Path

from .core import Manifest


def mcp_mcpServers(m: Manifest, base_dir: Path) -> dict:
    return json.loads((base_dir / "mcp.json").read_text())


def mcp_servers(m: Manifest, base_dir: Path) -> dict:
    """Copilot uses 'servers' instead of 'mcpServers'."""
    base = json.loads((base_dir / "mcp.json").read_text())
    return {"servers": base["mcpServers"]}


def mcp_opencode_embedded(m: Manifest, base_dir: Path) -> dict:
    """OpenCode wraps each server with type/command/environment/enabled keys."""
    base = json.loads((base_dir / "mcp.json").read_text())["mcpServers"]
    mcp = {
        server_name: {
            "type": "local",
            "command": [server_cfg["command"]] + server_cfg.get("args", []),
            "environment": server_cfg.get("env", {}),
            "enabled": True,
        }
        for server_name, server_cfg in base.items()
    }
    return {
        "$schema": "https://opencode.ai/config.json",
        "mcp": mcp,
    }


def mcp_amazonq(m: Manifest, base_dir: Path) -> dict:
    from .manifest_builders import amazonq_agent
    return amazonq_agent(m, base_dir)


JSON_MCP_BUILDERS = {
    "mcpServers": mcp_mcpServers,
    "servers": mcp_servers,
    "opencode_embedded": mcp_opencode_embedded,
    "amazonq": mcp_amazonq,
}

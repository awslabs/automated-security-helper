"""JSON manifest builders — Python dict construction beats Jinja for nested JSON.

Each builder takes (Manifest, base_dir) and returns a dict ready for json.dumps.
"""
from __future__ import annotations

import json
from pathlib import Path

from .core import Manifest


def claude_plugin_json(m: Manifest, base_dir: Path) -> dict:
    return {
        "name": m.name,
        "version": m.version,
        "description": m.description,
        "author": {"name": m.author_name, "url": m.author_url},
        "homepage": m.homepage,
        "repository": m.repository,
        "license": m.license,
        "keywords": list(m.keywords),
    }


def codex_plugin_json(m: Manifest, base_dir: Path) -> dict:
    return {
        "name": m.name,
        "version": m.version,
        "description": m.description,
        "author": {"name": m.author_name, "url": m.author_url},
        "homepage": m.homepage,
        "repository": m.repository,
        "license": m.license,
        "keywords": list(m.keywords),
        "skills": "./skills/",
        "mcpServers": "./.mcp.json",
        "interface": {
            "displayName": m.display_name,
            "shortDescription": "Run security scans via ASH MCP",
            "longDescription": m.description,
            "developerName": m.author_name,
            "category": "Security",
            "capabilities": ["Read"],
            "websiteURL": m.homepage,
            "defaultPrompt": [
                "Scan this project for security vulnerabilities",
                "Run an ASH security audit and prioritize findings",
                "Check the dependencies for known CVEs",
            ],
        },
    }


def codex_marketplace(m: Manifest, base_dir: Path) -> dict:
    return {
        "name": f"{m.name}-marketplace",
        "interface": {
            "displayName": f"{m.display_name} Marketplace",
            "shortDescription": f"Single-plugin marketplace for {m.display_name}",
        },
        "plugins": [
            {
                "name": m.name,
                "source": {"source": "local", "path": "."},
                "policy": {
                    "installation": "AVAILABLE",
                    "authentication": "ON_INSTALL",
                },
                "category": "Security",
            }
        ],
    }


def gemini_extension(m: Manifest, base_dir: Path) -> dict:
    return {
        "name": m.name,
        "version": m.version,
        "description": m.description,
        "mcpServers": json.loads((base_dir / "mcp.json").read_text())["mcpServers"],
    }


def amazonq_agent(m: Manifest, base_dir: Path) -> dict:
    return {
        "name": m.name,
        "description": m.description,
        "mcpServers": json.loads((base_dir / "mcp.json").read_text())["mcpServers"],
        "tools": [f"@{m.name}/*"],
        "allowedTools": [],
    }


PLUGIN_MANIFEST_BUILDERS = {
    "claude": claude_plugin_json,
    "codex": codex_plugin_json,
}

EXTENSION_MANIFEST_BUILDERS = {
    "gemini": gemini_extension,
}

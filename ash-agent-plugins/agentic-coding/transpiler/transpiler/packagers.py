"""Packagers for binary release artifacts.

Currently just MCPB (Anthropic Desktop Extensions ZIP archive). Future:
.vsix for VS Code extensions, npm pack for OpenCode, etc.

Reproducibility: zipfile entries use fixed mtime (1980-01-01) and explicit
external_attr so the archive is byte-identical across runs/machines —
required so the committed .mcpb can be drift-checked.
"""
from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path

from .core import Manifest


def mcpb_manifest(m: Manifest, base_dir: Path,
                  manifest_version: str, server_type: str,
                  server_entry_point: str, long_description: str | None) -> dict:
    """The MCPB manifest.json content. Embeds the canonical _base/mcp.json
    server invocation so users get one-click install via uvx."""
    base_mcp = json.loads((base_dir / "mcp.json").read_text())["mcpServers"]
    _server_name, server_cfg = next(iter(base_mcp.items()))

    return {
        "manifest_version": manifest_version,
        "name": m.name,
        "version": m.version,
        "description": m.description,
        "long_description": long_description if long_description else m.description,
        "author": {"name": m.author_name, "url": m.author_url},
        "homepage": m.homepage,
        "repository": {"type": "git", "url": m.repository},
        "license": m.license,
        "keywords": list(m.keywords),
        "server": {
            "type": server_type,
            "entry_point": server_entry_point,
            "mcp_config": {
                "command": server_cfg["command"],
                "args": server_cfg.get("args", []),
                "env": server_cfg.get("env", {}),
            },
        },
        "compatibility": {
            "platforms": ["darwin", "linux", "win32"],
        },
    }


def mcpb_archive(manifest_obj: dict) -> bytes:
    """Build a deterministic .mcpb ZIP archive.

    Determinism: fixed mtime, fixed compression, fixed external_attr — produces
    byte-identical output across runs/machines/zlib versions. Required so the
    committed .mcpb can participate in CI drift detection.
    """
    manifest_bytes = (
        json.dumps(manifest_obj, indent=2, ensure_ascii=False) + "\n"
    ).encode("utf-8")

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w",
                         compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        info = zipfile.ZipInfo(filename="manifest.json",
                               date_time=(1980, 1, 1, 0, 0, 0))
        info.external_attr = 0o644 << 16
        info.compress_type = zipfile.ZIP_DEFLATED
        zf.writestr(info, manifest_bytes)
    return buf.getvalue()

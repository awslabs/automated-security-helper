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
import re
import zipfile
from pathlib import Path

from .core import Manifest


# `v4.0.0` -> `4.0.0`. ash_version is a release tag; a bundle version is semver.
_ASH_TAG = re.compile(r"^v(\d+\.\d+\.\d+)$")


def mcpb_bundle_version(ash_version: str) -> str:
    """The .mcpb bundle's own `version`: the ASH release the bundle launches.

    A desktop MCP host decides whether a downloaded bundle replaces the installed one
    by comparing this field, so it has to move when the bundle moves. It used to be the
    plugin version from _base/manifest.json, which is 1.0.0 and never changes, so a host
    holding the bundle for one ASH release saw the next one as the same version. The
    bundle's mcp_config launches `uvx --from=git+...@<ash_version>`, so the ASH release
    is what the bundle installs, and it is the version a host should compare.

    Derived from ash_version rather than given its own key: pyproject.toml's
    [tool.commitizen] version_files already rewrites `_base/manifest.json:ash_version`
    on every bump, so the bundle version moves with it and with nothing else, and the
    plugin `version` key keeps meaning the plugin version for every other backend.
    """
    match = _ASH_TAG.match(ash_version)
    if not match:
        raise ValueError(
            f"ash_version {ash_version!r} in _base/manifest.json is not a release tag "
            "of the form vMAJOR.MINOR.PATCH, so no bundle version can be derived from it"
        )
    return match.group(1)


def mcpb_manifest(
    m: Manifest,
    base_dir: Path,
    manifest_version: str,
    server_type: str,
    server_entry_point: str,
    long_description: str | None,
) -> dict:
    """The MCPB manifest.json content. Embeds the canonical _base/mcp.json
    server invocation so users get one-click install via uvx."""
    base_mcp = json.loads((base_dir / "mcp.json").read_text())["mcpServers"]
    _server_name, server_cfg = next(iter(base_mcp.items()))

    return {
        "manifest_version": manifest_version,
        "name": m.name,
        "version": mcpb_bundle_version(m.ash_version),
        "description": m.description,
        "long_description": long_description or m.description,
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
    with zipfile.ZipFile(
        buf, mode="w", compression=zipfile.ZIP_DEFLATED, compresslevel=6
    ) as zf:
        info = zipfile.ZipInfo(
            filename="manifest.json", date_time=(1980, 1, 1, 0, 0, 0)
        )
        info.external_attr = 0o644 << 16
        info.compress_type = zipfile.ZIP_DEFLATED
        zf.writestr(info, manifest_bytes)
    return buf.getvalue()

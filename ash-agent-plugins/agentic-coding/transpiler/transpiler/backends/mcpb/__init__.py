"""MCPB backend.

Emits a .mcpb ZIP archive (manifest.json + bundled assets) for one-click
install in Claude Desktop. The archive is committed; the release phase
copies it into dist/ for GitHub release attachment.
"""
from __future__ import annotations

import json
import shutil
import zipfile

from ...core import (
    BaseBackend,
    BuildContext,
    BuildPhase,
    MCPBBundle,
)
from ...registry import register_backend


@register_backend
class MCPBBackend(BaseBackend):
    NAME = "mcpb"
    OUTPUT_DIR = "mcpb"

    MCPB_BUNDLE = MCPBBundle(
        archive_path="ash.mcpb",
        manifest_version="0.3",
        server_type="binary",
        long_description=(
            "Run ASH (Automated Security Helper) security scans directly in Claude\n"
            "Desktop. Bundles uvx-based ASH MCP server invocation; no separate\n"
            "install step required beyond having uvx on the user's PATH.\n"
        ),
    )

    PHASES = (
        BuildPhase(
            name="copy-archive",
            description="Copy ash.mcpb into dist/ for GitHub release attachment",
            stage="release",
        ),
    )

    def phase_copy_archive(self, ctx: BuildContext) -> None:
        """Copy the deterministic .mcpb archive to the dist directory.

        Stamps the filename with the manifest version (e.g. dist/ash-1.0.0.mcpb).
        The plain ash.mcpb in plugins/mcpb/ stays as the canonical, committed
        artifact; dist/ is the staging area for release uploads."""
        if ctx.dist_dir is None:
            return
        src = ctx.out / self.MCPB_BUNDLE.archive_path
        if not src.exists():
            raise FileNotFoundError(
                f"{src} missing — run `agentic-plugins build mcpb` before release"
            )
        ctx.dist_dir.mkdir(parents=True, exist_ok=True)
        dest = ctx.dist_dir / f"ash-{ctx.manifest.version}.mcpb"
        shutil.copy2(src, dest)

    def smoke_test(self, ctx: BuildContext) -> dict | None:
        """Validate ash.mcpb archive contains a parseable manifest.json.

        The MCPB spec mandates manifest.json at the archive root with at
        least `name`, `version`, and `dxt_version` fields. We reach into
        the ZIP and parse the manifest to confirm Claude Desktop will
        accept it."""
        archive = ctx.out / "ash.mcpb"
        if not archive.exists():
            return {"ok": False, "reason": "ash.mcpb archive missing"}

        try:
            with zipfile.ZipFile(archive) as zf:
                names = zf.namelist()
                if "manifest.json" not in names:
                    return {"ok": False, "reason": "manifest.json missing from archive root"}
                with zf.open("manifest.json") as f:
                    manifest = json.loads(f.read().decode("utf-8"))
        except zipfile.BadZipFile as e:
            return {"ok": False, "reason": f"ash.mcpb is not a valid ZIP: {e}"}
        except json.JSONDecodeError as e:
            return {"ok": False, "reason": f"manifest.json inside archive invalid: {e}"}

        for required in ("name", "version", "manifest_version"):
            if required not in manifest:
                return {"ok": False, "reason": f"manifest.json missing `{required}`"}

        return {"ok": True, "detail": f"ash.mcpb OK ({len(names)} entries, manifest_version={manifest['manifest_version']})"}

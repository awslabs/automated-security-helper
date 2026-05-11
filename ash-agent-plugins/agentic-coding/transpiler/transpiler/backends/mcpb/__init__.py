"""MCPB / Claude Desktop one-click install backend.

Emits both the source `manifest.json` (committed for review) and a
deterministic `.mcpb` ZIP archive (committed binary). The archive is what
end-users double-click in Claude Desktop to install ASH as an MCP server
with no terminal commands.

The release() phase copies `ash.mcpb` into the dist/ directory with the
manifest version embedded in the filename, so a CI release workflow can
attach it to a GitHub release with a stable name.
"""
from __future__ import annotations

import shutil

from ...core import BaseBackend, BuildContext, BuildPhase, MCPBBundle
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
        """Copy the deterministic .mcpb archive to the dist directory with a
        version-stamped filename (e.g. dist/ash-1.0.0.mcpb). The plain
        ash.mcpb in plugins/mcpb/ stays as the canonical, committed artifact;
        dist/ is the staging area for release uploads."""
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

"""MCPB backend.

Emits a .mcpb ZIP archive (manifest.json + bundled assets) for one-click
install in Claude Desktop. The archive is committed; the release phase
copies it into dist/ for GitHub release attachment.
"""
from __future__ import annotations

from pathlib import Path

import json
import shutil
import zipfile

from ...core import (
    BaseBackend,
    BuildContext,
    BuildPhase,
    MCPBBundle,
)
from ...formats import MCPB_BUNDLE
from ...registry import register_backend


@register_backend
class MCPBBackend(BaseBackend):
    NAME = "mcpb"
    OUTPUT_DIR = "mcpb"
    FORMAT = MCPB_BUNDLE

    MCPB_BUNDLE = MCPBBundle(
        archive_path="ash.mcpb",
        manifest_version="0.4",
        server_type="binary",
        server_entry_point="uvx",
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

        structural = {
            "ok": True,
            "detail": f"ash.mcpb OK ({len(names)} entries, manifest_version={manifest['manifest_version']})",
        }
        # Upgrade to the official validator when @anthropic-ai/mcpb is present.
        # Per github.com/modelcontextprotocol/mcpb/blob/main/CLI.md, `mcpb
        # validate` accepts a manifest path or directory. We extract the
        # manifest from the archive and validate it directly — `mcpb
        # validate` does not accept .mcpb archives.
        import tempfile
        pins = self._load_cli_pins(ctx.base_dir)
        if "mcpb" in pins:
            ver = self._assert_version_pin("mcpb", ["mcpb", "--version"], pins["mcpb"])
            if ver and ver.get("ok") is False:
                return ver
        with tempfile.TemporaryDirectory() as tmp:
            manifest_out = Path(tmp) / "manifest.json"
            manifest_out.write_text(json.dumps(manifest, indent=2))
            cli_result = self._invoke_validator(
                ["mcpb", "validate", str(manifest_out)],
            )
        if cli_result.get("ok") is False:
            return cli_result
        if cli_result.get("skipped"):
            return structural
        return {
            "ok": True,
            "detail": f"{structural['detail']}; mcpb validate OK",
        }

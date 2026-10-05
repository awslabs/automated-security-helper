"""MCPB backend.

Emits a .mcpb ZIP archive for one-click install in Claude Desktop. The archive
is committed; the release phase copies it into dist/ for GitHub release
attachment.

WHAT IS ACTUALLY IN THE ARCHIVE

Exactly one member: manifest.json, authored here from _base/manifest.json and
_base/mcp.json. No assets are bundled, and that is the correct shape rather than
an unfinished one -- the manifest's mcp_config invokes uvx against a pinned git
ref, so the server is fetched at run time by the user's own uvx. There is
nothing to vendor, and nothing has been left out.

This docstring used to say "manifest.json + bundled assets". That describes an
archive that has never existed, and the direction of the error is the dangerous
one: it reads as an invitation to add the assets somebody assumed were missing.
packaging/README.md draws the line those additions would cross -- ASH's own code
may ship in a published artifact, third-party code never may. One ASH-authored
manifest sits on the permitted side.

It stays there only while the member count is one, which is why the release path
asserts that count rather than trusting this comment. That is the same one-file
invariant the .deb and .rpm are held to by counting bundled wheels: cheap to
check, hard to get wrong by accident, and it turns "did anyone vendor a scanner"
from a per-file judgment into arithmetic.
"""

from __future__ import annotations

from pathlib import Path

import json
import shutil
import zipfile
import zlib

from ...core import (
    BaseBackend,
    BuildContext,
    BuildPhase,
    MCPBBundle,
)
from ...formats import MCPB_BUNDLE
from ...cli_tools import CLI_MCPB
from ...registry import register_backend


@register_backend
class MCPBBackend(BaseBackend):
    NAME = "mcpb"
    OUTPUT_DIR = "mcpb"
    FORMAT = MCPB_BUNDLE
    CLI_TOOLS = (CLI_MCPB,)

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
        artifact; dist/ is the staging area for release uploads.

        READ THIS BEFORE "FIXING" THE VERSION IN THAT FILENAME

        ctx.manifest.version is the *plugin* version from
        transpiler/_base/manifest.json. It is deliberately not ASH's package
        version, so a release attaches an asset named after the plugin version.
        That looks like a bug and is not one: pyproject.toml's
        [tool.commitizen] version_files matches `_base/manifest.json:ash_version`
        specifically so that a bump rewrites the ASH tag the manifest pins
        WITHOUT touching this field. Wiring this filename to the ASH version
        would mean a version_files entry that matches the plugin `version` key,
        which is the collision that entry is written to avoid.

        This copy is a plain copy2 of a committed file, so it proves nothing
        about the archive's contents on its own. What establishes that the
        attached asset matches _base/ is `agentic-plugins check`, which rebuilds
        every backend into a sandbox and byte-compares, ash.mcpb included. The
        release workflow runs that check before calling this phase for exactly
        that reason; without it, release would publish a hand-edited archive."""
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

        The MCPB spec mandates manifest.json at the archive root. The three
        fields required below -- `name`, `version`, `manifest_version` -- are
        the ones this check enforces. `manifest_version` and not
        `dxt_version`: MCPB was renamed from DXT (Desktop Extensions), and the
        version key was renamed with it.

        A damaged archive is reported, not raised. zipfile validates the
        container from the central directory, so a corrupt deflate stream gets
        past BadZipFile and surfaces from the member read as zlib.error, and a
        manifest that is not valid UTF-8 raises UnicodeDecodeError, which is not
        a json.JSONDecodeError. validate.validate_mcpb_archive handles the same
        two cases the same way."""
        archive = ctx.out / "ash.mcpb"
        if not archive.exists():
            return {"ok": False, "reason": "ash.mcpb archive missing"}

        try:
            with zipfile.ZipFile(archive) as zf:
                names = zf.namelist()
                if "manifest.json" not in names:
                    return {
                        "ok": False,
                        "reason": "manifest.json missing from archive root",
                    }
                with zf.open("manifest.json") as f:
                    manifest = json.loads(f.read().decode("utf-8"))
        except (zipfile.BadZipFile, zlib.error) as e:
            return {"ok": False, "reason": f"ash.mcpb is not a valid ZIP: {e}"}
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
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

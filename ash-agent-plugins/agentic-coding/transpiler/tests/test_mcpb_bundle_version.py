"""The .mcpb bundle's `version` is the ASH release it launches, not the plugin version.

A desktop MCP host compares a bundle's manifest `version` to decide whether a download
replaces what it has installed. The bundle used to carry the plugin version, 1.0.0 on
every release, so the host could not see one bundle replace the next. The version is
now derived from `_base/manifest.json:ash_version`, the field commitizen bumps; these
tests hold the derivation, the committed archive and the release file name to it.
"""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from transpiler.packagers import mcpb_bundle_version

TRANSPILER = Path(__file__).resolve().parents[1]
BASE_MANIFEST = TRANSPILER / "_base" / "manifest.json"
COMMITTED = TRANSPILER.parent / "plugins" / "mcpb" / "ash.mcpb"


def test_the_bundle_version_is_the_ash_release_tag_without_its_v():
    assert mcpb_bundle_version("v4.0.0") == "4.0.0"
    assert mcpb_bundle_version("v10.2.13") == "10.2.13"


@pytest.mark.parametrize("tag", ["4.0.0", "v4.0", "v4.0.0rc1", "", "latest"])
def test_a_tag_that_is_not_a_release_is_refused(tag):
    with pytest.raises(ValueError, match="not a release tag"):
        mcpb_bundle_version(tag)


def test_the_committed_bundle_carries_the_ash_version():
    base = json.loads(BASE_MANIFEST.read_text(encoding="utf-8"))
    with zipfile.ZipFile(COMMITTED) as archive:
        bundled = json.loads(archive.read("manifest.json").decode("utf-8"))
    assert bundled["version"] == base["ash_version"].removeprefix("v")
    # The plugin version is a different number, and must not be what the bundle says.
    assert base["version"] != bundled["version"]


def test_the_release_file_is_named_after_the_bundle_version(tmp_path):
    from transpiler import orchestrator

    base = json.loads(BASE_MANIFEST.read_text(encoding="utf-8"))
    orchestrator.release_one("mcpb", tmp_path)
    staged = sorted(p.name for p in tmp_path.glob("*.mcpb"))
    assert staged == [f"ash-{base['ash_version'].removeprefix('v')}.mcpb"]

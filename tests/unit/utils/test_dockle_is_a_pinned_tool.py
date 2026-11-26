# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""dockle, the container-image linter's tool, is a pinned tool.

It follows the repository's pinned-tool conventions like gosec and trivy: a
version, a release-asset table per platform, a digest for each archive and for
the executable inside it, a license entry, and an install line in the image.
The dockle register declares the pinned shape (runtime PINNED_BINARY,
``tool_versions_key`` ``dockle``, the four platforms the release builds for);
these tests hold the pin tables to it. The archive digests are transcribed from
the release's own ``dockle_0.4.15_checksums.txt`` and were re-verified by
downloading each asset.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.core.exceptions import ToolNotProvisionableError
from automated_security_helper.utils import tool_downloads
from automated_security_helper.utils.tool_downloads import (
    THIRD_PARTY_LICENSES,
    TOOL_VERSIONS,
    get_tool_asset,
    supported_platforms,
)

pytestmark = pytest.mark.unit

PLATFORMS = [
    ("linux", "amd64"),
    ("linux", "arm64"),
    ("darwin", "amd64"),
    ("darwin", "arm64"),
]


@pytest.mark.parametrize("platform_arch", PLATFORMS)
def test_every_platform_resolves_a_pinned_asset(platform_arch):
    asset = get_tool_asset("dockle", *platform_arch)
    assert asset.version == TOOL_VERSIONS["dockle"] == "v0.4.15"
    assert asset.url.startswith(
        "https://github.com/goodwithtech/dockle/releases/download/v0.4.15/dockle_0.4.15_"
    )
    assert asset.archive is True
    assert len(asset.sha256) == 64
    assert asset.executable_sha256 is not None and len(asset.executable_sha256) == 64
    assert asset.member_name == "dockle"


def test_the_published_platforms_are_the_four_the_release_builds():
    # dockle v0.4.15 publishes Linux and macOS archives for amd64 and arm64 (plus
    # 32-bit, ARM and loong64 Linux, outside ASH's platform vocabulary) and no
    # Windows build at all.
    assert sorted(supported_platforms("dockle")) == sorted(PLATFORMS)


@pytest.mark.parametrize("platform_arch", [("windows", "amd64"), ("windows", "arm64")])
def test_windows_is_refused_by_name(platform_arch):
    with pytest.raises(ToolNotProvisionableError):
        get_tool_asset("dockle", *platform_arch)


def test_the_license_entry_names_the_pinned_version():
    entry = THIRD_PARTY_LICENSES["dockle"]
    assert entry.version == TOOL_VERSIONS["dockle"]
    assert entry.license == "Apache-2.0"
    assert entry.repository == "https://github.com/goodwithtech/dockle"
    assert len(entry.commit) == 40
    # The release archive carries the Apache-2.0 text as LICENSE; the image stages
    # it from the archive, so the file needs no URL digest of its own.
    assert [f.name for f in entry.files] == ["LICENSE"]
    assert all(f.url is None for f in entry.files)


def test_the_register_citation_and_the_entry_agree_on_the_read():
    """The operational register's license read cites the bytes this pin installs."""
    from automated_security_helper.plugin_modules.ash_dockle_plugins.dockle_scanner import (
        DockleScanner,
    )

    citation = DockleScanner.operational_facets.provenance.upstream_license
    assert citation.startswith("Apache-2.0 (source: LICENSE in dockle_0.4.15_")
    assert TOOL_VERSIONS["dockle"].lstrip("v") in citation
    assert THIRD_PARTY_LICENSES["dockle"].commit[:8] in citation


def test_the_image_installs_the_pinned_dockle():
    dockerfile = (Path(__file__).resolve().parents[3] / "Dockerfile").read_text()
    assert "install-pinned-tool dockle " in dockerfile
    assert f'ARG DOCKLE_VERSION="{TOOL_VERSIONS["dockle"]}"' in dockerfile
    assert "RUN dockle --version" in dockerfile


def test_the_digest_tables_agree_on_the_assets():
    for filename in tool_downloads._DOCKLE_ASSETS.values():
        assert filename in tool_downloads._DIGESTS
        assert filename in tool_downloads._EXECUTABLE_DIGESTS

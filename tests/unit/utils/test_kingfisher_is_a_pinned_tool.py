# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""kingfisher, the alpha secret scanner's tool, is a pinned tool.

Same conventions as grype and crane: a version, a release-asset table per
platform, a digest for each archive and for the executable inside it, a license
entry, and an install line in the image. kingfisher names its assets without a
version (``kingfisher-linux-x64.tgz`` in every release), so like crane and
hadolint it also has a ``_DIGESTS_TAKEN_AT`` row: a version bump that forgets
the digests is refused by name instead of failing as a digest mismatch. The
release publishes no checksums file, so the digests were taken by downloading
each asset and hashing it, and the executables inside were hashed the same way
(the provenance comment above the digest table says so).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.utils import tool_downloads
from automated_security_helper.utils.tool_downloads import (
    THIRD_PARTY_LICENSES,
    TOOL_VERSIONS,
    get_tool_asset,
)

pytestmark = pytest.mark.unit

PLATFORMS = [
    ("linux", "amd64"),
    ("linux", "arm64"),
    ("darwin", "amd64"),
    ("darwin", "arm64"),
    ("windows", "amd64"),
    ("windows", "arm64"),
]


@pytest.mark.parametrize("platform_arch", PLATFORMS)
def test_every_platform_resolves_a_pinned_asset(platform_arch):
    asset = get_tool_asset("kingfisher", *platform_arch)
    assert asset.version == TOOL_VERSIONS["kingfisher"] == "v2.19.1"
    assert asset.url.startswith(
        "https://github.com/mongodb/kingfisher/releases/download/v2.19.1/kingfisher-"
    )
    assert asset.archive is True
    assert len(asset.sha256) == 64
    assert asset.executable_sha256 is not None and len(asset.executable_sha256) == 64
    assert asset.member_name == (
        "kingfisher.exe" if platform_arch[0] == "windows" else "kingfisher"
    )


def test_an_unlisted_platform_is_refused_by_name():
    from automated_security_helper.core.exceptions import ToolNotProvisionableError

    with pytest.raises(ToolNotProvisionableError):
        get_tool_asset("kingfisher", "linux", "ppc64le")


def test_versionless_asset_names_have_a_digests_taken_at_row():
    assert tool_downloads._DIGESTS_TAKEN_AT["kingfisher"] == TOOL_VERSIONS["kingfisher"]


def test_the_license_entry_names_the_pinned_version():
    entry = THIRD_PARTY_LICENSES["kingfisher"]
    assert entry.version == TOOL_VERSIONS["kingfisher"]
    assert entry.license == "Apache-2.0"
    assert entry.repository == "https://github.com/mongodb/kingfisher"
    assert len(entry.commit) == 40
    # The release archive holds the executable, a CHECKSUM.txt and third-party
    # notices, but no license file, so the LICENSE comes from the repository at
    # the pinned commit, with its own digest.
    license_files = [f for f in entry.files if f.name == "LICENSE"]
    assert len(license_files) == 1
    assert license_files[0].url is not None
    assert entry.commit in license_files[0].url
    assert len(license_files[0].sha256) == 64


def test_the_register_claims_the_pin():
    """The operational register flips to the pinned shape with the pin."""
    from automated_security_helper.base import scanner_operational_facets as opsf
    from automated_security_helper.plugin_modules.ash_kingfisher_plugins.kingfisher_scanner import (
        KingfisherScanner,
    )

    facets = KingfisherScanner.operational_facets
    assert facets.runtime.kind is opsf.RuntimeKind.PINNED_BINARY
    assert facets.runtime.tool_versions_key == "kingfisher"
    assert facets.platforms.provisionable == opsf.PLATFORMS_ALL


def test_the_image_installs_the_pinned_kingfisher():
    dockerfile = (Path(__file__).resolve().parents[3] / "Dockerfile").read_text()
    assert "install-pinned-tool kingfisher " in dockerfile
    assert f'ARG KINGFISHER_VERSION="{TOOL_VERSIONS["kingfisher"]}"' in dockerfile


def test_the_digest_tables_agree_on_the_assets():
    for filename in tool_downloads._KINGFISHER_ASSETS.values():
        assert filename in tool_downloads._DIGESTS
        assert filename in tool_downloads._EXECUTABLE_DIGESTS

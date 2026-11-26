# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""crane, the registry client that resolves a tag to a digest, is a pinned tool.

It follows the repository's pinned-tool conventions like grype and syft: a
version, a release-asset table per platform, a digest for each archive and for
the executable inside it, a license entry, and an install line in the image.
Which scanners declare the registry read it makes is pinned too, so the network
use of the resolver is in the register and not only in the code.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.base import scanner_operational_facets as opsf
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
]


@pytest.mark.parametrize("platform_arch", PLATFORMS)
def test_every_platform_resolves_a_pinned_asset(platform_arch):
    asset = get_tool_asset("crane", *platform_arch)
    assert asset.version == TOOL_VERSIONS["crane"] == "v0.22.1"
    assert asset.url.startswith(
        "https://github.com/google/go-containerregistry/releases/download/v0.22.1/"
        "go-containerregistry_"
    )
    assert asset.archive is True
    assert len(asset.sha256) == 64
    assert asset.executable_sha256 is not None and len(asset.executable_sha256) == 64
    assert asset.member_name == (
        "crane.exe" if platform_arch[0] == "windows" else "crane"
    )


def test_an_unlisted_platform_is_refused_by_name():
    from automated_security_helper.core.exceptions import ToolNotProvisionableError

    with pytest.raises(ToolNotProvisionableError):
        get_tool_asset("crane", "windows", "arm64")


def test_the_license_entry_names_the_pinned_version():
    entry = THIRD_PARTY_LICENSES["crane"]
    assert entry.version == TOOL_VERSIONS["crane"]
    assert entry.license == "Apache-2.0"
    assert entry.repository == "https://github.com/google/go-containerregistry"


def test_the_image_installs_the_pinned_crane():
    dockerfile = (Path(__file__).resolve().parents[3] / "Dockerfile").read_text()
    assert "install-pinned-tool crane " in dockerfile
    assert f'ARG CRANE_VERSION="{TOOL_VERSIONS["crane"]}"' in dockerfile


@pytest.mark.parametrize("scanner", ["grype", "trivy"])
def test_the_scanners_that_key_ids_on_the_digest_declare_the_registry_read(scanner):
    from automated_security_helper.plugin_modules.ash_builtin.scanners.grype_scanner import (
        GrypeScanner,
    )
    from automated_security_helper.plugin_modules.ash_builtin.scanners.trivy_scanner import (
        TrivyScanner,
    )

    cls = {"grype": GrypeScanner, "trivy": TrivyScanner}[scanner]
    network = cls.operational_facets.network
    assert opsf.Fetched.IMAGE_DIGEST in network.fetches
    assert network.sandbox_network is opsf.SandboxNetwork.ONLINE


def test_the_digest_tables_agree_on_the_assets():
    for filename in tool_downloads._CRANE_ASSETS.values():
        assert filename in tool_downloads._DIGESTS
        assert filename in tool_downloads._EXECUTABLE_DIGESTS


def test_the_image_asks_crane_its_version_with_the_version_subcommand():
    """crane has no --version flag. The image's license check asked it that way, and
    every image build stopped there on "Error: unknown flag: --version". Its
    `version` subcommand prints the release with no leading v (cmd/crane/cmd/version.go
    and the ldflags in the release's .goreleaser.yml, at the pinned commit), which is
    what the image's own `RUN crane version` step prints."""
    assert THIRD_PARTY_LICENSES["crane"].version_args == ("version",)
    dockerfile = (Path(__file__).resolve().parents[3] / "Dockerfile").read_text()
    assert "\nRUN crane version\n" in dockerfile

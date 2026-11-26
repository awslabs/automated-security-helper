# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""gosec, the Go SAST scanner's tool, is a pinned tool.

It follows the repository's pinned-tool conventions like grype and crane: a
version, a release-asset table per platform, a digest for each archive and for
the executable inside it, a license entry, and an install line in the image.
The gosec register already declares the pinned shape (runtime PINNED_BINARY,
``tool_versions_key`` ``gosec``, all six platforms); these tests hold the pin
tables to it. The archive digests are transcribed from the release's own
``gosec_2.30.0_checksums.txt`` and were re-verified by downloading each asset.
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
    asset = get_tool_asset("gosec", *platform_arch)
    assert asset.version == TOOL_VERSIONS["gosec"] == "v2.30.0"
    assert asset.url.startswith(
        "https://github.com/securego/gosec/releases/download/v2.30.0/gosec_2.30.0_"
    )
    assert asset.archive is True
    assert len(asset.sha256) == 64
    assert asset.executable_sha256 is not None and len(asset.executable_sha256) == 64
    assert asset.member_name == (
        "gosec.exe" if platform_arch[0] == "windows" else "gosec"
    )


def test_an_unlisted_platform_is_refused_by_name():
    from automated_security_helper.core.exceptions import ToolNotProvisionableError

    # The release also publishes linux ppc64le and s390x archives; ASH's platform
    # vocabulary has no such arch, and an unknown pair is refused, never guessed.
    with pytest.raises(ToolNotProvisionableError):
        get_tool_asset("gosec", "linux", "ppc64le")


def test_the_license_entry_names_the_pinned_version():
    entry = THIRD_PARTY_LICENSES["gosec"]
    assert entry.version == TOOL_VERSIONS["gosec"]
    assert entry.license == "Apache-2.0"
    assert entry.repository == "https://github.com/securego/gosec"
    assert len(entry.commit) == 40
    # The release archive carries the Apache-2.0 text as LICENSE.txt; the image
    # stages it from the archive, so the file needs no URL digest of its own.
    assert [f.name for f in entry.files] == ["LICENSE.txt"]
    assert all(f.url is None for f in entry.files)


def test_the_register_citation_and_the_entry_agree_on_the_read():
    """The operational register's license read cites the bytes this pin installs."""
    from automated_security_helper.plugin_modules.ash_gosec_plugins.gosec_scanner import (
        GosecScanner,
    )

    citation = GosecScanner.operational_facets.provenance.upstream_license
    assert citation.startswith("Apache-2.0 (source: LICENSE.txt in gosec_2.30.0_")
    assert TOOL_VERSIONS["gosec"].lstrip("v") in citation


def test_the_image_installs_the_pinned_gosec():
    dockerfile = (Path(__file__).resolve().parents[3] / "Dockerfile").read_text()
    assert "install-pinned-tool gosec " in dockerfile
    assert f'ARG GOSEC_VERSION="{TOOL_VERSIONS["gosec"]}"' in dockerfile


def test_the_digest_tables_agree_on_the_assets():
    for filename in tool_downloads._GOSEC_ASSETS.values():
        assert filename in tool_downloads._DIGESTS
        assert filename in tool_downloads._EXECUTABLE_DIGESTS

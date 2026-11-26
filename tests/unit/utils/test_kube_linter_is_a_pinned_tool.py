# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""kube-linter, the alpha Kubernetes linter's tool, is a pinned tool.

Same conventions as grype, crane and kingfisher: a version, a release-asset table per
platform, a digest for each archive and for the executable inside it, a license entry,
and an install line in the image. KubeLinter names its assets without a version
(``kube-linter-linux.tar.gz`` in every release), so it also has a ``_DIGESTS_TAKEN_AT``
row: a version bump that forgets the digests is refused by name instead of failing as
a digest mismatch. The release publishes no checksums file; the archive digests are
the ``digest`` GitHub reports for each asset, confirmed by downloading and hashing it,
and the executables inside were hashed after extraction. ``kube-linter --version`` is
an unknown flag, so the license entry's version probe is ``kube-linter version``.
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

DOCKERFILE = Path(__file__).resolve().parents[3] / "Dockerfile"


@pytest.mark.parametrize("platform_arch", PLATFORMS)
def test_every_platform_resolves_a_pinned_asset(platform_arch):
    asset = get_tool_asset("kube-linter", *platform_arch)
    assert asset.version == TOOL_VERSIONS["kube-linter"] == "v0.8.3"
    assert asset.url.startswith(
        "https://github.com/stackrox/kube-linter/releases/download/v0.8.3/kube-linter-"
    )
    assert asset.url.endswith(".tar.gz")
    assert asset.archive is True
    assert len(asset.sha256) == 64
    assert asset.executable_sha256 is not None and len(asset.executable_sha256) == 64
    assert asset.member_name == (
        "kube-linter.exe" if platform_arch[0] == "windows" else "kube-linter"
    )


def test_an_unlisted_platform_is_refused_by_name():
    from automated_security_helper.core.exceptions import ToolNotProvisionableError

    with pytest.raises(ToolNotProvisionableError):
        get_tool_asset("kube-linter", "linux", "ppc64le")


def test_versionless_asset_names_have_a_digests_taken_at_row():
    assert (
        tool_downloads._DIGESTS_TAKEN_AT["kube-linter"] == TOOL_VERSIONS["kube-linter"]
    )


def test_a_half_applied_bump_is_refused_by_name(monkeypatch):
    from automated_security_helper.core.exceptions import ToolNotProvisionableError

    monkeypatch.setitem(tool_downloads.TOOL_VERSIONS, "kube-linter", "v0.9.0")
    with pytest.raises(ToolNotProvisionableError, match="half-applied"):
        get_tool_asset("kube-linter", "linux", "amd64")


def test_the_digest_tables_agree_on_the_assets():
    assets = tool_downloads._KUBE_LINTER_ASSETS
    assert sorted(assets) == sorted(PLATFORMS)
    for filename in assets.values():
        assert filename in tool_downloads._DIGESTS
        assert filename in tool_downloads._EXECUTABLE_DIGESTS
        # The archive and the executable inside it are different bytes.
        assert (
            tool_downloads._DIGESTS[filename]
            != tool_downloads._EXECUTABLE_DIGESTS[filename]
        )


def test_the_license_entry_names_the_pinned_version():
    entry = THIRD_PARTY_LICENSES["kube-linter"]
    assert entry.version == TOOL_VERSIONS["kube-linter"]
    assert entry.license == "Apache-2.0"
    assert not entry.copyleft
    assert entry.repository == "https://github.com/stackrox/kube-linter"
    assert len(entry.commit) == 40
    # Every release archive carries the Apache-2.0 text as LICENSE beside the
    # executable, so the image reads it from the archive the digest already checked.
    assert [f.name for f in entry.files] == ["LICENSE"]
    assert entry.files[0].from_archive


def test_the_version_check_is_the_version_subcommand():
    entry = THIRD_PARTY_LICENSES["kube-linter"]
    assert entry.version_probe == ("kube-linter", "version")
    assert not entry.executables


def test_the_register_claims_the_pin():
    from automated_security_helper.base import scanner_operational_facets as opsf
    from automated_security_helper.plugin_modules.ash_kube_linter_plugins.kube_linter_scanner import (
        KubeLinterScanner,
    )

    facets = KubeLinterScanner.operational_facets
    assert facets.runtime.kind is opsf.RuntimeKind.PINNED_BINARY
    assert facets.runtime.tool_versions_key == "kube-linter"
    assert facets.platforms.provisionable == opsf.PLATFORMS_ALL
    assert facets.provenance.source is opsf.ProvenanceSource.PINNED_RELEASE_BINARY


def test_the_register_citation_names_the_pinned_release():
    from automated_security_helper.plugin_modules.ash_kube_linter_plugins.kube_linter_scanner import (
        KubeLinterScanner,
    )

    citation = KubeLinterScanner.operational_facets.provenance.upstream_license
    assert citation.startswith("Apache-2.0 (source: the LICENSE file inside the ")
    assert TOOL_VERSIONS["kube-linter"] in citation
    assert THIRD_PARTY_LICENSES["kube-linter"].commit[:8] in citation


def test_the_image_installs_and_smoke_checks_the_pinned_kube_linter():
    dockerfile = DOCKERFILE.read_text()
    assert "install-pinned-tool kube-linter -b /usr/local/bin" in dockerfile
    assert f'ARG KUBE_LINTER_VERSION="{TOOL_VERSIONS["kube-linter"]}"' in dockerfile
    assert "RUN kube-linter version" in dockerfile
    assert "automated_security_helper.plugin_modules.ash_kube_linter_plugins" in (
        dockerfile
    )

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""conftest, the policy-test scanner's tool, is a pinned tool.

It follows the repository's pinned-tool conventions like gosec and grype: a
version, a release-asset table per platform, a digest for each archive and for
the executable inside it, a license entry, and an install line in the image.
The conftest register declares the pinned shape (runtime PINNED_BINARY,
``tool_versions_key`` ``conftest``, all six platforms); these tests hold the pin
tables to it. The archive digests are transcribed from the release's own
``checksums.txt`` and were re-verified by downloading each asset.

Nix mode and Homebrew do not install the pin. The repository flake supplies
nixpkgs' conftest, whose version the flake records beside it, and the Nix CI leg
proves it runs; the install-package facet names the flake and the Homebrew formula
for ``--providers``.
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
    ("windows", "arm64"),
]

ROOT = Path(__file__).resolve().parents[3]
DOCKERFILE = ROOT / "Dockerfile"
FLAKE = ROOT / "flake.nix"
NIX_ACTION = ROOT / ".github" / "actions" / "validate-nix" / "action.yml"


@pytest.mark.parametrize("platform_arch", PLATFORMS)
def test_every_platform_resolves_a_pinned_asset(platform_arch):
    asset = get_tool_asset("conftest", *platform_arch)
    assert asset.version == TOOL_VERSIONS["conftest"] == "v0.62.0"
    assert asset.url.startswith(
        "https://github.com/open-policy-agent/conftest/releases/download/v0.62.0/"
        "conftest_0.62.0_"
    )
    assert asset.archive is True
    assert len(asset.sha256) == 64
    assert asset.executable_sha256 is not None and len(asset.executable_sha256) == 64
    assert asset.member_name == (
        "conftest.exe" if platform_arch[0] == "windows" else "conftest"
    )


@pytest.mark.parametrize("arch", ["ppc64le", "s390x"])
def test_an_unlisted_platform_is_refused_by_name(arch):
    from automated_security_helper.core.exceptions import ToolNotProvisionableError

    # The release also publishes linux ppc64le and s390x archives; ASH's platform
    # vocabulary has no such arch, and an unknown pair is refused, never guessed.
    with pytest.raises(ToolNotProvisionableError):
        get_tool_asset("conftest", "linux", arch)


def test_the_license_entry_names_the_pinned_version():
    entry = THIRD_PARTY_LICENSES["conftest"]
    assert entry.version == TOOL_VERSIONS["conftest"]
    assert entry.license == "Apache-2.0"
    assert entry.repository == "https://github.com/open-policy-agent/conftest"
    assert len(entry.commit) == 40
    # Every pinned release archive carries the license as LICENSE; the image
    # stages it from the archive, so the file needs no URL digest of its own.
    assert [f.name for f in entry.files] == ["LICENSE"]
    assert all(f.url is None for f in entry.files)


def test_the_register_declares_the_pinned_shape_the_tables_hold():
    from automated_security_helper.plugin_modules.ash_conftest_plugins.conftest_scanner import (
        ConftestScanner,
    )

    row = ConftestScanner.operational_facets
    assert row.runtime.kind is opsf.RuntimeKind.PINNED_BINARY
    assert row.runtime.tool_versions_key == "conftest"
    assert row.platforms.provisionable == opsf.PLATFORMS_ALL
    assert row.provenance.source is opsf.ProvenanceSource.PINNED_RELEASE_BINARY


def test_the_register_citation_and_the_entry_agree_on_the_read():
    """The operational register's license read cites the bytes this pin installs."""
    from automated_security_helper.plugin_modules.ash_conftest_plugins.conftest_scanner import (
        ConftestScanner,
    )

    citation = ConftestScanner.operational_facets.provenance.upstream_license
    assert citation.startswith("Apache-2.0 (source: LICENSE in conftest_0.62.0_")
    assert TOOL_VERSIONS["conftest"].lstrip("v") in citation
    assert THIRD_PARTY_LICENSES["conftest"].license == citation.split(" ", 1)[0]


def test_the_image_installs_the_pinned_conftest():
    dockerfile = DOCKERFILE.read_text(encoding="utf-8")
    assert "install-pinned-tool conftest " in dockerfile
    assert f'ARG CONFTEST_VERSION="{TOOL_VERSIONS["conftest"]}"' in dockerfile
    assert "\nRUN conftest --version\n" in dockerfile


def test_the_image_loads_the_plugin_module_in_both_stages():
    dockerfile = DOCKERFILE.read_text(encoding="utf-8")
    module = "automated_security_helper.plugin_modules.ash_conftest_plugins"
    lists = [
        line
        for line in dockerfile.splitlines()
        if line.startswith('ARG ASH_ALPHA_PLUGIN_MODULES="')
    ]
    assert len(lists) == 2, lists
    for line in lists:
        assert module in line.split('"')[1].split(","), line


def test_the_digest_tables_agree_on_the_assets():
    for filename in tool_downloads._CONFTEST_ASSETS.values():
        assert filename in tool_downloads._DIGESTS
        assert filename in tool_downloads._EXECUTABLE_DIGESTS


def _comment_above(text: str, line: str) -> str:
    """The run of ``#`` comment lines directly above ``line`` in ``text``."""
    lines = text.splitlines()
    index = lines.index(line)
    note = []
    while index > 0 and lines[index - 1].lstrip().startswith("#"):
        index -= 1
        note.insert(0, lines[index].strip())
    return " ".join(note)


def test_the_flake_supplies_conftest_and_records_the_version_gap():
    flake = FLAKE.read_text(encoding="utf-8")
    scanners = flake.split("scannersFor = system:", 1)[1].split("in\n    {", 1)[0]
    assert "\n          pkgs.conftest\n" in scanners
    note = _comment_above(flake, "          pkgs.conftest")
    # nixpkgs' version at the locked revision, and the pin it differs from.
    assert "0.63.0" in note and TOOL_VERSIONS["conftest"] in note, note


def test_the_nix_leg_loads_the_module_seeds_a_policy_and_requires_conftest():
    text = NIX_ACTION.read_text(encoding="utf-8")
    module = "automated_security_helper.plugin_modules.ash_conftest_plugins"
    assert f"--ash-plugin-modules {module}" in text
    # Without Rego the policy gate reads SKIPPED with or without a binary, so the leg
    # writes one; its deny fires on the fixture template.
    assert "/tmp/ash-nix-selftest/policy/fixture.rego" in text
    assert "deny contains msg if {" in text
    listing = text.split("flake_supplied = [", 1)[1].split("]", 1)[0]
    assert '"conftest",' in listing
    assert 'statuses["conftest"].upper() != "FAILED"' in text


def test_the_install_facet_offers_the_nix_and_brew_routes():
    from automated_security_helper.base.install_package_facets import (
        INSTALL_PACKAGE_FACETS,
        NIX_FLAKE_OUTPUT,
        install_package_facet,
    )

    facet = install_package_facet("conftest")
    assert facet is INSTALL_PACKAGE_FACETS["conftest"]
    nix = facet.row_for("nix")
    assert nix is not None and nix.package == NIX_FLAKE_OUTPUT and nix.caveat
    brew = facet.row_for("brew")
    assert brew is not None and brew.package == "conftest" and brew.caveat

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The install-package facet is declared data, consistent with the providers.

Every row names an ecosystem that is an implemented install provider (a row for a
stub would promise a route that refuses), a row's package is not blank, a tool is
declared once, the Nix rows name the flake output the repository actually builds,
and a row scoped to some platforms matches what the flake lists for them.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from automated_security_helper.base.install_package_facets import (
    DEFAULT_PREFERENCE,
    INSTALL_PACKAGE_FACETS,
    NIX_FLAKE_OUTPUT,
    ROW_PLATFORMS,
    EcosystemPackage,
    install_package_facet,
)
from automated_security_helper.utils.install_providers import INSTALL_PROVIDERS

pytestmark = pytest.mark.unit

_FLAKE = Path(__file__).parents[3] / "flake.nix"

#: The flake's Linux-only addition to ``scannersFor``.
_LINUX_ONLY_ENTRIES = re.compile(
    r"\+\+\s*pkgs\.lib\.optionals\s+pkgs\.stdenv\.hostPlatform\.isLinux\s*"
    r"\[(?P<body>[^\]]*)\]"
)


def test_every_row_names_an_implemented_provider_and_a_package():
    for tool, facet in INSTALL_PACKAGE_FACETS.items():
        assert facet.tool == tool
        assert facet.rows, tool
        for row in facet.rows:
            provider = INSTALL_PROVIDERS.get(row.ecosystem)
            assert provider is not None and provider.implemented, (tool, row)
            assert row.package.strip(), (tool, row)
        assert len({row.ecosystem for row in facet.rows}) == len(facet.rows), tool


def test_every_preferred_ecosystem_is_a_known_provider():
    for facet in INSTALL_PACKAGE_FACETS.values():
        for name in facet.preference:
            assert name in INSTALL_PROVIDERS, (facet.tool, name)
    assert set(DEFAULT_PREFERENCE) <= set(INSTALL_PROVIDERS)


def test_a_row_that_installs_other_than_the_declared_range_says_so():
    for facet in INSTALL_PACKAGE_FACETS.values():
        for row in facet.rows:
            assert row.caveat, (facet.tool, row.ecosystem)


def test_the_nix_row_names_the_flake_output_the_repository_builds():
    flake = _FLAKE.read_text(encoding="utf-8")

    assert f"{NIX_FLAKE_OUTPUT} = pkgs.buildEnv" in flake
    for facet in INSTALL_PACKAGE_FACETS.values():
        row = facet.row_for("nix")
        if row is not None:
            assert row.package == NIX_FLAKE_OUTPUT


def test_a_scoped_row_names_known_platforms():
    for facet in INSTALL_PACKAGE_FACETS.values():
        for row in facet.rows:
            if row.platforms is not None:
                assert row.platforms, (facet.tool, row)
                assert set(row.platforms) <= set(ROW_PLATFORMS), (facet.tool, row)


@pytest.mark.parametrize("platforms", [(), ("macos",), ("linux", "solaris")])
def test_a_row_scoped_to_no_platform_or_an_unknown_one_is_refused(platforms):
    with pytest.raises(ValueError, match="is scoped to"):
        EcosystemPackage("nix", NIX_FLAKE_OUTPUT, "caveat", platforms=platforms)


def test_a_scoped_row_holds_on_its_platforms_only():
    scoped = EcosystemPackage("nix", NIX_FLAKE_OUTPUT, "caveat", platforms=("linux",))
    unscoped = EcosystemPackage("nix", NIX_FLAKE_OUTPUT, "caveat")

    assert scoped.holds_on("linux")
    assert not scoped.holds_on("darwin")
    assert not scoped.holds_on("unknown")
    assert unscoped.holds_on("darwin") and unscoped.holds_on("unknown")


def test_the_linux_scoped_nix_rows_are_the_flakes_linux_only_entries():
    """A tool the flake lists for Linux only has a nix row scoped to linux, and
    the reverse: with an unscoped nix row, ``--providers nix`` on macOS would
    realize a shell that does not carry the tool instead of refusing it."""
    flake = _FLAKE.read_text(encoding="utf-8")
    blocks = _LINUX_ONLY_ENTRIES.findall(flake)
    assert len(blocks) == 1, blocks
    listed = set(re.findall(r"pkgs\.([A-Za-z0-9_-]+)", blocks[0]))

    scoped = set()
    for tool, facet in INSTALL_PACKAGE_FACETS.items():
        row = facet.row_for("nix")
        if row is not None and row.platforms == ("linux",):
            scoped.add(tool)

    assert "dockle" in scoped
    assert scoped == listed
    for tool in listed:
        # Listed once, inside the guard: unguarded it would break the darwin outputs.
        assert len(re.findall(rf"pkgs\.{re.escape(tool)}\b", flake)) == 1, tool


def test_an_undeclared_tool_has_no_facet():
    assert install_package_facet("not-a-tool") is None
    assert install_package_facet(None) is None
    assert install_package_facet("checkov") is INSTALL_PACKAGE_FACETS["checkov"]

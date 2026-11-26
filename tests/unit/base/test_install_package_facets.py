# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The install-package facet is declared data, consistent with the providers.

Every row names an ecosystem that is an implemented install provider (a row for a
stub would promise a route that refuses), a row's package is not blank, a tool is
declared once, and the Nix rows name the flake output the repository actually builds.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.base.install_package_facets import (
    DEFAULT_PREFERENCE,
    INSTALL_PACKAGE_FACETS,
    NIX_FLAKE_OUTPUT,
    install_package_facet,
)
from automated_security_helper.utils.install_providers import INSTALL_PROVIDERS

pytestmark = pytest.mark.unit


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
    flake = (Path(__file__).parents[3] / "flake.nix").read_text(encoding="utf-8")

    assert f"{NIX_FLAKE_OUTPUT} = pkgs.buildEnv" in flake
    for facet in INSTALL_PACKAGE_FACETS.values():
        row = facet.row_for("nix")
        if row is not None:
            assert row.package == NIX_FLAKE_OUTPUT


def test_an_undeclared_tool_has_no_facet():
    assert install_package_facet("not-a-tool") is None
    assert install_package_facet(None) is None
    assert install_package_facet("checkov") is INSTALL_PACKAGE_FACETS["checkov"]

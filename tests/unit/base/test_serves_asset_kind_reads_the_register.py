# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Asset routing asks the operational-facets register, nothing else.

``serves_asset_kind`` is the one predicate the scan phase routes by (C3 of the
container-targets design): CONTAINER_IMAGE is served iff the class's OWN
register row declares ``TargetKind.CONTAINER_IMAGE``; FILESYSTEM is served by
every filesystem-side declaration and by a class with no row at all, which is
every third-party plugin the register has never seen. The rows here pin both
directions against the real builtin rows, so wiring a scanner in a later unit
(declaring CONTAINER_IMAGE on its row) flips exactly the row written for it.
"""

from __future__ import annotations

import pytest

from automated_security_helper.base.scanner_operational_facets import (
    FILESYSTEM_SIDE_KINDS,
    TargetKind,
    declared_operational_facets,
    serves_asset_kind,
)
from automated_security_helper.core.asset import AssetKind

pytestmark = pytest.mark.unit


def _grype_class():
    from automated_security_helper.plugin_modules.ash_builtin.scanners.grype_scanner import (
        GrypeScanner,
    )

    return GrypeScanner


class TestFilesystemSideKinds:
    def test_the_filesystem_side_is_everything_but_container_image(self):
        assert FILESYSTEM_SIDE_KINDS == frozenset(TargetKind) - {
            TargetKind.CONTAINER_IMAGE
        }

    def test_container_image_is_not_on_the_filesystem_side(self):
        assert TargetKind.CONTAINER_IMAGE not in FILESYSTEM_SIDE_KINDS


class TestDeclaredOperationalFacets:
    def test_a_builtin_scanner_answers_with_its_own_row(self):
        facets = declared_operational_facets(_grype_class())
        assert facets is not None
        assert facets.targets.kinds

    def test_an_undeclared_class_answers_none(self):
        class ThirdPartyScanner:
            pass

        assert declared_operational_facets(ThirdPartyScanner) is None

    def test_an_inherited_row_never_answers_for_a_subclass(self):
        class SubclassWithoutItsOwnRow(_grype_class()):
            pass

        assert declared_operational_facets(SubclassWithoutItsOwnRow) is None


class TestServesAssetKind:
    def test_a_builtin_scanner_serves_filesystem(self):
        assert serves_asset_kind(_grype_class(), AssetKind.FILESYSTEM) is True

    def test_a_wired_scanner_serves_container_image(self):
        # grype claims TargetKind.CONTAINER_IMAGE on its row since the wiring
        # commit; the iff-suite holds the claim to the dispatch override.
        assert serves_asset_kind(_grype_class(), AssetKind.CONTAINER_IMAGE) is True

    def test_an_unwired_builtin_scanner_does_not_serve_container_image(self):
        from automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner import (
            BanditScanner,
        )

        assert serves_asset_kind(BanditScanner, AssetKind.CONTAINER_IMAGE) is False

    def test_an_undeclared_class_serves_filesystem_as_today(self):
        class ThirdPartyScanner:
            pass

        assert serves_asset_kind(ThirdPartyScanner, AssetKind.FILESYSTEM) is True

    def test_an_undeclared_class_is_never_handed_an_image(self):
        class ThirdPartyScanner:
            pass

        assert serves_asset_kind(ThirdPartyScanner, AssetKind.CONTAINER_IMAGE) is False

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The asset contract: a scan's subject is an Asset naming exactly one locator.

The asset model (``core/asset.py``) is the C1 row of the container-targets
design: a FILESYSTEM asset is backed by a local directory exactly as today, and
a CONTAINER_IMAGE asset carries a resource locator, never bytes -- ASH fetches
nothing itself. These rows pin the shape every surface (CLI, MCP, orchestrator)
relies on: an ``ImageLocator`` names exactly one of a registry reference, an
OCI layout directory or a saved-image archive; an ``Asset``'s kind and its
locator can never disagree; and the models are frozen, so a plugin handed one
cannot repoint the scan's subject mid-run.
"""

from pathlib import Path

import pytest
from pydantic import ValidationError

from automated_security_helper.core.asset import (
    Asset,
    AssetKind,
    FilesystemLocator,
    ImageLocator,
)

pytestmark = pytest.mark.unit


class TestImageLocatorNamesExactlyOneShape:
    def test_a_registry_ref_alone_is_accepted(self):
        locator = ImageLocator(ref="registry.example.com/repo/app:1.2.3")
        assert locator.ref == "registry.example.com/repo/app:1.2.3"
        assert locator.oci_layout is None
        assert locator.oci_archive is None

    def test_an_oci_layout_directory_alone_is_accepted(self):
        locator = ImageLocator(oci_layout=Path("/images/app-layout"))
        assert locator.oci_layout == Path("/images/app-layout")

    def test_a_saved_archive_alone_is_accepted(self):
        locator = ImageLocator(oci_archive=Path("/images/app.tar"))
        assert locator.oci_archive == Path("/images/app.tar")

    def test_no_shape_at_all_is_refused(self):
        with pytest.raises(ValidationError, match="exactly one"):
            ImageLocator()

    def test_two_shapes_at_once_are_refused(self):
        with pytest.raises(ValidationError, match="exactly one"):
            ImageLocator(
                ref="repo/app:latest",
                oci_archive=Path("/images/app.tar"),
            )

    def test_a_blank_ref_is_refused(self):
        # A ref of whitespace names nothing; refused at construction rather
        # than carried to a scanner's argv.
        with pytest.raises(ValidationError):
            ImageLocator(ref="   ")

    def test_resolved_digest_rides_any_shape(self):
        locator = ImageLocator(
            ref="repo/app:latest",
            resolved_digest="sha256:" + "a" * 64,
        )
        assert locator.resolved_digest == "sha256:" + "a" * 64

    @pytest.mark.parametrize(
        "digest",
        [
            pytest.param("latest", id="a-tag"),
            pytest.param("sha256:abc", id="short"),
            pytest.param("sha256:" + "A" * 64, id="uppercase"),
            pytest.param("sha512:" + "a" * 128, id="another-algorithm"),
            pytest.param("sha256:" + "a" * 64 + "\n", id="trailing-newline"),
            pytest.param(" sha256:" + "a" * 64, id="padded"),
        ],
    )
    def test_a_resolved_digest_is_a_sha256_digest(self, digest):
        # The digest is pinned into the tools' argv (pulled_ref) and recorded
        # as the scan's identity; a caller's "latest" became name@latest.
        with pytest.raises(ValidationError, match="sha256"):
            ImageLocator(
                ref="repo/app:1",
                resolved_digest=digest,
                resolved_from="registry",
            )

    def test_shown_names_the_ref_or_the_path(self):
        assert ImageLocator(ref="repo/app:1").shown() == "repo/app:1"
        assert (
            ImageLocator(oci_layout=Path("/images/app-layout")).shown()
            == "/images/app-layout"
        )
        assert (
            ImageLocator(oci_archive=Path("/images/app.tar")).shown()
            == "/images/app.tar"
        )

    def test_the_locator_is_frozen(self):
        locator = ImageLocator(ref="repo/app:1")
        with pytest.raises(ValidationError):
            locator.ref = "repo/other:2"


class TestAssetKindAndLocatorAgree:
    def test_a_filesystem_asset_carries_its_root(self, tmp_path):
        asset = Asset.for_filesystem(tmp_path)
        assert asset.kind == AssetKind.FILESYSTEM
        assert asset.filesystem == FilesystemLocator(root=tmp_path)
        assert asset.image is None

    def test_an_image_asset_carries_its_locator(self):
        locator = ImageLocator(ref="repo/app:1")
        asset = Asset.for_image(locator)
        assert asset.kind == AssetKind.CONTAINER_IMAGE
        assert asset.image == locator
        assert asset.filesystem is None

    def test_a_filesystem_kind_with_an_image_locator_is_refused(self):
        with pytest.raises(ValidationError):
            Asset(
                kind=AssetKind.FILESYSTEM,
                image=ImageLocator(ref="repo/app:1"),
            )

    def test_an_image_kind_with_a_filesystem_locator_is_refused(self):
        with pytest.raises(ValidationError):
            Asset(
                kind=AssetKind.CONTAINER_IMAGE,
                filesystem=FilesystemLocator(root=Path("/src")),
            )

    def test_a_kind_with_no_locator_is_refused(self):
        with pytest.raises(ValidationError):
            Asset(kind=AssetKind.CONTAINER_IMAGE)

    def test_both_locators_at_once_are_refused(self):
        with pytest.raises(ValidationError):
            Asset(
                kind=AssetKind.FILESYSTEM,
                filesystem=FilesystemLocator(root=Path("/src")),
                image=ImageLocator(ref="repo/app:1"),
            )

    def test_the_asset_is_frozen(self):
        asset = Asset.for_image(ImageLocator(ref="repo/app:1"))
        with pytest.raises(ValidationError):
            asset.kind = AssetKind.FILESYSTEM

    def test_the_kind_values_are_the_designed_vocabulary(self):
        # The register vocabulary is TargetKind (operational facets); the asset
        # vocabulary is AssetKind, and these two literals are its whole range.
        assert {kind.value for kind in AssetKind} == {
            "filesystem",
            "container_image",
        }

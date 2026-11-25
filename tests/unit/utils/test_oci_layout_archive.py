# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An OCI image-layout directory re-packed as a docker-archive, for trivy.

The committed saved-image fixture is re-packed in both directions: archive ->
layout (the test helper, the inverse) -> archive (production), and what the
image is made of must survive: the config, each layer's bytes, and the order of
the layers.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import tarfile
from pathlib import Path

import pytest

from automated_security_helper.utils.oci_layout_archive import (
    LayoutConversionError,
    layout_to_docker_archive,
)
from tests.utils.image_archive_fixture import (
    build_secret_image_archive,
    archive_to_layout,
)

pytestmark = pytest.mark.unit

COMMITTED = (
    Path(__file__).resolve().parents[2] / "test_data" / "images" / "secret-image.tar"
)
README = COMMITTED.parent / "README.md"


def _members(archive: Path) -> dict:
    with tarfile.open(archive) as handle:
        return {
            member.name: handle.extractfile(member).read()
            for member in handle.getmembers()
            if member.isfile()
        }


def _plain(layer: bytes) -> bytes:
    """A layer as an image's diff id names it: uncompressed."""
    return gzip.decompress(layer) if layer[:2] == b"\x1f\x8b" else layer


def _the_image_of(archive: Path):
    """``(config bytes, [uncompressed layer bytes in order])`` of a docker-archive."""
    members = _members(archive)
    listing = json.loads(members["manifest.json"])[0]
    return (
        members[listing["Config"]],
        [_plain(members[name]) for name in listing["Layers"]],
    )


class TestTheCommittedFixture:
    def test_the_readme_records_the_archives_sha256(self):
        digest = hashlib.sha256(COMMITTED.read_bytes()).hexdigest()
        assert digest in README.read_text(encoding="utf-8")

    def test_the_builder_reproduces_the_committed_image(self, tmp_path):
        """Member by member and decompressed: deflate bytes are the building
        zlib's, so the committed file is pinned by its digest above and the
        builder by the image it writes."""
        rebuilt = build_secret_image_archive(tmp_path / "again.tar")
        assert _the_image_of(rebuilt) == _the_image_of(COMMITTED)
        assert sorted(_members(rebuilt)) == sorted(_members(COMMITTED))

    def test_the_committed_bytes_hold_no_token_text(self):
        assert b"ghp_" not in COMMITTED.read_bytes()

    def test_the_layer_matches_the_diff_id_the_config_names(self):
        config, (layer,) = _the_image_of(COMMITTED)
        diff_id = json.loads(config)["rootfs"]["diff_ids"][0]
        assert diff_id == f"sha256:{hashlib.sha256(layer).hexdigest()}"


class TestRepackRoundTrip:
    @pytest.mark.parametrize("compress", [True, False], ids=["gzip", "plain"])
    def test_archive_to_layout_to_archive_keeps_the_image(self, tmp_path, compress):
        saved = build_secret_image_archive(tmp_path / "saved.tar", compress=compress)
        layout = archive_to_layout(saved, tmp_path / "layout")
        repacked = layout_to_docker_archive(layout, tmp_path / "repacked.tar")

        assert _the_image_of(repacked) == _the_image_of(saved)

    def test_a_gzip_layer_is_written_uncompressed(self, tmp_path):
        layout = archive_to_layout(COMMITTED, tmp_path / "layout")
        repacked = layout_to_docker_archive(layout, tmp_path / "repacked.tar")
        members = _members(repacked)
        listing = json.loads(members["manifest.json"])[0]
        for name in listing["Layers"]:
            assert members[name][:2] != b"\x1f\x8b"
            assert members[name][257:262] == b"ustar"

    def test_the_layers_stay_in_the_manifests_order(self, tmp_path):
        saved = build_secret_image_archive(tmp_path / "saved.tar")
        layout = archive_to_layout(saved, tmp_path / "layout")
        # A second, different layer on top: the order the manifest lists is the
        # order the archive's manifest.json lists.
        blobs = layout / "blobs" / "sha256"
        # Two zero blocks are a valid, empty tar stream.
        extra = b"\0" * 1024
        extra_hex = hashlib.sha256(extra).hexdigest()
        (blobs / extra_hex).write_bytes(extra)
        manifest_path = next(
            path for path in blobs.iterdir() if b"schemaVersion" in path.read_bytes()
        )
        manifest = json.loads(manifest_path.read_text())
        first = manifest["layers"][0]["digest"]
        manifest["layers"].append(
            {
                "mediaType": "application/vnd.oci.image.layer.v1.tar",
                "digest": f"sha256:{extra_hex}",
                "size": len(extra),
            }
        )
        manifest_path.write_text(json.dumps(manifest))

        repacked = layout_to_docker_archive(layout, tmp_path / "repacked.tar")
        listing = json.loads(_members(repacked)["manifest.json"])[0]
        assert [name.split("/")[0] for name in listing["Layers"]] == [
            first.split(":")[1],
            extra_hex,
        ]


class TestRefusals:
    def test_a_layout_with_no_index_is_refused(self, tmp_path):
        (tmp_path / "layout").mkdir()
        with pytest.raises(LayoutConversionError):
            layout_to_docker_archive(tmp_path / "layout", tmp_path / "out.tar")
        assert not (tmp_path / "out.tar").exists()

    def test_a_manifest_digest_cannot_leave_the_layout(self, tmp_path):
        layout = archive_to_layout(COMMITTED, tmp_path / "layout")
        index = json.loads((layout / "index.json").read_text())
        index["manifests"][0]["digest"] = "sha256:../../../etc/passwd"
        (layout / "index.json").write_text(json.dumps(index))
        with pytest.raises(LayoutConversionError):
            layout_to_docker_archive(layout, tmp_path / "out.tar")

    def test_a_zstd_layer_is_refused_by_name(self, tmp_path):
        layout = archive_to_layout(COMMITTED, tmp_path / "layout")
        blobs = layout / "blobs" / "sha256"
        manifest_path = next(
            path for path in blobs.iterdir() if b"schemaVersion" in path.read_bytes()
        )
        manifest = json.loads(manifest_path.read_text())
        layer_hex = manifest["layers"][0]["digest"].split(":")[1]
        (blobs / layer_hex).write_bytes(b"\x28\xb5\x2f\xfd" + b"x" * 16)
        with pytest.raises(LayoutConversionError, match="zstd"):
            layout_to_docker_archive(layout, tmp_path / "out.tar")
        assert not (tmp_path / "out.tar").exists()

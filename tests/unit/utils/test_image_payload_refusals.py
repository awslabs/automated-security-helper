# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The stat-level gate on the two direct-payload image shapes.

``--image-archive`` and ``--image-layout`` are checked before anything uses the
path, exactly as a source directory is: exists, right file kind, readable, and
the one shape sniff each (ustar magic; the ``oci-layout`` marker file). The
rows here are the gate's whole contract, one per refusal text, plus the
accepting controls, so a wording change or a sniff that stops looking is a red
row rather than a surprise at a scanner.
"""

from __future__ import annotations

import tarfile

import pytest

from automated_security_helper.utils.image_payload_refusals import (
    image_archive_refusal,
    image_layout_refusal,
)

pytestmark = pytest.mark.unit


def _real_tar(path):
    """A genuine one-member tar at *path*, as ``docker save`` writes one.

    One member, deliberately: the ustar magic sits in each MEMBER's header
    block, so an empty archive (end-of-archive zero blocks only) carries none
    and is refused -- the row below pins that too, because a saved image
    always has members and an all-zero file is not one.
    """
    import io

    with tarfile.open(path, "w") as archive:
        info = tarfile.TarInfo(name="manifest.json")
        info.size = 2
        archive.addfile(info, io.BytesIO(b"[]"))
    return path


class TestImageArchiveRefusals:
    def test_a_real_tar_is_accepted(self, tmp_path):
        archive = _real_tar(tmp_path / "image.tar")
        assert image_archive_refusal(archive) is None

    def test_an_empty_archive_has_no_member_and_no_magic(self, tmp_path):
        empty = tmp_path / "empty.tar"
        with tarfile.open(empty, "w"):
            pass
        refusal = image_archive_refusal(empty)
        assert refusal == f"Image archive is not a tar archive: {empty}"

    def test_a_missing_file_does_not_exist(self, tmp_path):
        missing = tmp_path / "absent.tar"
        refusal = image_archive_refusal(missing)
        assert refusal == f"Image archive does not exist: {missing}"

    def test_a_directory_is_not_a_file(self, tmp_path):
        refusal = image_archive_refusal(tmp_path)
        assert refusal == f"Image archive is not a file: {tmp_path}"

    def test_a_file_without_tar_magic_is_not_a_tar_archive(self, tmp_path):
        not_tar = tmp_path / "notes.txt"
        not_tar.write_bytes(b"not an image" + b"\x00" * 600)
        refusal = image_archive_refusal(not_tar)
        assert refusal == f"Image archive is not a tar archive: {not_tar}"

    def test_a_short_file_is_not_a_tar_archive(self, tmp_path):
        short = tmp_path / "short.tar"
        short.write_bytes(b"ustar")  # the magic, but not where tar puts it
        refusal = image_archive_refusal(short)
        assert refusal == f"Image archive is not a tar archive: {short}"

    def test_a_gzip_compressed_archive_names_the_remedy(self, tmp_path):
        import gzip

        gzipped = tmp_path / "image.tar.gz"
        gzipped.write_bytes(gzip.compress(b"\x00" * 1024))
        refusal = image_archive_refusal(gzipped)
        assert refusal is not None
        assert refusal.startswith(f"Image archive is not a tar archive: {gzipped}")
        assert "gzip" in refusal
        assert "docker save" in refusal

    def test_a_path_with_an_embedded_nul_is_not_a_valid_path(self, tmp_path):
        bad = f"{tmp_path}/with\x00nul.tar"
        refusal = image_archive_refusal(bad)
        assert refusal == f"Image archive is not a valid path: {bad}"


class TestImageLayoutRefusals:
    def _layout(self, tmp_path, marker: bool = True):
        layout = tmp_path / "layout"
        layout.mkdir()
        if marker:
            (layout / "oci-layout").write_text('{"imageLayoutVersion": "1.0.0"}')
        return layout

    def test_a_directory_with_the_marker_is_accepted(self, tmp_path):
        layout = self._layout(tmp_path)
        assert image_layout_refusal(layout) is None

    def test_a_missing_directory_does_not_exist(self, tmp_path):
        missing = tmp_path / "absent"
        refusal = image_layout_refusal(missing)
        assert refusal == f"Image layout does not exist: {missing}"

    def test_a_file_is_not_a_directory(self, tmp_path):
        file_path = tmp_path / "layout.tar"
        file_path.write_bytes(b"")
        refusal = image_layout_refusal(file_path)
        assert refusal == f"Image layout is not a directory: {file_path}"

    def test_a_directory_without_the_marker_is_refused(self, tmp_path):
        layout = self._layout(tmp_path, marker=False)
        refusal = image_layout_refusal(layout)
        assert refusal == f"Image layout has no oci-layout marker file: {layout}"

    def test_a_marker_that_is_a_directory_does_not_count(self, tmp_path):
        layout = tmp_path / "layout"
        (layout / "oci-layout").mkdir(parents=True)
        refusal = image_layout_refusal(layout)
        assert refusal == f"Image layout has no oci-layout marker file: {layout}"

    def test_a_path_with_an_embedded_nul_is_not_a_valid_path(self, tmp_path):
        bad = f"{tmp_path}/with\x00nul"
        refusal = image_layout_refusal(bad)
        assert refusal == f"Image layout is not a valid path: {bad}"

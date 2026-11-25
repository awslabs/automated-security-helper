# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""run_ash_scan's image side of the submission contract (C2 of the design).

Exactly one of ``image``, ``image_archive`` and ``image_layout``; never beside
an explicit ``source_dir``, a workspace, saved results, a git-history scope or
a non-local mode; the two payload shapes stat-gated before anything uses the
path. Each refusal is the usage exit (5) with the text every surface shares,
checked here through the library entry point so the CLI's early copy and this
one cannot drift apart silently. The accepting rows pin what the helper builds:
the Asset the orchestrator threads to the scan phase, and the phase list with
CONVERT dropped, because an image asset presents no source files to convert.
"""

from __future__ import annotations

import tarfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.core.asset import AssetKind
from automated_security_helper.core.constants import ASH_EXIT_USAGE_ERROR
from automated_security_helper.core.enums import ExecutionPhase, RunMode
from automated_security_helper.interactions.run_ash_scan import (
    ScanRefusedExit,
    _image_asset_or_refusal,
    run_ash_scan,
)

pytestmark = pytest.mark.unit

IMAGE_REF = "registry.example.com/team/app:1.2.3"


def _helper(**overrides):
    arguments = {
        "image": None,
        "image_archive": None,
        "image_layout": None,
        "source_dir": None,
        "mode": RunMode.local,
        "workspace_plan": None,
        "existing_results": None,
        "changed_files_only": False,
    }
    arguments.update(overrides)
    return _image_asset_or_refusal(**arguments)


def _refusal_of(**overrides) -> str:
    with pytest.raises(ScanRefusedExit) as exc_info:
        _helper(**overrides)
    assert exc_info.value.code == ASH_EXIT_USAGE_ERROR
    return exc_info.value.message


def _real_tar(path: Path) -> Path:
    # One member: the ustar magic sits in a member's header, and an empty
    # archive carries none (the payload gate's own suite pins that row).
    import io

    with tarfile.open(path, "w") as archive:
        info = tarfile.TarInfo(name="manifest.json")
        info.size = 2
        archive.addfile(info, io.BytesIO(b"[]"))
    return path


def _layout(tmp_path: Path) -> Path:
    layout = tmp_path / "layout"
    layout.mkdir()
    (layout / "oci-layout").write_text('{"imageLayoutVersion": "1.0.0"}')
    return layout


class TestNoImageOptionChangesNothing:
    def test_no_option_builds_no_asset(self):
        assert _helper() is None

    def test_no_option_beside_a_source_dir_builds_no_asset(self, tmp_path):
        assert _helper(source_dir=tmp_path) is None


class TestExclusivityRefusals:
    def test_two_image_options_are_refused(self, tmp_path):
        archive = _real_tar(tmp_path / "image.tar")
        text = _refusal_of(image=IMAGE_REF, image_archive=archive)
        assert "only one may be given" in text

    def test_an_image_beside_an_explicit_source_dir_is_refused(self, tmp_path):
        text = _refusal_of(image=IMAGE_REF, source_dir=tmp_path)
        assert "one scan has one subject" in text

    def test_an_image_beside_a_workspace_is_refused(self):
        text = _refusal_of(image=IMAGE_REF, workspace_plan=MagicMock())
        assert "workspace" in text

    def test_an_image_in_container_mode_is_refused(self):
        text = _refusal_of(image=IMAGE_REF, mode=RunMode.container)
        assert "local mode" in text

    def test_an_image_in_precommit_mode_is_refused(self):
        text = _refusal_of(image=IMAGE_REF, mode=RunMode.precommit)
        assert "local mode" in text

    def test_an_image_beside_existing_results_is_refused(self):
        text = _refusal_of(image=IMAGE_REF, existing_results="/results")
        assert "existing results" in text

    def test_an_image_beside_changed_files_only_is_refused(self):
        text = _refusal_of(image=IMAGE_REF, changed_files_only=True)
        assert "changed_files_only" in text

    def test_a_whitespace_ref_names_nothing(self):
        text = _refusal_of(image="   ")
        assert "names no reference" in text


class TestPayloadGates:
    def test_a_missing_archive_is_refused_with_the_gate_text(self, tmp_path):
        missing = tmp_path / "absent.tar"
        text = _refusal_of(image_archive=missing)
        assert text == f"Image archive does not exist: {missing}"

    def test_a_non_tar_archive_is_refused_with_the_gate_text(self, tmp_path):
        not_tar = tmp_path / "notes.txt"
        not_tar.write_bytes(b"words" + b"\x00" * 600)
        text = _refusal_of(image_archive=not_tar)
        assert text == f"Image archive is not a tar archive: {not_tar}"

    def test_a_markerless_layout_is_refused_with_the_gate_text(self, tmp_path):
        bare = tmp_path / "layout"
        bare.mkdir()
        text = _refusal_of(image_layout=bare)
        assert text == f"Image layout has no oci-layout marker file: {bare}"


class TestWhatTheAcceptingRowsBuild:
    def test_a_ref_builds_a_container_image_asset(self):
        asset = _helper(image=f"  {IMAGE_REF}  ")
        assert asset is not None
        assert asset.kind == AssetKind.CONTAINER_IMAGE
        assert asset.image.ref == IMAGE_REF
        assert asset.filesystem is None

    def test_an_archive_builds_an_absolute_archive_locator(self, tmp_path):
        archive = _real_tar(tmp_path / "image.tar")
        asset = _helper(image_archive=archive)
        assert asset.kind == AssetKind.CONTAINER_IMAGE
        assert asset.image.oci_archive == archive.absolute()
        assert asset.image.ref is None

    def test_a_layout_builds_an_absolute_layout_locator(self, tmp_path):
        layout = _layout(tmp_path)
        asset = _helper(image_layout=layout)
        assert asset.kind == AssetKind.CONTAINER_IMAGE
        assert asset.image.oci_layout == layout.absolute()


class _StopAtOptions(Exception):
    """Raised by the patched ScanOptions to stop run_ash_scan after the parse."""


class TestWhatRunAshScanThreads:
    """The run_ash_scan body, up to ScanOptions: asset built, CONVERT dropped."""

    def _captured_options(self, tmp_path, **kwargs):
        captured = {}

        def capture(**options):
            captured.update(options)
            raise _StopAtOptions

        with patch(
            "automated_security_helper.interactions.run_ash_scan.ScanOptions",
            side_effect=capture,
        ):
            with pytest.raises(_StopAtOptions):
                run_ash_scan(output_dir=tmp_path / "out", **kwargs)
        return captured

    def test_an_image_ref_threads_an_asset_and_drops_convert(self, tmp_path):
        options = self._captured_options(tmp_path, image=IMAGE_REF)
        asset = options["asset"]
        assert asset.kind == AssetKind.CONTAINER_IMAGE
        assert asset.image.ref == IMAGE_REF
        assert ExecutionPhase.CONVERT not in options["phases"]
        assert ExecutionPhase.SCAN in options["phases"]
        assert ExecutionPhase.REPORT in options["phases"]

    def test_no_image_threads_no_asset_and_keeps_convert(self, tmp_path):
        options = self._captured_options(tmp_path, source_dir=tmp_path)
        assert options["asset"] is None
        assert options["phases"] is None or ExecutionPhase.CONVERT in options["phases"]

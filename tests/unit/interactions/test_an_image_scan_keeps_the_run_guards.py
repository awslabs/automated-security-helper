# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The guards around an image scan: decorators, phases, shards, recorded source.

- ``run_ash_scan`` keeps the two decorators that give every run its log scope and
  register its scanned tree; the image-scope helper beside it is not decorated.
- An image scan has no convert phase, so a request for the convert phase alone
  leaves nothing to run and is refused, instead of falling through to the local
  mode's default of convert, scan and report.
- An image scan is not sharded: a shard would write the "image was not scanned"
  note while another shard scanned the image.
- The ``scan_source`` an image scan records names the image, not the directory
  the scan was started from.
"""

from __future__ import annotations

import io
import tarfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from automated_security_helper.core.asset import Asset, ImageLocator
from automated_security_helper.core.constants import ASH_EXIT_USAGE_ERROR
from automated_security_helper.core.enums import ExecutionPhase
from automated_security_helper.interactions import run_ash_scan as module
from automated_security_helper.interactions.run_ash_scan import (
    ScanRefusedExit,
    run_ash_scan,
)

pytestmark = pytest.mark.unit

IMAGE_REF = "registry.example.com/team/app:1.2.3"


class _StopAtOptions(Exception):
    pass


def _captured_options(tmp_path, **kwargs):
    captured = {}

    def capture(**options):
        captured.update(options)
        raise _StopAtOptions

    with patch.object(module, "ScanOptions", side_effect=capture):
        with pytest.raises(_StopAtOptions):
            run_ash_scan(output_dir=tmp_path / "out", **kwargs)
    return captured


class TestTheDecoratorsStayOnRunAshScan:
    def test_run_ash_scan_is_wrapped_by_both_scope_decorators(self):
        # Two layers, counted: either decorator alone satisfied a bare
        # hasattr, and the regression being pinned was losing BOTH.
        inner = run_ash_scan.__wrapped__
        assert hasattr(inner, "__wrapped__")
        assert not hasattr(inner.__wrapped__, "__wrapped__")

    def test_the_image_scope_helper_is_not_wrapped(self):
        assert not hasattr(module._refuse_an_image_scan_scope, "__wrapped__")


class TestAnImageScanHasNoConvertPhaseToFallBackTo:
    def test_convert_alone_is_refused(self, tmp_path):
        with pytest.raises(ScanRefusedExit) as raised:
            run_ash_scan(
                image=IMAGE_REF,
                phases=[ExecutionPhase.CONVERT],
                output_dir=tmp_path / "out",
            )
        assert raised.value.code == ASH_EXIT_USAGE_ERROR
        assert "convert" in raised.value.message

    def test_convert_beside_scan_keeps_scan(self, tmp_path):
        options = _captured_options(
            tmp_path,
            image=IMAGE_REF,
            phases=[ExecutionPhase.CONVERT, ExecutionPhase.SCAN],
        )
        assert options["phases"] == [ExecutionPhase.SCAN]


class TestAnImageScanIsNotSharded:
    @pytest.mark.parametrize("option", ["image", "image_archive", "image_layout"])
    def test_a_shard_is_refused_for_each_image_option(self, tmp_path, option):
        if option == "image":
            target = IMAGE_REF
        elif option == "image_archive":
            target = tmp_path / "image.tar"
            with tarfile.open(target, "w") as archive:
                info = tarfile.TarInfo(name="manifest.json")
                info.size = 2
                archive.addfile(info, io.BytesIO(b"[]"))
        else:
            target = tmp_path / "layout"
            target.mkdir()
            (target / "oci-layout").write_text('{"imageLayoutVersion": "1.0.0"}')
        with pytest.raises(ScanRefusedExit) as raised:
            run_ash_scan(
                output_dir=tmp_path / "out",
                shard_index=0,
                shard_count=2,
                **{option: target},
            )
        assert raised.value.code == ASH_EXIT_USAGE_ERROR
        assert "shard" in raised.value.message

    def test_a_pre_built_asset_is_refused_too(self, tmp_path):
        with pytest.raises(ScanRefusedExit) as raised:
            run_ash_scan(
                asset=Asset.for_image(ImageLocator(ref=IMAGE_REF)),
                output_dir=tmp_path / "out",
                shard_index=1,
                shard_count=2,
            )
        assert "shard" in raised.value.message

    def test_the_control_a_filesystem_shard_is_not_refused(self, tmp_path):
        options = _captured_options(
            tmp_path, source_dir=tmp_path, shard_index=0, shard_count=2
        )
        assert (options["shard_index"], options["shard_count"]) == (0, 2)


class TestTheRecordedScanSource:
    def _opts(self, source_dir: Path, asset):
        return SimpleNamespace(source_dir=source_dir, asset=asset)

    def test_an_image_scan_records_the_image(self, tmp_path):
        opts = self._opts(tmp_path, Asset.for_image(ImageLocator(ref=IMAGE_REF)))
        recorded = module._scan_source_for(opts, lambda *a, **k: tmp_path, {})
        assert recorded == f"image:{IMAGE_REF}"

    def test_a_filesystem_scan_records_what_it_always_did(self, tmp_path):
        from automated_security_helper.utils.scan_source import recorded_scan_source

        opts = self._opts(tmp_path, None)
        expected = recorded_scan_source(tmp_path, lambda *a, **k: None, {})
        assert module._scan_source_for(opts, lambda *a, **k: None, {}) == expected
        assert expected is not None and not expected.startswith("image:")

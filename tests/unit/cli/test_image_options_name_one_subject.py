# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash scan``'s image options: one subject, gated before any work.

The CLI copy of the submission contract's exclusivity rules, refused with the
usage exit (5) before the workspace block, before any path default resolves
and before run_ash_scan starts, so a conflicting invocation does no work
first. The payload gate rows show the stat-level texts of
``utils/image_payload_refusals.py`` reaching the operator unchanged. The
pass-through row pins what the CLI hands run_ash_scan: the image options as
given and NO source_dir, which is how run_ash_scan's own exclusivity rule
reads an image scan.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.core.constants import ASH_EXIT_USAGE_ERROR

pytestmark = pytest.mark.unit

IMAGE_REF = "registry.example.com/team/app:1.2.3"


@pytest.fixture(autouse=True)
def _here(tmp_path, monkeypatch):
    for name in ("ASH_SOURCE_DIR", "ASH_OUTPUT_DIR", "ASH_CONFIG", "ASH_WORKSPACE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("COLUMNS", "400")
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.chdir(tmp_path)


def _scan(*options: str):
    return CliRunner().invoke(app, ["scan", *options])


class TestExclusivityIsRefusedBeforeAnyWork:
    def test_two_image_options_are_refused(self):
        result = _scan("--image", IMAGE_REF, "--image-archive", "image.tar")
        assert result.exit_code == ASH_EXIT_USAGE_ERROR
        assert "only one may be given" in result.output

    def test_an_image_beside_source_dir_names_the_flag(self, tmp_path):
        result = _scan("--image", IMAGE_REF, "--source-dir", str(tmp_path))
        assert result.exit_code == ASH_EXIT_USAGE_ERROR
        assert "--source-dir" in result.output
        assert "one scan has one subject" in result.output

    def test_an_image_beside_ash_source_dir_names_the_variable(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.setenv("ASH_SOURCE_DIR", str(tmp_path))
        result = _scan("--image", IMAGE_REF)
        assert result.exit_code == ASH_EXIT_USAGE_ERROR
        assert "ASH_SOURCE_DIR" in result.output

    def test_an_image_beside_a_workspace_is_refused(self, tmp_path):
        workspace = tmp_path / "dev.code-workspace"
        workspace.write_text('{"folders": [{"path": "."}]}', encoding="utf-8")
        result = _scan("--image", IMAGE_REF, "--workspace", str(workspace))
        assert result.exit_code == ASH_EXIT_USAGE_ERROR
        assert "--workspace" in result.output


class TestOptionsThatReadTheWorkingDirectoryAreRefused:
    """These flags resolve against the directory a scan starts in, which is not an
    image scan's subject: ``--staged`` could exit 0 as "nothing staged" without the
    image ever being scanned, and the others would read or filter by the cwd."""

    @pytest.mark.parametrize(
        "image_options",
        [
            pytest.param(("--image", IMAGE_REF), id="image"),
            pytest.param(("--image-archive", "image.tar"), id="image-archive"),
            pytest.param(("--image-layout", "layout"), id="image-layout"),
        ],
    )
    @pytest.mark.parametrize(
        "other",
        [
            pytest.param(("--staged",), id="staged"),
            pytest.param(("--baseline", "base.json"), id="baseline"),
            pytest.param(("--use-existing",), id="use-existing"),
            pytest.param(("--changed-files-only",), id="changed-files-only"),
        ],
    )
    def test_each_is_refused_with_the_flag_named(self, image_options, other):
        result = _scan(*image_options, *other)
        assert result.exit_code == ASH_EXIT_USAGE_ERROR
        assert other[0] in result.output
        assert image_options[0] in result.output


class TestThePayloadGateReachesTheOperator:
    def test_a_missing_archive_shows_the_gate_text(self, tmp_path):
        missing = tmp_path / "absent.tar"
        result = _scan("--image-archive", str(missing))
        assert result.exit_code == ASH_EXIT_USAGE_ERROR
        assert f"Image archive does not exist: {missing}" in result.output

    def test_a_markerless_layout_shows_the_gate_text(self, tmp_path):
        bare = tmp_path / "layout"
        bare.mkdir()
        result = _scan("--image-layout", str(bare))
        assert result.exit_code == ASH_EXIT_USAGE_ERROR
        assert f"Image layout has no oci-layout marker file: {bare}" in result.output


class TestWhatTheCliHandsRunAshScan:
    def test_an_image_scan_passes_the_ref_and_no_source_dir(self):
        with patch(
            # The module-dict binding _deferred reads first, which is the seam
            # cli/scan.py documents for a test's patch of `cli.scan.<name>`.
            "automated_security_helper.cli.scan.run_ash_scan",
        ) as run:
            result = _scan("--image", IMAGE_REF)
        assert result.exit_code == 0, result.output
        assert run.call_count == 1
        kwargs = run.call_args.kwargs
        assert kwargs["image"] == IMAGE_REF
        assert kwargs["image_archive"] is None
        assert kwargs["image_layout"] is None
        assert kwargs["source_dir"] is None

    def test_a_directory_scan_still_passes_its_source_dir(self, tmp_path):
        with patch(
            # The module-dict binding _deferred reads first, which is the seam
            # cli/scan.py documents for a test's patch of `cli.scan.<name>`.
            "automated_security_helper.cli.scan.run_ash_scan",
        ) as run:
            result = _scan("--source-dir", str(tmp_path))
        assert result.exit_code == 0, result.output
        kwargs = run.call_args.kwargs
        assert kwargs["image"] is None
        assert kwargs["source_dir"] == str(tmp_path)

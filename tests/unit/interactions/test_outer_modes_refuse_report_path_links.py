# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Container and nix mode do not answer from a reports directory holding a link.

In both modes an inner ASH writes the reports, and its report phase refuses a link
at a file its reporters write, exiting 1. The outer process treats 1 as a verdict
and re-derives its own from the results file, and ``_compute_exit_code`` re-reads
``reports/ash.sarif``, so without a check of its own the outer process exited with
whatever the results file said and read the SARIF through the link. The inner run
is replaced here by a stand-in that leaves what such a run leaves: a results file,
and the link. The refusal is observed as ``SystemExit`` with code 1 and a reason
naming the link, so on a tree without the check these fail on what they assert.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.interactions.run_ash_scan import (
    ScanOptions,
    _compute_exit_code,
    _run_container_mode,
    _run_nix_mode,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.utils.inner_run_outcome import mark_run_completed
from automated_security_helper.utils.subprocess_utils import create_completed_process

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(
        sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
    ),
]

RUN_ASH_SCAN = "automated_security_helper.interactions.run_ash_scan"


def _opts(tmp_path: Path, **overrides) -> ScanOptions:
    kwargs = {"source_dir": tmp_path / "src", "output_dir": tmp_path / "out"}
    kwargs.update(overrides)
    return ScanOptions(**kwargs)


def _leave_results_and_link(tmp_path: Path, output_dir: Path) -> Path:
    """What an inner run that refused leaves: its results file, and the link."""
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "ash_aggregated_results.json").write_text(
        AshAggregatedResults().model_dump_json(by_alias=True), encoding="utf-8"
    )
    outside = tmp_path / "outside.sarif"
    outside.write_text(json.dumps({"version": "2.1.0", "runs": []}), encoding="utf-8")
    reports = output_dir / "reports"
    reports.mkdir(exist_ok=True)
    link = reports / "ash.sarif"
    link.symlink_to(outside)
    return link


def _assert_refused_naming(refused: pytest.ExceptionInfo, link: Path) -> None:
    assert refused.value.code == 1
    assert f"{link.as_posix()} is a symlink" in getattr(refused.value, "reason", "")


def test_a_container_run_that_leaves_a_link_in_reports_is_refused(tmp_path):
    opts = _opts(tmp_path)
    left: list = []

    def inner_run_refused(*args, **kwargs):
        left.append(_leave_results_and_link(tmp_path, opts.output_dir))
        return create_completed_process(
            args=["run"], returncode=1, stdout="", stderr=""
        )

    with (
        patch(f"{RUN_ASH_SCAN}.run_ash_container", side_effect=inner_run_refused),
        pytest.raises(SystemExit) as refused,
    ):
        _run_container_mode(opts, MagicMock())

    _assert_refused_naming(refused, left[0])


def test_a_container_run_with_existing_results_and_a_kept_link_is_refused(tmp_path):
    """``--use-existing`` keeps reports/, so a link left there is still there afterwards."""
    opts = _opts(tmp_path)
    link = _leave_results_and_link(tmp_path, opts.output_dir)
    opts.existing_results = (opts.output_dir / "ash_aggregated_results.json").as_posix()

    with (
        patch(
            f"{RUN_ASH_SCAN}.run_ash_container",
            return_value=create_completed_process(
                args=["run"], returncode=1, stdout="", stderr=""
            ),
        ),
        pytest.raises(SystemExit) as refused,
    ):
        _run_container_mode(opts, MagicMock())

    _assert_refused_naming(refused, link)


def test_a_nix_run_that_leaves_a_link_in_reports_is_refused(tmp_path):
    opts = _opts(tmp_path)
    left: list = []

    def inner_run_refused(*args, **kwargs):
        left.append(_leave_results_and_link(tmp_path, opts.output_dir))
        return create_completed_process(args=[], returncode=1)

    with (
        patch(f"{RUN_ASH_SCAN}.run_ash_nix", side_effect=inner_run_refused),
        patch(f"{RUN_ASH_SCAN}.nix_preflight", lambda: None),
        pytest.raises(SystemExit) as refused,
    ):
        _run_nix_mode(opts, MagicMock())

    _assert_refused_naming(refused, left[0])


def test_a_container_run_whose_reports_directory_is_a_dangling_link_is_refused(
    tmp_path,
):
    opts = _opts(tmp_path)
    reports = opts.output_dir / "reports"

    def inner_run_failed(*args, **kwargs):
        opts.output_dir.mkdir(parents=True, exist_ok=True)
        (opts.output_dir / "ash_aggregated_results.json").write_text(
            AshAggregatedResults().model_dump_json(by_alias=True), encoding="utf-8"
        )
        reports.symlink_to(tmp_path / "missing", target_is_directory=True)
        return create_completed_process(
            args=["run"], returncode=1, stdout="", stderr=""
        )

    with (
        patch(f"{RUN_ASH_SCAN}.run_ash_container", side_effect=inner_run_failed),
        pytest.raises(SystemExit) as refused,
    ):
        _run_container_mode(opts, MagicMock())

    assert refused.value.code == 1
    assert f"reports directory {reports.as_posix()} is a symlink" in getattr(
        refused.value, "reason", ""
    )


def test_a_container_run_without_a_link_is_read_back(tmp_path):
    opts = _opts(tmp_path)

    def clean_run(*args, **kwargs):
        reports = opts.output_dir / "reports"
        reports.mkdir(parents=True, exist_ok=True)
        (reports / "ash.sarif").write_text("{}", encoding="utf-8")
        results = AshAggregatedResults(name="read back")
        # The marker the in-container run writes when it completes.
        mark_run_completed(results, kwargs["outer_run_id"])
        (opts.output_dir / "ash_aggregated_results.json").write_text(
            results.model_dump_json(by_alias=True), encoding="utf-8"
        )
        return create_completed_process(
            args=["run"], returncode=0, stdout="", stderr=""
        )

    with patch(f"{RUN_ASH_SCAN}.run_ash_container", side_effect=clean_run):
        results = _run_container_mode(opts, MagicMock())

    assert results.name == "read back"


def test_the_exit_code_is_not_read_through_a_linked_sarif_report(tmp_path):
    """Its count would come from the file the link points to."""
    opts = _opts(tmp_path, fail_on_findings=True)
    link = _leave_results_and_link(tmp_path, opts.output_dir)

    with pytest.raises(SystemExit) as refused:
        _compute_exit_code(AshAggregatedResults(), opts)

    _assert_refused_naming(refused, link)


def test_the_exit_code_reads_a_regular_sarif_report_as_before(tmp_path):
    opts = _opts(tmp_path, fail_on_findings=True)
    reports = opts.output_dir / "reports"
    reports.mkdir(parents=True)
    (reports / "ash.sarif").write_text(
        json.dumps({"version": "2.1.0", "runs": []}), encoding="utf-8"
    )

    assert _compute_exit_code(AshAggregatedResults(), opts) == 0


@pytest.mark.parametrize("mode", ["container", "nix"])
@pytest.mark.parametrize("target", ["a directory", "nothing"])
def test_a_reports_directory_that_is_a_link_is_refused_before_the_inner_run(
    tmp_path, capsys, mode, target
):
    """Refused before the outer process clears the output directory or starts a run.

    Clearing it would rmtree through a link to a directory, which fails, or remove a
    dangling link without saying so. Container mode called on its own refuses it
    with the checks of what it mounts, which print the reason; nix mode carries it
    on the exit.
    """
    opts = _opts(tmp_path)
    opts.output_dir.mkdir(parents=True)
    outside = tmp_path / "outside"
    if target == "a directory":
        outside.mkdir()
        (outside / "keep.txt").write_text("unchanged", encoding="utf-8")
    reports = opts.output_dir / "reports"
    reports.symlink_to(outside, target_is_directory=True)
    runner = MagicMock(side_effect=AssertionError("the inner run was started"))
    run_mode, runner_name = (
        (_run_container_mode, "run_ash_container")
        if mode == "container"
        else (_run_nix_mode, "run_ash_nix")
    )

    with (
        patch(f"{RUN_ASH_SCAN}.{runner_name}", runner),
        patch(f"{RUN_ASH_SCAN}.nix_preflight", lambda: None),
        pytest.raises(SystemExit) as refused,
    ):
        run_mode(opts, MagicMock())

    # Exit 3, as every output directory refused through a link does.
    assert refused.value.code == 3
    said = getattr(refused.value, "reason", "") or "".join(
        capsys.readouterr().out.split()
    )
    assert "".join(f"{reports.as_posix()} is a symlink".split()) in "".join(
        said.split()
    ), said
    runner.assert_not_called()
    assert reports.is_symlink()
    if target == "a directory":
        assert sorted(path.name for path in outside.iterdir()) == ["keep.txt"]

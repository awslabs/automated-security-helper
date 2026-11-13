# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash merge`` says why it exits 1 when conversion in the merged scan was incomplete.

``_merged_exit_code`` counts incomplete converters through ``_compute_exit_code``,
but the summary's exit-1 branch listed only incomplete scanners, so a merge that
failed for an archive over an extraction limit or one that could not be read
printed the counts and nothing about the cause.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.cli.merge import _merged_exit_code, _print_merge_summary
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ConverterStatusInfo,
    FailedInputInfo,
    RefusedInputInfo,
)

pytestmark = pytest.mark.unit


def merged_with_incomplete_conversion() -> AshAggregatedResults:
    merged = AshAggregatedResults()
    merged.converter_results["archive"] = ConverterStatusInfo(
        refused_inputs=[
            RefusedInputInfo(path="big.zip", reason="over", limit="max_total_bytes")
        ],
        failed_inputs=[FailedInputInfo(path="cut.tar", reason="truncated")],
    )
    return merged


def test_the_merge_summary_names_the_incomplete_converter(tmp_path, capsys):
    merged = merged_with_incomplete_conversion()
    code = _merged_exit_code(
        merged,
        tmp_path,
        "MEDIUM",
        fail_on_findings=False,
        fail_on_incomplete_scanners=True,
    )
    assert code == 1

    _print_merge_summary(merged, Path("merged") / "ash_aggregated_results.json", code)

    out = capsys.readouterr().out
    assert "ERROR (1)" in out
    assert "conversion" in out
    assert "archive:" in out
    assert "cut.tar" in out
    assert "big.zip (max_total_bytes)" in out


def test_a_merge_with_complete_conversion_adds_no_conversion_line(tmp_path, capsys):
    merged = AshAggregatedResults()
    merged.converter_results["archive"] = ConverterStatusInfo(
        refused_inputs=[RefusedInputInfo(path="x.zip", reason="nested")]
    )

    _print_merge_summary(merged, Path("merged") / "ash_aggregated_results.json", 0)

    assert "conversion" not in capsys.readouterr().out

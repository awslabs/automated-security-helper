# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash merge`` prints its exit-1 summary when a shard's converter lost coverage.

``incomplete_converters`` returns three-field rows (name, reason, kinds). The
merge summary unpacked each row as a (name, reason) pair, so a merged scan with
any incomplete converter ended in "too many values to unpack" instead of the
summary that names the converter. These tests drive the whole command, through
typer, for each way a converter can be incomplete.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.models.asharp_model import (
    ConverterStatusInfo,
    FailedInputInfo,
    RefusedInputInfo,
)
from tests.unit.cli.test_merge import build_shards, write_shards

SUMMARY_LINE = "conversion in the merged scan was incomplete"


def _invoke(args):
    """Run ``ash merge`` with the reporter plugins out of the way.

    The summary under test is printed after the reports are written, and a
    reporter's own dependency checks are not what these tests are about.
    """
    manager = MagicMock()
    manager.plugin_modules.return_value = []
    with (
        patch("automated_security_helper.cli.merge.ash_plugin_manager", manager),
        patch("automated_security_helper.cli.merge.load_plugins"),
    ):
        return CliRunner().invoke(app, ["merge", *args])


def _merge_args(tmp_path, shards, *flags):
    paths = write_shards(tmp_path / "artifacts", shards)
    args = ["--output-dir", str(tmp_path / "out"), *flags]
    for path in paths:
        args += ["--results", path]
    return args


def _flat(output: str) -> str:
    """The console text with its line wrapping undone."""
    return " ".join(output.split())


def _ended_by_an_exit(result) -> bool:
    """Whether the command ended by exiting, not by an exception escaping it."""
    return result.exception is None or isinstance(result.exception, SystemExit)


def _assert_exited_through_the_summary(result):
    assert result.exit_code == 1, result.output
    assert _ended_by_an_exit(result), repr(result.exception)


#: converter name, its recorded row, and the reason the summary quotes for it.
INCOMPLETE_ROWS = [
    pytest.param(
        "archive",
        lambda: ConverterStatusInfo(
            refused_inputs=[
                RefusedInputInfo(
                    path="big.zip",
                    reason="its members declare more bytes than the limit",
                    limit="max_total_bytes",
                )
            ]
        ),
        "refused 1 input over an extraction limit: big.zip (max_total_bytes)",
        id="archive-over-a-limit",
    ),
    pytest.param(
        "jupyter",
        lambda: ConverterStatusInfo(failure="RuntimeError: nbconvert crashed"),
        "RuntimeError: nbconvert crashed",
        id="converter-crashed",
    ),
    pytest.param(
        "jupyter",
        lambda: ConverterStatusInfo(
            failed_inputs=[
                FailedInputInfo(path="nb.ipynb", reason="nbconvert timed out")
            ]
        ),
        "could not convert 1 input: nb.ipynb",
        id="input-failed-to-convert",
    ),
    pytest.param(
        "jupyter",
        lambda: ConverterStatusInfo(dependencies_satisfied=False, candidate_inputs=2),
        "dependencies unavailable, so it never ran",
        id="tool-absent-with-inputs",
    ),
]


class TestMergeWithAnIncompleteConverter:
    @pytest.mark.parametrize("name, make_row, reason", INCOMPLETE_ROWS)
    def test_the_summary_names_the_converter_and_the_exit_is_one(
        self, tmp_path, name, make_row, reason
    ):
        shards = build_shards(3)
        shards[1].converter_results[name] = make_row()

        result = _invoke(_merge_args(tmp_path, shards, "--fail-on-incomplete-scanners"))

        _assert_exited_through_the_summary(result)
        flat = _flat(result.output)
        assert f"ERROR (1) Exiting because {SUMMARY_LINE}: 1 converter(s)" in flat, (
            result.output
        )
        assert f"{name}: {reason}" in flat, result.output

    def test_two_incomplete_converters_are_both_listed(self, tmp_path):
        shards = build_shards(3)
        shards[0].converter_results["archive"] = ConverterStatusInfo(
            refused_inputs=[
                RefusedInputInfo(path="big.zip", reason="over", limit="max_files")
            ]
        )
        shards[2].converter_results["jupyter"] = ConverterStatusInfo(
            failure="RuntimeError: nbconvert crashed"
        )

        result = _invoke(_merge_args(tmp_path, shards, "--fail-on-incomplete-scanners"))

        _assert_exited_through_the_summary(result)
        flat = _flat(result.output)
        assert f"{SUMMARY_LINE}: 2 converter(s)" in flat, result.output
        assert (
            "archive: refused 1 input over an extraction limit: big.zip (max_files)"
            in flat
        ), result.output
        assert "jupyter: RuntimeError: nbconvert crashed" in flat, result.output

    def test_converters_that_completed_add_no_conversion_line(self, tmp_path):
        """Control: the line appears for an incomplete converter and no other."""
        shards = build_shards(3)
        for model in shards:
            model.converter_results["jupyter"] = ConverterStatusInfo(
                converted_paths=["converted/nb.py"]
            )

        result = _invoke(_merge_args(tmp_path, shards, "--fail-on-incomplete-scanners"))

        assert _ended_by_an_exit(result), repr(result.exception)
        assert SUMMARY_LINE not in _flat(result.output), result.output

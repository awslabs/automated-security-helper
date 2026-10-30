# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Three readings of utils/inner_run_outcome.py.

A second report phase over the same results (``ash merge`` with an off-host
reporter) used to replace the first phase's record of the reports written, so
the ``ash.sarif`` entry the exit code is read from was lost; the record is
extended only when this process wrote it, so one an earlier run left in results
that were loaded with it is replaced, not extended. And
read_refusal_outcome opened the inner run's outcome file with a plain open after
a separate lstat check, so a link put at the name in between was followed.
"""

from __future__ import annotations

import json
import string
import sys
from types import SimpleNamespace

import pytest

from automated_security_helper.utils.inner_run_outcome import (
    INNER_RUN_OUTCOME_FILE,
    read_refusal_outcome,
    record_refusal_outcome,
    record_reports_written,
    report_file_written_as,
)

pytestmark = pytest.mark.unit

#: A run id of the shape ASH gives an inner run, assembled from its digits.
RUN = "".join(string.hexdigits[index % 16] for index in range(32))


def test_a_second_report_phase_keeps_the_first_phases_entries():
    results = SimpleNamespace(validation_checkpoints=[])
    record_reports_written(results, [("ash.sarif", "sarif"), ("ash.html", "html")])

    record_reports_written(results, [("ash.s3.json", "s3")])

    assert report_file_written_as(results, "sarif") == "ash.sarif"
    assert report_file_written_as(results, "html") == "ash.html"
    assert report_file_written_as(results, "s3") == "ash.s3.json"
    records = [
        checkpoint
        for checkpoint in results.validation_checkpoints
        if checkpoint.get("type") == "reports_written"
    ]
    assert len(records) == 1
    assert records[0]["metadata"]["files"] == ["ash.html", "ash.s3.json", "ash.sarif"]


def test_an_empty_second_phase_still_records_the_first_phases_files():
    results = SimpleNamespace(validation_checkpoints=[])
    record_reports_written(results, [("ash.sarif", "sarif")])

    record_reports_written(results, [])

    assert report_file_written_as(results, "sarif") == "ash.sarif"


def _earlier_run_record(**metadata):
    return {
        "type": "reports_written",
        "severity": "info",
        "message": "The report files this run wrote.",
        "metadata": {"files": ["old.sarif"], "formats": {"old.sarif": "sarif"}}
        | metadata,
    }


@pytest.mark.parametrize(
    "metadata",
    [{}, {"run_token": "a-token-from-another-process"}],
    ids=["no token", "another process's token"],
)
def test_a_record_another_run_wrote_is_replaced_not_extended(metadata):
    results = SimpleNamespace(validation_checkpoints=[_earlier_run_record(**metadata)])

    record_reports_written(results, [("ash.html", "html")])

    assert report_file_written_as(results, "sarif") is None
    assert report_file_written_as(results, "html") == "ash.html"
    (record,) = results.validation_checkpoints
    assert record["metadata"]["files"] == ["ash.html"]


def test_an_empty_phase_does_not_keep_the_files_another_run_wrote():
    results = SimpleNamespace(validation_checkpoints=[_earlier_run_record()])

    record_reports_written(results, [])

    assert report_file_written_as(results, "sarif") is None
    (record,) = results.validation_checkpoints
    assert record["metadata"]["files"] == []


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges")
def test_a_link_put_at_the_outcome_file_is_not_followed(tmp_path):
    elsewhere = tmp_path / "elsewhere"
    assert record_refusal_outcome(elsewhere, "refused for a reason", RUN)
    out = tmp_path / "out"
    out.mkdir()
    (out / INNER_RUN_OUTCOME_FILE).symlink_to(elsewhere / INNER_RUN_OUTCOME_FILE)

    assert read_refusal_outcome(out, RUN) is None
    assert read_refusal_outcome(elsewhere, RUN) is not None


def test_a_regular_outcome_file_still_reads_back(tmp_path):
    out = tmp_path / "out"
    assert record_refusal_outcome(out, "refused for a reason", RUN)

    refusal = read_refusal_outcome(out, RUN)

    assert refusal is not None and refusal.message == "refused for a reason"
    record = json.loads((out / INNER_RUN_OUTCOME_FILE).read_text(encoding="utf-8"))
    assert record["metadata"]["run_id"] == RUN

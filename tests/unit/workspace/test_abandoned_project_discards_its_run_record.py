# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An abandoned project's history record goes with its results file.

``_discard_project_output`` removed the results file and the reports directory
but left ``projects/<key>/history/<report_id>.json`` in place, so the abandoned
run stayed a point in ``ash results trend`` beside a FAILED verdict. The record removed
is the one the removed results file names by its ``report_id``; a results file
that is missing or unreadable names none, and other runs' records stay.
"""

from __future__ import annotations

import json

import pytest

from automated_security_helper.workspace.execution import (
    RESULTS_FILENAME,
    _discard_project_output,
)

pytestmark = pytest.mark.unit

RECORD_ID = "ASH-20260101000001-0123456789ab"
OTHER_ID = "ASH-20260101000002-0123456789ab"


def _project(tmp_path, *, report_id=RECORD_ID, results=True):
    output = tmp_path / "out"
    history = output / "history"
    history.mkdir(parents=True)
    if results:
        (output / RESULTS_FILENAME).write_text(
            json.dumps({"metadata": {"report_id": report_id}}), encoding="utf-8"
        )
    for name in (RECORD_ID, OTHER_ID):
        (history / f"{name}.json").write_text("{}", encoding="utf-8")
    return output


def test_the_abandoned_runs_record_goes_and_other_runs_records_stay(tmp_path):
    output = _project(tmp_path)
    _discard_project_output(output, RECORD_ID)
    assert not (output / RESULTS_FILENAME).exists()
    assert not (output / "history" / f"{RECORD_ID}.json").exists()
    assert (output / "history" / f"{OTHER_ID}.json").exists()


def test_a_missing_or_unreadable_results_file_names_no_record(tmp_path):
    output = _project(tmp_path, results=False)
    _discard_project_output(output, RECORD_ID)
    assert (output / "history" / f"{RECORD_ID}.json").exists()

    output2 = tmp_path / "out2"
    (output2 / "history").mkdir(parents=True)
    (output2 / RESULTS_FILENAME).write_text("{not json", encoding="utf-8")
    (output2 / "history" / f"{RECORD_ID}.json").write_text("{}", encoding="utf-8")
    _discard_project_output(output2, RECORD_ID)
    assert (output2 / "history" / f"{RECORD_ID}.json").exists()


def test_a_report_id_that_is_not_a_record_name_removes_nothing(tmp_path):
    output = _project(tmp_path, report_id="../escape")
    _discard_project_output(output, RECORD_ID)
    assert (output / "history" / f"{RECORD_ID}.json").exists()
    assert (output / "history" / f"{OTHER_ID}.json").exists()


def test_a_restored_previous_results_file_does_not_cost_the_earlier_run_its_record(
    tmp_path,
):
    # A scan that failed or was cancelled inside its phases has the PREVIOUS
    # completed run's results file put back (core/orchestrator), so the id the
    # file holds is the earlier run's. The abandoned run's own id differs, and
    # the earlier run's record is not the abandon's to remove.
    output = _project(tmp_path, report_id=OTHER_ID)
    _discard_project_output(output, RECORD_ID)
    assert not (output / RESULTS_FILENAME).exists()
    assert (output / "history" / f"{RECORD_ID}.json").exists()
    assert (output / "history" / f"{OTHER_ID}.json").exists()


def test_an_abandon_with_no_known_run_id_removes_no_record(tmp_path):
    output = _project(tmp_path)
    _discard_project_output(output)
    assert not (output / RESULTS_FILENAME).exists()
    assert (output / "history" / f"{RECORD_ID}.json").exists()
    assert (output / "history" / f"{OTHER_ID}.json").exists()


def test_the_report_id_is_read_from_the_results_the_scan_returned():
    from types import SimpleNamespace

    from automated_security_helper.workspace.execution import _report_id_of

    assert (
        _report_id_of(SimpleNamespace(metadata=SimpleNamespace(report_id="x"))) == "x"
    )
    assert _report_id_of({"metadata": {"report_id": "y"}}) == "y"
    assert _report_id_of(None) is None
    assert _report_id_of({"metadata": "text"}) is None

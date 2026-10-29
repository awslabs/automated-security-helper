# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The helpers that read and write an inner run's records (utils/inner_run_outcome.py)."""

from __future__ import annotations

import json
import os
import sys

import pytest

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.utils.inner_run_outcome import (
    INNER_RUN_OUTCOME_FILE,
    as_seen_from_the_host,
    existing_results_problem,
    mark_run_completed,
    not_a_regular_file,
    read_refusal_outcome,
    record_refusal_outcome,
)

pytestmark = pytest.mark.unit

RUN = "0123456789abcdef0123456789abcdef"  # pragma: allowlist secret


def test_a_recorded_refusal_reads_back_for_its_own_run_only(tmp_path):
    assert record_refusal_outcome(tmp_path / "out", "refused for a reason", RUN)

    refusal = read_refusal_outcome(tmp_path / "out", RUN)

    assert refusal is not None
    assert refusal.message == "refused for a reason"
    assert refusal.inner_output_dir == (tmp_path / "out").as_posix()
    assert read_refusal_outcome(tmp_path / "out", "f" * 32) is None
    assert not (tmp_path / "out" / "ash_aggregated_results.json").exists()


@pytest.mark.parametrize(
    "content",
    [
        "not json",
        json.dumps([1]),
        json.dumps({"type": "run_completed"}),
        # A refusal of this run, but larger than any this ASH writes.
        json.dumps(
            {"type": "report_path_refused", "message": "m", "metadata": {"run_id": RUN}}
        )
        + " " * (2 << 20),
    ],
    ids=["not json", "not an object", "another record", "oversized"],
)
def test_a_record_that_is_not_a_refusal_reads_as_none(tmp_path, content):
    (tmp_path / INNER_RUN_OUTCOME_FILE).write_text(content, encoding="utf-8")

    assert read_refusal_outcome(tmp_path, RUN) is None


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges")
def test_only_a_regular_file_is_read_without_question(tmp_path):
    regular = tmp_path / "regular.json"
    regular.write_text("{}", encoding="utf-8")
    link = tmp_path / "link.json"
    link.symlink_to(regular)
    directory = tmp_path / "directory.json"
    directory.mkdir()
    fifo = tmp_path / "fifo.json"
    os.mkfifo(fifo)

    assert not_a_regular_file(regular) is None
    assert not_a_regular_file(tmp_path / "absent.json") is None
    assert not_a_regular_file(link) == "is a symlink"
    assert not_a_regular_file(directory) == "is not a regular file"
    assert not_a_regular_file(fifo) == "is not a regular file"


def test_results_with_findings_hold_a_scan():
    """Findings without scanner entries, as a converted or hand-built file holds."""
    results = AshAggregatedResults.model_validate(
        {"sarif": {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "x"}}}]}}
    )
    assert existing_results_problem(results) is not None
    results = AshAggregatedResults.model_validate(
        {
            "sarif": {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {"driver": {"name": "x"}},
                        "results": [{"message": {"text": "a finding"}}],
                    }
                ],
            }
        }
    )

    assert existing_results_problem(results) is None


def test_workspace_results_hold_their_projects_scans():
    """A workspace run's unified results carry no top-level scanner results."""
    from automated_security_helper.models.workspace import WorkspaceResults

    results = AshAggregatedResults()
    assert existing_results_problem(results) is not None
    results.workspace = WorkspaceResults.model_construct()

    assert existing_results_problem(results) is None


def test_only_the_inner_runs_output_directory_is_given_as_the_hosts():
    message = "not a file in /out/reports, nor in /src/out/reports, nor /outer"

    assert as_seen_from_the_host(message, "/out", "/host/out") == (
        "not a file in /host/out/reports, nor in /src/out/reports, nor /outer"
    )


def test_the_host_directory_is_inserted_as_written():
    """A backslash or group reference in the host path is not a regex escape."""
    host = r"C:\scans\1\out"

    assert as_seen_from_the_host("in /out/reports", "/out", host) == (
        f"in {host}/reports"
    )


@pytest.mark.parametrize(
    "longer", ["/out-dir/x", "/out.bak/x", "/out:/y", "/out_old", "/out~"]
)
def test_a_longer_name_that_starts_with_the_inner_directory_is_left_alone(longer):
    message = f"not a file in {longer}"

    assert as_seen_from_the_host(message, "/out", "/host/out") == message


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        ("in /out", "in /host/out"),
        ("in /out/reports", "in /host/out/reports"),
        ("in '/out'", "in '/host/out'"),
        ('in "/out"', 'in "/host/out"'),
        ("in (/out)", "in (/host/out)"),
        ("in /out, then", "in /host/out, then"),
        ("in /out; then", "in /host/out; then"),
        ("in /out\nthen", "in /host/out\nthen"),
    ],
)
def test_the_inner_directory_is_mapped_where_it_ends_a_path(message, expected):
    assert as_seen_from_the_host(message, "/out", "/host/out") == expected


def test_the_same_directory_leaves_the_message_unchanged():
    assert as_seen_from_the_host("in /x/reports", "/x", "/x") == "in /x/reports"


def test_no_results_is_left_alone():
    mark_run_completed(None, "0" * 32)

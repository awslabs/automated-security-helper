# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The helpers that read and write an inner run's records (utils/inner_run_outcome.py)."""

from __future__ import annotations

from automated_security_helper.utils.inner_run_outcome import (
    as_seen_from_the_host,
    mark_run_completed,
)


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


def test_the_same_directory_leaves_the_message_unchanged():
    assert as_seen_from_the_host("in /x/reports", "/x", "/x") == "in /x/reports"


def test_no_results_is_left_alone():
    mark_run_completed(None, "0" * 32)

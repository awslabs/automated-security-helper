# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash merge --output-formats`` naming an off-host reporter's format runs it.

Why this file exists
--------------------
``ash merge`` ran its off-host reporters only when no ``--output-formats`` was
given, on the premise that no format value names one. The ``ExportFormat``
members do name them (``aws-security-hub``, ``s3``, ``cloudwatch-logs``,
``bedrock-summary-reporter``), so an operator who enabled one and asked for its
format by name got no upload, and the local report phase told them no reporter
produces that format. A scan given the same request runs that reporter. The
merge now splits the requested formats between its two report phases, and a
requested off-host format that neither phase runs (its reporter not enabled by
the operator) keeps the line the local phase used to print for it.

The stand-in is the off-host reporter of ``off_host_plugin_support`` named
``s3``: an ``ExportFormat`` member, so ``--output-formats`` accepts it, while the
real reporter of that name lives in the AWS plugin module, which this run does
not load. The command runs in a subprocess for the reason given there.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.unit.cli.off_host_plugin_support import (
    DEFAULT_ENDPOINT,
    make_plugin_site,
    reporter_source,
    reporter_texts,
    run_merge,
)

pytestmark = pytest.mark.integration

PLUGIN = "s3_standin_ash_plugins"
REPORTER = "s3"
NO_PRODUCER = "No report will be written for requested format"


@pytest.fixture
def s3_site(tmp_path: Path) -> Path:
    return make_plugin_site(
        tmp_path,
        PLUGIN,
        reporter_source(
            "S3StandIn", REPORTER, "s3.json", enabled=False, declares_destinations=True
        ),
    )


def _merge(tmp_path: Path, site: Path, requested: str, *, enabled: bool = True):
    return run_merge(
        tmp_path,
        site,
        [f"reporters.{REPORTER}.enabled=true"] if enabled else [],
        plugin=PLUGIN,
        reporter=REPORTER,
        extra_args=["--output-formats", requested],
    )


def test_naming_the_off_host_reporters_format_runs_it(tmp_path, s3_site):
    result = _merge(tmp_path, s3_site, REPORTER)

    written = reporter_texts(result)
    assert len(written) == 1, (result["reports"], result["output"])
    assert DEFAULT_ENDPOINT in written[0], written
    # Only the requested format was produced, and the request was not reported
    # as one no reporter produces.
    assert all('"endpoint"' in text for text in result["reports"].values()), result[
        "reports"
    ]
    assert not any(NO_PRODUCER in warning for warning in result["warnings"]), result[
        "warnings"
    ]


def test_naming_only_a_local_format_leaves_the_off_host_reporter_out(tmp_path, s3_site):
    result = _merge(tmp_path, s3_site, "sarif")

    assert reporter_texts(result) == [], result["reports"]
    assert "ash.sarif" in result["reports"], result["reports"]
    assert not any(NO_PRODUCER in warning for warning in result["warnings"]), result[
        "warnings"
    ]


def test_naming_a_local_and_an_off_host_format_runs_both_phases(tmp_path, s3_site):
    """The case the split exists for, which no other test here reaches: with
    ``sarif,s3`` the local phase must be handed ``sarif`` without ``s3`` and the
    off-host phase must still run. A merge that dropped the off-host phase
    whenever a local format was requested, or handed ``s3`` to the local phase
    too, passed the single-format cases above."""
    result = _merge(tmp_path, s3_site, "sarif,s3")

    written = reporter_texts(result)
    assert len(written) == 1, (result["reports"], result["output"])
    assert DEFAULT_ENDPOINT in written[0], written
    assert "ash.sarif" in result["reports"], result["reports"]
    # Neither phase reported the other's format as one no reporter produces.
    assert not any(NO_PRODUCER in warning for warning in result["warnings"]), result[
        "warnings"
    ]


def test_naming_an_off_host_format_the_operator_did_not_enable_is_said(
    tmp_path, s3_site
):
    # The operator's file enables the reporter, but for an off-host reporter only
    # an override counts, so with none it does not run. Neither report phase then
    # produces the requested format, and the operator is told so with the report
    # phase's own line, as before the request was split between the phases.
    result = _merge(tmp_path, s3_site, REPORTER, enabled=False)

    assert reporter_texts(result) == [], result["reports"]
    said = [w for w in result["warnings"] if NO_PRODUCER in w and f"'{REPORTER}'" in w]
    assert len(said) == 1, result["warnings"]
    assert f"reporters.{REPORTER}.enabled=true" in said[0], said

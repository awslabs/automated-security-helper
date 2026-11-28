# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The per-scanner metrics of a SARIF report leave out a result that states no finding.

``get_severity_metrics_from_sarif`` counts a scanner's results into the severity
buckets the scanner's row carries, and ``ScannerExecutor`` takes the row's finding
count from it. The statistics calculator's per-scanner read leaves a result of kind
``pass``, ``notApplicable`` or ``informational`` (``sarif_utils.NON_FINDING_KINDS``)
that states no finding out of the buckets, because SARIF gives such a result level
``none``, which ASH grades INFO. This reader graded it by level alone, so the same
scan reported an INFO finding in the row the scanner wrote and none in the summary
built from the SARIF. A result states no finding when its kind is one of those and
nothing in it reports a problem: its level is ``none`` or not stated, and no
``issue_severity`` it declares is above INFO. One whose level reports a problem is a
finding, counted by its level.

Every test with a non-finding kind has a control that changes the kind and nothing
else. A result that states no finding is in no bucket, suppressed or not.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.phases.scanner_executor import ScannerExecutor
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.sarif_utils import (
    NON_FINDING_KINDS,
    get_severity_metrics_from_sarif,
)

pytestmark = pytest.mark.unit

# Sorted, so every pytest-xdist worker collects the same ids in the same order.
NON_FINDING = sorted(NON_FINDING_KINDS)
# The kinds that assert a finding. A result that states no kind is a failing one.
FINDING = ["fail", "open", "review"]
ANY_FINDING = [pytest.param(None, id="absent"), *FINDING]


def _high() -> dict[str, Any]:
    """A HIGH finding of the scanner the notes below name."""
    return {
        "ruleId": "R-HIGH",
        "level": "error",
        "message": {"text": "a finding"},
        "properties": {"scanner_name": "trivy", "issue_severity": "HIGH"},
    }


def _note(
    kind: str | None, *, level: str = "none", suppressed: bool = False
) -> dict[str, Any]:
    """The note a scanner records for an image it did not scan, with *kind* and
    *level*."""
    result: dict[str, Any] = {
        "ruleId": "N1",
        "level": level,
        "message": {"text": "the image was not scanned"},
        "properties": {"scanner_name": "trivy"},
    }
    if kind is not None:
        result["kind"] = kind
    if suppressed:
        result["suppressions"] = [{"kind": "external", "justification": "accepted"}]
    return result


def _report(*results: dict[str, Any]) -> SarifReport:
    return SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "trivy"}}, "results": list(results)}],
        }
    )


def _executor(tmp_path: Path) -> ScannerExecutor:
    context = PluginContext(
        source_dir=tmp_path, output_dir=tmp_path / "out", config=AshConfig()
    )
    return ScannerExecutor(
        plugin_context=context, progress_display=None, scanner_tasks=[]
    )


# ---------------------------------------------------------------------------
# The metrics of the report
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("kind", NON_FINDING)
def test_a_result_that_states_no_finding_is_in_no_severity_bucket(kind):
    counts = get_severity_metrics_from_sarif(_report(_high(), _note(kind)), None)

    assert (counts.high, counts.info, counts.total) == (1, 0, 1)


@pytest.mark.parametrize("kind", ANY_FINDING)
def test_the_same_result_that_asserts_a_finding_is_counted_as_info(kind):
    counts = get_severity_metrics_from_sarif(_report(_high(), _note(kind)), None)

    assert (counts.high, counts.info, counts.total) == (1, 1, 2)


@pytest.mark.parametrize("kind", NON_FINDING)
def test_a_report_of_nothing_but_such_results_counts_nothing(kind):
    counts = get_severity_metrics_from_sarif(_report(_note(kind)), None)

    assert (counts.info, counts.total, counts.suppressed) == (0, 0, 0)


@pytest.mark.parametrize("kind", NON_FINDING)
def test_a_suppressed_result_that_states_no_finding_is_in_no_count(kind):
    """A result that states no finding counts in no figure, suppressed or not."""
    counts = get_severity_metrics_from_sarif(
        _report(_high(), _note(kind, suppressed=True)), None
    )

    assert (counts.high, counts.info, counts.suppressed, counts.total) == (1, 0, 0, 1)


@pytest.mark.parametrize("kind", NON_FINDING)
def test_a_result_whose_level_reports_a_problem_is_counted_by_its_level(kind):
    """A result of such a kind at level warning is a MEDIUM finding, as any result at
    that level is."""
    counts = get_severity_metrics_from_sarif(
        _report(_high(), _note(kind, level="warning")), None
    )

    assert (counts.high, counts.medium, counts.info, counts.total) == (1, 1, 0, 2)


# ---------------------------------------------------------------------------
# The finding count the executor takes from it
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("kind", NON_FINDING)
def test_the_executor_counts_a_result_that_states_no_finding_in_no_finding_count(
    tmp_path, kind
):
    counts, finding_count = _executor(tmp_path)._extract_metrics_from_sarif(
        _report(_high(), _note(kind))
    )

    assert finding_count == 1
    assert (counts.high, counts.info) == (1, 0)


@pytest.mark.parametrize("kind", ANY_FINDING)
def test_the_executor_counts_the_same_result_when_it_asserts_a_finding(tmp_path, kind):
    _, finding_count = _executor(tmp_path)._extract_metrics_from_sarif(
        _report(_high(), _note(kind))
    )

    assert finding_count == 2


@pytest.mark.parametrize("kind", NON_FINDING)
def test_the_executor_count_leaves_out_a_suppressed_result_that_states_no_finding(
    tmp_path, kind
):
    """The count is the findings plus the suppressed ones, and a suppressed result that
    states no finding is neither."""
    _, finding_count = _executor(tmp_path)._extract_metrics_from_sarif(
        _report(_high(), _note(kind, suppressed=True))
    )

    assert finding_count == 1

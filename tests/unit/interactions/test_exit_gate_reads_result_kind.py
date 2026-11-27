# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A result that states no finding does not fail the exit-code gate.

A SARIF result of kind ``pass``, ``notApplicable`` or ``informational`` says that a
rule passed, did not apply, or reported information only
(``sarif_utils.NON_FINDING_KINDS``). SARIF asks for level ``none`` beside those
kinds, which ASH grades INFO, and a threshold of ``ALL`` fails INFO. Graded by its
level alone, the note a scan records for an image it did not scan counted as a
finding at that threshold and the scan exited 2. A result states no finding when its
kind is one of those and nothing in it reports a problem: its level is ``none`` or
not stated, and no ``issue_severity`` it declares is above INFO. A result of such a
kind whose level or ``issue_severity`` does report a problem is a finding, graded
as any other result is.

Every test with a non-finding kind has a control that changes the kind and nothing
else. A failing result (the default kind), and the two kinds that assert a finding a
reader still has to judge, ``open`` and ``review``, keep the grade they had.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.phases.scan_phase import ScanPhase
from automated_security_helper.interactions import run_ash_scan as ras
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.schemas.sarif_schema_model import (
    Kind,
    Level,
    Message,
    Message1,
    PropertyBag,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils.inner_run_outcome import record_reports_written
from automated_security_helper.utils.sarif_utils import NON_FINDING_KINDS

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()

# Sorted, so every pytest-xdist worker collects the same ids in the same order.
NON_FINDING = sorted(NON_FINDING_KINDS)
# The kinds that assert a finding. A result that states no kind is a failing one.
FINDING = ["fail", "open", "review"]
ANY_FINDING = [pytest.param(None, id="absent"), *FINDING]

IMAGE = "registry.example/app:1"


def _note(kind: str | None, level: str = "none") -> dict[str, Any]:
    """The image-not-scanned note as reports/ash.sarif holds it, with *kind* and
    *level*."""
    note: dict[str, Any] = {
        "ruleId": ScanPhase.IMAGE_NOT_SCANNED_RULE_ID,
        "level": level,
        "message": {"text": "the image was not scanned"},
        "properties": {"image": IMAGE},
    }
    if kind is not None:
        note["kind"] = kind
    return note


def _model_note(kind: str, level: Level = Level.none) -> Result:
    """The same note as the scan phase builds it, with *kind* and *level*."""
    return Result(
        ruleId=ScanPhase.IMAGE_NOT_SCANNED_RULE_ID,
        kind=Kind(kind),
        level=level,
        message=Message(root=Message1(text="the image was not scanned")),
        properties=PropertyBag.model_validate({"image": IMAGE}),
    )


def _at_all(_scanner: object) -> str:
    """The threshold lookup of a scan in which every scanner gates at ALL."""
    return "ALL"


def _at_medium(_scanner: object) -> str:
    """The threshold lookup of a scan in which every scanner gates at MEDIUM."""
    return "MEDIUM"


# ---------------------------------------------------------------------------
# The one actionability rule of the exit code
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("kind", NON_FINDING)
def test_a_json_result_that_states_no_finding_does_not_fail_the_gate(kind):
    assert ras._result_fails_its_scanner_threshold(_note(kind), _at_all) is False


@pytest.mark.parametrize("kind", NON_FINDING)
def test_a_model_result_that_states_no_finding_does_not_fail_the_gate(kind):
    assert ras._result_fails_its_scanner_threshold(_model_note(kind), _at_all) is False


@pytest.mark.parametrize("kind", ANY_FINDING)
def test_the_same_json_result_that_asserts_a_finding_fails_the_all_gate(kind):
    assert ras._result_fails_its_scanner_threshold(_note(kind), _at_all) is True


@pytest.mark.parametrize("kind", FINDING)
def test_the_same_model_result_that_asserts_a_finding_fails_the_all_gate(kind):
    assert ras._result_fails_its_scanner_threshold(_model_note(kind), _at_all) is True


@pytest.mark.parametrize("kind", NON_FINDING)
def test_a_json_result_whose_level_reports_a_problem_fails_the_medium_gate(kind):
    """A result of a non-finding kind at level warning is graded MEDIUM, which the
    default threshold fails."""
    result = _note(kind, level="warning")

    assert ras._result_fails_its_scanner_threshold(result, _at_medium) is True


@pytest.mark.parametrize("kind", NON_FINDING)
def test_a_model_result_whose_level_reports_a_problem_fails_the_medium_gate(kind):
    """The same pair as a model: the level it states is the one the gate grades."""
    result = _model_note(kind, Level.warning)

    assert ras._result_fails_its_scanner_threshold(result, _at_medium) is True


@pytest.mark.parametrize("kind", NON_FINDING)
def test_the_min_severity_check_does_not_read_a_non_finding_as_actionable(kind):
    """The check that keeps exit 2 standing reads the same rule as the count."""
    assert (
        ras._actionable_under_its_scanner_threshold(
            _model_note(kind), None, threshold_for=_at_all
        )
        is False
    )


@pytest.mark.parametrize("kind", FINDING)
def test_the_min_severity_check_still_reads_a_finding_as_actionable(kind):
    assert (
        ras._actionable_under_its_scanner_threshold(
            _model_note(kind), None, threshold_for=_at_all
        )
        is True
    )


# ---------------------------------------------------------------------------
# The count and the exit code over the report a scan wrote
# ---------------------------------------------------------------------------


def _scan_results(
    tmp_path, note: dict[str, Any], threshold: str = "ALL"
) -> AshAggregatedResults:
    """Results gated at *threshold*, and the report this run wrote holding only *note*.

    The exit code counts the persisted report when the results record it as written
    by this run's SARIF reporter, so the file goes under reports/ and is recorded
    the way the report phase records it. The model holds the same note.
    """
    results = AshAggregatedResults()
    results.ash_config = AshConfig.model_validate(
        {
            "project_name": "non-finding-kinds",
            "global_settings": {"severity_threshold": threshold},
        }
    )
    results.sarif = SarifReport(
        version="2.1.0",
        runs=[
            Run(
                tool=Tool(driver=ToolComponent(name="ASH", version="1.0")),
                results=[Result.model_validate(note)],
            )
        ],
    )
    record_reports_written(results, [("ash.sarif", "sarif")])
    report = tmp_path / "out" / "reports" / "ash.sarif"
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(
        json.dumps(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {"driver": {"name": "ASH", "version": "1.0"}},
                        "results": [note],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return results


def _opts(tmp_path) -> ras.ScanOptions:
    return ras.ScanOptions(source_dir=tmp_path / "src", output_dir=tmp_path / "out")


def _no_scanner_counts(monkeypatch) -> None:
    """The scanner metrics count nothing, so only the written report decides."""
    monkeypatch.setattr(
        ras, "get_unified_scanner_metrics", lambda *_args, **_kwargs: []
    )


@pytest.mark.parametrize("kind", NON_FINDING)
def test_a_scan_whose_only_result_states_no_finding_exits_0_at_all(
    tmp_path, monkeypatch, kind
):
    _no_scanner_counts(monkeypatch)
    results = _scan_results(tmp_path, _note(kind))
    opts = _opts(tmp_path)

    assert ras._gating_actionable_count(results, opts, True) == 0
    assert (
        ras._compute_exit_code(results, opts, report_sarif_written_this_run=True) == 0
    )


@pytest.mark.parametrize("kind", ANY_FINDING)
def test_the_same_scan_with_a_kind_that_asserts_a_finding_exits_2_at_all(
    tmp_path, monkeypatch, kind
):
    _no_scanner_counts(monkeypatch)
    results = _scan_results(tmp_path, _note(kind))
    opts = _opts(tmp_path)

    assert ras._gating_actionable_count(results, opts, True) == 1
    assert (
        ras._compute_exit_code(results, opts, report_sarif_written_this_run=True) == 2
    )


@pytest.mark.parametrize("kind", NON_FINDING)
def test_a_scan_whose_only_result_is_such_a_pair_exits_2_at_medium(
    tmp_path, monkeypatch, kind
):
    """A result of a non-finding kind at level warning is a MEDIUM finding, so the scan
    fails at the default threshold."""
    _no_scanner_counts(monkeypatch)
    results = _scan_results(tmp_path, _note(kind, level="warning"), "MEDIUM")
    opts = _opts(tmp_path)

    assert ras._gating_actionable_count(results, opts, True) == 1
    assert (
        ras._compute_exit_code(results, opts, report_sarif_written_this_run=True) == 2
    )

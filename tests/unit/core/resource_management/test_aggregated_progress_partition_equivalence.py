# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The aggregated progress partition decides what the per-row filter decided.

``_oracle_add_aggregated_scanner_progress``, ``_oracle_extract_findings_summary``
and ``_oracle_update_findings`` below are the code that
``scan_tracking._add_aggregated_scanner_progress``, ``extract_findings_summary``
and ``ScannerProgress.update_findings`` ran before the findings were partitioned
by scanner in one frame pass, kept as an oracle. They call the same leaf helpers
(``_sarif_run_results``, ``_counts_of_document``, ``result_severity``,
``result_scanner_name``, ``is_result_suppressed``), so a difference between the
oracle and the live code is a difference in the partition or the tally.

The cases cover recorded counts that are null, negative, bool or text; unknown,
``total`` and ``actionable`` keys; empty rows; results naming no scanner; a run
with no driver, which falls back to ``unknown``; a row named like the driver;
each suppression state; null runs; and an entry that is not an object, whose
error text must match.
"""

import copy
from typing import Any, Dict, List

import pytest

from automated_security_helper.core.resource_management import scan_tracking
from automated_security_helper.core.resource_management.scan_tracking import (
    UNKNOWN_SEVERITY,
    MCScannerStatus,
    ScannerProgress,
    ScanProgress,
    _counts_of_document,
    _recorded_duration,
    _run_driver_name,
    _sarif_run_results,
    _UnusableResultsError,
    empty_severity_counts,
    scanner_status_from_results,
)
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.utils.scanner_tool_types import result_scanner_name
from automated_security_helper.utils.severity_ladder import result_severity

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# the oracle: the code as it was
# ---------------------------------------------------------------------------


def _oracle_extract_findings_summary(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    summary = empty_severity_counts()

    for finding in findings:
        severity = str(finding.get("severity") or "").lower()
        # An unrecognized or missing severity goes to the catch-all rather than
        # being dropped, so sum(summary.values()) == len(findings) always holds.
        if severity not in summary:
            severity = UNKNOWN_SEVERITY
        summary[severity] += 1

    return summary


def _oracle_update_findings(
    progress: ScannerProgress, findings: List[Dict[str, Any]]
) -> None:
    progress.severity_counts = _oracle_extract_findings_summary(findings)
    progress.finding_count = sum(
        value
        for bucket, value in progress.severity_counts.items()
        if bucket != "suppressed"
    )


def _oracle_add_aggregated_scanner_progress(
    scan_progress: ScanProgress, results: Dict[str, Any]
) -> None:
    from automated_security_helper.utils.sarif_utils import is_result_suppressed

    findings = []

    for run, result in _sarif_run_results(results.get("sarif")):
        findings.append(
            {
                "id": result.get("ruleId", "unknown"),
                "severity": (
                    "suppressed"
                    if is_result_suppressed(result)
                    else result_severity(result)
                ),
                "scanner": result_scanner_name(result) or _run_driver_name(run),
            }
        )

    scanner_results = results.get("scanner_results") or {}
    for scanner_name, scanner_info in scanner_results.items():
        if not isinstance(scanner_info, dict):
            raise _UnusableResultsError(
                f"scanner_results[{scanner_name!r}] must be an object, found "
                f"{type(scanner_info).__name__}"
            )

    # Create scanner progress objects for each completed scanner
    for scanner_name, scanner_info in scanner_results.items():
        # Filter findings for this scanner
        scanner_findings = [f for f in findings if f.get("scanner") == scanner_name]

        recorded_count, recorded_counts = _counts_of_document(scanner_info)
        if not recorded_counts:
            recorded_counts = None

        mapped_status = scanner_status_from_results(
            scanner_info.get("status", ScannerStatus.PASSED.value)
        )
        source_progress = ScannerProgress(
            scanner_name=scanner_name,
            target_type="source",
            status=mapped_status,
            duration=(
                None
                if mapped_status is MCScannerStatus.SKIPPED
                else _recorded_duration(scanner_info)
            ),
            finding_count=recorded_count or 0,
        )

        if recorded_counts is not None:
            counts = empty_severity_counts()
            for severity, value in recorded_counts.items():
                counts[severity if severity in counts else UNKNOWN_SEVERITY] += value
            graded = sum(
                value for bucket, value in counts.items() if bucket != "suppressed"
            )
            if recorded_count is None:
                source_progress.finding_count = graded
            elif recorded_count > graded:
                counts[UNKNOWN_SEVERITY] += recorded_count - graded
            source_progress.severity_counts = counts
        elif scanner_findings:
            _oracle_update_findings(source_progress, scanner_findings)
            unmatched = (recorded_count or 0) - source_progress.finding_count
            if unmatched > 0:
                source_progress.finding_count += unmatched
                source_progress.severity_counts[UNKNOWN_SEVERITY] += unmatched
        elif recorded_count:
            source_progress.severity_counts = empty_severity_counts()
            source_progress.severity_counts[UNKNOWN_SEVERITY] = recorded_count
        else:
            source_progress.severity_counts = empty_severity_counts()

        scan_progress.add_scanner_progress(source_progress)


# ---------------------------------------------------------------------------
# the comparison
# ---------------------------------------------------------------------------


def _snapshot(scan_progress: ScanProgress) -> Dict[str, Any]:
    """Everything an observer reads: rows in order, their dicts, the totals."""
    return {
        "scanner_order": list(scan_progress.scanners),
        "rows": [
            (name, target, progress.to_dict(), list(progress.severity_counts))
            for name, targets in scan_progress.scanners.items()
            for target, progress in targets.items()
        ],
        "total_findings": scan_progress.total_findings,
        "severity_counts": scan_progress.severity_counts,
        "severity_order": list(scan_progress.severity_counts),
    }


def _run(fn, results: Dict[str, Any]):
    progress = ScanProgress(scan_id="s")
    try:
        fn(progress, copy.deepcopy(results))
    except Exception as error:  # the error text is part of the contract
        return ("error", type(error), str(error))
    return ("ok", _snapshot(progress))


def _same(results: Dict[str, Any]) -> None:
    oracle = _run(_oracle_add_aggregated_scanner_progress, results)
    live = _run(scan_tracking._add_aggregated_scanner_progress, results)
    assert live == oracle


def _result(scanner=None, severity=None, level=None, suppressions=None, rule="r"):
    properties: Dict[str, Any] = {}
    if scanner is not None:
        properties["scanner_name"] = scanner
    if severity is not None:
        properties["issue_severity"] = severity
    result: Dict[str, Any] = {"ruleId": rule, "properties": properties}
    if level is not None:
        result["level"] = level
    if suppressions is not None:
        result["suppressions"] = suppressions
    return result


def _sarif(*runs):
    return {"runs": list(runs)}


def _run_of(results, driver="ASH"):
    run: Dict[str, Any] = {"results": results}
    if driver is not None:
        run["tool"] = {"driver": {"name": driver}}
    return run


# ---------------------------------------------------------------------------
# hand-built cases
# ---------------------------------------------------------------------------

CASES: Dict[str, Dict[str, Any]] = {
    "no scanners": {"sarif": _sarif(_run_of([_result("a", "HIGH")]))},
    "no sarif": {"scanner_results": {"a": {"status": "PASSED"}}},
    "sarif only, no recorded counts": {
        "scanner_results": {"a": {}, "b": {}},
        "sarif": _sarif(
            _run_of(
                [
                    _result("a", "HIGH"),
                    _result("b", "low"),
                    _result("a", "CRITICAL"),
                    _result("a", level="error"),
                    _result("b", level="note"),
                ]
            )
        ),
    },
    "scanner order follows scanner_results, not the sarif": {
        "scanner_results": {"z": {}, "a": {}, "m": {}},
        "sarif": _sarif(
            _run_of([_result("a", "HIGH"), _result("m", "LOW"), _result("z", "INFO")])
        ),
    },
    "first-seen order among buckets does not move the dict": {
        "scanner_results": {"a": {}},
        "sarif": _sarif(
            _run_of(
                [_result("a", "INFO"), _result("a", "CRITICAL"), _result("a", "INFO")]
            )
        ),
    },
    "exact name only: a lower-cased row finds nothing": {
        "scanner_results": {"bandit": {}, "Bandit": {}},
        "sarif": _sarif(_run_of([_result("Bandit", "HIGH"), _result("bandit", "LOW")])),
    },
    "exact name only: a differently cased row finds nothing": {
        "scanner_results": {"BANDIT": {}},
        "sarif": _sarif(_run_of([_result("bandit", "HIGH")])),
    },
    "results with no scanner name fall back to the driver": {
        "scanner_results": {"ASH": {}, "other": {}},
        "sarif": _sarif(_run_of([_result(None, "HIGH"), _result("", "LOW")])),
    },
    "a run with no driver falls back to unknown": {
        "scanner_results": {"unknown": {}, "a": {}},
        "sarif": _sarif(
            _run_of([_result(None, "HIGH"), _result(None, "MEDIUM")], driver=None)
        ),
    },
    "a run whose tool is not an object falls back to unknown": {
        "scanner_results": {"unknown": {}},
        "sarif": _sarif(
            {"tool": "x", "results": [_result(None, "HIGH")]},
            {"tool": {"driver": "x"}, "results": [_result(None, "LOW")]},
            {"tool": {"driver": {"name": ""}}, "results": [_result(None, "LOW")]},
            {"tool": {"driver": {"name": 7}}, "results": [_result(None, "LOW")]},
        ),
    },
    "a row named like the driver": {
        "scanner_results": {"ASH": {}, "SomeDriver": {}},
        "sarif": _sarif(
            _run_of([_result(None, "HIGH"), _result("ASH", "LOW")], driver="ASH"),
            _run_of([_result(None, "MEDIUM")], driver="SomeDriver"),
        ),
    },
    "suppression states": {
        "scanner_results": {"a": {}},
        "sarif": _sarif(
            _run_of(
                [
                    _result("a", "HIGH", suppressions=[{"kind": "inSource"}]),
                    _result("a", "HIGH", suppressions=[{"state": "accepted"}]),
                    _result("a", "HIGH", suppressions=[{"state": "rejected"}]),
                    _result("a", "HIGH", suppressions=[{"state": "underReview"}]),
                    _result("a", "LOW", suppressions=[]),
                    _result("a", "LOW", suppressions=None),
                    _result("a", "LOW"),
                ]
            )
        ),
    },
    "all suppressed": {
        "scanner_results": {"a": {}},
        "sarif": _sarif(
            _run_of([_result("a", "HIGH", suppressions=[{"state": "accepted"}])] * 3)
        ),
    },
    "null and malformed runs and results": {
        "scanner_results": {"a": {}},
        "sarif": _sarif(
            {"results": None},
            {"tool": {"driver": {"name": "a"}}},
            "not a run",
            None,
            _run_of(["not a result", None, 3, _result("a", "HIGH")]),
            {"results": "text"},
        ),
    },
    "sarif that is not an object": {
        "scanner_results": {"a": {}},
        "sarif": ["runs"],
    },
    "sarif runs that is not a list": {
        "scanner_results": {"a": {}},
        "sarif": {"runs": {"results": []}},
    },
    "empty scanner_results": {"scanner_results": {}, "sarif": _sarif(_run_of([]))},
    "null scanner_results": {"scanner_results": None},
    "a severity outside the ladder": {
        "scanner_results": {"a": {}},
        "sarif": _sarif(
            _run_of(
                [
                    _result("a", "BLOCKER"),
                    _result("a", level="warning"),
                    _result("a", level="weird"),
                    _result("a"),
                ]
            )
        ),
    },
    "recorded counts beat the sarif": {
        "scanner_results": {
            "a": {"finding_count": 5, "severity_counts": {"high": 2, "low": 1}}
        },
        "sarif": _sarif(_run_of([_result("a", "HIGH")] * 9)),
    },
    "a recorded count with no buckets keeps the sarif and tops up unknown": {
        "scanner_results": {"a": {"finding_count": 7}},
        "sarif": _sarif(_run_of([_result("a", "HIGH"), _result("a", "LOW")])),
    },
    "a recorded count below the sarif is the sarif's to raise": {
        "scanner_results": {"a": {"finding_count": 1}},
        "sarif": _sarif(_run_of([_result("a", "HIGH"), _result("a", "LOW")] * 2)),
    },
    "a recorded count with nothing found is unknown": {
        "scanner_results": {"a": {"finding_count": 4}, "b": {"finding_count": 0}},
    },
    "recorded buckets with a null count": {
        "scanner_results": {
            "a": {
                "finding_count": None,
                "severity_counts": {"HIGH": 2, "suppressed": 5, "weird": 1},
            }
        },
    },
    "recorded buckets above the count": {
        "scanner_results": {
            "a": {"finding_count": 9, "severity_counts": {"high": 2, "suppressed": 1}}
        },
    },
    "unknown, total and actionable keys": {
        "scanner_results": {
            "a": {
                "finding_count": 3,
                "severity_counts": {
                    "total": 99,
                    "actionable": 99,
                    "unknown": 2,
                    "high": 1,
                },
            }
        },
    },
    "empty recorded buckets read as none recorded": {
        "scanner_results": {
            "a": {"severity_counts": {}},
            "b": {"severity_counts": {"high": "3", "low": -1, "info": True}},
        },
        "sarif": _sarif(_run_of([_result("a", "HIGH"), _result("b", "LOW")])),
    },
    "counts that are null, negative, bool or text": {
        "scanner_results": {
            "null": {"finding_count": None},
            "negative": {"finding_count": -3},
            "bool": {"finding_count": True},
            "text": {"finding_count": "4"},
            "float": {"finding_count": 2.0},
            "counts not a dict": {"severity_counts": [1, 2]},
        },
        "sarif": _sarif(
            _run_of([_result(name, "HIGH") for name in ("null", "bool", "text")])
        ),
    },
    "status and duration pass through": {
        "scanner_results": {
            "ran": {"status": "FAILED", "duration": 2.5},
            "skipped": {"status": "SKIPPED", "duration": 9},
            "odd": {"status": "nonsense", "duration": True},
            "none": {"status": None, "duration": "x"},
        },
        "sarif": _sarif(_run_of([_result("ran", "LOW"), _result("skipped", "LOW")])),
    },
    "a non-dict entry": {
        "scanner_results": {"a": {}, "b": "text", "c": {}},
        "sarif": _sarif(_run_of([_result("a", "HIGH")])),
    },
    "a null entry": {"scanner_results": {"a": None}},
    "a list entry": {"scanner_results": {"a": [1]}},
    "many findings, many scanners": {
        "scanner_results": {f"s{i}": {} for i in range(12)},
        "sarif": _sarif(
            _run_of(
                [
                    _result(
                        f"s{i % 12}",
                        ("HIGH", "LOW", "INFO", "MEDIUM", "CRITICAL")[i % 5],
                        suppressions=[{"state": "accepted"}] if i % 7 == 0 else None,
                    )
                    for i in range(300)
                ]
            )
        ),
    },
    "non-ascii and surrogate names": {
        "scanner_results": {"scänner": {}, "\ud800x": {}, "日本": {}, "a\x00b": {}},
        "sarif": _sarif(
            _run_of(
                [
                    _result("scänner", "HIGH"),
                    _result("\ud800x", "LOW"),
                    _result("日本", "INFO"),
                    _result("a\x00b", "MEDIUM"),
                    _result("scanner", "HIGH"),
                ]
            )
        ),
    },
}


@pytest.mark.parametrize("name", sorted(CASES))
def test_partition_matches_the_per_row_filter(name):
    _same(CASES[name])


def test_a_case_with_findings_reaches_the_partition():
    """A control: the oracle's rows carry counts the partition has to reproduce."""
    status, snapshot = _run(
        _oracle_add_aggregated_scanner_progress, CASES["sarif only, no recorded counts"]
    )
    assert status == "ok"
    rows = {name: row for name, _, row, _ in snapshot["rows"]}
    assert rows["a"]["finding_count"] == 3
    assert rows["a"]["severity_counts"]["critical"] == 2


def test_the_non_dict_entry_error_text_matches():
    oracle = _run(_oracle_add_aggregated_scanner_progress, CASES["a non-dict entry"])
    live = _run(
        scan_tracking._add_aggregated_scanner_progress, CASES["a non-dict entry"]
    )
    assert oracle[0] == "error"
    assert live == oracle
    assert oracle[1] is _UnusableResultsError
    assert "scanner_results['b'] must be an object, found str" in oracle[2]


def test_exact_name_only_a_differently_cased_scanner_gets_nothing():
    status, snapshot = _run(
        scan_tracking._add_aggregated_scanner_progress,
        CASES["exact name only: a differently cased row finds nothing"],
    )
    assert status == "ok"
    ((_, _, row, _),) = snapshot["rows"]
    assert row["finding_count"] == 0
    assert not any(row["severity_counts"].values())


def test_the_extract_findings_summary_fold_is_the_oracle_fold():
    findings = [
        {"severity": value}
        for value in ("HIGH", "high", "Low", None, "", "weird", "suppressed", 3, False)
    ] + [{}]
    assert scan_tracking.extract_findings_summary(
        findings
    ) == _oracle_extract_findings_summary(findings)


def test_the_update_findings_tally_is_the_oracle_tally():
    findings = [{"severity": value} for value in ("HIGH", "suppressed", "x", None)]
    live = ScannerProgress("a", "source")
    oracle = ScannerProgress("a", "source")
    live.update_findings(findings)
    _oracle_update_findings(oracle, findings)
    assert live.to_dict() == oracle.to_dict()
    assert list(live.severity_counts) == list(oracle.severity_counts)


# ---------------------------------------------------------------------------
# generated documents
# ---------------------------------------------------------------------------

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import HealthCheck, given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

_NAMES = ["a", "A", "bandit", "Bandit", "ASH", "unknown", "日本", "x y", ""]
_SEVERITIES = [
    None,
    "HIGH",
    "high",
    "LOW",
    "Info",
    "MEDIUM",
    "CRITICAL",
    "BLOCKER",
    "",
]
_SUPPRESSIONS = [
    None,
    [],
    [{"state": "accepted"}],
    [{"state": "rejected"}],
    [{"state": "underReview"}],
    [{"kind": "inSource"}],
]

_result_strategy = st.fixed_dictionaries(
    {
        "scanner": st.sampled_from([None, *_NAMES]),
        "severity": st.sampled_from(_SEVERITIES),
        "level": st.sampled_from([None, "error", "warning", "note", "none", "odd"]),
        "suppressions": st.sampled_from(_SUPPRESSIONS),
    }
).map(lambda d: _result(**d))

_run_strategy = st.builds(
    _run_of,
    st.lists(_result_strategy, max_size=8),
    st.sampled_from(["ASH", "bandit", None, "a"]),
)

_info_strategy = st.one_of(
    st.just({}),
    st.fixed_dictionaries(
        {},
        optional={
            "finding_count": st.one_of(
                st.none(), st.integers(-2, 6), st.booleans(), st.just("3")
            ),
            "severity_counts": st.one_of(
                st.none(),
                st.dictionaries(
                    st.sampled_from(
                        ["high", "HIGH", "low", "suppressed", "unknown", "total", "odd"]
                    ),
                    st.one_of(st.integers(-1, 5), st.booleans(), st.just("2")),
                    max_size=4,
                ),
            ),
            "status": st.sampled_from(["PASSED", "FAILED", "SKIPPED", "weird", None]),
            "duration": st.one_of(st.none(), st.floats(0, 5), st.booleans()),
        },
    ),
)


@settings(
    max_examples=300,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large],
)
@given(
    scanner_results=st.dictionaries(
        st.sampled_from(_NAMES), _info_strategy, max_size=5
    ),
    runs=st.lists(_run_strategy, max_size=3),
)
def test_generated_documents(scanner_results, runs):
    _same({"scanner_results": scanner_results, "sarif": _sarif(*runs)})

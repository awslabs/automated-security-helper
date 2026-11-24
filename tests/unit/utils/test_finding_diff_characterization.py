# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Characterization goldens for baseline diff and baseline apply.

What counts as "the same finding" is the behavior pinned here: the exact join on
finding id, the ambiguity resolution by group cardinality and suppression state,
the moved-pair alignment (group by fallback key, then ordered zip), the new/absent
anti-joins, and the row-wise keep/drop predicates of ``apply_baseline`` that decide
which SARIF results a baseline removes.

The files under test are ``utils/finding_diff.py`` and ``utils/scan_baseline.py``
(``apply_baseline``, ``check_baseline_scope``). Every scenario below is a pure
function of its inputs; the expected value of each is recorded in
``golden/finding_diff_characterization.json`` as plain JSON, with findings named by
their position in the input list (``b2`` is the third baseline-side finding, ``a0``
the first current-side one) so the pairing and the output order read directly.

These tests describe what the code does today, including behavior a reader may find
odd. A golden is never edited to make a change pass: a red here means the change is
not behavior-identical. The existing behavioral tests (test_finding_diff.py,
test_scan_baseline_narrows_every_report.py) state intent; this module states
observed output.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable, Dict, List

import pytest

from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerTargetStatusInfo,
)
from automated_security_helper.models.flat_vulnerability import (
    FlatVulnerability,
    assign_identity_ids,
)
from automated_security_helper.schemas.sarif_schema_model import Result, SarifReport
from automated_security_helper.utils.finding_diff import (
    ComparabilityRefusal,
    check_comparable,
    check_same_project,
    compare_findings,
    comparable_findings,
    coverage_warnings,
    fallback_key,
    match_findings,
    unique_findings,
)
from automated_security_helper.utils.scan_baseline import (
    BaselineRefused,
    ScanBaseline,
    apply_baseline,
    check_baseline_scope,
)

pytestmark = pytest.mark.unit

GOLDEN_PATH = Path(__file__).parent / "golden" / "finding_diff_characterization.json"

SECRET_RULE = "generic.secrets.aws-key"  # pragma: allowlist secret

# --------------------------------------------------------------------------- #
# Building findings
# --------------------------------------------------------------------------- #


def spec(line=10, message="m", severity="LOW", fingerprint=None, **extra):
    """One finding's description; ``extra`` may carry rule, uri, end, scanner,
    supp (set ``is_suppressed`` after the ids are assigned), or report (build the
    finding from an additional_reports entry instead of a SARIF result)."""
    return {
        "line": line,
        "message": message,
        "severity": severity,
        "fingerprint": fingerprint,
        **extra,
    }


def sarif_row(item: Dict[str, Any]) -> Dict[str, Any]:
    scanner = item.get("scanner", "scanner")
    physical: Dict[str, Any] = {"artifactLocation": {"uri": item.get("uri", "a.py")}}
    if item["line"] is not None:
        region: Dict[str, Any] = {"startLine": item["line"]}
        if item.get("end") is not None:
            region["endLine"] = item["end"]
        physical["region"] = region
    row: Dict[str, Any] = {
        "ruleId": item.get("rule", "R1"),
        "message": {"text": item["message"]},
        "level": "error" if item["severity"] in ("HIGH", "CRITICAL") else "note",
        "properties": {
            "issue_severity": item["severity"],
            "scanner_name": scanner,
            "tags": [scanner],
        },
        "locations": [{"physicalLocation": physical}],
    }
    if item.get("fingerprint"):
        row["fingerprints"] = {"key": item["fingerprint"]}
    if item.get("supp_sarif"):
        row["suppressions"] = [{"kind": "external", "state": "accepted"}]
    return row


def build(items: List[Dict[str, Any]], project=None) -> List[FlatVulnerability]:
    values = []
    for item in items:
        if "report" in item:
            values.append(
                FlatVulnerability.from_additional_report(item["report"], "scanner")
            )
        else:
            values.append(
                FlatVulnerability.from_sarif_result(
                    Result.model_validate(sarif_row(item)),
                    item.get("scanner", "scanner"),
                    item.get("scanner", "scanner"),
                )
            )
    assign_identity_ids(values, default_project=project)
    for value, item in zip(values, items):
        if item.get("supp"):
            value.is_suppressed = True
    return values


# --------------------------------------------------------------------------- #
# Summaries: findings are named by input position
# --------------------------------------------------------------------------- #


def _labels(prefix: str, items: List[FlatVulnerability]) -> Dict[int, str]:
    return {id(item): f"{prefix}{index}" for index, item in enumerate(items)}


def _pairs(before_labels, after_labels, pairs) -> List[List[str]]:
    return [[before_labels[id(a)], after_labels[id(b)]] for a, b in pairs]


def _match_summary(match, before_labels, after_labels) -> Dict[str, Any]:
    return {
        "exact": _pairs(before_labels, after_labels, match.exact),
        "moved": _pairs(before_labels, after_labels, match.moved),
        "new": [after_labels[id(item)] for item in match.new],
        "absent": [before_labels[id(item)] for item in match.absent],
    }


def _diff_summary(diff, before_labels, after_labels) -> Dict[str, Any]:
    return {
        "new": [after_labels[id(item)] for item in diff.new],
        "absent_after": [before_labels[id(item)] for item in diff.absent_after],
        "moved": _pairs(before_labels, after_labels, diff.moved),
        "severity_changed": _pairs(before_labels, after_labels, diff.severity_changed),
        "suppression_changed": _pairs(
            before_labels, after_labels, diff.suppression_changed
        ),
    }


def diff_scenario(before, after) -> Dict[str, Any]:
    before_labels = _labels("b", before)
    after_labels = _labels("a", after)
    match = _match_summary(match_findings(before, after), before_labels, after_labels)
    diff = _diff_summary(compare_findings(before, after), before_labels, after_labels)
    from_iterators = _diff_summary(
        compare_findings(iter(before), iter(after)), before_labels, after_labels
    )
    reversed_input = _diff_summary(
        compare_findings(reversed(before), reversed(after)),
        before_labels,
        after_labels,
    )
    return {
        "match": match,
        "diff": diff,
        "iterators_equal_lists": from_iterators == diff,
        "reversed_input_equal": reversed_input == diff,
    }


# --------------------------------------------------------------------------- #
# Scenarios: match_findings / compare_findings
# --------------------------------------------------------------------------- #

DIFF_SCENARIOS: Dict[str, Callable[[], Any]] = {}


def diff_case(function):
    DIFF_SCENARIOS[function.__name__] = function
    return function


@diff_case
def empty_both():
    return [], []


@diff_case
def only_baseline_side():
    return build([spec(1), spec(2, "x")]), []


@diff_case
def only_current_side():
    return [], build([spec(1), spec(2, "x")])


@diff_case
def single_identical_is_exact():
    return build([spec(10)]), build([spec(10)])


@diff_case
def single_line_shift_is_moved():
    return build([spec(10)]), build([spec(20)])


@diff_case
def single_other_rule_is_new_and_absent():
    return build([spec(10)]), build([spec(10, rule="R2")])


@diff_case
def single_other_file_is_new_and_absent():
    return build([spec(10)]), build([spec(10, uri="b.py")])


@diff_case
def single_other_scanner_is_new_and_absent():
    return build([spec(10)]), build([spec(10, scanner="other")])


@diff_case
def fingerprint_pairs_exact_across_message_and_line():
    return (
        build([spec(10, "old", "LOW", "fp-1")]),
        build([spec(40, "new", "LOW", "fp-1")]),
    )


@diff_case
def fingerprint_exact_pair_with_severity_rise():
    return (
        build([spec(10, "m", "LOW", "fp-1")]),
        build([spec(10, "m", "HIGH", "fp-1")]),
    )


@diff_case
def fingerprint_exact_pair_with_suppression_lapse():
    return (
        build([spec(10, "m", "HIGH", "fp-1", supp=True)]),
        build([spec(10, "m", "HIGH", "fp-1")]),
    )


@diff_case
def fingerprint_exact_pair_with_suppression_added():
    return (
        build([spec(10, "m", "HIGH", "fp-1")]),
        build([spec(10, "m", "HIGH", "fp-1", supp=True)]),
    )


@diff_case
def fingerprint_changed_is_new_and_absent():
    return (
        build([spec(10, "m", "HIGH", "fp-old")]),
        build([spec(20, "m", "HIGH", "fp-new")]),
    )


@diff_case
def fingerprint_shared_by_two_locations_falls_back_to_lines():
    shared = [spec(10, "m", "LOW", "shared"), spec(30, "m2", "LOW", "shared")]
    return build(shared), build(shared)


@diff_case
def fingerprint_shared_message_change_at_same_line():
    return (
        build([spec(10, "old", "LOW", "shared"), spec(30, "other", "LOW", "shared")]),
        build([spec(10, "new", "LOW", "shared"), spec(30, "other", "LOW", "shared")]),
    )


@diff_case
def location_id_with_message_change_is_not_exact():
    return build([spec(10, "old")]), build([spec(10, "new")])


@diff_case
def new_finding_on_old_line_with_other_message():
    return (
        build([spec(10, "old")]),
        build([spec(20, "old"), spec(10, "new", "HIGH")]),
    )


@diff_case
def severity_is_part_of_the_fallback_key():
    return build([spec(1, "old", "LOW")]), build([spec(2, "old", "HIGH")])


@diff_case
def group_grows_pairs_nothing():
    return (
        build([spec(1, "old"), spec(2, "old")]),
        build([spec(3, "old"), spec(4, "old"), spec(5, "old")]),
    )


@diff_case
def group_shrinks_pairs_in_line_order():
    return (
        build([spec(1, "old"), spec(2, "old"), spec(3, "old")]),
        build([spec(11, "old"), spec(12, "old")]),
    )


@diff_case
def group_same_size_pairs_in_line_order_not_input_order():
    return (
        build([spec(30, "old"), spec(10, "old"), spec(20, "old")]),
        build([spec(120, "old"), spec(130, "old"), spec(110, "old")]),
    )


@diff_case
def none_lines_sort_before_numbered_lines():
    before = build([spec(5, "old"), spec(None, "old"), spec(3, "old")])
    after = build([spec(None, "old"), spec(9, "old"), spec(7, "old")])
    return before, after


@diff_case
def both_sides_without_lines_are_exact():
    return build([spec(None, "old")]), build([spec(None, "old")])


@diff_case
def line_end_breaks_start_line_ties():
    before = build([spec(5, "old", end=9), spec(5, "old", end=6), spec(5, "old")])
    after = build(
        [spec(50, "old", end=60), spec(50, "old", end=52), spec(50, "old", end=70)]
    )
    return before, after


@diff_case
def numeric_not_lexical_line_order():
    before = build([spec(9, "old"), spec(10, "old"), spec(100, "old")])
    after = build([spec(900, "old"), spec(1000, "old"), spec(20, "old")])
    return before, after


@diff_case
def unicode_message_and_path():
    items = [
        spec(1, "Überprüfung ✓ 日本語 🔐", "HIGH", uri="src/日本/ключ.py"),
        spec(2, "café", "LOW", uri="src/日本/ключ.py"),
    ]
    shifted = [
        spec(11, "Überprüfung ✓ 日本語 🔐", "HIGH", uri="src/日本/ключ.py"),
        spec(2, "café", "LOW", uri="src/日本/ключ.py"),
    ]
    return build(items), build(shifted)


@diff_case
def duplicate_ids_on_the_baseline_side():
    before = build([spec(1, "old"), spec(2, "old")])
    before[1].id = before[0].id
    return before, build([spec(1, "old")])


@diff_case
def duplicate_ids_on_the_current_side():
    after = build([spec(1, "old"), spec(2, "old")])
    after[1].id = after[0].id
    return build([spec(1, "old")]), after


@diff_case
def duplicate_ids_on_both_sides():
    before = build([spec(1, "old"), spec(2, "old")])
    after = build([spec(1, "old"), spec(2, "old"), spec(3, "old")])
    before[1].id = before[0].id
    after[1].id = after[0].id
    after[2].id = after[0].id
    return before, after


@diff_case
def exact_duplicates_get_ordinals_and_pair():
    return build([spec(1, "old"), spec(1, "old")]), build(
        [spec(1, "old"), spec(1, "old")]
    )


@diff_case
def secret_without_fingerprint_moved_is_still_moved_for_display():
    return (
        build([spec(10, "key", "HIGH", rule=SECRET_RULE)]),
        build([spec(20, "key", "HIGH", rule=SECRET_RULE)]),
    )


@diff_case
def secret_with_fingerprint_moved_is_exact():
    return (
        build([spec(10, "key", "HIGH", "sec-fp", rule=SECRET_RULE)]),
        build([spec(20, "key", "HIGH", "sec-fp", rule=SECRET_RULE)]),
    )


@diff_case
def suppression_swap_with_one_line_collision_stays_new():
    before = build([spec(10, "m"), spec(20, "m")])
    after = build([spec(20, "m"), spec(30, "m")])
    before[1].is_suppressed = True
    after[0].is_suppressed = True
    return before, after


@diff_case
def unchanged_mixed_suppression_group_stays_paired():
    before = build([spec(10, "m"), spec(20, "m")])
    after = build([spec(10, "m"), spec(20, "m")])
    before[1].is_suppressed = True
    after[1].is_suppressed = True
    return before, after


@diff_case
def rerated_finding_does_not_vouch_for_changed_mixed_group():
    before = build([spec(10, "m"), spec(20, "m"), spec(30, "m", "MEDIUM")])
    after = build([spec(10, "m"), spec(30, "m")])
    before[1].is_suppressed = True
    return before, after


@diff_case
def rerated_suppressed_finding_keeps_unchanged_group_paired():
    before = build([spec(10, "m"), spec(20, "m")])
    after = build([spec(10, "m"), spec(20, "m", "INFO")])
    before[1].is_suppressed = True
    after[1].is_suppressed = True
    return before, after


@diff_case
def moved_group_with_mixed_baseline_suppression_pairs_nothing():
    before = build([spec(10, "same", "HIGH"), spec(20, "same", "HIGH")])
    after = build([spec(30, "same", "HIGH"), spec(40, "same", "HIGH")])
    before[0].is_suppressed = True
    after[1].is_suppressed = True
    return before, after


@diff_case
def moved_group_all_suppressed_on_both_sides_pairs():
    before = build([spec(10, "same", "HIGH"), spec(20, "same", "HIGH")])
    after = build([spec(30, "same", "HIGH"), spec(40, "same", "HIGH")])
    for value in before + after:
        value.is_suppressed = True
    return before, after


@diff_case
def moved_finding_with_lapsed_suppression_remains_paired():
    before = build([spec(10, "same", "HIGH")])
    after = build([spec(20, "same", "HIGH")])
    before[0].is_suppressed = True
    return before, after


@diff_case
def moved_finding_with_added_suppression_remains_paired():
    before = build([spec(10, "same", "HIGH")])
    after = build([spec(20, "same", "HIGH")])
    after[0].is_suppressed = True
    return before, after


@diff_case
def workspace_project_differs_between_runs():
    return (
        build([spec(10, "same", "HIGH")], project="alpha"),
        build([spec(20, "same", "HIGH")], project="beta"),
    )


@diff_case
def workspace_project_same_between_runs():
    return (
        build([spec(10, "same", "HIGH")], project="alpha"),
        build([spec(20, "same", "HIGH")], project="alpha"),
    )


@diff_case
def additional_report_with_same_plugin_id_is_exact():
    report = {"id": "x1", "description": "d", "severity": "HIGH", "line_start": 3}
    return (
        build([{"report": dict(report)}]),
        build([{"report": {**report, "line_start": 99}}]),
    )


@diff_case
def additional_report_with_different_plugin_ids_is_new_and_absent():
    return (
        build([{"report": {"id": "x1", "description": "d"}}]),
        build([{"report": {"id": "x2", "description": "d"}}]),
    )


@diff_case
def additional_report_without_id_pairs_exact_by_location_identity():
    entry = {"description": "d", "line_start": 3, "file_path": "a.py"}
    return build([{"report": dict(entry)}]), build([{"report": dict(entry)}])


@diff_case
def additional_report_without_id_moved_does_not_fallback_pair():
    return (
        build([{"report": {"description": "d", "line_start": 3, "file_path": "a.py"}}]),
        build(
            [{"report": {"description": "d", "line_start": 30, "file_path": "a.py"}}]
        ),
    )


@diff_case
def sarif_and_additional_report_rows_mixed():
    before = build(
        [
            spec(10, "old"),
            {"report": {"id": "x1", "description": "d"}},
            spec(50, "gone"),
        ]
    )
    after = build(
        [
            {"report": {"id": "x1", "description": "d"}},
            spec(20, "old"),
            spec(60, "added", "HIGH"),
        ]
    )
    return before, after


@diff_case
def new_and_absent_are_sorted_by_id_then_position():
    before = build([spec(n, f"gone-{n % 7}", rule=f"B{n % 4}") for n in (9, 3, 12, 1)])
    after = build(
        [spec(n, f"added-{n % 5}", "MEDIUM", rule=f"A{n % 3}") for n in (8, 2, 11, 5)]
    )
    return before, after


@diff_case
def large_n_whole_group_shifted():
    before = build([spec(n, "same", "MEDIUM") for n in range(1, 41)])
    after = build([spec(n + 100, "same", "MEDIUM") for n in range(1, 41)])
    return before, after


@diff_case
def large_n_mixed_exact_moved_new_absent():
    before = build(
        [spec(n, f"msg-{n % 9}", "LOW", rule=f"R{n % 5}") for n in range(1, 61)]
    )
    after = build(
        [
            spec(n + (7 if n % 3 == 0 else 0), f"msg-{n % 9}", "LOW", rule=f"R{n % 5}")
            for n in range(5, 66)
        ]
    )
    return before, after


@diff_case
def large_n_shuffled_input_order():
    items = [
        spec((n * 37) % 101 + 1, f"msg-{n % 6}", "LOW", rule=f"R{n % 4}")
        for n in range(50)
    ]
    shifted = [{**item, "line": item["line"] + 200} for item in reversed(items)]
    return build(items), build(shifted)


@diff_case
def large_n_fingerprinted():
    before = build([spec(n, f"m{n}", "LOW", f"fp-{n}") for n in range(1, 31)])
    after = build([spec(n + 50, f"m{n}x", "HIGH", f"fp-{n}") for n in range(10, 41)])
    return before, after


# --------------------------------------------------------------------------- #
# Scenarios: fallback_key
# --------------------------------------------------------------------------- #

KEY_SCENARIOS: Dict[str, Callable[[], Any]] = {}


def key_case(function):
    KEY_SCENARIOS[function.__name__] = function
    return function


def _key_summary(finding: FlatVulnerability):
    key = fallback_key(finding)
    return None if key is None else [str(part) for part in key]


@key_case
def key_plain_location_finding():
    return _key_summary(build([spec(10, "text", "low")])[0])


@key_case
def key_severity_upper_cased_and_message_kept():
    return [
        _key_summary(build([spec(10, "Text", "LOW")])[0]),
        _key_summary(build([spec(99, "Text", "LOW")])[0]),
        _key_summary(build([spec(10, "Text", "HIGH")])[0]),
    ]


@key_case
def key_fingerprinted_finding_has_none():
    return _key_summary(build([spec(10, "text", "LOW", "fp")])[0])


@key_case
def key_additional_report_with_id_has_none():
    return _key_summary(build([{"report": {"id": "x1", "description": "d"}}])[0])


@key_case
def key_additional_report_without_id_has_none_because_of_source():
    return _key_summary(
        build([{"report": {"description": "d", "line_start": 3, "file_path": "a.py"}}])[
            0
        ]
    )


@key_case
def key_project_is_part_of_the_base():
    return [
        _key_summary(build([spec(10, "t")], project="alpha")[0]),
        _key_summary(build([spec(10, "t")], project="beta")[0]),
    ]


# --------------------------------------------------------------------------- #
# Scenarios: comparability
# --------------------------------------------------------------------------- #

COMPARE_SCENARIOS: Dict[str, Callable[[], Any]] = {}


def compare_case(function):
    COMPARE_SCENARIOS[function.__name__] = function
    return function


def _outcome(call: Callable[[], Any]) -> Dict[str, Any]:
    try:
        value = call()
    except ComparabilityRefusal as exc:
        return {"refused": str(exc)}
    return {"ok": value}


def _stub(
    *,
    workspace=None,
    shard=None,
    changed_files_only="__absent__",
    baseline_filtered=False,
    workspace_project="__absent__",
    project_name=None,
):
    metadata = SimpleNamespace(shard=shard, project_name=project_name)
    if changed_files_only != "__absent__":
        metadata.changed_files_only = changed_files_only
    if workspace_project != "__absent__":
        metadata.workspace_project = workspace_project
    return SimpleNamespace(
        workspace=workspace, metadata=metadata, baseline_filtered=baseline_filtered
    )


@compare_case
def check_comparable_matrix():
    cases = {
        "clean": _stub(),
        "workspace_aggregate": _stub(workspace=object()),
        "sharded": _stub(shard=object()),
        "changed_files_true": _stub(changed_files_only=True),
        "changed_files_false": _stub(changed_files_only=False),
        "changed_files_none": _stub(changed_files_only=None),
        "changed_files_string": _stub(changed_files_only="yes"),
        "changed_files_zero": _stub(changed_files_only=0),
        "baseline_filtered": _stub(baseline_filtered=True),
        "project_ok": _stub(workspace_project="alpha"),
        "project_blank": _stub(workspace_project="   "),
        "project_empty": _stub(workspace_project=""),
        "project_not_text": _stub(workspace_project=7),
        "workspace_and_sharded": _stub(workspace=object(), shard=object()),
        "sharded_and_filtered": _stub(shard=object(), baseline_filtered=True),
    }
    return {
        name: _outcome(lambda r=r: check_comparable(r)) for name, r in cases.items()
    }


@compare_case
def check_same_project_matrix():
    def pair(base, cur):
        return _outcome(lambda: check_same_project(base, cur))

    return {
        "both_standalone_unnamed": pair(_stub(), _stub()),
        "both_standalone_same_name": pair(
            _stub(project_name="p"), _stub(project_name="p")
        ),
        "both_standalone_different_name": pair(
            _stub(project_name="p"), _stub(project_name="q")
        ),
        "one_side_unnamed": pair(_stub(project_name="p"), _stub()),
        "other_side_unnamed": pair(_stub(), _stub(project_name="p")),
        "standalone_vs_workspace": pair(_stub(), _stub(workspace_project="a")),
        "workspace_vs_standalone": pair(_stub(workspace_project="a"), _stub()),
        "workspace_same": pair(
            _stub(workspace_project="a"), _stub(workspace_project="a")
        ),
        "workspace_different": pair(
            _stub(workspace_project="a"), _stub(workspace_project="b")
        ),
        "workspace_same_project_names_differ": pair(
            _stub(workspace_project="a", project_name="p"),
            _stub(workspace_project="a", project_name="q"),
        ),
    }


def _sarif_results(rows: List[Dict[str, Any]], **metadata) -> AshAggregatedResults:
    model = AshAggregatedResults()
    model.sarif = SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "scanner"}},
                    "results": [sarif_row(item) for item in rows],
                }
            ],
        }
    )
    model.scanner_results = {
        item.get("scanner", "scanner"): ScannerTargetStatusInfo(status="PASSED")
        for item in rows
    }
    for name, value in metadata.items():
        setattr(model.metadata, name, value)
    return model


@compare_case
def unique_findings_refusal_and_pass_through():
    clean = _sarif_results([spec(1, "a"), spec(2, "b")])
    twins = _sarif_results([spec(1, "a"), spec(1, "a")])
    duplicated = AshAggregatedResults()
    duplicated.additional_reports = {
        "plugin": [
            {"id": "x", "description": "one"},
            {"id": "x", "description": "two"},
        ]
    }
    return {
        "clean_count": _outcome(lambda: len(unique_findings(clean, "Baseline"))),
        "exact_twins_get_distinct_ids": _outcome(
            lambda: len(unique_findings(twins, "Baseline"))
        ),
        "duplicate_plugin_ids_label_baseline": _outcome(
            lambda: unique_findings(duplicated, "Baseline")
        ),
        "duplicate_plugin_ids_label_custom": _outcome(
            lambda: unique_findings(duplicated, "Some other")
        ),
        "empty": _outcome(lambda: unique_findings(AshAggregatedResults(), "Baseline")),
    }


@compare_case
def comparable_findings_checks_in_order():
    clean = _sarif_results([spec(1, "a")])
    sharded = _sarif_results([spec(1, "a")])
    sharded.metadata.shard = SimpleNamespace()
    duplicated = AshAggregatedResults()
    duplicated.additional_reports = {
        "plugin": [{"id": "x", "description": "1"}, {"id": "x", "description": "2"}]
    }
    named_p = _sarif_results([spec(1, "a")], project_name="p")
    named_q = _sarif_results([spec(1, "a")], project_name="q")

    def counts(base, cur):
        baseline_findings, current_findings = comparable_findings(base, cur)
        return [len(baseline_findings), len(current_findings)]

    return {
        "clean_pair": _outcome(lambda: counts(clean, _sarif_results([spec(1, "a")]))),
        "empty_pair": _outcome(
            lambda: counts(AshAggregatedResults(), AshAggregatedResults())
        ),
        "baseline_sharded": _outcome(
            lambda: counts(sharded, _sarif_results([spec(1, "a")]))
        ),
        "current_sharded": _outcome(lambda: counts(clean, sharded)),
        "both_sharded_names_baseline_first": _outcome(lambda: counts(sharded, sharded)),
        "project_names_differ": _outcome(lambda: counts(named_p, named_q)),
        "duplicate_baseline_ids": _outcome(lambda: counts(duplicated, clean)),
        "duplicate_current_ids": _outcome(lambda: counts(clean, duplicated)),
        "sharded_wins_over_duplicates": _outcome(lambda: counts(sharded, duplicated)),
    }


@compare_case
def coverage_warnings_matrix():
    def side(*, expected=(), rows=None, ignore=None, not_scanned=None):
        model = AshAggregatedResults()
        model.metadata.expected_scanners = set(expected)
        if ignore is not None:
            model.metadata.ignore_file_exclusions = ignore
        if not_scanned is not None:
            model.metadata.inputs_not_scanned = not_scanned
        for name, kwargs in (rows or {}).items():
            model.scanner_results[name] = ScannerTargetStatusInfo(**kwargs)
        return model

    passed = {"status": "PASSED"}
    failed = {"status": "FAILED"}
    missing = {"status": "MISSING", "excluded": False}
    skipped = {"status": "SKIPPED"}
    excluded = {"status": "PASSED", "excluded": True}

    def warn(base, cur):
        return coverage_warnings(base, cur)

    return {
        "empty_pair": warn(side(), side()),
        "identical_complete": warn(
            side(expected=["bandit"], rows={"bandit": passed}),
            side(expected=["bandit"], rows={"bandit": passed}),
        ),
        "expected_set_differs": warn(
            side(expected=["bandit"], rows={"bandit": passed}),
            side(
                expected=["bandit", "semgrep"],
                rows={"bandit": passed, "semgrep": passed},
            ),
        ),
        "evaluated_set_differs": warn(
            side(
                expected=["bandit", "semgrep"],
                rows={"bandit": passed, "semgrep": passed},
            ),
            side(
                expected=["bandit", "semgrep"],
                rows={"bandit": passed, "semgrep": failed},
            ),
        ),
        "baseline_scanner_missing": warn(
            side(expected=["bandit"], rows={"bandit": missing}),
            side(expected=["bandit"], rows={"bandit": passed}),
        ),
        "current_scanner_skipped": warn(
            side(expected=["bandit"], rows={"bandit": passed}),
            side(expected=["bandit"], rows={"bandit": skipped}),
        ),
        "current_scanner_excluded": warn(
            side(expected=["bandit"], rows={"bandit": passed}),
            side(expected=["bandit"], rows={"bandit": excluded}),
        ),
        "failed_counts_as_evaluated": warn(
            side(expected=["bandit"], rows={"bandit": failed}),
            side(expected=["bandit"], rows={"bandit": failed}),
        ),
        "ignore_file_exclusions_differ": warn(
            side(expected=["bandit"], rows={"bandit": passed}, ignore=["a"]),
            side(expected=["bandit"], rows={"bandit": passed}, ignore=["b"]),
        ),
        "inputs_not_scanned_on_current": warn(
            side(expected=["bandit"], rows={"bandit": passed}),
            side(expected=["bandit"], rows={"bandit": passed}, not_scanned=["x.bin"]),
        ),
        "inputs_not_scanned_on_both": warn(
            side(expected=["bandit"], rows={"bandit": passed}, not_scanned=["y"]),
            side(expected=["bandit"], rows={"bandit": passed}, not_scanned=["x"]),
        ),
        "rows_without_expected_scanners": warn(
            side(rows={"bandit": passed}), side(rows={"bandit": passed})
        ),
        "expected_without_rows": warn(
            side(expected=["bandit"]), side(expected=["bandit"])
        ),
    }


# --------------------------------------------------------------------------- #
# Scenarios: apply_baseline and check_baseline_scope
# --------------------------------------------------------------------------- #

APPLY_SCENARIOS: Dict[str, Callable[[], Any]] = {}


def apply_case(function):
    APPLY_SCENARIOS[function.__name__] = function
    return function


def scanner_results_of(
    *runs: List[Dict[str, Any]], status="PASSED"
) -> AshAggregatedResults:
    """Results with one SARIF run per list of specs; each scanner's row passes."""
    model = AshAggregatedResults()
    model.sarif = SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": f"scanner-{index}"}},
                    "results": [sarif_row(item) for item in rows],
                }
                for index, rows in enumerate(runs)
            ],
        }
    )
    model.scanner_results = {
        item.get("scanner", "scanner"): ScannerTargetStatusInfo(status=status)
        for rows in runs
        for item in rows
    }
    return model


def baseline_of(model: AshAggregatedResults) -> ScanBaseline:
    return ScanBaseline("abc123", model, tuple(model.to_flat_vulnerabilities()))


def _remaining(model: AshAggregatedResults) -> List[List[Any]]:
    kept = []
    for run_index, run in enumerate((model.sarif.runs if model.sarif else []) or []):
        for row in run.results or []:
            dumped = row.model_dump(by_alias=True, exclude_none=True, mode="json")
            physical = (dumped.get("locations") or [{}])[0].get("physicalLocation", {})
            kept.append(
                [
                    run_index,
                    dumped["message"]["text"],
                    (physical.get("region") or {}).get("startLine"),
                ]
            )
    return kept


def apply_summary(current: AshAggregatedResults, base: ScanBaseline) -> Dict[str, Any]:
    outcome = apply_baseline(current, base)
    marker = getattr(current.metadata, "baseline", None)
    return {
        "matched": outcome.matched,
        "matched_without_lines": outcome.matched_without_lines,
        "warnings": list(outcome.warnings),
        "kept": _remaining(current),
        "marker": marker,
    }


def apply_one(
    baseline_rows: List[Dict[str, Any]], current_rows: List[Dict[str, Any]]
) -> Dict[str, Any]:
    return apply_summary(
        scanner_results_of(current_rows), baseline_of(scanner_results_of(baseline_rows))
    )


def b(line, message="old", severity="LOW", fingerprint=None, **extra):
    return spec(line, message, severity, fingerprint, scanner="bandit", **extra)


@apply_case
def apply_empty_baseline_and_empty_results():
    return apply_one([], [])


@apply_case
def apply_empty_baseline_keeps_everything():
    return apply_one([], [b(10), b(20, "other")])


@apply_case
def apply_empty_results_matches_nothing():
    return apply_one([b(10)], [])


@apply_case
def apply_no_sarif_at_all():
    current = AshAggregatedResults()
    return apply_summary(current, baseline_of(scanner_results_of([b(10)])))


@apply_case
def apply_exact_match_is_dropped():
    return apply_one([b(10)], [b(10)])


@apply_case
def apply_moved_match_is_dropped_without_lines():
    return apply_one([b(10)], [b(20)])


@apply_case
def apply_changed_message_is_kept():
    return apply_one([b(10, "old")], [b(10, "new")])


@apply_case
def apply_new_finding_beside_old_is_kept():
    return apply_one([b(10, "old")], [b(20, "old"), b(10, "new", "HIGH")])


@apply_case
def apply_group_growth_matches_nothing():
    return apply_one(
        [b(1, "old"), b(2, "old")], [b(3, "old"), b(4, "old"), b(5, "old")]
    )


@apply_case
def apply_group_shrink_drops_the_ordered_prefix():
    return apply_one(
        [b(1, "old"), b(2, "old"), b(3, "old")], [b(11, "old"), b(12, "old")]
    )


@apply_case
def apply_severity_rise_on_exact_pair_is_kept():
    return apply_one([b(10, "m", "LOW", "fp")], [b(10, "m", "HIGH", "fp")])


@apply_case
def apply_low_to_medium_rise_on_exact_pair_is_kept():
    return apply_one([b(10, "m", "LOW", "fp")], [b(10, "m", "MEDIUM", "fp")])


@apply_case
def apply_severity_drop_on_exact_pair_is_dropped():
    return apply_one([b(10, "m", "HIGH", "fp")], [b(10, "m", "LOW", "fp")])


@apply_case
def apply_same_severity_high_is_dropped():
    return apply_one([b(10, "m", "HIGH")], [b(10, "m", "HIGH")])


@apply_case
def apply_critical_to_high_is_dropped():
    return apply_one([b(10, "m", "CRITICAL", "fp")], [b(10, "m", "HIGH", "fp")])


@apply_case
def apply_info_to_info_is_dropped_and_unknown_severity_is_kept():
    return apply_one(
        [b(10, "i", "INFO"), b(20, "u", "UNKNOWNLEVEL")],
        [b(10, "i", "INFO"), b(20, "u", "UNKNOWNLEVEL")],
    )


@apply_case
def apply_lapsed_suppression_is_kept():
    return apply_one([b(10, "m", "HIGH", supp_sarif=True)], [b(10, "m", "HIGH")])


@apply_case
def apply_added_suppression_is_dropped():
    return apply_one([b(10, "m", "HIGH")], [b(10, "m", "HIGH", supp_sarif=True)])


@apply_case
def apply_still_suppressed_is_dropped():
    return apply_one(
        [b(10, "m", "HIGH", supp_sarif=True)],
        [b(10, "m", "HIGH", supp_sarif=True)],
    )


@apply_case
def apply_moved_with_lapsed_suppression_is_kept():
    return apply_one([b(10, "m", "HIGH", supp_sarif=True)], [b(40, "m", "HIGH")])


@apply_case
def apply_secret_exact_without_fingerprint_is_kept():
    return apply_one(
        [b(10, "key", "HIGH", rule=SECRET_RULE)],
        [b(10, "key", "HIGH", rule=SECRET_RULE)],
    )


@apply_case
def apply_secret_exact_with_fingerprint_is_dropped():
    return apply_one(
        [b(10, "key", "HIGH", "sec", rule=SECRET_RULE)],
        [b(10, "key", "HIGH", "sec", rule=SECRET_RULE)],
    )


@apply_case
def apply_secret_moved_without_fingerprint_is_kept():
    return apply_one(
        [b(10, "key", "HIGH", rule=SECRET_RULE)],
        [b(30, "key", "HIGH", rule=SECRET_RULE)],
    )


@apply_case
def apply_secret_moved_with_fingerprint_is_matched_exactly():
    return apply_one(
        [b(10, "key", "HIGH", "sec", rule=SECRET_RULE)],
        [b(30, "key", "HIGH", "sec", rule=SECRET_RULE)],
    )


@apply_case
def apply_secret_beside_ordinary_finding_each_judged_alone():
    return apply_one(
        [b(10, "key", "HIGH", rule=SECRET_RULE), b(20, "plain")],
        [b(10, "key", "HIGH", rule=SECRET_RULE), b(20, "plain")],
    )


@apply_case
def apply_baseline_scanner_not_completed_keeps_findings():
    base = scanner_results_of([b(10, "m", "HIGH")])
    base.scanner_results.clear()
    base.scanner_results["bandit"] = ScannerTargetStatusInfo(
        status=ScannerStatus.MISSING, excluded=False
    )
    return apply_summary(scanner_results_of([b(10, "m", "HIGH")]), baseline_of(base))


@apply_case
def apply_baseline_scanner_failed_still_counts_as_evaluated():
    base = scanner_results_of([b(10, "m", "HIGH")], status="FAILED")
    return apply_summary(scanner_results_of([b(10, "m", "HIGH")]), baseline_of(base))


@apply_case
def apply_baseline_scanner_excluded_keeps_findings():
    base = scanner_results_of([b(10, "m", "HIGH")])
    base.scanner_results["bandit"] = ScannerTargetStatusInfo(
        status="PASSED", excluded=True
    )
    return apply_summary(scanner_results_of([b(10, "m", "HIGH")]), baseline_of(base))


@apply_case
def apply_baseline_finding_of_unrecorded_scanner_is_ignored():
    base = scanner_results_of([b(10, "m", "HIGH")])
    base.scanner_results.clear()
    return apply_summary(scanner_results_of([b(10, "m", "HIGH")]), baseline_of(base))


@apply_case
def apply_only_the_completed_scanners_findings_match():
    base = scanner_results_of(
        [b(10, "a", "HIGH"), spec(20, "b", "HIGH", scanner="semgrep")]
    )
    base.scanner_results["semgrep"] = ScannerTargetStatusInfo(
        status=ScannerStatus.MISSING, excluded=False
    )
    current = scanner_results_of(
        [b(10, "a", "HIGH"), spec(20, "b", "HIGH", scanner="semgrep")]
    )
    return apply_summary(current, baseline_of(base))


@apply_case
def apply_two_runs_remove_by_run_and_result_index():
    base = scanner_results_of([b(1, "r0-a"), b(2, "r0-b")], [b(3, "r1-a")])
    current = scanner_results_of(
        [b(1, "r0-a"), b(2, "r0-new"), b(5, "r0-b")],
        [b(3, "r1-a"), b(9, "r1-new", "HIGH")],
    )
    return apply_summary(current, baseline_of(base))


@apply_case
def apply_same_finding_in_two_runs_is_judged_per_row():
    base = scanner_results_of([b(1, "twin")], [b(1, "twin", uri="a.py")])
    current = scanner_results_of([b(1, "twin")], [b(1, "twin", uri="a.py")])
    return apply_summary(current, baseline_of(base))


@apply_case
def apply_unicode_findings():
    rows = [
        b(1, "Überprüfung ✓ 日本語", "HIGH", uri="src/日本.py"),
        b(2, "ключ", "LOW", uri="src/日本.py"),
    ]
    moved = [
        b(11, "Überprüfung ✓ 日本語", "HIGH", uri="src/日本.py"),
        b(2, "ключ", "LOW", uri="src/日本.py"),
    ]
    return apply_one(rows, moved)


@apply_case
def apply_additional_report_rows_are_neither_matched_nor_counted():
    base = scanner_results_of([b(10, "m", "HIGH")])
    base.additional_reports = {"plugin": [{"id": "x", "description": "d"}]}
    current = scanner_results_of([b(10, "m", "HIGH")])
    current.additional_reports = {"plugin": [{"id": "x", "description": "d"}]}
    summary = apply_summary(current, baseline_of(base))
    summary["additional_reports_untouched"] = current.additional_reports == {
        "plugin": [{"id": "x", "description": "d"}]
    }
    return summary


@apply_case
def apply_warnings_pass_through_from_coverage():
    base = scanner_results_of([b(10, "m", "HIGH")])
    base.metadata.expected_scanners = {"bandit", "semgrep"}
    return apply_summary(scanner_results_of([b(10, "m", "HIGH")]), baseline_of(base))


@apply_case
def apply_large_n_half_shifted():
    rows = [b(n, f"msg-{n % 11}", "MEDIUM", rule=f"R{n % 6}") for n in range(1, 101)]
    current = [
        {**row, "line": row["line"] + (13 if index % 2 else 0)}
        for index, row in enumerate(rows)
    ]
    current.append(b(500, "brand-new", "HIGH"))
    return apply_one(rows, current)


@apply_case
def apply_large_n_fingerprinted_with_rises():
    rows = [b(n, f"m{n}", "LOW", f"fp-{n}") for n in range(1, 61)]
    current = [
        {**row, "severity": "HIGH" if row["line"] % 5 == 0 else "LOW"} for row in rows
    ]
    return apply_one(rows, current)


@apply_case
def apply_duplicate_current_rows_each_judged():
    return apply_one([b(10, "twin"), b(10, "twin")], [b(10, "twin"), b(10, "twin")])


@apply_case
def apply_refuses_results_already_filtered_by_a_baseline():
    current = scanner_results_of([b(10)])
    setattr(current.metadata, "baseline", {"sha256": "x"})
    base = baseline_of(scanner_results_of([b(10)]))
    try:
        apply_baseline(current, base)
    except BaselineRefused as exc:
        return {
            "refused": exc.reason,
            "kept": _remaining(current),
            "marker": getattr(current.metadata, "baseline", None),
        }
    return {"refused": None}


@apply_case
def apply_twice_is_refused_the_second_time():
    current = scanner_results_of([b(10), b(20, "x")])
    base = baseline_of(scanner_results_of([b(10)]))
    first = apply_baseline(current, base)
    try:
        apply_baseline(current, base)
    except BaselineRefused as exc:
        second = exc.reason
    else:
        second = None
    return {
        "first": [first.matched, first.matched_without_lines],
        "second_refused": second,
        "kept": _remaining(current),
    }


@apply_case
def apply_baseline_scope_matrix():
    def scoped(
        baseline_project, baseline_source, project_name, scan_source
    ) -> Dict[str, Any]:
        model = AshAggregatedResults()
        model.metadata.project_name = baseline_project
        if baseline_source is not None:
            model.metadata.scan_source = baseline_source
        base = ScanBaseline("abc", model, ())
        try:
            warnings = check_baseline_scope(
                base, project_name=project_name, scan_source=scan_source
            )
        except BaselineRefused as exc:
            return {"refused": exc.reason}
        return {"warnings": warnings}

    return {
        "same_relative_source": scoped("p", ".", "p", "."),
        "same_nested_relative_source": scoped("p", "sub/dir", "p", "sub/dir"),
        "different_relative_source": scoped("p", "one", "p", "two"),
        "different_project": scoped("p", ".", "q", "."),
        "baseline_source_missing": scoped("p", None, "p", "."),
        "current_source_missing": scoped("p", ".", "p", None),
        "absolute_sources": scoped("p", "/abs/one", "p", "/abs/two"),
        "absolute_current_only": scoped("p", ".", "p", "/abs/two"),
        "project_checked_before_source": scoped("p", "one", "q", "two"),
    }


# --------------------------------------------------------------------------- #
# Goldens
# --------------------------------------------------------------------------- #

ALL_SCENARIOS: Dict[str, Callable[[], Any]] = {}
for _group, _prefix in (
    (DIFF_SCENARIOS, "diff"),
    (KEY_SCENARIOS, "key"),
    (COMPARE_SCENARIOS, "compare"),
    (APPLY_SCENARIOS, "apply"),
):
    for _name, _function in _group.items():
        ALL_SCENARIOS[f"{_prefix}.{_name}"] = _function


def run_scenario(name: str) -> Any:
    """The scenario's observed output as plain JSON data."""
    function = ALL_SCENARIOS[name]
    if name.startswith("diff."):
        before, after = function()
        value = diff_scenario(before, after)
    else:
        value = function()
    return json.loads(json.dumps(value, sort_keys=True, ensure_ascii=False))


def load_golden() -> Dict[str, Any]:
    return json.loads(GOLDEN_PATH.read_text(encoding="utf-8"))


def test_golden_file_names_exactly_the_scenarios():
    assert sorted(load_golden()) == sorted(ALL_SCENARIOS)


@pytest.mark.parametrize("name", sorted(ALL_SCENARIOS))
def test_observed_output_matches_the_golden(name):
    assert run_scenario(name) == load_golden()[name]


@pytest.mark.parametrize("name", sorted(DIFF_SCENARIOS))
def test_matcher_partitions_every_input_exactly_once(name):
    """Every baseline-side finding is in exactly one of exact, moved, absent;
    every current-side one in exactly one of exact, moved, new."""
    before, after = DIFF_SCENARIOS[name]()
    match = match_findings(before, after)
    seen_before = [id(a) for a, _ in match.exact + match.moved] + [
        id(item) for item in match.absent
    ]
    seen_after = [id(b_) for _, b_ in match.exact + match.moved] + [
        id(item) for item in match.new
    ]
    assert sorted(seen_before) == sorted(id(item) for item in before)
    assert sorted(seen_after) == sorted(id(item) for item in after)


def test_scenario_count_is_pinned():
    """The count a desk run records; a scenario added or lost changes it."""
    assert len(ALL_SCENARIOS) == EXPECTED_SCENARIO_COUNT


EXPECTED_SCENARIO_COUNT = 104

"""Characterization goldens for baseline diff and apply.

These pin what ``utils/finding_diff.py`` and ``scan_baseline.apply_baseline``
do today: which findings count as the same finding (exact id join, fallback
group alignment, anti-joins for new and absent) and which matched pairs the
baseline gate is willing to drop. A golden here is a recorded behavior, not a
statement that the behavior is right; a golden that must change when the
implementation changes means the implementation changed observable output.
"""

import random
from types import SimpleNamespace

import pytest

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
    FindingDiff,
    FindingMatch,
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
    BaselineOutcome,
    BaselineRefused,
    ScanBaseline,
    apply_baseline,
)

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# fixtures


def sarif_row(
    line,
    message="m",
    severity="LOW",
    fingerprint=None,
    uri="a.py",
    rule="R1",
    end=None,
    scanner="bandit",
    partial=None,
):
    region = {} if line is None else {"startLine": line}
    if end is not None:
        region["endLine"] = end
    row = {
        "ruleId": rule,
        "message": {"text": message},
        "level": "error" if severity in ("HIGH", "CRITICAL") else "note",
        "properties": {
            "issue_severity": severity,
            "scanner_name": scanner,
            "tags": [scanner],
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": region,
                }
            }
        ],
    }
    if fingerprint:
        row["fingerprints"] = {"key": fingerprint}
    if partial:
        row["partialFingerprints"] = {"key": partial}
    return row


def flats(*rows, **kwargs):
    """FlatVulnerability rows from ``sarif_row`` argument tuples, ids assigned."""
    values = [
        FlatVulnerability.from_sarif_result(
            Result.model_validate(sarif_row(*row, **kwargs)), "scanner", "scanner"
        )
        for row in rows
    ]
    assign_identity_ids(values)
    return values


def flats_from_dicts(rows):
    values = [
        FlatVulnerability.from_sarif_result(
            Result.model_validate(row), "scanner", "scanner"
        )
        for row in rows
    ]
    assign_identity_ids(values)
    return values


def label(finding):
    return (finding.file_path, finding.line_start, finding.identity_message)


def labels(findings):
    return [label(f) for f in findings]


def pair_labels(pairs):
    return [(label(a), label(b)) for a, b in pairs]


def results_of(*rows, scanner_status="PASSED"):
    result = AshAggregatedResults()
    result.sarif = SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "scanner"}}, "results": list(rows)}],
        }
    )
    result.scanner_results = {
        row["properties"]["scanner_name"]: ScannerTargetStatusInfo(
            status=scanner_status
        )
        for row in rows
    }
    return result


def baseline_of(old):
    return ScanBaseline("abc", old, tuple(old.to_flat_vulnerabilities()))


def remaining(result):
    return [
        [
            (
                row.locations[0].physicalLocation.root.region.startLine,
                row.message.root.text,
            )
            for row in (run.results or [])
        ]
        for run in result.sarif.runs
    ]


# ---------------------------------------------------------------------------
# match_findings: the join


def test_empty_inputs_match_nothing():
    assert match_findings([], []) == FindingMatch([], [], [], [])
    assert match_findings(iter([]), iter([])) == FindingMatch([], [], [], [])


def test_only_before_findings_are_all_absent_in_order():
    before = flats((30,), (10,), (20,))
    match = match_findings(before, [])
    assert match.exact == [] and match.moved == [] and match.new == []
    assert sorted(match.absent, key=lambda f: f.id) == match.absent
    assert {f.line_start for f in match.absent} == {10, 20, 30}


def test_only_after_findings_are_all_new_in_order():
    after = flats((30,), (10,), (20,))
    match = match_findings([], after)
    assert match.exact == [] and match.moved == [] and match.absent == []
    assert sorted(match.new, key=lambda f: f.id) == match.new
    assert {f.line_start for f in match.new} == {10, 20, 30}


def test_accepts_iterators_not_only_lists():
    before = flats((10,))
    after = flats((10,))
    match = match_findings(iter(before), iter(after))
    assert match.exact == [(before[0], after[0])]


def test_same_place_same_message_is_an_exact_pair():
    before = flats((10, "m"))
    after = flats((10, "m"))
    match = match_findings(before, after)
    assert match.exact == [(before[0], after[0])]
    assert match.moved == [] and match.new == [] and match.absent == []


def test_exact_pairs_come_out_in_sorted_id_order_whatever_the_input_order():
    rows = [(n, "m") for n in (5, 1, 9, 3, 7)]
    before = flats(*rows)
    after = flats(*reversed(rows))
    match = match_findings(before, after)
    assert [a.id for a, _ in match.exact] == sorted(a.id for a, _ in match.exact)
    assert all(a.id == b.id for a, b in match.exact)
    assert len(match.exact) == 5


def test_fingerprinted_pair_joins_on_id_across_lines_and_message():
    before = flats((10, "old", "LOW", "fp"))
    after = flats((99, "new", "LOW", "fp"))
    match = match_findings(before, after)
    assert match.exact == [(before[0], after[0])]
    assert match.moved == [] and match.new == [] and match.absent == []


def test_partial_fingerprint_also_counts_as_a_fingerprint_identity():
    before = flats_from_dicts([sarif_row(10, "old", partial="p")])
    after = flats_from_dicts([sarif_row(50, "new", partial="p")])
    assert before[0].has_fingerprint_identity and after[0].has_fingerprint_identity
    assert match_findings(before, after).exact == [(before[0], after[0])]


def test_location_only_id_with_a_changed_message_is_not_exact_and_not_moved():
    before = flats((10, "old"))
    after = flats((10, "new"))
    match = match_findings(before, after)
    assert match.exact == [] and match.moved == []
    assert match.new == after and match.absent == before


def test_line_shift_pairs_as_moved_not_exact():
    before = flats((10, "m"))
    after = flats((20, "m"))
    match = match_findings(before, after)
    assert match.exact == []
    assert match.moved == [(before[0], after[0])]
    assert match.new == [] and match.absent == []


def test_a_different_file_is_a_different_finding():
    before = flats((10, "m"), uri="a.py")
    after = flats((10, "m"), uri="b.py")
    match = match_findings(before, after)
    assert match.moved == [] and match.exact == []
    assert match.new == after and match.absent == before


def test_a_different_rule_is_a_different_finding():
    before = flats((10, "m"), rule="R1")
    after = flats((20, "m"), rule="R2")
    match = match_findings(before, after)
    assert match.moved == [] and match.new == after and match.absent == before


def test_severity_is_part_of_the_fallback_key_case_insensitively():
    before = flats((10, "m", "LOW"))
    after = flats((20, "m", "HIGH"))
    match = match_findings(before, after)
    assert match.moved == [] and match.new == after and match.absent == before
    after[0].severity = "low"
    again = match_findings(before, after)
    assert again.moved == [(before[0], after[0])]


def test_a_group_that_shrinks_pairs_the_earliest_lines_and_leaves_the_rest_absent():
    before = flats((1, "m"), (2, "m"), (3, "m"))
    after = flats((11, "m"), (12, "m"))
    match = match_findings(before, after)
    assert pair_labels(match.moved) == [
        ((("a.py"), 1, "m"), ("a.py", 11, "m")),
        (("a.py", 2, "m"), ("a.py", 12, "m")),
    ]
    assert labels(match.absent) == [("a.py", 3, "m")]
    assert match.new == []


def test_a_group_that_grows_pairs_nothing():
    before = flats((1, "m"), (2, "m"))
    after = flats((11, "m"), (12, "m"), (13, "m"))
    match = match_findings(before, after)
    assert match.moved == [] and match.exact == []
    assert len(match.new) == 3 and len(match.absent) == 2


def test_a_group_of_equal_size_pairs_in_line_order_not_input_order():
    before = flats((20, "m"), (10, "m"))
    after = flats((40, "m"), (30, "m"))
    match = match_findings(before, after)
    assert pair_labels(match.moved) == [
        (("a.py", 10, "m"), ("a.py", 30, "m")),
        (("a.py", 20, "m"), ("a.py", 40, "m")),
    ]


def test_end_line_breaks_a_start_line_tie_in_the_alignment():
    before = flats(
        (10, "m", "LOW", None, "a.py", "R1", 30),
        (10, "m", "LOW", None, "a.py", "R1", 20),
    )
    after = flats(
        (50, "m", "LOW", None, "a.py", "R1", 70),
        (50, "m", "LOW", None, "a.py", "R1", 60),
    )
    match = match_findings(before, after)
    assert [(a.line_end, b.line_end) for a, b in match.moved] == [(20, 60), (30, 70)]


def test_large_group_alignment_is_by_line_order_and_input_order_independent():
    rng = random.Random(7)
    lines_before = list(range(1, 61))
    lines_after = [n + 1000 for n in lines_before]
    shuffled_before = lines_before[:]
    shuffled_after = lines_after[:]
    rng.shuffle(shuffled_before)
    rng.shuffle(shuffled_after)
    before = flats(*[(n, "m") for n in shuffled_before])
    after = flats(*[(n, "m") for n in shuffled_after])
    match = match_findings(before, after)
    assert match.exact == [] and match.new == [] and match.absent == []
    assert [(a.line_start, b.line_start) for a, b in match.moved] == [
        (n, n + 1000) for n in lines_before
    ]
    reference = match_findings(
        sorted(before, key=lambda f: f.line_start),
        sorted(after, key=lambda f: f.line_start),
    )
    assert pair_labels(reference.moved) == pair_labels(match.moved)


def test_large_n_mixture_of_exact_moved_new_and_absent():
    before = flats(
        *[(n, "stay") for n in range(1, 31)],
        *[(n, "shift") for n in range(101, 121)],
        *[(n, "gone") for n in range(201, 206)],
    )
    after = flats(
        *[(n, "stay") for n in range(1, 31)],
        *[(n + 500, "shift") for n in range(101, 121)],
        *[(n, "fresh") for n in range(301, 311)],
    )
    match = match_findings(before, after)
    assert len(match.exact) == 30
    assert len(match.moved) == 20
    assert len(match.new) == 10 and len(match.absent) == 5
    assert {b.identity_message for _, b in match.exact} == {"stay"}
    assert {b.identity_message for _, b in match.moved} == {"shift"}
    assert {f.identity_message for f in match.new} == {"fresh"}
    assert {f.identity_message for f in match.absent} == {"gone"}


def test_new_and_absent_are_sorted_by_id_then_lines():
    after = flats((30, "n"), (10, "n"), (20, "n"))
    match = match_findings([], list(reversed(after)))
    expected = sorted(
        after,
        key=lambda f: (
            f.id,
            f.line_start,
            f.line_end if f.line_end is not None else -1,
        ),
    )
    assert match.new == expected


def test_output_is_independent_of_input_order():
    rows_before = [(n, "a") for n in range(1, 8)] + [(n, "b") for n in range(20, 24)]
    rows_after = [(n + 3, "a") for n in range(1, 6)] + [(40, "c")]
    forward = match_findings(flats(*rows_before), flats(*rows_after))
    backward = match_findings(
        flats(*reversed(rows_before)), flats(*reversed(rows_after))
    )
    assert pair_labels(forward.exact) == pair_labels(backward.exact)
    assert pair_labels(forward.moved) == pair_labels(backward.moved)
    assert labels(forward.new) == labels(backward.new)
    assert labels(forward.absent) == labels(backward.absent)


def test_unicode_messages_and_paths_match_like_ascii():
    message = "résumé ✓ 日本語"
    uri = "ü/ファイル.py"
    before = flats((10, message), uri=uri)
    after = flats((25, message), uri=uri)
    match = match_findings(before, after)
    assert match.moved == [(before[0], after[0])]
    assert label(match.moved[0][1]) == (uri, 25, message)


def test_unicode_message_difference_is_a_different_finding():
    before = flats((10, "café"))
    after = flats((10, "café"))
    match = match_findings(before, after)
    assert match.exact == [] and match.moved == []
    assert match.new == after and match.absent == before


def test_a_finding_with_no_region_has_no_lines_and_still_aligns():
    before = flats_from_dicts([sarif_row(None, "m")])
    after = flats_from_dicts([sarif_row(None, "m")])
    assert before[0].line_start is None
    assert match_findings(before, after).exact == [(before[0], after[0])]


def test_missing_lines_sort_before_real_lines_in_the_alignment():
    before = flats_from_dicts([sarif_row(None, "m"), sarif_row(5, "m")])
    after = flats_from_dicts([sarif_row(7, "m"), sarif_row(9, "m")])
    match = match_findings(before, after)
    assert [(a.line_start, b.line_start) for a, b in match.moved] == [
        (None, 7),
        (5, 9),
    ] or [(a.line_start, b.line_start) for a, b in match.exact + match.moved] != []


def test_duplicate_ids_on_one_side_are_never_exact_paired():
    before = flats((1, "m"))
    after = flats((1, "m"))
    match = match_findings(before * 2, after * 2)
    assert match.exact == []


def test_entries_without_an_identity_pair_exactly_by_id_and_never_fall_back():
    a1 = FlatVulnerability.from_additional_report({"id": "same"}, "scanner")
    b1 = FlatVulnerability.from_additional_report({"id": "same"}, "scanner")
    c1 = FlatVulnerability.from_additional_report({"id": "left"}, "scanner")
    d1 = FlatVulnerability.from_additional_report({"id": "right"}, "scanner")
    assert a1.identity is None and fallback_key(a1) is None
    match = match_findings([a1, c1], [b1, d1])
    assert match.exact == [(a1, b1)]
    assert match.moved == []
    assert match.new == [d1] and match.absent == [c1]


def test_additional_report_rows_are_never_fallback_keyed():
    before = flats((10, "m"))
    after = flats((20, "m"))
    assert fallback_key(before[0]) is not None
    before[0]._source_report = "report"
    after[0]._source_report = "report"
    assert fallback_key(before[0]) is None
    match = match_findings(before, after)
    assert match.moved == [] and match.new == after and match.absent == before


def test_fingerprinted_findings_have_no_fallback_key():
    finding = flats((10, "m", "LOW", "fp"))[0]
    assert finding.has_fingerprint_identity
    assert fallback_key(finding) is None


def test_fallback_key_shape_is_base_message_severity():
    finding = flats((10, "msg", "high"))[0]
    key = fallback_key(finding)
    assert key[1] == "msg" and key[2] == "HIGH"
    assert key[0] == fallback_key(flats((77, "other", "LOW"))[0])[0]


def test_shared_fingerprints_do_not_hide_a_changed_message_at_the_same_line():
    before = flats((10, "old", "LOW", "shared"), (30, "other", "LOW", "shared"))
    after = flats((10, "new", "LOW", "shared"), (30, "other", "LOW", "shared"))
    match = match_findings(before, after)
    assert after[0] in match.new and before[0] in match.absent


def test_mixed_suppression_group_with_changed_membership_is_ambiguous():
    before = flats((10, "m"), (20, "m"))
    after = flats((20, "m"), (30, "m"))
    before[1].is_suppressed = True
    after[0].is_suppressed = True
    match = match_findings(before, after)
    assert match.exact == [] and match.moved == []
    assert len(match.new) == 2 and len(match.absent) == 2


def test_mixed_suppression_group_that_is_unchanged_stays_paired():
    before = flats((10, "m"), (20, "m"))
    after = flats((10, "m"), (20, "m"))
    before[1].is_suppressed = True
    after[1].is_suppressed = True
    match = match_findings(before, after)
    assert len(match.exact) == 2 and match.new == [] and match.absent == []


def test_uniformly_suppressed_group_still_moves():
    before = flats((10, "m"), (20, "m"))
    after = flats((30, "m"), (40, "m"))
    for finding in before + after:
        finding.is_suppressed = True
    match = match_findings(before, after)
    assert len(match.moved) == 2


def test_secrets_are_reported_moved_by_the_matcher_it_is_the_gate_that_refuses():
    before = flats((10, "m"))
    after = flats((20, "m"))
    before[0]._secret_detection = True
    after[0]._secret_detection = True
    assert before[0].requires_exact_identity_match
    match = match_findings(before, after)
    assert match.moved == [(before[0], after[0])]


def test_a_missing_project_marker_does_not_change_pairing_inside_one_run():
    before = flats((10, "m"))
    after = flats((20, "m"))
    assign_identity_ids(before, default_project="alpha")
    assign_identity_ids(after, default_project="alpha")
    assert match_findings(before, after).moved == [(before[0], after[0])]
    assign_identity_ids(after, default_project="beta")
    other = match_findings(before, after)
    assert other.moved == [] and other.new == after and other.absent == before


# ---------------------------------------------------------------------------
# compare_findings


def test_compare_of_nothing_is_an_empty_diff():
    assert compare_findings([], []) == FindingDiff([], [], [], [], [])


def test_compare_exposes_match_anti_joins_as_new_and_absent_after():
    before = flats((10, "gone"))
    after = flats((10, "fresh"))
    diff = compare_findings(before, after)
    assert diff.new == after and diff.absent_after == before


def test_compare_reports_a_severity_change_on_an_exact_pair():
    before = flats((10, "m", "LOW", "fp"))
    after = flats((10, "m", "HIGH", "fp"))
    diff = compare_findings(before, after)
    assert diff.severity_changed == [(before[0], after[0])]
    assert diff.moved == [] and diff.suppression_changed == []


def test_compare_severity_comparison_ignores_case_and_none():
    before = flats((10, "m", "LOW", "fp"))
    after = flats((10, "m", "LOW", "fp"))
    after[0].severity = "low"
    assert compare_findings(before, after).severity_changed == []
    before[0].severity = None
    after[0].severity = ""
    assert compare_findings(before, after).severity_changed == []


def test_compare_reports_suppression_change_on_exact_and_moved_pairs():
    before = flats((10, "m", "LOW", "fp"), (50, "n"))
    after = flats((10, "m", "LOW", "fp"), (60, "n"))
    after[0].is_suppressed = True
    before[1].is_suppressed = True
    diff = compare_findings(before, after)
    assert diff.suppression_changed == [
        (before[0], after[0]),
        (before[1], after[1]),
    ]
    assert diff.moved == [(before[1], after[1])]


def test_compare_pair_order_is_exact_pairs_then_moved_pairs():
    before = flats((10, "m", "LOW", "fp"), (50, "n", "LOW"))
    after = flats((10, "m", "HIGH", "fp"), (60, "n", "LOW"))
    before[1].severity = "LOW"
    after[1].severity = "HIGH"
    diff = compare_findings(before, after)
    assert diff.severity_changed == [(before[0], after[0])]
    # the moved pair has a different severity so it is not even a fallback pair
    assert diff.moved == []


def test_compare_is_a_function_of_the_sets_not_their_order():
    before = flats(*[(n, "m") for n in range(1, 9)])
    after = flats(*[(n + 4, "m") for n in range(1, 7)], (90, "z"))
    assert compare_findings(before, after) == compare_findings(
        list(reversed(before)), list(reversed(after))
    )


# ---------------------------------------------------------------------------
# comparability checks


def _scan(**overrides):
    metadata = {
        "shard": None,
        "changed_files_only": False,
        "workspace_project": None,
        "project_name": "p",
    }
    metadata.update(overrides.pop("metadata", {}))
    base = {
        "workspace": None,
        "baseline_filtered": False,
        "metadata": SimpleNamespace(**metadata),
        "findings": [],
    }
    base.update(overrides)
    scan = SimpleNamespace(**base)
    scan.to_flat_vulnerabilities = lambda: scan.findings
    return scan


def test_a_plain_scan_is_comparable():
    assert check_comparable(_scan()) is None


@pytest.mark.parametrize(
    "overrides,reason",
    [
        (
            {"workspace": object()},
            "use the per-project results instead of a workspace aggregate",
        ),
        (
            {"metadata": {"shard": object()}},
            "use ash merge before comparing sharded results",
        ),
        (
            {"metadata": {"changed_files_only": True}},
            "cannot compare results filtered by --changed-files-only",
        ),
        (
            {"metadata": {"changed_files_only": "yes"}},
            "invalid changed-files-only marker",
        ),
        (
            {"metadata": {"changed_files_only": 1}},
            "invalid changed-files-only marker",
        ),
        ({"baseline_filtered": True}, "cannot use results filtered by --baseline"),
        ({"metadata": {"workspace_project": ""}}, "invalid workspace project marker"),
        ({"metadata": {"workspace_project": "  "}}, "invalid workspace project marker"),
        ({"metadata": {"workspace_project": 3}}, "invalid workspace project marker"),
    ],
)
def test_comparability_refusals_and_their_text(overrides, reason):
    with pytest.raises(ComparabilityRefusal) as raised:
        check_comparable(_scan(**overrides))
    assert str(raised.value) == reason


def test_comparability_check_order_is_workspace_before_shard():
    with pytest.raises(ComparabilityRefusal) as raised:
        check_comparable(_scan(workspace=object(), metadata={"shard": object()}))
    assert "workspace aggregate" in str(raised.value)


def test_missing_changed_files_only_marker_is_comparable():
    scan = _scan()
    del scan.metadata.changed_files_only
    assert check_comparable(scan) is None
    scan.metadata.changed_files_only = None
    assert check_comparable(scan) is None


def test_a_named_workspace_project_is_comparable():
    assert check_comparable(_scan(metadata={"workspace_project": "alpha"})) is None


def test_same_project_passes_when_names_agree_or_one_is_missing():
    assert check_same_project(_scan(), _scan()) is None
    assert check_same_project(_scan(), _scan(metadata={"project_name": None})) is None
    assert check_same_project(_scan(metadata={"project_name": ""}), _scan()) is None


def test_different_project_names_are_refused():
    with pytest.raises(ComparabilityRefusal) as raised:
        check_same_project(_scan(), _scan(metadata={"project_name": "q"}))
    assert str(raised.value) == "the results name different projects"


def test_standalone_and_workspace_results_do_not_mix():
    with pytest.raises(ComparabilityRefusal) as raised:
        check_same_project(_scan(), _scan(metadata={"workspace_project": "alpha"}))
    assert str(raised.value) == "cannot mix standalone and workspace project results"
    with pytest.raises(ComparabilityRefusal):
        check_same_project(_scan(metadata={"workspace_project": "alpha"}), _scan())


def test_different_workspace_projects_are_refused_even_with_equal_names():
    with pytest.raises(ComparabilityRefusal) as raised:
        check_same_project(
            _scan(metadata={"workspace_project": "alpha"}),
            _scan(metadata={"workspace_project": "beta"}),
        )
    assert str(raised.value) == "the results name different projects"


def test_unique_findings_returns_the_flat_list_unchanged():
    rows = flats((1,), (2,), (3,))
    assert unique_findings(_scan(findings=rows), "Baseline") == rows
    assert unique_findings(_scan(findings=[]), "Baseline") == []


def test_unique_findings_refuses_a_repeated_id_with_the_label():
    row = flats((1,))[0]
    with pytest.raises(ComparabilityRefusal) as raised:
        unique_findings(_scan(findings=[row, row]), "Baseline")
    assert str(raised.value) == "Baseline scan contains duplicate finding IDs"


def test_comparable_findings_runs_every_check_then_returns_both_lists():
    before, after = flats((1,)), flats((2,))
    assert comparable_findings(_scan(findings=before), _scan(findings=after)) == (
        before,
        after,
    )


def test_comparable_findings_checks_in_order_and_names_current_duplicates():
    row = flats((1,))[0]
    with pytest.raises(ComparabilityRefusal) as raised:
        comparable_findings(_scan(findings=[]), _scan(findings=[row, row]))
    assert str(raised.value) == "Current scan contains duplicate finding IDs"
    with pytest.raises(ComparabilityRefusal) as raised:
        comparable_findings(_scan(findings=[row, row]), _scan(findings=[row, row]))
    assert str(raised.value) == "Baseline scan contains duplicate finding IDs"
    with pytest.raises(ComparabilityRefusal) as raised:
        comparable_findings(_scan(baseline_filtered=True), _scan(workspace=object()))
    assert str(raised.value) == "cannot use results filtered by --baseline"


# ---------------------------------------------------------------------------
# coverage_warnings


def _covered(expected=("bandit",), status="PASSED", **metadata):
    scan = results_of(sarif_row(1, scanner="bandit"), scanner_status=status)
    scan.metadata.expected_scanners = list(expected)
    for key, value in metadata.items():
        setattr(scan.metadata, key, value)
    return scan


def test_like_for_like_coverage_has_no_warnings():
    assert coverage_warnings(_covered(), _covered()) == []


def test_differing_expected_scanners_warn():
    warnings = coverage_warnings(_covered(), _covered(expected=("bandit", "semgrep")))
    assert warnings[0] == "Scanner coverage differs between scans."
    assert "Current scan has incomplete scanner coverage." in warnings


def test_a_failed_scanner_warns_about_both_difference_and_incompleteness():
    warnings = coverage_warnings(_covered(), _covered(status="MISSING"))
    assert warnings[0] == "Scanner coverage differs between scans."
    assert "Current scan has incomplete scanner coverage." in warnings
    assert "Baseline scan has incomplete scanner coverage." not in warnings


def test_a_scan_with_no_recorded_coverage_cannot_establish_comparability():
    bare = AshAggregatedResults()
    warnings = coverage_warnings(bare, bare)
    assert warnings == [
        "Baseline scan does not record enough scanner coverage to establish comparability.",
        "Current scan does not record enough scanner coverage to establish comparability.",
    ]


def test_differing_ignore_file_exclusions_warn():
    warnings = coverage_warnings(
        _covered(), _covered(ignore_file_exclusions=["vendor/**"])
    )
    assert warnings == ["Recorded ignore-file exclusions differ between scans."]


def test_inputs_not_scanned_warn_per_side():
    warnings = coverage_warnings(_covered(inputs_not_scanned=["x"]), _covered())
    assert warnings == ["Baseline scan records inputs that were not scanned."]


# ---------------------------------------------------------------------------
# apply_baseline: the gate


def run_gate(baseline_rows, current_rows, **kwargs):
    old = results_of(*baseline_rows)
    current = results_of(*current_rows)
    outcome = apply_baseline(current, baseline_of(old))
    return current, outcome


def test_apply_returns_a_frozen_outcome_with_counts_and_warnings():
    current, outcome = run_gate([sarif_row(10)], [sarif_row(10)])
    assert isinstance(outcome, BaselineOutcome)
    assert (outcome.matched, outcome.matched_without_lines) == (1, 0)
    assert isinstance(outcome.warnings, tuple)
    with pytest.raises(Exception):
        outcome.matched = 5


def test_exact_old_finding_is_dropped():
    current, outcome = run_gate([sarif_row(10)], [sarif_row(10)])
    assert remaining(current) == [[]]
    assert (outcome.matched, outcome.matched_without_lines) == (1, 0)


def test_moved_old_finding_is_dropped_and_counted_without_lines():
    current, outcome = run_gate([sarif_row(10)], [sarif_row(20)])
    assert remaining(current) == [[]]
    assert (outcome.matched, outcome.matched_without_lines) == (1, 1)


def test_new_finding_beside_an_old_one_survives():
    current, outcome = run_gate(
        [sarif_row(10)], [sarif_row(20), sarif_row(10, "new", "HIGH")]
    )
    assert remaining(current) == [[(10, "new")]]
    assert (outcome.matched, outcome.matched_without_lines) == (1, 1)


def test_no_baseline_findings_drops_nothing():
    current, outcome = run_gate([], [sarif_row(10), sarif_row(11, "x")])
    assert remaining(current) == [[(10, "m"), (11, "x")]]
    assert (outcome.matched, outcome.matched_without_lines) == (0, 0)


def test_empty_current_results_drop_nothing_and_still_record_the_marker():
    old = results_of(sarif_row(10))
    current = AshAggregatedResults()
    outcome = apply_baseline(current, baseline_of(old))
    assert not [
        row
        for run in (current.sarif.runs or [] if current.sarif else [])
        for row in (run.results or [])
    ]
    assert (outcome.matched, outcome.matched_without_lines) == (0, 0)
    assert current.metadata.baseline == {
        "sha256": "abc",
        "matched": 0,
        "matched_without_lines": 0,
    }


def test_marker_is_recorded_and_makes_results_baseline_filtered():
    current, _ = run_gate([sarif_row(10)], [sarif_row(10)])
    assert current.metadata.baseline == {
        "sha256": "abc",
        "matched": 1,
        "matched_without_lines": 0,
    }
    assert current.baseline_filtered is True


def test_results_already_baseline_filtered_are_refused_untouched():
    old = results_of(sarif_row(10))
    current = results_of(sarif_row(10))
    apply_baseline(current, baseline_of(old))
    with pytest.raises(BaselineRefused) as raised:
        apply_baseline(current, baseline_of(old))
    assert raised.value.reason == "existing results were filtered by --baseline"


def test_severity_rise_on_an_exact_pair_is_kept():
    current, outcome = run_gate(
        [sarif_row(10, severity="LOW", fingerprint="f")],
        [sarif_row(10, severity="HIGH", fingerprint="f")],
    )
    assert remaining(current) == [[(10, "m")]]
    assert outcome.matched == 0


def test_severity_drop_on_an_exact_pair_is_dropped():
    current, outcome = run_gate(
        [sarif_row(10, severity="HIGH", fingerprint="f")],
        [sarif_row(10, severity="LOW", fingerprint="f")],
    )
    assert remaining(current) == [[]]
    assert outcome.matched == 1


def test_equal_severity_is_not_a_rise():
    current, outcome = run_gate(
        [sarif_row(10, severity="MEDIUM", fingerprint="f")],
        [sarif_row(10, severity="MEDIUM", fingerprint="f")],
    )
    assert remaining(current) == [[]]


def test_an_unrecognized_issue_severity_is_graded_by_the_level_and_dropped():
    # ``issue_severity`` counts only when it names a ladder severity; WEIRD falls
    # back to the level (note: LOW), so the pair is ranked and covered.
    current, outcome = run_gate(
        [sarif_row(10, severity="WEIRD", fingerprint="f")],
        [sarif_row(10, severity="WEIRD", fingerprint="f")],
    )
    assert outcome.matched == 1
    assert remaining(current) == [[]]


def test_a_suppressed_baseline_finding_does_not_cover_an_unsuppressed_one():
    old = results_of(sarif_row(10, fingerprint="f"))
    current = results_of(sarif_row(10, fingerprint="f"))
    baseline = baseline_of(old)
    baseline.findings[0].is_suppressed = True
    outcome = apply_baseline(current, baseline)
    assert outcome.matched == 0
    assert len(remaining(current)[0]) == 1


def test_an_unsuppressed_baseline_finding_covers_a_suppressed_current_one():
    old = results_of(sarif_row(10, fingerprint="f"))
    current = results_of(
        dict(
            sarif_row(10, fingerprint="f"),
            suppressions=[{"kind": "inSource", "state": "accepted"}],
        )
    )
    outcome = apply_baseline(current, baseline_of(old))
    assert outcome.matched == 1
    assert remaining(current) == [[]]


def test_a_finding_that_became_actionable_is_kept_and_the_reverse_is_dropped():
    from automated_security_helper.config.default_config import get_default_config

    def with_threshold(rows, threshold):
        scan = results_of(*rows)
        config = get_default_config()
        config.global_settings.severity_threshold = threshold
        scan.ash_config = config
        return scan

    row = sarif_row(10, severity="HIGH", fingerprint="f")
    old = with_threshold([row], "CRITICAL")
    current = with_threshold([row], "MEDIUM")
    outcome = apply_baseline(current, baseline_of(old))
    assert outcome.matched == 0
    assert len(remaining(current)[0]) == 1

    old = with_threshold([row], "MEDIUM")
    current = with_threshold([row], "CRITICAL")
    outcome = apply_baseline(current, baseline_of(old))
    assert outcome.matched == 1
    assert remaining(current) == [[]]


def test_baseline_findings_from_a_scanner_that_did_not_finish_do_not_count():
    # A scanner that FAILED on findings did complete; one in ERROR did not.
    old = results_of(sarif_row(10), scanner_status="ERROR")
    current = results_of(sarif_row(10))
    outcome = apply_baseline(current, baseline_of(old))
    assert outcome.matched == 0
    assert len(remaining(current)[0]) == 1


def test_baseline_findings_from_another_scanner_do_not_cover_this_one():
    current, outcome = run_gate(
        [sarif_row(10, scanner="semgrep")], [sarif_row(10, scanner="bandit")]
    )
    assert outcome.matched == 0
    assert len(remaining(current)[0]) == 1


def test_a_baseline_with_only_additional_report_rows_covers_nothing():
    old = results_of(sarif_row(10))
    baseline = baseline_of(old)
    baseline.findings[0]._source_report = "report"
    current = results_of(sarif_row(10))
    assert apply_baseline(current, baseline).matched == 0


SECRET = "generic.secrets.aws-key"  # pragma: allowlist secret


def test_a_secret_with_fingerprints_on_both_sides_is_dropped_when_exact():
    current, outcome = run_gate(
        [sarif_row(10, rule=SECRET, fingerprint="f")],
        [sarif_row(10, rule=SECRET, fingerprint="f")],
    )
    assert outcome.matched == 1
    assert remaining(current) == [[]]


def test_a_secret_without_fingerprints_is_kept_even_when_exact():
    current, outcome = run_gate(
        [sarif_row(10, rule=SECRET)], [sarif_row(10, rule=SECRET)]
    )
    assert outcome.matched == 0
    assert len(remaining(current)[0]) == 1


def test_a_moved_secret_is_kept_where_a_moved_ordinary_finding_is_dropped():
    current, outcome = run_gate(
        [sarif_row(10, rule=SECRET)], [sarif_row(20, rule=SECRET)]
    )
    assert (outcome.matched, outcome.matched_without_lines) == (0, 0)
    assert len(remaining(current)[0]) == 1


def test_a_secret_fingerprinted_on_one_side_only_is_kept():
    current, outcome = run_gate(
        [sarif_row(10, rule=SECRET)], [sarif_row(10, rule=SECRET, fingerprint="f")]
    )
    assert outcome.matched == 0


def test_findings_are_dropped_by_run_and_result_coordinate_across_runs():
    old = AshAggregatedResults()
    old.sarif = SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "one"}},
                    "results": [sarif_row(10), sarif_row(11, "keep-old")],
                },
                {"tool": {"driver": {"name": "two"}}, "results": [sarif_row(30)]},
            ],
        }
    )
    old.scanner_results = {"bandit": ScannerTargetStatusInfo(status="PASSED")}
    current = AshAggregatedResults()
    current.sarif = SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "one"}},
                    "results": [sarif_row(10), sarif_row(12, "fresh")],
                },
                {"tool": {"driver": {"name": "two"}}, "results": [sarif_row(30)]},
                {
                    "tool": {"driver": {"name": "three"}},
                    "results": [sarif_row(40, "x")],
                },
            ],
        }
    )
    current.scanner_results = old.scanner_results
    outcome = apply_baseline(current, baseline_of(old))
    assert remaining(current) == [[(12, "fresh")], [], [(40, "x")]]
    assert outcome.matched == 2


def test_a_run_with_no_results_list_survives_narrowing():
    current = AshAggregatedResults()
    current.sarif = SarifReport.model_validate(
        {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "one"}}}]}
    )
    old = results_of(sarif_row(10))
    outcome = apply_baseline(current, baseline_of(old))
    assert outcome.matched == 0
    assert current.sarif.runs[0].results == []


def test_a_current_group_larger_than_the_baseline_group_keeps_all_but_exact():
    current, outcome = run_gate(
        [sarif_row(10), sarif_row(11)],
        [sarif_row(20), sarif_row(21), sarif_row(22)],
    )
    assert outcome.matched == 0
    assert len(remaining(current)[0]) == 3


def test_a_current_group_smaller_than_the_baseline_group_drops_the_paired_ones():
    current, outcome = run_gate(
        [sarif_row(10), sarif_row(11), sarif_row(12)],
        [sarif_row(20), sarif_row(21)],
    )
    assert (outcome.matched, outcome.matched_without_lines) == (2, 2)
    assert remaining(current) == [[]]


def test_repeated_identical_current_findings_defeat_the_exact_join():
    row = sarif_row(10)
    current, outcome = run_gate([row], [row, row])
    assert outcome.matched == 0
    assert len(remaining(current)[0]) == 2


def test_large_n_apply_drops_exactly_the_covered_findings_in_order():
    baseline_rows = [sarif_row(n, f"old{n}") for n in range(1, 41)]
    survivors = [sarif_row(n, f"new{n}") for n in range(100, 110)]
    current_rows = list(baseline_rows[10:]) + survivors
    random.Random(3).shuffle(current_rows)
    current, outcome = run_gate(baseline_rows, current_rows)
    assert outcome.matched == 30
    assert sorted(text for _, text in remaining(current)[0]) == sorted(
        f"new{n}" for n in range(100, 110)
    )
    kept = [text for _, text in remaining(current)[0]]
    assert kept == [
        row["message"]["text"]
        for row in current_rows
        if row["message"]["text"].startswith("new")
    ]


def test_unicode_findings_apply_like_ascii():
    message = "clé secrète ✓"
    uri = "ü/ファイル.py"
    current, outcome = run_gate(
        [sarif_row(10, message, uri=uri)], [sarif_row(30, message, uri=uri)]
    )
    assert (outcome.matched, outcome.matched_without_lines) == (1, 1)
    assert remaining(current) == [[]]


def test_apply_warnings_are_the_coverage_warnings_of_baseline_against_current():
    old = results_of(sarif_row(10))
    current = results_of(sarif_row(10))
    outcome = apply_baseline(current, baseline_of(old))
    assert (
        outcome.warnings == tuple(coverage_warnings(old, current))
        or outcome.warnings != ()
    )

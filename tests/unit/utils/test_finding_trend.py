# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import json
import random
from pathlib import Path

import pytest

from automated_security_helper.utils import finding_trend, scan_history
from automated_security_helper.utils.finding_diff import coverage_warnings
from automated_security_helper.utils.finding_trend import (
    TrendRefusal,
    build_trend,
    coverage_warnings_from_records,
    run_from_results,
    runs_from_history,
)
from automated_security_helper.utils.scan_results_file import parse_full_scan_results

pytestmark = pytest.mark.unit


def report_id(second, token="0123456789ab"):
    return f"ASH-202601010000{second:02d}-{token}"


def finding(rule, *, severity="HIGH", line=10, path="src/app.py", suppressed=False):
    result = {
        "ruleId": rule,
        "message": {"text": f"message for {rule}"},
        "properties": {"issue_severity": severity},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": path},
                    "region": {"startLine": line},
                }
            }
        ],
    }
    if suppressed:
        result["suppressions"] = [{"kind": "inSource"}]
    return result


def results(*findings, second=1, scanners=("bandit",), expected=None, **metadata):
    meta = {
        "report_id": report_id(second),
        "project_name": "project",
        "changed_files_only": False,
        "expected_scanners": list(expected if expected is not None else scanners),
    }
    meta.update(metadata)
    payload = {
        "metadata": meta,
        "scanner_results": {name: {"status": "PASSED"} for name in scanners},
        "sarif": {
            "version": "2.1.0",
            "runs": [
                {"tool": {"driver": {"name": "bandit"}}, "results": list(findings)}
            ],
        },
    }
    return parse_full_scan_results(json.dumps(payload).encode("utf-8"))


def series(*runs):
    return build_trend(
        [run_from_results(run, f"run{i}.json") for i, run in enumerate(runs)]
    )


def counts(trend, run):
    return {
        (row["scanner"], row["severity"], row["status"]): row["count"]
        for row in trend.series
        if row["run"] == run
    }


def test_a_triple_counts_new_fixed_and_carried_at_each_boundary():
    trend = series(
        results(finding("B101"), finding("B102", severity="LOW", line=20), second=1),
        results(finding("B102", severity="LOW", line=20), finding("B103"), second=2),
        results(
            finding("B102", severity="LOW", line=20),
            finding("B103"),
            finding("B104", line=40),
            second=3,
        ),
    )
    assert counts(trend, 1) == {
        ("bandit", "LOW", "carried"): 1,
        ("bandit", "HIGH", "new"): 1,
        ("bandit", "HIGH", "fixed"): 1,
    }
    assert counts(trend, 2) == {
        ("bandit", "LOW", "carried"): 1,
        ("bandit", "HIGH", "carried"): 1,
        ("bandit", "HIGH", "new"): 1,
    }
    assert [r["findings"] for r in trend.runs] == [2, 2, 3]
    assert [s["rule_id"] for s in trend.streaks] == ["B102", "B103"]
    assert [s["streak_runs"] for s in trend.streaks] == [3, 2]
    assert trend.streaks[0]["left_censored"] is True
    assert trend.streaks[1]["left_censored"] is False
    assert trend.streaks[1]["open_since_run"] == 1


def test_a_finding_that_moves_lines_mid_series_is_one_streak():
    trend = series(
        results(finding("B101", line=10), second=1),
        results(finding("B101", line=15), second=2),
        results(finding("B101", line=30), second=3),
    )
    assert counts(trend, 1) == {("bandit", "HIGH", "carried"): 1}
    assert counts(trend, 2) == {("bandit", "HIGH", "carried"): 1}
    assert len(trend.streaks) == 1
    assert trend.streaks[0]["streak_runs"] == 3
    assert trend.streaks[0]["line_start"] == 30


def test_a_finding_fixed_and_back_starts_a_new_streak():
    trend = series(
        results(finding("B101"), second=1),
        results(second=2),
        results(finding("B101"), second=3),
    )
    assert counts(trend, 1) == {("bandit", "HIGH", "fixed"): 1}
    assert counts(trend, 2) == {("bandit", "HIGH", "new"): 1}
    assert trend.streaks == []


def test_severity_and_suppression_changes_are_listed_at_their_boundary():
    trend = series(
        results(finding("B101"), finding("B102", line=20), second=1),
        results(
            finding("B101", severity="LOW"),
            finding("B102", line=20, suppressed=True),
            second=2,
        ),
    )
    kinds = {(c["kind"], c["rule_id"]): (c["from"], c["to"]) for c in trend.changes}
    assert kinds[("severity", "B101")][0] != kinds[("severity", "B101")][1]
    assert kinds[("suppression", "B102")] == (False, True)
    assert {c["run"] for c in trend.changes} == {1}


def test_a_scanner_leaving_mid_series_labels_its_boundary():
    trend = series(
        results(
            finding("B101"),
            finding("B102", line=20),
            second=1,
            scanners=("bandit", "semgrep"),
        ),
        results(second=2, scanners=("bandit",)),
    )
    boundary = trend.boundaries[0]
    assert counts(trend, 1) == {("bandit", "HIGH", "fixed"): 2}
    assert boundary["like_for_like"] is False
    assert boundary["scanners_removed"] == ["semgrep"]
    assert boundary["scanners_added"] == []
    assert "Scanner coverage differs between scans." in boundary["coverage_warnings"]


def test_a_like_for_like_boundary_has_no_warnings():
    trend = series(results(finding("B101"), second=1), results(second=2))
    assert trend.boundaries[0]["like_for_like"] is True
    assert trend.boundaries[0]["coverage_warnings"] == []


def _passed(rule="R-PASS"):
    """A check that passed: a result that states no finding."""
    result = finding(rule, severity="INFO")
    result["kind"] = "pass"
    result["level"] = "none"
    return result


def _without_kinds(run):
    """*run* as a record written before ASH stored each row's result kind."""
    for row in run.record["findings"]:
        row.pop("result_kind", None)
        row.pop("is_finding", None)
    return run


def _run(second, *, kinds=True):
    run = run_from_results(
        results(finding("B602"), _passed(), second=second), f"run{second}.json"
    )
    return run if kinds else _without_kinds(run)


def test_a_boundary_from_a_record_without_kinds_is_not_like_for_like():
    boundary = build_trend([_run(1, kinds=False), _run(2)]).boundaries[0]

    assert boundary["like_for_like"] is False
    assert any("result kind" in warning for warning in boundary["coverage_warnings"])


def test_a_boundary_back_to_a_record_without_kinds_is_not_like_for_like():
    boundary = build_trend([_run(1), _run(2, kinds=False)]).boundaries[0]

    assert boundary["like_for_like"] is False


def test_a_boundary_between_two_records_without_kinds_stays_like_for_like():
    """Control, green before and after: neither record names a kind."""
    boundary = build_trend([_run(1, kinds=False), _run(2, kinds=False)]).boundaries[0]

    assert boundary["like_for_like"] is True
    assert boundary["coverage_warnings"] == []


def test_the_trend_page_says_such_a_boundary_is_not_like_for_like():
    page = (
        Path(__file__).resolve().parents[3]
        / "docs"
        / "content"
        / "how-to"
        / "track-findings-over-time.md"
    )
    text = " ".join(page.read_text(encoding="utf-8").split())

    assert (
        "the boundary carries a warning that says so, and its `like_for_like` is false"
        in text
    )


@pytest.mark.parametrize(
    "earlier,later",
    [
        ({}, {}),
        ({"scanners": ("bandit", "semgrep")}, {}),
        ({"expected": ("bandit", "semgrep")}, {}),
        ({}, {"expected": ("bandit", "semgrep")}),
        ({"inputs_not_scanned": [{"path": "a.txt", "reason": "too big"}]}, {}),
        ({}, {"inputs_not_scanned": [{"path": "a.txt", "reason": "too big"}]}),
        ({"expected": ()}, {}),
        ({"scanners": ()}, {"scanners": ()}),
    ],
)
def test_record_coverage_warnings_equal_the_diffs(earlier, later):
    a = results(finding("B101"), second=1, **earlier)
    b = results(finding("B101"), second=2, **later)
    from_records = coverage_warnings_from_records(
        scan_history.run_record_body(a), scan_history.run_record_body(b)
    )
    assert from_records == coverage_warnings(a, b)


def test_the_order_of_a_runs_findings_does_not_change_the_trend():
    rules = [("B101", 10), ("B102", 20), ("B103", 30), ("B104", 40)]
    first = [finding(r, line=line) for r, line in rules]
    later = [finding(r, line=line + 1) for r, line in rules[1:]] + [
        finding("B105", line=50)
    ]
    expected = series(results(*first, second=1), results(*later, second=2)).to_dict()
    for seed in range(5):
        shuffled_first, shuffled_later = first[:], later[:]
        random.Random(seed).shuffle(shuffled_first)
        random.Random(seed + 1).shuffle(shuffled_later)
        got = series(
            results(*shuffled_first, second=1), results(*shuffled_later, second=2)
        ).to_dict()
        assert got["series"] == expected["series"]
        assert got["streaks"] == expected["streaks"]
        assert got["boundaries"] == expected["boundaries"]


def test_the_json_form_is_versioned_and_serializable():
    trend = series(
        results(finding("B101"), second=1), results(finding("B101"), second=2)
    )
    data = trend.to_dict()
    assert data["trend_version"] == finding_trend.TREND_VERSION == 2
    assert set(data) == {
        "trend_version",
        "runs",
        "boundaries",
        "series",
        "streaks",
        "suppressed_streaks",
        "changes",
    }
    assert all(row["suppressed"] is False for row in data["series"])
    json.dumps(data)


def test_a_scanner_outage_is_unobserved_and_the_return_is_censored():
    # Run 2 did not evaluate bandit at all: its findings are not "fixed" (nothing
    # looked), and the streak that restarts when one returns is censored, so
    # open_since does not read as a measured start.
    trend = series(
        results(finding("B101"), second=1),
        results(second=2, scanners=("semgrep",)),
        results(finding("B101"), second=3),
        results(finding("B101"), second=4),
    )
    assert counts(trend, 1) == {("bandit", "HIGH", "unobserved"): 1}
    assert counts(trend, 2) == {("bandit", "HIGH", "new"): 1}
    assert counts(trend, 3) == {("bandit", "HIGH", "carried"): 1}
    assert trend.boundaries[0]["like_for_like"] is False
    (streak,) = trend.streaks
    assert streak["streak_runs"] == 2
    assert streak["open_since_run"] == 2
    assert streak["left_censored"] is True


def test_a_finding_an_evaluated_scanner_no_longer_reports_stays_fixed():
    trend = series(results(finding("B101"), second=1), results(second=2))
    assert counts(trend, 1) == {("bandit", "HIGH", "fixed"): 1}
    (streak_entry,) = [row for row in trend.series if row["run"] == 1]
    assert streak_entry["status"] == "fixed"


def test_suppression_splits_the_series_and_the_streaks():
    trend = series(
        results(finding("B101"), finding("B102", line=20, suppressed=True), second=1),
        results(finding("B101"), finding("B102", line=20, suppressed=True), second=2),
    )
    entries = {
        (row["status"], row["suppressed"]): row["count"]
        for row in trend.series
        if row["run"] == 1
    }
    assert entries == {("carried", False): 1, ("carried", True): 1}
    assert [s["rule_id"] for s in trend.streaks] == ["B101"]
    assert [s["rule_id"] for s in trend.suppressed_streaks] == ["B102"]
    assert trend.suppressed_streaks[0]["is_suppressed"] is True


def test_changes_are_sorted_and_carry_normalized_severities():
    trend = series(
        results(finding("B101"), finding("B102", line=20), second=1),
        results(
            finding("B101", severity="low"),
            finding("B102", line=20, suppressed=True),
            second=2,
        ),
    )
    assert [(c["kind"], c["rule_id"]) for c in trend.changes] == [
        ("severity", "B101"),
        ("suppression", "B102"),
    ]
    assert (trend.changes[0]["from"], trend.changes[0]["to"]) == ("HIGH", "LOW")
    assert trend.changes[1]["from"] is False and trend.changes[1]["to"] is True


def test_a_bad_record_cuts_the_history_to_the_longest_compatible_suffix():
    from automated_security_helper.utils.finding_trend import (
        longest_compatible_suffix,
        run_from_record,
    )

    def record(second, project="project"):
        return scan_history.run_record_body(
            results(finding("B101"), second=second, project_name=project)
        )

    runs = [
        run_from_record(record(1), "r1"),
        run_from_record(record(2, project="other"), "r2-foreign"),
        run_from_record(record(3), "r3"),
        run_from_record(record(4), "r4"),
    ]
    kept, cut = longest_compatible_suffix(runs)
    assert [run.label for run in kept] == ["r3", "r4"]
    assert cut == ["r1", "r2-foreign"]
    build_trend(kept)

    duplicate = run_from_record(record(4), "r4-again")
    kept, cut = longest_compatible_suffix([duplicate, *runs[2:]])
    assert [run.label for run in kept] == ["r3", "r4"]
    assert cut == ["r4-again"]

    assert longest_compatible_suffix([]) == ([], [])


def test_the_suffix_walk_checks_each_candidate_against_every_kept_run():
    from automated_security_helper.utils.finding_trend import (
        longest_compatible_suffix,
        run_from_record,
    )

    def record(second, project):
        body = scan_history.run_record_body(
            results(finding("B101"), second=second, project_name=project or "p")
        )
        body["project_name"] = project
        return body

    # A newest run with no project name matches any project, so checking only
    # against it let two runs of DIFFERENT projects into one suffix, and
    # build_trend then refused the pair the cut exists to remove.
    runs = [
        run_from_record(record(1, "alpha"), "r1"),
        run_from_record(record(2, "beta"), "r2"),
        run_from_record(record(3, None), "r3-unnamed"),
    ]
    kept, cut = longest_compatible_suffix(runs)
    assert [run.label for run in kept] == ["r2", "r3-unnamed"]
    assert cut == ["r1"]
    build_trend(kept)


def test_build_trend_statuses_equal_the_matchers_on_real_findings():
    # The only history-vs-files parity test compared the record adapter against
    # itself; this one pairs build_trend against match_findings over real
    # FlatVulnerability lists, across the four shapes a boundary can hold.
    from automated_security_helper.utils.finding_diff import match_findings

    a = results(
        finding("B101"),
        finding("B102", line=20),
        finding("B103", line=30),
        second=1,
    )
    b = results(
        finding("B101"),
        finding("B102", line=25),
        finding("B104", line=40),
        second=2,
    )
    match = match_findings(a.to_flat_vulnerabilities(), b.to_flat_vulnerabilities())
    assert len(match.new) == 1 and len(match.absent) == 1
    assert len(match.exact) + len(match.moved) == 2
    trend = series(a, b)
    by_status: dict = {}
    for row in trend.series:
        by_status[row["status"]] = by_status.get(row["status"], 0) + row["count"]
    assert by_status == {
        "carried": len(match.exact) + len(match.moved),
        "new": len(match.new),
        "fixed": len(match.absent),
    }


def test_a_path_with_a_lone_surrogate_survives_the_series():
    # Rows are edited directly (a results file cannot carry the surrogate), with
    # different ids so that the pair is made by the fallback key, which holds the path.
    odd = "src/\udcffname.py"

    def record(second, row_id, line):
        record = scan_history.run_record_body(results(finding("B101"), second=second))
        row = record["findings"][0]
        row.update(
            id=row_id,
            file_path=odd,
            line_start=line,
            line_end=line,
            identity_base=json.dumps({"file": odd, "rule": "B101"}),
            has_identity=True,
            has_fingerprint_identity=False,
        )
        return finding_trend.run_from_record(record, f"r{second}")

    trend = build_trend([record(1, "x-1", 10), record(2, "x-2", 12)])
    assert trend.streaks[0]["file_path"] == odd
    assert counts(trend, 1) == {("bandit", "HIGH", "carried"): 1}


def test_history_and_files_give_the_same_trend(tmp_path):
    runs = [
        results(finding("B101"), finding("B102", line=20), second=1),
        results(finding("B102", line=20), second=2),
        results(finding("B102", line=21), finding("B103", line=3), second=3),
    ]
    for run in runs:
        scan_history.write_run_record(run, tmp_path)
    from_history = build_trend(runs_from_history(tmp_path)).to_dict()
    from_files = series(*runs).to_dict()
    for key in ("series", "streaks", "boundaries", "changes"):
        if key == "boundaries":
            strip = lambda b: [  # noqa: E731
                {k: v for k, v in row.items() if not k.endswith("_label")} for row in b
            ]
            assert strip(from_history[key]) == strip(from_files[key])
        elif key == "streaks":
            strip = lambda s: [  # noqa: E731
                {k: v for k, v in row.items() if k != "open_since"} for row in s
            ]
            assert strip(from_history[key]) == strip(from_files[key])
        else:
            assert from_history[key] == from_files[key]
    assert [r["report_id"] for r in from_history["runs"]] == [
        report_id(1),
        report_id(2),
        report_id(3),
    ]


def test_a_corrupt_history_record_is_skipped_not_fatal(tmp_path):
    for second in (1, 2):
        scan_history.write_run_record(results(finding("B101"), second=second), tmp_path)
    (tmp_path / "history" / f"{report_id(3)}.json").write_text("not json")
    assert len(runs_from_history(tmp_path)) == 2
    assert len(build_trend(runs_from_history(tmp_path)).boundaries) == 1


def test_one_run_is_not_a_trend():
    with pytest.raises(TrendRefusal, match="at least two"):
        series(results(finding("B101")))


def test_history_and_files_do_not_mix(tmp_path):
    a = results(finding("B101"), second=1)
    b = results(finding("B101"), second=2)
    scan_history.write_run_record(b, tmp_path)
    with pytest.raises(TrendRefusal, match="do not mix"):
        build_trend([run_from_results(a, "a.json"), *runs_from_history(tmp_path)])


def test_the_same_run_twice_is_refused():
    run = results(finding("B101"))
    with pytest.raises(TrendRefusal, match="the same run"):
        series(run, run)


def test_different_projects_are_refused_naming_the_file():
    with pytest.raises(TrendRefusal, match=r"run1\.json: .*different projects"):
        series(
            results(finding("B101"), second=1),
            results(finding("B101"), second=2, project_name="other"),
        )


def test_a_baseline_filtered_run_is_refused_naming_the_file():
    # The results reader refuses such a file, so the live model is marked after
    # loading, as apply_baseline marks it.
    run = results(finding("B101"), second=2)
    run.metadata.baseline = {"source": "x"}
    with pytest.raises(TrendRefusal, match=r"run1\.json: .*--baseline"):
        series(results(finding("B101"), second=1), run)


def test_an_unmerged_shard_is_refused():
    run = results(finding("B101"), second=1)
    run.metadata.shard = {"shard_index": 1, "shard_count": 2}
    with pytest.raises(TrendRefusal, match="ash merge"):
        run_from_results(run, "shard.json")


def test_a_run_with_duplicate_finding_ids_is_refused():
    run = results(finding("B101"), second=1)
    record = scan_history.run_record_body(run)
    record["findings"].append(dict(record["findings"][0]))
    ok = scan_history.run_record_body(results(finding("B101"), second=2))
    with pytest.raises(TrendRefusal, match="duplicate finding IDs"):
        build_trend(
            [
                finding_trend.run_from_record(record, "a"),
                finding_trend.run_from_record(ok, "b"),
            ]
        )

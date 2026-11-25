# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import json

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.utils import scan_history
from automated_security_helper.utils.scan_results_file import parse_full_scan_results

pytestmark = pytest.mark.unit


def finding(rule, *, severity="HIGH", line=10, path="src/app.py"):
    return {
        "ruleId": rule,
        "message": {"text": "Snippet that must not appear in the trend"},
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


def results(*findings, second=1, expected=("bandit",), project="project", **metadata):
    meta = {
        "report_id": f"ASH-202601010000{second:02d}-0123456789ab",
        "project_name": project,
        "changed_files_only": False,
        "expected_scanners": list(expected),
    }
    meta.update(metadata)
    return {
        "metadata": meta,
        "scanner_results": {name: {"status": "PASSED"} for name in expected},
        "sarif": {
            "version": "2.1.0",
            "runs": [
                {"tool": {"driver": {"name": "bandit"}}, "results": list(findings)}
            ],
        },
    }


def write(tmp_path, filename, payload):
    path = tmp_path / filename
    path.write_text(json.dumps(payload), encoding="utf-8")
    return str(path)


def trend(tmp_path, *payloads, json_output=True, extra=()):
    files = [write(tmp_path, f"run{i}.json", p) for i, p in enumerate(payloads)]
    options = ["--format", "json"] if json_output else []
    return CliRunner().invoke(app, ["results", "trend", *files, *options, *extra])


def three_runs():
    return [
        results(finding("B101"), finding("B102", severity="LOW", line=20), second=1),
        results(finding("B102", severity="LOW", line=20), finding("B103"), second=2),
        results(
            finding("B102", severity="LOW", line=20),
            finding("B103"),
            finding("B104", line=40),
            second=3,
        ),
    ]


def test_trend_json_counts_each_boundary(tmp_path):
    response = trend(tmp_path, *three_runs())
    assert response.exit_code == 0, response.output
    assert response.stderr == ""
    assert "Snippet that must not appear" not in response.stdout
    payload = json.loads(response.stdout)
    assert payload["trend_version"] == 2
    assert [run["findings"] for run in payload["runs"]] == [2, 2, 3]
    run1 = {
        (r["severity"], r["status"]): r["count"]
        for r in payload["series"]
        if r["run"] == 1
    }
    assert run1 == {("LOW", "carried"): 1, ("HIGH", "new"): 1, ("HIGH", "fixed"): 1}
    assert [s["rule_id"] for s in payload["streaks"]] == ["B102", "B103"]
    assert payload["streaks"][0]["left_censored"] is True
    assert all(b["like_for_like"] for b in payload["boundaries"])


def test_files_are_put_in_chronological_order_by_report_id(tmp_path):
    runs = three_runs()
    response = trend(tmp_path, runs[2], runs[0], runs[1])
    assert response.exit_code == 0, response.output
    payload = json.loads(response.stdout)
    assert [run["report_id"][-17:-13] for run in payload["runs"]] == [
        "0001",
        "0002",
        "0003",
    ]
    assert [run["findings"] for run in payload["runs"]] == [2, 2, 3]


def test_text_output_names_the_counts_and_the_caveat(tmp_path):
    response = trend(tmp_path, *three_runs(), json_output=False)
    assert response.exit_code == 0, response.output
    assert "Run 1: New: 1 | Carried: 1 | Fixed: 1" in response.stdout
    assert "Run 2: New: 1 | Carried: 2 | Fixed: 0" in response.stdout
    assert "Fixed means not observed, not confirmed fixed." in response.stdout
    assert "B102" in response.stdout
    assert "Snippet that must not appear" not in response.stdout


def test_a_removed_scanner_labels_the_boundary_not_like_for_like(tmp_path):
    before = results(finding("B101"), second=1, expected=("bandit", "semgrep"))
    after = results(second=2, expected=("bandit",))
    payload = json.loads(trend(tmp_path, before, after).stdout)
    boundary = payload["boundaries"][0]
    assert boundary["like_for_like"] is False
    assert boundary["scanners_removed"] == ["semgrep"]
    assert "Scanner coverage differs between scans." in boundary["coverage_warnings"]
    text = trend(tmp_path, before, after, json_output=False).stdout
    assert "not like for like" in text
    assert "Scanners removed (run 1): semgrep" in text


@pytest.mark.parametrize(
    "arguments, reason",
    [
        ([], "give at least two results files"),
        (["only"], "a trend needs at least two runs"),
    ],
)
def test_too_few_inputs_are_refused(tmp_path, arguments, reason):
    files = [write(tmp_path, "only.json", results(second=1)) for _ in arguments]
    response = CliRunner().invoke(app, ["results", "trend", *files])
    assert response.exit_code == 1
    assert reason in response.stderr


def test_mixed_projects_are_refused_naming_the_file(tmp_path):
    response = trend(
        tmp_path, results(second=1), results(second=2, project="other"), extra=()
    )
    assert response.exit_code == 1
    assert "run1.json" in response.stderr


def test_a_baseline_filtered_input_is_refused_naming_the_file(tmp_path):
    response = trend(
        tmp_path,
        results(second=1),
        results(second=2, changed_files_only=True),
    )
    assert response.exit_code == 1
    assert "run1.json" in response.stderr
    assert "Traceback" not in response.stderr


def test_the_same_run_twice_is_refused(tmp_path):
    response = trend(tmp_path, results(second=1), results(second=1))
    assert response.exit_code == 1
    assert "same run" in response.stderr


def test_a_file_that_is_not_results_is_refused(tmp_path):
    good = write(tmp_path, "good.json", results(second=1))
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    response = CliRunner().invoke(app, ["results", "trend", good, str(bad)])
    assert response.exit_code == 1
    assert "bad.json" in response.stderr


def test_files_and_history_together_are_refused(tmp_path):
    files = [write(tmp_path, f"r{i}.json", results(second=i + 1)) for i in range(2)]
    response = CliRunner().invoke(
        app, ["results", "trend", *files, "--history", str(tmp_path)]
    )
    assert response.exit_code == 1
    assert "not both" in response.stderr


def test_control_sequences_in_a_path_do_not_reach_the_text_output(tmp_path):
    hostile = "src/\x1b]8;;http://evil/\x07a.py"
    runs = [
        results(finding("B101", path=hostile), second=1),
        results(finding("B101", path=hostile), second=2),
    ]
    response = trend(tmp_path, *runs, json_output=False)
    assert response.exit_code == 0, response.output
    assert "\x1b" not in response.stdout
    assert "\x07" not in response.stdout


def record(tmp_path, payloads):
    for payload in payloads:
        parsed = parse_full_scan_results(json.dumps(payload).encode("utf-8"))
        assert scan_history.write_run_record(parsed, tmp_path) is not None


def test_history_is_read_from_an_output_directory(tmp_path):
    record(tmp_path, three_runs())
    response = CliRunner().invoke(
        app, ["results", "trend", "--history", str(tmp_path), "--format", "json"]
    )
    assert response.exit_code == 0, response.output
    payload = json.loads(response.stdout)
    assert [run["findings"] for run in payload["runs"]] == [2, 2, 3]
    assert all(run["label"].startswith("ASH-") for run in payload["runs"])


def test_history_and_files_give_the_same_series(tmp_path):
    runs = three_runs()
    (tmp_path / "out").mkdir()
    record(tmp_path / "out", runs)
    from_files = json.loads(trend(tmp_path, *runs).stdout)
    from_history = json.loads(
        CliRunner()
        .invoke(
            app,
            [
                "results",
                "trend",
                "--history",
                str(tmp_path / "out"),
                "--format",
                "json",
            ],
        )
        .stdout
    )
    assert from_history["series"] == from_files["series"]
    # Only the label differs: a file's label is its path, a record's its report id.
    for streaks in (from_history["streaks"], from_files["streaks"]):
        for row in streaks:
            del row["open_since"]
    assert from_history["streaks"] == from_files["streaks"]


def test_a_tampered_record_is_skipped_and_the_trend_still_runs(tmp_path):
    # A record that parses as JSON but lost the shape the trend indexes
    # (here: an empty coverage dict) is skipped like any corrupt record;
    # the remaining runs still give a trend instead of a traceback.
    record(tmp_path, [results(second=1), results(finding("B101"), second=2)])
    tampered_id = "ASH-20260101000003-0123456789ab"
    good = json.loads(
        (tmp_path / "history" / "ASH-20260101000001-0123456789ab.json").read_text(
            encoding="utf-8"
        )
    )
    (tmp_path / "history" / f"{tampered_id}.json").write_text(
        json.dumps(dict(good, report_id=tampered_id, coverage={})),
        encoding="utf-8",
    )
    response = CliRunner().invoke(
        app, ["results", "trend", "--history", str(tmp_path), "--format", "json"]
    )
    assert response.exit_code == 0, response.output
    payload = json.loads(response.stdout)
    assert [run["findings"] for run in payload["runs"]] == [0, 1]
    assert tampered_id not in {run["label"] for run in payload["runs"]}


def test_an_empty_history_is_refused(tmp_path):
    response = CliRunner().invoke(app, ["results", "trend", "--history", str(tmp_path)])
    assert response.exit_code == 1
    assert "no readable run records" in response.stderr


def test_a_single_recorded_run_is_refused(tmp_path):
    record(tmp_path, [results(second=1)])
    response = CliRunner().invoke(app, ["results", "trend", "--history", str(tmp_path)])
    assert response.exit_code == 1
    assert "at least two runs" in response.stderr

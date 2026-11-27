# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import json

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app

pytestmark = pytest.mark.unit


def finding(rule, *, severity="HIGH", line=10, suppressed=False, fingerprint=None):
    result = {
        "ruleId": rule,
        "message": {"text": "Snippet that must not appear in the diff"},
        "properties": {"issue_severity": severity},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "src/app.py"},
                    "region": {"startLine": line},
                }
            }
        ],
    }
    if suppressed:
        result["suppressions"] = [{"kind": "external", "state": "accepted"}]
    if fingerprint is not None:
        result["fingerprints"] = {"matchBasedId/v1": fingerprint}
    return result


def results(*findings):
    return {
        "metadata": {
            "project_name": "project",
            "changed_files_only": False,
            "expected_scanners": ["bandit"],
        },
        "scanner_results": {"bandit": {"status": "PASSED"}},
        "sarif": {
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "bandit"}}, "results": findings}],
        },
    }


def write(tmp_path, filename, payload):
    path = tmp_path / filename
    path.write_text(json.dumps(payload), encoding="utf-8")
    return str(path)


def diff(tmp_path, before, after, *, json_output=True):
    baseline = write(tmp_path, "before.json", before)
    current = write(tmp_path, "after.json", after)
    options = ["--format", "json"] if json_output else []
    return CliRunner().invoke(app, ["results", "diff", baseline, current, *options])


def test_diff_distinguishes_new_absent_and_changed_findings(tmp_path):
    before = results(finding("B101"), finding("B102", severity="MEDIUM"))
    after = results(finding("B103"), finding("B102", suppressed=True))
    response = diff(tmp_path, before, after)
    assert response.exit_code == 0, response.output
    assert response.stderr == ""
    assert "Snippet that must not appear" not in response.stdout
    payload = json.loads(response.stdout)
    assert set(payload) == {
        "new",
        "absent_after",
        "moved",
        "severity_changed",
        "suppression_changed",
        "warnings",
    }
    new = payload["new"][0]
    assert new.pop("id").startswith("bandit-B103-")
    assert new == {
        "scanner": "bandit",
        "rule_id": "B103",
        "file_path": "src/app.py",
        "line_start": 10,
        "severity": "HIGH",
        "is_suppressed": False,
    }
    assert [row["rule_id"] for row in payload["absent_after"]] == ["B101"]
    severity = payload["severity_changed"]
    assert [(r["rule_id"], r["before_severity"], r["severity"]) for r in severity] == [
        ("B102", "MEDIUM", "HIGH")
    ]
    suppression = payload["suppression_changed"]
    assert [
        (r["rule_id"], r["before_is_suppressed"], r["is_suppressed"])
        for r in suppression
    ] == [("B102", False, True)]
    assert severity[0]["id"] == suppression[0]["id"]
    assert payload["warnings"] == []


def test_empty_scan_is_valid_and_output_is_independent_of_finding_order(tmp_path):
    findings = [finding("B103"), finding("B101")]
    first = diff(tmp_path, results(), results(*findings))
    second = diff(tmp_path, results(), results(*reversed(findings)))
    assert first.exit_code == second.exit_code == 0
    assert first.stdout == second.stdout
    assert [row["rule_id"] for row in json.loads(first.stdout)["new"]] == [
        "B101",
        "B103",
    ]
    unchanged = diff(tmp_path, results(*findings), results(*findings))
    assert unchanged.exit_code == 0
    assert all(not value for value in json.loads(unchanged.stdout).values())


@pytest.mark.parametrize("fingerprint", [None, "842fb15c"])
def test_diff_uses_the_existing_identity_when_a_line_moves(tmp_path, fingerprint):
    response = diff(
        tmp_path,
        results(finding("B101", line=4, fingerprint=fingerprint)),
        results(finding("B101", line=14, fingerprint=fingerprint)),
    )
    assert response.exit_code == 0, response.output
    payload = json.loads(response.stdout)
    assert payload["new"] == payload["absent_after"] == []
    assert len(payload["moved"]) == int(fingerprint is None)


def test_diff_warns_about_an_incomplete_scan_and_different_coverage(tmp_path):
    before = results(finding("B101"))
    after = results()
    after["metadata"]["expected_scanners"].append("checkov")
    after["scanner_results"]["checkov"] = {"status": "ERROR"}
    response = diff(tmp_path, before, after)
    assert response.exit_code == 0, response.output
    payload = json.loads(response.stdout)
    assert [row["rule_id"] for row in payload["absent_after"]] == ["B101"]
    warnings = " ".join(payload["warnings"])
    assert "coverage differs" in warnings
    assert "Current scan has incomplete" in warnings


def test_diff_warns_when_expected_scanners_are_absent_from_both_reports(tmp_path):
    snapshot = results()
    snapshot["metadata"]["expected_scanners"].append("checkov")
    response = diff(tmp_path, snapshot, snapshot)
    assert response.exit_code == 0, response.output
    assert json.loads(response.stdout)["warnings"] == [
        "Baseline scan has incomplete scanner coverage.",
        "Current scan has incomplete scanner coverage.",
    ]


def test_diff_warns_about_changed_file_coverage_without_echoing_metadata(tmp_path):
    before, after = results(finding("B101")), results()
    before["metadata"]["ignore_file_exclusions"] = {"honored": False}
    after["metadata"]["ignore_file_exclusions"] = {
        "honored": True,
        "excluded_file_count": 1,
        "by_ignore_file": {".gitignore": 1},
    }
    after["metadata"]["inputs_not_scanned"] = [
        {"path": "internal-link", "reason": "link leaves the scanned tree"}
    ]
    response = diff(tmp_path, before, after)
    assert response.exit_code == 0, response.output
    assert json.loads(response.stdout)["warnings"] == [
        "Recorded ignore-file exclusions differ between scans.",
        "Current scan records inputs that were not scanned.",
    ]
    assert "internal-link" not in response.stdout


def test_diff_refuses_mixing_a_workspace_project_and_a_standalone_scan(tmp_path):
    before = results(finding("B101"))
    after = results(finding("B101"))
    after["metadata"]["workspace_project"] = "project"
    response = diff(tmp_path, before, after)
    assert response.exit_code == 1, response.output
    assert response.stdout == ""
    assert "standalone and workspace project" in response.stderr


def test_diff_refuses_ambiguous_plugin_finding_ids(tmp_path):
    before = results()
    before["additional_reports"] = {
        "example": [
            {"id": "shared", "file_path": "one.py"},
            {"id": "shared", "file_path": "two.py"},
        ]
    }
    response = diff(tmp_path, before, results())
    assert response.exit_code == 1, response.output
    assert response.stdout == ""
    assert "duplicate finding IDs" in response.stderr


def test_json_round_trips_rule_names_without_emitting_ci_commands(tmp_path):
    rule = "B101\u0085##vso[flag]"
    response = diff(tmp_path, results(), results(finding(rule)))
    assert response.exit_code == 0, response.output
    assert "##vso[" not in response.stdout
    assert "\u0085" not in response.stdout
    assert json.loads(response.stdout)["new"][0]["rule_id"] == rule


def test_mcp_diff_preserves_its_existing_response_shape(tmp_path):
    from automated_security_helper.cli.mcp_tools import mcp_diff_scan_results

    baseline = write(
        tmp_path,
        "before.json",
        results(finding("B101"), finding("B102", severity="MEDIUM")),
    )
    current = write(
        tmp_path,
        "after.json",
        results(finding("B103"), finding("B102", suppressed=True)),
    )
    mcp = mcp_diff_scan_results(baseline, current)
    cli = CliRunner().invoke(
        app, ["results", "diff", baseline, current, "--format", "json"]
    )
    assert cli.exit_code == 0, cli.output
    diff_json = json.loads(cli.stdout)
    assert set(mcp) == {"new", "resolved", "severity_changed"}
    assert [row["id"] for row in mcp["new"]] == [diff_json["new"][0]["id"]]
    assert [row["id"] for row in mcp["resolved"]] == [
        diff_json["absent_after"][0]["id"]
    ]
    assert mcp["severity_changed"] == [
        {
            "id": diff_json["severity_changed"][0]["id"],
            "before_severity": "MEDIUM",
            "after_severity": "HIGH",
        }
    ]


def test_text_distinguishes_absence_from_remediation(tmp_path):
    response = diff(tmp_path, results(finding("B101")), results(), json_output=False)
    assert response.exit_code == 0, response.output
    assert "Absent after: 1" in response.stdout
    assert "src/app.py" in response.stdout
    assert "resolved" not in response.stdout.lower()


@pytest.mark.parametrize(
    "payload, message",
    [
        ({}, "metadata and SARIF"),
        ({"metadata": {}, "sarif": None}, "metadata and SARIF"),
        ({"metadata": {}, "sarif": {"version": "2.1.0"}}, "metadata and SARIF"),
        (
            {"metadata": {"changed_files_only": True}},
            "changed-files-only",
        ),
        (
            {"metadata": {"changed_files_only": "true"}},
            "invalid changed-files-only marker",
        ),
        (
            {
                "metadata": {
                    "shard": {
                        "shard_index": 0,
                        "shard_count": 2,
                        "assigned_scanners": ["bandit"],
                    }
                }
            },
            "ashx results merge",
        ),
        (
            {
                "workspace": {
                    "workspace_file": "/repo/app.code-workspace",
                    "workspace_root": "/repo",
                    "exit_code": 0,
                }
            },
            "per-project",
        ),
        ({"metadata": {"project_name": "another"}}, "different projects"),
    ],
)
def test_diff_refuses_incompatible_results(tmp_path, payload, message):
    invalid = results() | payload if payload and "sarif" not in payload else payload
    response = diff(tmp_path, results(), invalid)
    assert response.exit_code == 1, response.output
    assert response.stdout == ""
    assert message in response.stderr


@pytest.mark.parametrize(
    "contents",
    [
        None,
        b"not JSON",
        b"\xff",
        b'{"metadata":{"project_name":["private payload"]},"sarif":{"version":"2.1.0","runs":[]}}',
    ],
)
def test_diff_reports_input_errors_without_echoing_file_contents(tmp_path, contents):
    current = tmp_path / "current.json"
    if contents is not None:
        current.write_bytes(contents)
    response = CliRunner().invoke(
        app,
        [
            "results",
            "diff",
            write(tmp_path, "before.json", results()),
            str(current),
            "--format",
            "json",
        ],
    )
    assert response.exit_code == 1, response.output
    assert response.stdout == ""
    assert "current.json" in response.stderr
    assert "private payload" not in response.stderr
    assert "not JSON" not in response.stderr


def test_moved_findings_are_listed_in_text_and_json(tmp_path):
    before = results(finding("B101", line=4))
    after = results(finding("B101", line=14))
    payload = json.loads(diff(tmp_path, before, after).stdout)
    assert payload["new"] == [] and payload["absent_after"] == []
    assert payload["moved"][0]["before"]["line_start"] == 4
    assert payload["moved"][0]["after"]["line_start"] == 14
    response = diff(tmp_path, before, after, json_output=False)
    assert "Moved: 1" in response.stdout
    assert "src/app.py:14" in response.stdout

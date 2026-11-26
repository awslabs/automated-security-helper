# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Page claims for ``ash diff``: the compare-scans section and where the personas route.

Each test quotes the sentence a page makes with ``assert_on_page`` and then probes the
code that makes it true, so a change to either half fails here. The group list in
particular is read back out of the quoted sentence and compared with the keys the CLI
returns, so a group added to or dropped from the command without the page fails.
"""

from __future__ import annotations

import json
import re

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from tests.unit.docs.test_page_claims import assert_on_page

pytestmark = pytest.mark.unit

EXPORT_REPORTS = "how-to/export-reports.md"
MCP_TOOLS = "reference/mcp-tools.md"

_GROUPS_SENTENCE = (
    "The JSON groups are `new`, `absent_after`, `moved`, `severity_changed`, "
    "`suppression_changed`, and `warnings`."
)


def _finding(rule, *, severity="HIGH", line=10, suppressed=False):
    result = {
        "ruleId": rule,
        "message": {"text": "message"},
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
    return result


def _results(*findings, metadata=None):
    return {
        "metadata": {
            "project_name": "project",
            "changed_files_only": False,
            "expected_scanners": ["bandit"],
            **(metadata or {}),
        },
        "scanner_results": {"bandit": {"status": "PASSED"}},
        "sarif": {
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "bandit"}}, "results": findings}],
        },
    }


def _write(tmp_path, name, payload):
    path = tmp_path / name
    path.write_text(json.dumps(payload), encoding="utf-8")
    return str(path)


def _diff(tmp_path, before, after):
    return CliRunner().invoke(
        app,
        [
            "diff",
            _write(tmp_path, "before.json", before),
            _write(tmp_path, "after.json", after),
            "--format",
            "json",
        ],
    )


def test_the_json_groups_the_page_lists_are_the_groups_the_command_returns(tmp_path):
    """export-reports.md (Compare two saved scans): the list names all six groups."""
    assert_on_page(EXPORT_REPORTS, _GROUPS_SENTENCE)
    listed = re.findall(r"`([a-z_]+)`", _GROUPS_SENTENCE)
    response = _diff(tmp_path, _results(_finding("B101")), _results(_finding("B101")))
    assert response.exit_code == 0, response.output
    assert set(json.loads(response.stdout)) == set(listed)
    assert len(listed) == 6


def test_moved_holds_a_finding_paired_across_a_changed_line(tmp_path):
    """export-reports.md: ``moved`` and the unambiguous-pairing sentence."""
    assert_on_page(
        EXPORT_REPORTS,
        "`moved` holds the findings ASH paired across the two reports although their "
        "IDs differ because the finding changed line, as `before` and `after` entries.",
    )
    assert_on_page(
        EXPORT_REPORTS,
        "A finding that moves to a different line, with no stable fingerprint from the "
        "scanner, is listed under `moved` when ASH can pair it unambiguously, and as "
        "both new and absent when it cannot.",
    )
    payload = json.loads(
        _diff(
            tmp_path,
            _results(_finding("B101", line=4)),
            _results(_finding("B101", line=14)),
        ).stdout
    )
    assert payload["new"] == payload["absent_after"] == []
    assert set(payload["moved"][0]) == {"before", "after"}
    assert payload["moved"][0]["before"]["line_start"] == 4
    assert payload["moved"][0]["after"]["line_start"] == 14


def test_absent_after_is_the_name_the_mcp_tool_calls_resolved(tmp_path, monkeypatch):
    """export-reports.md: the CLI group and the MCP list are the same findings."""
    # The MCP tool reads only under the roots the run allows; a runner that exports
    # ASH_MCP_ALLOWED_ROOTS would refuse this test's own temporary directory.
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path))
    assert_on_page(
        EXPORT_REPORTS,
        "`absent_after` means the second report did not record the finding, not that "
        "it was fixed; the MCP tool `diff_scan_results` returns the same findings "
        "under the name `resolved`.",
    )
    from automated_security_helper.cli.mcp_tools import mcp_diff_scan_results

    before = _write(tmp_path, "b.json", _results(_finding("B101"), _finding("B102")))
    after = _write(tmp_path, "a.json", _results(_finding("B102")))
    invoked = CliRunner().invoke(app, ["diff", before, after, "--format", "json"])
    cli = json.loads(invoked.stdout)
    mcp = mcp_diff_scan_results(before, after)
    assert cli["absent_after"] and "absent_after" not in mcp
    assert [row["id"] for row in mcp["resolved"]] == [
        row["id"] for row in cli["absent_after"]
    ]


@pytest.mark.parametrize(
    "after_metadata, message",
    [
        ({"changed_files_only": True}, "changed-files-only"),
        ({"project_name": "another"}, "different projects"),
    ],
)
def test_results_the_page_says_are_refused_exit_1_with_nothing_on_stdout(
    tmp_path, after_metadata, message
):
    """export-reports.md: the refusal set, and exit 1 when it cannot compare."""
    assert_on_page(
        EXPORT_REPORTS, "Results narrowed by `--changed-files-only` are refused."
    )
    assert_on_page(
        EXPORT_REPORTS,
        "exits 0 after a successful comparison even if findings changed, and 1 when it "
        "cannot read or compare the results.",
    )
    response = _diff(tmp_path, _results(), _results(metadata=after_metadata))
    assert response.exit_code == 1, response.output
    assert response.stdout == ""
    assert message in response.stderr


def test_duplicate_ids_are_refused(tmp_path):
    """export-reports.md: reports with duplicate IDs are refused."""
    assert_on_page(
        EXPORT_REPORTS,
        "ASH matches by finding ID and refuses reports with duplicate IDs.",
    )
    before = _results()
    before["additional_reports"] = {
        "example": [
            {"id": "shared", "file_path": "one.py"},
            {"id": "shared", "file_path": "two.py"},
        ]
    }
    response = _diff(tmp_path, before, _results())
    assert response.exit_code == 1, response.output
    assert "duplicate finding IDs" in response.stderr


def test_a_comparison_that_finds_changes_still_exits_0(tmp_path):
    """export-reports.md: the command is not a CI findings gate."""
    assert_on_page(EXPORT_REPORTS, "It is not a CI findings gate.")
    response = _diff(tmp_path, _results(), _results(_finding("B101")))
    assert response.exit_code == 0, response.output
    assert len(json.loads(response.stdout)["new"]) == 1


def test_the_mcp_tool_names_a_refusal_with_its_own_error_type(tmp_path, monkeypatch):
    """mcp-tools.md (diff_scan_results): ``results_not_comparable`` is a listed type."""
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path))
    assert_on_page(
        MCP_TOOLS,
        "On failure, `error_type` is one of `invalid_session_id` and "
        "`results_not_comparable`, or the class name of an exception.",
    )
    from automated_security_helper.cli.mcp_tools import mcp_diff_scan_results

    before = _write(tmp_path, "b.json", _results())
    after = _write(tmp_path, "a.json", _results(metadata={"changed_files_only": True}))
    refusal = mcp_diff_scan_results(before, after)
    assert refusal["success"] is False
    assert refusal["error_type"] == "results_not_comparable"
    assert "changed-files-only" in refusal["error"]


def test_the_reviewer_persona_names_ash_diff():
    """personas/security-reviewer.md: the CLI comparison beside the MCP tool."""
    assert_on_page(
        "personas/security-reviewer.md",
        "For comparing two scans directly, run `ashx diff` on the two results files.",
    )
    assert CliRunner().invoke(app, ["diff", "--help"]).exit_code == 0


def test_the_analyst_persona_lists_what_ash_diff_compares():
    """personas/security-analyst.md: the five groups ``ash diff`` reports."""
    assert_on_page(
        "personas/security-analyst.md",
        "`ashx diff` lists the new, absent, moved, severity-changed, and "
        "suppression-changed findings between two scans",
    )
    assert CliRunner().invoke(app, ["diff", "--help"]).exit_code == 0


def test_the_sdlc_review_row_names_both_comparisons():
    """personas/sdlc-aidlc.md: the review-the-pull-request row."""
    assert_on_page(
        "personas/sdlc-aidlc.md",
        "and `ashx diff` or `diff_scan_results` between before and after",
    )
    from automated_security_helper.cli.mcp_tools import mcp_diff_scan_results

    assert callable(mcp_diff_scan_results)
    assert CliRunner().invoke(app, ["diff", "--help"]).exit_code == 0

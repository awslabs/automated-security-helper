# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``_inject_invocation`` carries the tool's own invocation facts into ASH's.

The tool's SARIF can hold an invocation of its own: semgrep reports a rule
file it cannot read as a toolExecutionNotification there and sets
executionSuccessful false. Replacing ``runs[0].invocations`` outright discarded
both, so run_ash_scan's unevaluated-rules gate read a run the tool itself called
unsuccessful as a complete one with no notifications.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from tests.unit.base.test_scanner_plugin_coverage import _scanner

pytestmark = pytest.mark.unit

SARIF_WITH_A_TOOL_INVOCATION = {
    "version": "2.1.0",
    "runs": [
        {
            "tool": {"driver": {"name": "stub-tool", "version": "1.0.0"}},
            "invocations": [
                {
                    "executionSuccessful": False,
                    "toolExecutionNotifications": [
                        {
                            "level": "error",
                            "message": {"text": "rules file could not be read"},
                        }
                    ],
                }
            ],
            "results": [],
        }
    ],
}


@pytest.fixture
def plugin_context(tmp_path):
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    work_dir = output_dir / ASH_WORK_DIR_NAME
    work_dir.mkdir()
    return PluginContext(
        source_dir=source_dir,
        output_dir=output_dir,
        work_dir=work_dir,
        config=AshConfig(project_name="test"),
    )


def test_the_tools_notifications_and_its_failure_survive(plugin_context, tmp_path):
    scanner = _scanner(plugin_context)
    scanner.exit_code = 0
    report = SarifReport.model_validate(SARIF_WITH_A_TOOL_INVOCATION)

    scanner._inject_invocation(report, ["stub-tool", "scan"], Path(tmp_path))

    invocation = report.runs[0].invocations[0]
    notes = invocation.toolExecutionNotifications or []
    assert len(notes) == 1, invocation
    assert "rules file could not be read" in notes[0].message.root.text
    assert invocation.executionSuccessful is False
    # ASH's own facts are still written on the merged invocation.
    assert invocation.exitCode == 0


def _sarif_with_invocations(*invocations: dict) -> dict:
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "stub-tool", "version": "1.0.0"}},
                "invocations": list(invocations),
                "results": [],
            }
        ],
    }


def test_a_tool_that_says_it_succeeded_does_not_undo_a_failed_grade(
    plugin_context, tmp_path
):
    """The merge keeps ASH's graded rule: a tool writing its own
    ``executionSuccessful: true`` (semgrep does) must not lift a run ASH grades
    failed because a target failed."""
    scanner = _scanner(plugin_context)
    scanner.exit_code = 0
    scanner.targets_attempted = 1
    scanner.targets_failed = 1
    report = SarifReport.model_validate(
        _sarif_with_invocations({"executionSuccessful": True})
    )

    scanner._inject_invocation(report, ["stub-tool", "scan"], Path(tmp_path))

    assert report.runs[0].invocations[0].executionSuccessful is False


def test_the_tools_later_invocations_stay_after_ashs_own(plugin_context, tmp_path):
    scanner = _scanner(plugin_context)
    scanner.exit_code = 0
    report = SarifReport.model_validate(
        _sarif_with_invocations(
            {"executionSuccessful": True},
            {"executionSuccessful": True, "commandLine": "second-pass"},
        )
    )

    scanner._inject_invocation(report, ["stub-tool", "scan"], Path(tmp_path))

    invocations = report.runs[0].invocations
    assert len(invocations) == 2, invocations
    assert invocations[0].commandLine != "second-pass"
    assert invocations[1].commandLine == "second-pass"


def _note(text: str) -> dict:
    return {"level": "error", "message": {"text": text}}


def _all_note_texts(report: SarifReport) -> list[str]:
    return [
        note.message.root.text
        for invocation in report.runs[0].invocations
        for note in invocation.toolExecutionNotifications or []
    ]


def test_a_later_invocations_notification_is_recorded_once(plugin_context, tmp_path):
    """The tool's second invocation stays in the list as it is, notification
    included, so ASH's record must not carry a copy of it as well."""
    scanner = _scanner(plugin_context)
    scanner.exit_code = 0
    report = SarifReport.model_validate(
        _sarif_with_invocations(
            {"executionSuccessful": True, "toolExecutionNotifications": [_note("a1")]},
            {"executionSuccessful": True, "toolExecutionNotifications": [_note("b1")]},
        )
    )

    scanner._inject_invocation(report, ["stub-tool", "scan"], Path(tmp_path))

    assert sorted(_all_note_texts(report)) == ["a1", "b1"]
    ash_record = report.runs[0].invocations[0]
    assert [n.message.root.text for n in ash_record.toolExecutionNotifications] == [
        "a1"
    ]


def test_a_second_call_on_one_report_changes_nothing_it_carried(
    plugin_context, tmp_path
):
    scanner = _scanner(plugin_context)
    scanner.exit_code = 0
    report = SarifReport.model_validate(
        _sarif_with_invocations(
            {"executionSuccessful": True, "toolExecutionNotifications": [_note("a1")]},
            {"executionSuccessful": True, "toolExecutionNotifications": [_note("b1")]},
        )
    )

    scanner._inject_invocation(report, ["stub-tool", "scan"], Path(tmp_path))
    scanner._inject_invocation(report, ["stub-tool", "scan"], Path(tmp_path))

    assert sorted(_all_note_texts(report)) == ["a1", "b1"]
    assert len(report.runs[0].invocations) == 2


def test_ashs_earlier_verdict_is_not_read_back_as_the_tools(plugin_context, tmp_path):
    """The tool said it succeeded. ASH graded the first call failed because a
    target failed; once that is no longer so, the second call grades it
    succeeded, not failed on the strength of its own earlier record."""
    scanner = _scanner(plugin_context)
    scanner.exit_code = 0
    scanner.targets_attempted = 1
    scanner.targets_failed = 1
    report = SarifReport.model_validate(
        _sarif_with_invocations({"executionSuccessful": True})
    )

    scanner._inject_invocation(report, ["stub-tool", "scan"], Path(tmp_path))
    assert report.runs[0].invocations[0].executionSuccessful is False

    scanner.targets_failed = 0
    scanner._inject_invocation(report, ["stub-tool", "scan"], Path(tmp_path))

    assert report.runs[0].invocations[0].executionSuccessful is True


def test_the_tools_own_failure_verdict_survives_a_second_call(plugin_context, tmp_path):
    scanner = _scanner(plugin_context)
    scanner.exit_code = 0
    report = SarifReport.model_validate(
        _sarif_with_invocations({"executionSuccessful": False})
    )

    scanner._inject_invocation(report, ["stub-tool", "scan"], Path(tmp_path))
    scanner._inject_invocation(report, ["stub-tool", "scan"], Path(tmp_path))

    assert report.runs[0].invocations[0].executionSuccessful is False


def test_ashs_record_is_written_as_an_ordinary_invocation(plugin_context, tmp_path):
    """The record's class is for ASH's own bookkeeping; the SARIF it writes has
    no trace of it and reads back as a plain report."""
    scanner = _scanner(plugin_context)
    scanner.exit_code = 0
    report = SarifReport.model_validate(
        _sarif_with_invocations({"executionSuccessful": True})
    )

    scanner._inject_invocation(report, ["stub-tool", "scan"], Path(tmp_path))

    written = report.model_dump(mode="json", exclude_none=True)
    invocation = written["runs"][0]["invocations"][0]
    assert not any("unsuccessful" in key for key in invocation), invocation
    assert SarifReport.model_validate(written).runs[0].invocations[0].exitCode == 0

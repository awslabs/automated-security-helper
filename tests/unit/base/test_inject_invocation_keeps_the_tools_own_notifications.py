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

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``_inject_invocation`` sets SARIF ``executionSuccessful`` by the graded rule.

The invocation's flag was the exit code alone: a template scanner that counted
a failed target, or whose run was stopped or whose output ASH could not record,
reported ``executionSuccessful: true`` whenever its tool's code was an accepted
one, and the unevaluated-rules gate read that as a complete run. The flag now
reads ``_sarif_execution_successful`` as well, the rule the non-template
scanners already write.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from tests.unit.base.test_scanner_plugin_coverage import MINIMAL_SARIF, _scanner

pytestmark = pytest.mark.unit


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


def _flag(scanner, tmp_path) -> bool:
    report = SarifReport.model_validate(MINIMAL_SARIF)
    scanner._inject_invocation(report, ["stub-tool", "scan"], Path(tmp_path))
    return report.runs[0].invocations[0].executionSuccessful


def test_a_counted_failed_target_is_not_a_successful_execution(
    plugin_context, tmp_path
):
    scanner = _scanner(plugin_context)
    scanner.exit_code = 0
    scanner.targets_attempted = 1
    scanner.targets_failed = 1

    assert _flag(scanner, tmp_path) is False


def test_an_accepted_run_with_no_failed_target_stays_successful(
    plugin_context, tmp_path
):
    scanner = _scanner(plugin_context)
    scanner.exit_code = 0
    scanner.targets_attempted = 1
    scanner.targets_failed = 0

    assert _flag(scanner, tmp_path) is True

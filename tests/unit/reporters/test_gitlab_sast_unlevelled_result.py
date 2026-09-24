# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A GitLab SAST vulnerability must carry a severity even when SARIF omits level.

``level`` is optional in SARIF 2.1.0, and the reporter's severity cascade tests
``level_str`` against the four SARIF values. When ``result.level`` holds the
unvalidated ``Level`` enum member, ``str()`` renders "Level.error", no branch
matches, ``severity`` stays None, and the ``if severity:`` guard at the end of
the loop drops the key. The vulnerability still appears in the report, so the
loss is invisible in the file -- but the GitLab Security Dashboard has nothing
to triage or gate on.
"""

import json

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_builtin.reporters.gitlab_sast_reporter import (
    GitLabSASTReporter,
)
from automated_security_helper.schemas.sarif_schema_model import Level, Message, Result


@pytest.fixture
def reporter(tmp_path):
    return GitLabSASTReporter(
        context=PluginContext(
            source_dir=tmp_path / "source",
            output_dir=tmp_path / "output",
            work_dir=tmp_path / "work",
            config=AshConfig(),
        )
    )


def _model(result):
    model = AshAggregatedResults()
    model.sarif.runs[0].results = [result]
    return model


def test_absent_level_key_still_carries_a_severity(reporter):
    """``model_validate`` without the key is the path third-party SARIF takes."""
    result = Result.model_validate(
        {"ruleId": "B105", "message": {"text": "hardcoded password string"}}
    )

    report = json.loads(reporter.report(_model(result)))
    (vuln,) = report["vulnerabilities"]

    assert vuln.get("severity") == "High", (
        "an unlevelled error finding must not reach the dashboard with no severity"
    )


def test_level_held_as_an_enum_member_still_carries_a_severity(reporter):
    """Assignment is unvalidated too, so the reader cannot trust the field type."""
    result = Result(ruleId="B105", level="note", message=Message(text="x"))
    result.level = Level.error

    report = json.loads(reporter.report(_model(result)))
    (vuln,) = report["vulnerabilities"]

    assert vuln.get("severity") == "High"

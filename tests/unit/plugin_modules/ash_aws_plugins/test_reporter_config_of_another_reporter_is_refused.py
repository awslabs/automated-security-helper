# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A reporter is not built from a config that names another reporter.

Every reporter's ``config`` field runs through
``plugin_config.config_validated_by_declared_model``. Given a config of another
class it validates the fields that config set, and a subclass declares its
``name`` as a default, which the dump of the set fields leaves out. Without the
name in the check, the AWS reporters are off by default and another reporter's
``enabled: true`` turned a different one on, with none of its own options.

Each cell builds one reporter with the enabled config of another. boto3's Session
is a stand-in that fails a cell that reaches it, and no cell writes a file.
"""

from unittest.mock import MagicMock

import boto3
import pytest
from pydantic import ValidationError

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.plugin_modules.ash_aws_plugins.bedrock_summary_reporter import (
    BedrockSummaryReporter,
    BedrockSummaryReporterConfig,
)
from automated_security_helper.plugin_modules.ash_aws_plugins.cloudwatch_logs_reporter import (
    CloudWatchLogsReporter,
    CloudWatchLogsReporterConfig,
)
from automated_security_helper.plugin_modules.ash_aws_plugins.s3_reporter import (
    S3Reporter,
    S3ReporterConfig,
)
from automated_security_helper.plugin_modules.ash_aws_plugins.security_hub_reporter import (
    SecurityHubReporter,
    SecurityHubReporterConfig,
)

REPORTERS = [
    (SecurityHubReporter, SecurityHubReporterConfig),
    (S3Reporter, S3ReporterConfig),
    (CloudWatchLogsReporter, CloudWatchLogsReporterConfig),
    (BedrockSummaryReporter, BedrockSummaryReporterConfig),
]
#: Each reporter with the config of every other one.
PAIRS = [
    (reporter, other_config)
    for reporter, config in REPORTERS
    for _, other_config in REPORTERS
    if other_config is not config
]


@pytest.fixture(autouse=True)
def no_aws(monkeypatch):
    """No cell may build a real AWS session."""
    session = MagicMock(side_effect=AssertionError("AWS was contacted"))
    monkeypatch.setattr(boto3, "Session", session)
    return session


def _context(tmp_path) -> PluginContext:
    return PluginContext(
        source_dir=tmp_path,
        output_dir=tmp_path / "out",
        config=AshConfig(project_name="fixture-project"),
    )


@pytest.mark.parametrize(
    ("reporter_class", "given_class"),
    PAIRS,
    ids=[f"{r.__name__}<-{c.__name__}" for r, c in PAIRS],
)
def test_another_reporters_enabled_config_does_not_build_the_reporter(
    tmp_path, no_aws, reporter_class, given_class
):
    given = given_class(enabled=True)
    # The control: the object is another reporter's, enabled, and the dump of the
    # fields it set holds no name, so the dump alone would pass for this
    # reporter's.
    assert given.enabled is True
    assert "name" not in given.model_dump(exclude_unset=True)

    with pytest.raises(ValidationError) as raised:
        reporter_class(context=_context(tmp_path), config=given)

    no_aws.assert_not_called()
    assert "not this plugin's name" in str(raised.value)
    assert repr(given.name) in str(raised.value)


@pytest.mark.parametrize(
    ("reporter_class", "config_class"),
    REPORTERS,
    ids=[r.__name__ for r, _ in REPORTERS],
)
def test_a_reporters_own_enabled_config_still_builds_it(
    tmp_path, no_aws, reporter_class, config_class
):
    """The refusal is for a config that names another reporter, not for every
    enabled one."""
    reporter = reporter_class(
        context=_context(tmp_path), config=config_class(enabled=True)
    )

    assert reporter.config.enabled is True
    no_aws.assert_not_called()

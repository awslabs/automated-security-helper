# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The AWS reporters' retry caps hold where the report phase builds the reporters.

``ReportPhase`` builds each reporter from its section of the resolved config, a
plain dict. A reporter's ``config`` field accepts its own config model or the base
``ReporterPluginConfigBase``. When the reporter's own model refused the dict, for
example ``max_delay: 120`` over the 60-second cap, pydantic built the base model
instead, kept the value and raised nothing. So the caps on ``max_retries``,
``base_delay`` and ``max_delay`` held only where the options model was built
directly, which is what ``test_reporter_retry_caps.py`` does.

These tests build the reporters the way the phase does, from an ``AshConfig``, and
stop at the instances it built: ``filter_enabled_plugins`` is replaced by a
recorder that returns nothing, so no reporter checks credentials or calls AWS.
Each case pairs a value at a cap with one just over it, so a phase that refuses
every value fails as surely as one that accepts every value.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Tuple

import pytest

from automated_security_helper.base.plugin_config import plugin_config_key
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.phases.report_phase import ReportPhase
from automated_security_helper.core.progress import LiveProgressDisplay
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_aws_plugins.aws_utils import (
    MAX_RETRIES,
    MAX_RETRY_DELAY_SECONDS,
)
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

pytestmark = pytest.mark.unit

#: Each reporter that declares the retry options, with its own config model.
_REPORTERS = [
    (S3Reporter, S3ReporterConfig),
    (CloudWatchLogsReporter, CloudWatchLogsReporterConfig),
    (BedrockSummaryReporter, BedrockSummaryReporterConfig),
]

#: For each cap: options at it, options just over it, and the words the error for
#: the second has to contain.
_CAPS: List[Tuple[str, Dict[str, Any], Dict[str, Any], Tuple[str, ...]]] = [
    (
        "max_retries",
        {"max_retries": MAX_RETRIES},
        {"max_retries": MAX_RETRIES + 1},
        ("max_retries", str(MAX_RETRIES)),
    ),
    (
        "max_delay",
        {"max_delay": MAX_RETRY_DELAY_SECONDS},
        {"max_delay": MAX_RETRY_DELAY_SECONDS + 1},
        ("max_delay", str(MAX_RETRY_DELAY_SECONDS)),
    ),
    (
        "base_delay",
        {"base_delay": MAX_RETRY_DELAY_SECONDS},
        {"base_delay": MAX_RETRY_DELAY_SECONDS + 1},
        ("base_delay", str(MAX_RETRY_DELAY_SECONDS)),
    ),
    (
        "base_delay_over_max_delay",
        {"base_delay": 5.0, "max_delay": 5.0},
        {"base_delay": 6.0, "max_delay": 5.0},
        ("base_delay", "max_delay"),
    ),
]

_CASES = [
    (reporter, model, at_cap, over_cap, words, f"{reporter.__name__}-{cap}")
    for reporter, model in _REPORTERS
    for cap, at_cap, over_cap, words in _CAPS
]


def _built_by_the_report_phase(reporter_class, options, tmp_path) -> list:
    """The reporter instances ``ReportPhase`` built from this reporter's section."""
    key = plugin_config_key(reporter_class)
    config = AshConfig.model_validate(
        {"reporters": {key: {"enabled": True, "options": options}}}
    )
    output_dir = tmp_path / "out"
    context = PluginContext(
        source_dir=tmp_path / "src",
        output_dir=output_dir,
        work_dir=output_dir / "work",
        config=config,
    )
    phase = ReportPhase(
        plugins=[reporter_class],
        plugin_context=context,
        progress_display=LiveProgressDisplay(show_progress=False),
        asharp_model=AshAggregatedResults(),
    )
    built: list = []

    def _record(plugin_instances, **_kwargs):
        built.extend(plugin_instances)
        return []

    phase.filter_enabled_plugins = _record
    phase._execute_phase(
        report_dir=output_dir / "reports",
        aggregated_results=AshAggregatedResults(),
        cli_output_formats=[key],
        python_based_plugins_only=False,
    )
    return built


@pytest.mark.parametrize(
    "reporter_class,config_model,at_cap,over_cap,words",
    [case[:5] for case in _CASES],
    ids=[case[5] for case in _CASES],
)
def test_the_report_phase_builds_the_reporter_up_to_the_cap_and_not_past_it(
    reporter_class, config_model, at_cap, over_cap, words, tmp_path, caplog
):
    built = _built_by_the_report_phase(reporter_class, at_cap, tmp_path / "at")

    assert len(built) == 1, built
    assert type(built[0].config) is config_model, type(built[0].config)
    for name, value in at_cap.items():
        assert getattr(built[0].config.options, name) == value

    caplog.clear()
    caplog.set_level(logging.DEBUG)
    built = _built_by_the_report_phase(reporter_class, over_cap, tmp_path / "over")

    assert built == [], (
        f"{reporter_class.__name__} was built with {over_cap} as "
        f"{[type(instance.config).__name__ for instance in built]}; its own "
        f"{config_model.__name__} refuses that value"
    )
    errors = [
        record.getMessage()
        for record in caplog.records
        if record.levelno >= logging.ERROR
        and reporter_class.__name__ in record.getMessage()
    ]
    assert errors, f"nothing at ERROR named {reporter_class.__name__}"
    assert any(all(word in message for word in words) for message in errors), errors

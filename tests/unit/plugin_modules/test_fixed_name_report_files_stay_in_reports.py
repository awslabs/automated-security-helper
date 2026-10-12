# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Reporters that write their own files in the reports directory do not follow a symlink.

Besides the file ``ReportPhase`` writes, three reporters write files of their own
in ``<output>/reports``: the unused-suppressions reporter's markdown (on by
default), the S3 reporter's local copy and the Bedrock reporter's summaries. For a
CLI scan the default output directory is inside the scanned repository, so one
of those names can be a symlink the repository put there. Each test makes the
name a symlink to a file outside and checks that the write is refused, as every
output write below the output directory is (``fs_guard.OutputLinkRefused``), and
that the file is unchanged.
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.models.asharp_model import AshAggregatedResults

AWS = "automated_security_helper.plugin_modules.ash_aws_plugins"


@pytest.fixture
def caplog_ash():
    """Warnings ASH_LOGGER emits during the test, as messages."""
    import logging

    from automated_security_helper.base.options import (
        reset_refused_tool_version_warnings,
    )
    from automated_security_helper.utils.log import ASH_LOGGER

    messages = []

    class _Collect(logging.Handler):
        def emit(self, record):
            if record.levelno >= logging.WARNING:
                messages.append(record.getMessage())

    reset_refused_tool_version_warnings()
    handler = _Collect(level=logging.DEBUG)
    ASH_LOGGER.addHandler(handler)
    try:
        yield messages
    finally:
        ASH_LOGGER.removeHandler(handler)
        reset_refused_tool_version_warnings()


def _context(tmp_path: Path) -> PluginContext:
    return PluginContext(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "out" / "work",
        config=AshConfig(),
    )


def _plant(tmp_path: Path, name: str) -> Path:
    outside = tmp_path / "outside.txt"
    outside.write_text("unchanged", encoding="utf-8")
    reports = tmp_path / "out" / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    (reports / name).symlink_to(outside)
    return outside


@pytest.mark.skipif(
    sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
)
def test_the_unused_suppressions_markdown_does_not_follow_a_symlink(tmp_path):
    from automated_security_helper.plugin_modules.ash_builtin.reporters.unused_suppressions_reporter import (
        UnusedSuppressionsReporter,
    )

    from automated_security_helper.utils.sandbox.fs_guard import OutputLinkRefused

    outside = _plant(tmp_path, "ash.unused-suppressions.md")

    with pytest.raises(OutputLinkRefused):
        UnusedSuppressionsReporter(context=_context(tmp_path)).report(
            AshAggregatedResults()
        )

    assert outside.read_text(encoding="utf-8") == "unchanged"


def test_the_unused_suppressions_markdown_is_still_written(tmp_path):
    from automated_security_helper.plugin_modules.ash_builtin.reporters.unused_suppressions_reporter import (
        UnusedSuppressionsReporter,
    )

    UnusedSuppressionsReporter(context=_context(tmp_path)).report(
        AshAggregatedResults()
    )

    markdown = tmp_path / "out" / "reports" / "ash.unused-suppressions.md"
    assert markdown.is_file() and not markdown.is_symlink()
    assert markdown.read_text(encoding="utf-8")


def _s3_report(tmp_path: Path) -> None:
    from automated_security_helper.plugin_modules.ash_aws_plugins.s3_reporter import (
        S3Reporter,
        S3ReporterConfig,
        S3ReporterConfigOptions,
    )

    with patch(f"{AWS}.s3_reporter.boto3") as boto3:
        boto3.Session.return_value.client.return_value = MagicMock()
        reporter = S3Reporter(
            context=_context(tmp_path),
            config=S3ReporterConfig(
                options=S3ReporterConfigOptions(
                    aws_region="us-west-2",
                    aws_profile="test-profile",
                    bucket_name="test-bucket",
                    file_format="json",
                )
            ),
        )
        model = MagicMock()
        model.metadata.generated_at = "20250606-120000"
        model.to_simple_dict.return_value = {"test": "data"}
        reporter.report(model)


@pytest.mark.skipif(
    sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
)
def test_the_s3_local_copy_does_not_follow_a_symlink(tmp_path):
    outside = _plant(tmp_path, "s3-report.json")

    _s3_report(tmp_path)

    assert outside.read_text(encoding="utf-8") == "unchanged"


def test_the_s3_local_copy_is_still_written(tmp_path):
    _s3_report(tmp_path)

    local = tmp_path / "out" / "reports" / "s3-report.json"
    assert local.is_file() and '"test"' in local.read_text(encoding="utf-8")


class _RuntimeDouble:
    def converse(self, **kwargs):
        return {
            "output": {"message": {"role": "assistant", "content": [{"text": "x"}]}}
        }


def _bedrock_write(tmp_path: Path) -> None:
    from automated_security_helper.plugin_modules.ash_aws_plugins.bedrock_summary_reporter import (
        BedrockSummaryReporter,
        BedrockSummaryReporterConfig,
        BedrockSummaryReporterConfigOptions,
    )

    with patch(f"{AWS}.bedrock_summary_reporter.boto3"):
        reporter = BedrockSummaryReporter(
            context=_context(tmp_path),
            config=BedrockSummaryReporterConfig(
                options=BedrockSummaryReporterConfigOptions(
                    aws_region="us-west-2",
                    model_id="test-vendor.test-model-v1:0",
                    enable_caching=False,
                )
            ),
        )
        reporter._write_markdown_files(
            _RuntimeDouble(), AshAggregatedResults(), [], [], "summary"
        )


@pytest.mark.skipif(
    sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
)
def test_the_bedrock_files_do_not_follow_a_symlink(tmp_path):
    from automated_security_helper.utils.sandbox.fs_guard import OutputLinkRefused

    outsides = []
    for index, name in enumerate(
        ["ash.bedrock.summary.md", "bedrock-executive.md", "bedrock-technical.md"]
    ):
        outside = tmp_path / f"outside-{index}.txt"
        outside.write_text("unchanged", encoding="utf-8")
        reports = tmp_path / "out" / "reports"
        reports.mkdir(parents=True, exist_ok=True)
        (reports / name).symlink_to(outside)
        outsides.append(outside)

    with pytest.raises(OutputLinkRefused):
        _bedrock_write(tmp_path)

    assert [o.read_text(encoding="utf-8") for o in outsides] == ["unchanged"] * 3


def test_the_bedrock_files_are_still_written(tmp_path):
    _bedrock_write(tmp_path)

    reports = tmp_path / "out" / "reports"
    assert (reports / "ash.bedrock.summary.md").read_text(encoding="utf-8") == (
        "summary"
    )
    assert (reports / "bedrock-executive.md").is_file()
    assert (reports / "bedrock-technical.md").is_file()


def test_a_bedrock_file_name_with_a_path_writes_nothing_outside(tmp_path):
    """The writer refuses a path too, for a value that skipped the options' validation."""
    from automated_security_helper.plugin_modules.ash_aws_plugins.bedrock_summary_reporter import (
        BedrockSummaryReporter,
        BedrockSummaryReporterConfig,
        BedrockSummaryReporterConfigOptions,
    )

    options = BedrockSummaryReporterConfigOptions(
        aws_region="us-west-2",
        model_id="test-vendor.test-model-v1:0",
        enable_caching=False,
    )
    # Assigned after construction, which is not validated, so the writer's own check
    # is what this exercises (the options replace such a value; see below).
    options.output_file = "../escaped-summary.md"
    with patch(f"{AWS}.bedrock_summary_reporter.boto3"):
        reporter = BedrockSummaryReporter(
            context=_context(tmp_path),
            config=BedrockSummaryReporterConfig(options=options),
        )
        reporter._write_markdown_files(
            _RuntimeDouble(), AshAggregatedResults(), [], [], "summary"
        )

    assert not (tmp_path / "out" / "escaped-summary.md").exists()


BEDROCK_FILE_OPTIONS = ("output_file", "output_executive_file", "output_technical_file")


@pytest.mark.parametrize("option", BEDROCK_FILE_OPTIONS)
@pytest.mark.parametrize(
    "value", ["../escaped.md", "sub/summary.md", "/abs/summary.md", "..", "a\\b.md"]
)
def test_a_bedrock_file_name_that_is_not_a_file_name_is_replaced_by_the_default(
    option, value, caplog_ash
):
    from automated_security_helper.plugin_modules.ash_aws_plugins.bedrock_summary_reporter import (
        BedrockSummaryReporterConfigOptions,
    )

    default = BedrockSummaryReporterConfigOptions.model_fields[option].default

    options = BedrockSummaryReporterConfigOptions(**{option: value})

    assert getattr(options, option) == default
    assert any(
        f"reporters.bedrock-summary-reporter.options.{option}" in message
        and repr(value) in message
        for message in caplog_ash
    ), caplog_ash


@pytest.mark.parametrize("option", BEDROCK_FILE_OPTIONS)
def test_a_bedrock_file_name_is_kept(option, caplog_ash):
    from automated_security_helper.plugin_modules.ash_aws_plugins.bedrock_summary_reporter import (
        BedrockSummaryReporterConfigOptions,
    )

    options = BedrockSummaryReporterConfigOptions(**{option: "team-summary.md"})

    assert getattr(options, option) == "team-summary.md"
    assert not any(option in message for message in caplog_ash), caplog_ash


def test_a_bedrock_file_name_from_config_overrides_is_validated(tmp_path, caplog_ash):
    """``--config-overrides`` reaches the same validation, when the reporter is built."""
    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.plugin_modules.ash_aws_plugins.bedrock_summary_reporter import (
        BedrockSummaryReporter,
    )

    source = tmp_path / "repo"
    source.mkdir()
    config = resolve_config(
        source_dir=source,
        config_overrides=[
            "reporters.bedrock-summary-reporter.options.output_file=../escaped.md"
        ],
    )

    with patch(f"{AWS}.bedrock_summary_reporter.boto3"):
        reporter = BedrockSummaryReporter(
            context=_context(tmp_path),
            config=config.get_plugin_config("reporter", "bedrock-summary-reporter"),
        )

    assert reporter.companion_file_names()[0] == "ash.bedrock.summary.md"
    assert any("../escaped.md" in message for message in caplog_ash), caplog_ash


def test_a_directory_at_the_name_does_not_lose_the_report(tmp_path):
    from automated_security_helper.plugin_modules.ash_builtin.reporters.unused_suppressions_reporter import (
        UnusedSuppressionsReporter,
    )

    (tmp_path / "out" / "reports" / "ash.unused-suppressions.md").mkdir(parents=True)

    result = UnusedSuppressionsReporter(context=_context(tmp_path)).report(
        AshAggregatedResults()
    )

    assert result and result.lstrip().startswith("{")


def test_write_report_file_returns_none_when_the_write_fails(tmp_path):
    from automated_security_helper.base.reporter_plugin import write_report_file

    (tmp_path / "reports" / "taken").mkdir(parents=True)

    assert write_report_file(tmp_path / "reports", "taken", "x") is None
    assert write_report_file(tmp_path / "reports", "free", "x") == (
        tmp_path / "reports" / "free"
    )


# The files each of these reporters writes are the ones it declares in
# companion_file_names, which is what the report phase checks for links before any
# reporter runs. Asserted against what the reporter really wrote.


def _written(tmp_path: Path) -> set:
    reports = tmp_path / "out" / "reports"
    return {path.name for path in reports.iterdir()} if reports.is_dir() else set()


def test_the_unused_suppressions_reporter_declares_what_it_writes(tmp_path):
    from automated_security_helper.plugin_modules.ash_builtin.reporters.unused_suppressions_reporter import (
        UnusedSuppressionsReporter,
    )

    reporter = UnusedSuppressionsReporter(context=_context(tmp_path))
    reporter.report(AshAggregatedResults())

    assert _written(tmp_path) == set(reporter.companion_file_names()) != set()


def test_the_unused_suppressions_reporter_declares_nothing_when_it_writes_nothing(
    tmp_path,
):
    from automated_security_helper.plugin_modules.ash_builtin.reporters.unused_suppressions_reporter import (
        UnusedSuppressionsReporter,
        UnusedSuppressionsReporterConfig,
        UnusedSuppressionsReporterConfigOptions,
    )

    reporter = UnusedSuppressionsReporter(
        context=_context(tmp_path),
        config=UnusedSuppressionsReporterConfig(
            options=UnusedSuppressionsReporterConfigOptions(output_format="json")
        ),
    )
    reporter.report(AshAggregatedResults())

    assert _written(tmp_path) == set(reporter.companion_file_names()) == set()


def test_the_s3_reporter_declares_its_local_copy(tmp_path):
    from automated_security_helper.plugin_modules.ash_aws_plugins.s3_reporter import (
        S3Reporter,
        S3ReporterConfig,
        S3ReporterConfigOptions,
    )

    _s3_report(tmp_path)
    reporter = S3Reporter(
        context=_context(tmp_path),
        config=S3ReporterConfig(
            options=S3ReporterConfigOptions(
                aws_region="us-west-2",
                aws_profile="test-profile",
                bucket_name="test-bucket",
                file_format="json",
            )
        ),
    )

    assert _written(tmp_path) == set(reporter.companion_file_names()) != set()


@pytest.mark.parametrize(
    "exclude_sections",
    [[], ["executive_summary"], ["technical_analysis"]],
    ids=["all-sections", "no-executive", "no-technical"],
)
def test_the_bedrock_reporter_declares_its_files(tmp_path, exclude_sections):
    from automated_security_helper.plugin_modules.ash_aws_plugins.bedrock_summary_reporter import (
        BedrockSummaryReporter,
        BedrockSummaryReporterConfig,
        BedrockSummaryReporterConfigOptions,
    )

    with patch(f"{AWS}.bedrock_summary_reporter.boto3"):
        reporter = BedrockSummaryReporter(
            context=_context(tmp_path),
            config=BedrockSummaryReporterConfig(
                options=BedrockSummaryReporterConfigOptions(
                    aws_region="us-west-2",
                    model_id="test-vendor.test-model-v1:0",
                    enable_caching=False,
                    exclude_sections=exclude_sections,
                )
            ),
        )
        reporter._write_markdown_files(
            _RuntimeDouble(), AshAggregatedResults(), [], [], "summary"
        )

    assert _written(tmp_path) == set(reporter.companion_file_names()) != set()

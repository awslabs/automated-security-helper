# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Reporters that write their own files in the reports directory do not follow a symlink.

Besides the file ``ReportPhase`` writes, three reporters write files of their own
in ``<output>/reports``: the unused-suppressions reporter's markdown (on by
default), the S3 reporter's local copy and the Bedrock reporter's summaries. For a
CLI scan the default output directory is inside the scanned repository, so one
of those names can be a symlink the repository put there. Each test makes the
name a symlink to a file outside and checks that the file is unchanged.
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.models.asharp_model import AshAggregatedResults

AWS = "automated_security_helper.plugin_modules.ash_aws_plugins"


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

    outside = _plant(tmp_path, "ash.unused-suppressions.md")

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
    """The output file options are file names; the operator sets them, but a path is refused."""
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
                    output_file="../escaped-summary.md",
                )
            ),
        )
        reporter._write_markdown_files(
            _RuntimeDouble(), AshAggregatedResults(), [], [], "summary"
        )

    assert not (tmp_path / "out" / "escaped-summary.md").exists()


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

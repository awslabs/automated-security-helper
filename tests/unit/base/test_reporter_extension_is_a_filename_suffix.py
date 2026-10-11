# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A reporter's ``extension`` names a file in the reports directory and nothing else.

``ReportPhase`` and the workspace report writer name each reporter's output
``ash.<extension>`` inside the reports directory. ``extension`` is a section-level
setting every reporter has, so any config could set it. It is now a plain filename
suffix from every source: a value with a path separator, ``..`` or NUL is replaced
by the reporter's default with one warning naming the key. The writers also check
that the file they write is directly inside the reports directory.
"""

import logging
from typing import List, Literal, Optional

import sys

import pytest
import yaml
from pydantic import ConfigDict

from automated_security_helper.base.options import reset_refused_tool_version_warnings
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
)
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.core.phases.report_phase import ReportPhase
from automated_security_helper.core.progress import LiveProgressDisplay
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_builtin.reporters.csv_reporter import (
    CSVReporterConfig,
)
from automated_security_helper.utils.log import ASH_LOGGER

REFUSED = [
    "x/../../escaped-probe.csv",
    "../escaped.csv",
    "..",
    "sub/report.csv",
    "/abs/report.csv",
    "x\\..\\..\\escaped.csv",
    "a\x00b",
]


@pytest.fixture
def ash_log():
    records: List[logging.LogRecord] = []

    class _Collect(logging.Handler):
        def emit(self, record):
            records.append(record)

    handler = _Collect(level=logging.DEBUG)
    previous_level = ASH_LOGGER.level
    ASH_LOGGER.addHandler(handler)
    ASH_LOGGER.setLevel(logging.DEBUG)
    reset_refused_tool_version_warnings()
    try:
        yield records
    finally:
        ASH_LOGGER.removeHandler(handler)
        ASH_LOGGER.setLevel(previous_level)
        reset_refused_tool_version_warnings()


def _warnings(records: List[logging.LogRecord]) -> List[str]:
    return [r.getMessage() for r in records if r.levelno >= logging.WARNING]


@pytest.mark.parametrize("value", REFUSED)
def test_a_value_that_is_not_a_filename_suffix_falls_back_to_the_default(
    value, ash_log
):
    config = CSVReporterConfig.model_validate({"extension": value})

    assert config.extension == "csv"
    warnings = _warnings(ash_log)
    assert len([w for w in warnings if "reporters.csv.extension" in w]) == 1, warnings


@pytest.mark.parametrize("value", ["custom.csv", "gl-sast-report.json", "csv"])
def test_a_filename_suffix_is_kept(value, ash_log):
    assert CSVReporterConfig.model_validate({"extension": value}).extension == value
    assert not _warnings(ash_log)


def test_the_same_refusal_is_logged_once(ash_log):
    for _ in range(3):
        CSVReporterConfig.model_validate({"extension": "../x"})

    assert len(_warnings(ash_log)) == 1


def test_an_in_tree_config_cannot_move_a_report(tmp_path, ash_log):
    source = tmp_path / "repo"
    (source / ".ash").mkdir(parents=True)
    (source / ".ash" / ".ash.yaml").write_text(
        yaml.safe_dump(
            {
                "project_name": "scanned",
                "reporters": {"csv": {"extension": "x/../../escaped-probe.csv"}},
            }
        )
    )

    config = resolve_config(source_dir=source)

    assert config.reporters.csv.extension == "csv"


def test_an_override_cannot_move_a_report_either(tmp_path, ash_log):
    source = tmp_path / "repo"
    source.mkdir()

    config = resolve_config(
        source_dir=source,
        config_overrides=["reporters.csv.extension=x/../../escaped-probe.csv"],
    )

    assert config.reporters.csv.extension == "csv"


def test_a_reporter_section_validated_later_is_covered(ash_log):
    """Reporters outside ReporterConfigSegment's declared fields are validated when built."""
    from automated_security_helper.plugin_modules.ash_aws_plugins.s3_reporter import (
        S3ReporterConfig,
    )

    config = S3ReporterConfig.model_validate({"extension": "../../s3.json"})

    assert config.extension == "s3.json"


class _UncheckedConfig(ReporterPluginConfigBase):
    """A default is not validated, so this reaches the writer unchanged."""

    model_config = ConfigDict(validate_default=False)

    name: Literal["unchecked-reporter"] = "unchecked-reporter"
    extension: str = "x/../../escaped-probe.json"
    enabled: bool = True


class _UncheckedReporter(ReporterPluginBase[_UncheckedConfig]):
    def model_post_init(self, context):
        if self.config is None:
            self.config = _UncheckedConfig()
        return super().model_post_init(context)

    def report(self, model: AshAggregatedResults) -> Optional[str]:
        return '{"findings": []}'


def _unchecked_phase(tmp_path, reporter):
    output_dir = tmp_path / "out"
    reports_dir = output_dir / "reports"
    (reports_dir / "ash.x").mkdir(parents=True)
    context = PluginContext(
        source_dir=tmp_path / "src",
        output_dir=output_dir,
        work_dir=output_dir / "work",
        config=AshConfig(),
    )
    phase = ReportPhase(
        plugins=[reporter],
        plugin_context=context,
        progress_display=LiveProgressDisplay(show_progress=False),
        asharp_model=AshAggregatedResults(),
    )
    return phase, reports_dir


def test_the_report_phase_writes_only_inside_the_reports_directory(tmp_path, ash_log):
    """A report name outside ``reports/`` refuses the run before any reporter writes."""
    from automated_security_helper.utils.report_path_links import ReportPathRefused

    phase, reports_dir = _unchecked_phase(tmp_path, _UncheckedReporter)

    with pytest.raises(ReportPathRefused) as excinfo:
        phase._execute_phase(
            report_dir=reports_dir,
            aggregated_results=AshAggregatedResults(),
            cli_output_formats=["unchecked-reporter"],
            python_based_plugins_only=False,
        )

    assert "is not a file in" in str(excinfo.value)
    assert not list(tmp_path.rglob("escaped-probe.json"))
    assert [entry.name for entry in reports_dir.iterdir()] == ["ash.x"]


class _DotDotConfig(ReporterPluginConfigBase):
    model_config = ConfigDict(validate_default=False)

    name: Literal["dotdot-reporter"] = "dotdot-reporter"
    extension: str = "../x"
    enabled: bool = True


class _DotDotReporter(ReporterPluginBase[_DotDotConfig]):
    def model_post_init(self, context):
        if self.config is None:
            self.config = _DotDotConfig()
        return super().model_post_init(context)

    def report(self, model: AshAggregatedResults) -> Optional[str]:
        return "escaped"


def test_an_extension_of_dot_dot_x_writes_nothing_and_fails_the_scan(tmp_path):
    """``extension: ../x`` that skipped validation: nothing outside ``reports/``, exit 1."""
    from automated_security_helper.interactions.run_ash_scan import (
        ReportPathRefusedExit,
        _refuse_report_path_link,
    )
    from automated_security_helper.utils.report_path_links import ReportPathRefused

    phase, reports_dir = _unchecked_phase(tmp_path, _DotDotReporter)
    before = sorted(path for path in tmp_path.rglob("*"))

    with pytest.raises(ReportPathRefused) as excinfo:
        phase._execute_phase(
            report_dir=reports_dir,
            aggregated_results=AshAggregatedResults(),
            cli_output_formats=["dotdot-reporter"],
            python_based_plugins_only=False,
        )
    with pytest.raises(ReportPathRefusedExit) as exited:
        _refuse_report_path_link(excinfo.value)

    assert exited.value.code == 1
    assert sorted(path for path in tmp_path.rglob("*")) == before
    assert not (reports_dir.parent / "x").exists()


def test_an_extension_of_dot_dot_x_in_a_config_file_writes_only_inside(
    tmp_path, ash_log
):
    """From a config file the value is replaced by the default, which stays inside."""
    source = tmp_path / "repo"
    (source / ".ash").mkdir(parents=True)
    (source / ".ash" / ".ash.yaml").write_text(
        yaml.safe_dump({"reporters": {"csv": {"extension": "../x"}}})
    )
    config = resolve_config(source_dir=source)
    from automated_security_helper.base.reporter_plugin import confined_report_path

    assert config.reporters.csv.extension == "csv"
    reports_dir = tmp_path / "out" / "reports"
    reports_dir.mkdir(parents=True)
    assert (
        confined_report_path(reports_dir, f"ash.{config.reporters.csv.extension}")
        == reports_dir / "ash.csv"
    )


def test_the_confined_path_helper_refuses_a_path_outside(tmp_path):
    from automated_security_helper.base.reporter_plugin import confined_report_path

    reports_dir = tmp_path / "reports"
    (reports_dir / "ash.x").mkdir(parents=True)

    assert confined_report_path(reports_dir, "ash.csv") == reports_dir / "ash.csv"
    assert confined_report_path(reports_dir, "ash.x/../../escaped.json") is None
    assert confined_report_path(reports_dir, "sub/ash.csv") is None


@pytest.mark.skipif(
    sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
)
def test_the_confined_path_helper_refuses_a_symlink_that_leads_outside(tmp_path):
    from automated_security_helper.base.reporter_plugin import confined_report_path

    reports_dir = tmp_path / "reports"
    reports_dir.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_text("{}")
    (reports_dir / "ash.link.json").symlink_to(outside)

    assert confined_report_path(reports_dir, "ash.link.json") is None

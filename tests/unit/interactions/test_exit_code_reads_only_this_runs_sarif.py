# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The exit code counts the SARIF report only when this run's SARIF reporter wrote it.

``_compute_exit_code`` counts actionable findings from the SARIF report, which
records every suppression, in preference to the model. ``--use-existing`` keeps
``reports/``, so with no SARIF reporter selected the ``ash.sarif`` there is an
earlier run's, and it used to decide the exit code. And a config can give another
reporter the SARIF report's name. So the report phase records each report file it
wrote with the format of the reporter that wrote it (a ``reports_written``
validation checkpoint), and only the file the ``sarif`` reporter wrote is counted,
under whatever name its extension gives it. Results with no such record count no
report file: the model's findings decide.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Dict, List, Literal, Optional

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
)
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.phases.report_phase import ReportPhase
from automated_security_helper.core.progress import LiveProgressDisplay
from automated_security_helper.interactions.run_ash_scan import (
    ScanOptions,
    _compute_exit_code,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults

pytestmark = pytest.mark.unit

#: A SARIF report with no findings: an earlier run's, of a clean tree.
CLEAN_SARIF = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "ASH"}}}]}


class _OtherConfig(ReporterPluginConfigBase):
    name: Literal["other-format"] = "other-format"
    extension: str = "other.json"
    enabled: bool = True


class _OtherReporter(ReporterPluginBase[_OtherConfig]):
    """A reporter that is not the SARIF reporter."""

    def model_post_init(self, context):
        if self.config is None:
            self.config = _OtherConfig()
        return super().model_post_init(context)

    def report(self, model) -> Optional[str]:
        return "{}"


def _report(output_dir: Path, results: AshAggregatedResults, *reporters):
    return ReportPhase(
        plugins=list(reporters),
        plugin_context=PluginContext(
            source_dir=output_dir.parent / "src",
            output_dir=output_dir,
            config=AshConfig(),
        ),
        progress_display=LiveProgressDisplay(show_progress=False),
        asharp_model=results,
    ).execute(
        report_dir=output_dir / "reports",
        aggregated_results=results,
        cli_output_formats=None,
        python_based_plugins_only=False,
    )


def _opts(tmp_path: Path) -> ScanOptions:
    return ScanOptions(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        fail_on_findings=True,
        fail_on_incomplete_scanners=False,
    )


def _earlier_runs_sarif(output_dir: Path) -> Path:
    reports = output_dir / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    sarif = reports / "ash.sarif"
    sarif.write_text(json.dumps(CLEAN_SARIF), encoding="utf-8")
    return sarif


def _with_findings(tmp_path: Path) -> AshAggregatedResults:
    """The fixture scan, whose actionable findings make the exit code 2."""
    from tests.snapshot.support.fixture_model import build_fixture_model

    return build_fixture_model(tmp_path / "fixture")


def _checkpoints(results: AshAggregatedResults) -> List[dict]:
    return [
        checkpoint
        for checkpoint in results.validation_checkpoints
        if checkpoint.get("type") == "reports_written"
    ]


def _records(results: AshAggregatedResults) -> List[dict]:
    """The files and formats each record lists, without the token naming its process."""
    return [
        {key: checkpoint["metadata"][key] for key in ("files", "formats")}
        for checkpoint in _checkpoints(results)
    ]


def _written(results: AshAggregatedResults, formats: Dict[str, str]) -> None:
    """Record that this run's reporters wrote ``formats`` (file name to format)."""
    results.validation_checkpoints.append(
        {
            "type": "reports_written",
            "metadata": {"files": sorted(formats), "formats": formats},
        }
    )


def test_the_report_phase_records_the_files_it_wrote(tmp_path):
    output_dir = tmp_path / "out"
    results = _report(output_dir, AshAggregatedResults(), _OtherReporter)
    results = _report(output_dir, results, _OtherReporter)

    assert _records(results) == [
        {"files": ["ash.other.json"], "formats": {"ash.other.json": "other-format"}}
    ]
    # The record also names the process that wrote it, which is how a later phase
    # of this run tells it from one an earlier run left in loaded results.
    (checkpoint,) = _checkpoints(results)
    assert re.fullmatch(r"[0-9a-f]{32}", checkpoint["metadata"]["run_token"])


class _FailingConfig(ReporterPluginConfigBase):
    name: Literal["failing-format"] = "failing-format"
    extension: str = "failing.json"
    enabled: bool = True


class _Failing(ReporterPluginBase[_FailingConfig]):
    def model_post_init(self, context):
        if self.config is None:
            self.config = _FailingConfig()
        return super().model_post_init(context)

    def report(self, model) -> Optional[str]:
        raise RuntimeError("reporter failed")


def test_a_reporter_that_fails_is_not_listed_as_written(tmp_path):
    """Its file was not written, so an earlier run's file there is not this run's."""
    results = _report(
        tmp_path / "out", AshAggregatedResults(), _OtherReporter, _Failing
    )

    assert _records(results) == [
        {"files": ["ash.other.json"], "formats": {"ash.other.json": "other-format"}}
    ]


def test_an_earlier_runs_clean_sarif_report_does_not_clear_this_run(tmp_path):
    """--use-existing with no SARIF reporter: the model's findings decide, as 2."""
    opts = _opts(tmp_path)
    assert _compute_exit_code(_with_findings(tmp_path), opts) == 2
    sarif = _earlier_runs_sarif(opts.output_dir)

    results = _report(opts.output_dir, _with_findings(tmp_path), _OtherReporter)

    assert _compute_exit_code(results, opts) == 2
    assert json.loads(sarif.read_text(encoding="utf-8")) == CLEAN_SARIF


def test_a_sarif_report_this_run_wrote_is_counted(tmp_path):
    """Written by the SARIF reporter, the file is counted: here it has no findings."""
    opts = _opts(tmp_path)
    _earlier_runs_sarif(opts.output_dir)
    results = _with_findings(tmp_path)
    _written(results, {"ash.sarif": "sarif"})

    assert _compute_exit_code(results, opts) == 0


def test_results_that_record_no_report_files_count_none(tmp_path):
    """No record, as for results no report phase wrote: the model's findings decide."""
    opts = _opts(tmp_path)
    _earlier_runs_sarif(opts.output_dir)

    assert _compute_exit_code(_with_findings(tmp_path), opts) == 2


def test_ash_sarif_written_by_another_reporter_is_not_counted(tmp_path):
    """Only the SARIF reporter's own file counts, under the name it was written to."""
    opts = _opts(tmp_path)
    reports = _earlier_runs_sarif(opts.output_dir).parent
    results = _with_findings(tmp_path)
    # The other reporter's file holds findings; the SARIF reporter's does not.
    (reports / "ash.sarif").write_text(
        results.sarif.model_dump_json(by_alias=True), encoding="utf-8"
    )
    (reports / "ash.sarif.orig").write_text(json.dumps(CLEAN_SARIF), encoding="utf-8")
    _written(results, {"ash.sarif": "cyclonedx", "ash.sarif.orig": "sarif"})

    assert _compute_exit_code(results, opts) == 0


def test_a_config_that_renames_the_sarif_report_cannot_clear_the_run(tmp_path):
    """The SARIF report moved aside, and another report written at ash.sarif.

    Through the real report phase and reporters, as a repository config would set
    them. The exit code counts the SARIF reporter's ``ash.sarif.orig``, not the
    CycloneDX document at ``ash.sarif``.
    """
    from tests.unit.core.phases.test_report_file_names_do_not_collide import _builtin

    opts = _opts(tmp_path)
    config = AshConfig.model_validate(
        {
            "reporters": {
                "sarif": {"extension": "sarif.orig"},
                "cyclonedx": {"extension": "sarif"},
            }
        }
    )
    phase = ReportPhase(
        plugins=[_builtin("sarif"), _builtin("cyclonedx")],
        plugin_context=PluginContext(
            source_dir=tmp_path / "src", output_dir=opts.output_dir, config=config
        ),
        progress_display=LiveProgressDisplay(show_progress=False),
        asharp_model=_with_findings(tmp_path),
    )
    results = phase.execute(
        report_dir=opts.output_dir / "reports",
        aggregated_results=_with_findings(tmp_path),
        cli_output_formats=["sarif", "cyclonedx"],
        python_based_plugins_only=False,
    )

    assert _records(results)[0]["formats"] == {
        "ash.sarif": "cyclonedx",
        "ash.sarif.orig": "sarif",
    }
    assert _compute_exit_code(results, opts) == 2

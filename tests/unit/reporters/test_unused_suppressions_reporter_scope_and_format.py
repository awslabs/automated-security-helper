# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The unused-suppressions reporter's scope in workspace mode, and its file name
under ``output_format: markdown``.

Why this file exists
--------------------
Workspace scope. The reporter is WORKSPACE_SCOPED: the workspace-level file
reports on workspace-level suppressions, of which this phase has none, and the
per-project files answer the per-project question. The code took the configured
list from the invoking context's config all the same, so ``ash report`` over a
workspace's unified results, with a config that holds suppressions, subtracted
the unified file's empty ``used_suppressions`` from them and listed every one as
unused under the workspace label. The markdown copy then read "All suppressions
are being used" (or a percentage unused) with no scope stated.

Markdown format. ``output_format: markdown`` made ``report`` return markdown,
which the report phase wrote to ``ash.unused-suppressions.json``, the file
``ash config lint --fix-unused`` reads as JSON. The report is now written under
the markdown extension instead. The first cure switched the name only when the
``extension`` field was unset, and the real run never met that: the report
phase builds the reporter from ``get_plugin_config``, a full dump of the
section, so the field arrived at its default and counted as set. The switch now
asks whether the extension is the default's value.
"""

import json

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.reporter_plugin import reporter_file_name
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.core import AshSuppression
from automated_security_helper.models.workspace import (
    ProjectRunStatus,
    WorkspaceProjectResult,
    WorkspaceResults,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.unused_suppressions_reporter import (
    UnusedSuppressionsReporter,
    UnusedSuppressionsReporterConfig,
)

pytestmark = pytest.mark.unit


def _context(tmp_path, **config_kwargs) -> PluginContext:
    config = AshConfig(**config_kwargs)
    config.global_settings.suppressions = [
        AshSuppression(path="src/app.py", rule_id="B201", reason="one"),
        AshSuppression(path="src/utils.py", rule_id="B603", reason="two"),
    ]
    return PluginContext(
        source_dir=tmp_path / "source",
        output_dir=tmp_path / "output",
        work_dir=tmp_path / "work",
        config=config,
    )


def _workspace_model(tmp_path) -> AshAggregatedResults:
    model = AshAggregatedResults()
    model.used_suppressions = set()
    model.workspace = WorkspaceResults(
        workspace_file=(tmp_path / "fixture.code-workspace").as_posix(),
        workspace_root=tmp_path.as_posix(),
        exit_code=0,
        projects=[
            WorkspaceProjectResult(
                project="api",
                relative_path="api",
                display_label="api",
                status=ProjectRunStatus.COMPLETED,
                severity_threshold="MEDIUM",
                finding_count=0,
                actionable_finding_count=0,
                exceeds_threshold=False,
                output_path="projects/api",
                scanners={"bandit": "PASSED"},
            )
        ],
        wall_clock_seconds=1.0,
    )
    return model


def test_the_workspace_report_does_not_list_the_invoking_configs_suppressions(
    tmp_path,
):
    """Red at the base: both configured entries were listed as unused."""
    context = _context(tmp_path)
    reporter = UnusedSuppressionsReporter(context=context)

    report = json.loads(reporter.report(_workspace_model(tmp_path)))

    assert report["scope"] == "workspace"
    assert report["summary"]["total_suppressions"] == 0
    assert report["unused_suppressions"] == []


def test_the_workspace_markdown_states_its_scope(tmp_path):
    """Red at the base: the markdown read as a judgment over every suppression."""
    context = _context(tmp_path)
    UnusedSuppressionsReporter(context=context).report(_workspace_model(tmp_path))

    markdown = (
        context.output_dir / "reports" / "ash.unused-suppressions.md"
    ).read_text(encoding="utf-8")
    assert "**Scope**: Counts cover workspace-level suppressions only." in markdown
    assert "All suppressions are being used" not in markdown
    assert "% of suppressions are unused" not in markdown


def test_the_workspace_report_carries_no_scanner_caveat(tmp_path):
    """The workspace report covers no suppression, so a project's scanner that
    did not run (recorded in the unified results) is not a caveat here; each
    project's own report carries it for that project's scan."""
    from automated_security_helper.core.enums import ScannerStatus
    from automated_security_helper.models.asharp_model import ScannerTargetStatusInfo

    context = _context(tmp_path)
    model = _workspace_model(tmp_path)
    model.scanner_results = {
        "npm-audit": ScannerTargetStatusInfo(
            status=ScannerStatus.MISSING, dependencies_satisfied=False
        )
    }

    report = json.loads(UnusedSuppressionsReporter(context=context).report(model))

    assert report["scope"] == "workspace"
    assert "scanners_not_run" not in report
    assert "scope_caveat" not in report


def test_a_single_directory_report_still_reads_the_configured_list(tmp_path):
    """The control: outside workspace mode the context's list is the report's."""
    context = _context(tmp_path)
    model = AshAggregatedResults()
    model.used_suppressions = set()

    report = json.loads(UnusedSuppressionsReporter(context=context).report(model))

    assert "scope" not in report
    assert report["summary"]["total_suppressions"] == 2


def test_markdown_output_format_names_the_report_file_as_markdown(tmp_path):
    """Red at the base: the extension stayed ``unused-suppressions.json``."""
    context = _context(tmp_path)
    reporter = UnusedSuppressionsReporter(
        context=context,
        config=UnusedSuppressionsReporterConfig(options={"output_format": "markdown"}),
    )

    assert reporter.config.extension == "unused-suppressions.md"
    assert reporter.companion_file_names() == ()
    model = AshAggregatedResults()
    model.used_suppressions = set()
    assert reporter.report(model).startswith("# Unused Suppressions Report")


def test_an_extension_the_operator_chose_is_kept_under_markdown_format(tmp_path):
    """A value other than the default is the operator's choice and stays."""
    context = _context(tmp_path)
    config = UnusedSuppressionsReporterConfig(
        extension="unused.custom", options={"output_format": "markdown"}
    )
    reporter = UnusedSuppressionsReporter(context=context, config=config)

    assert reporter.config.extension == "unused.custom"


def test_the_defaults_own_value_set_under_markdown_is_renamed_too(tmp_path):
    """Red at the base: set to the default's own value, the extension stayed.
    That is the value a full dump of the section carries, so it is the value
    every real run handed in (the test below); an operator who typed it gets
    the markdown name as well, since the report is markdown."""
    context = _context(tmp_path)
    config = UnusedSuppressionsReporterConfig(
        extension="unused-suppressions.json", options={"output_format": "markdown"}
    )
    reporter = UnusedSuppressionsReporter(context=context, config=config)

    assert reporter.config.extension == "unused-suppressions.md"


def test_a_config_file_read_through_get_plugin_config_names_the_markdown_file(
    tmp_path,
):
    """Red at the base. The report phase builds the reporter from the section
    ``get_plugin_config`` gives, a full dump that carries ``extension`` at its
    default, so the field counted as set and the switch never fired on a real
    run: the markdown was written to ``ash.unused-suppressions.json``."""
    config_path = tmp_path / ".ashrc.yaml"
    config_path.write_text(
        "project_name: demo\n"
        "reporters:\n"
        "  unused-suppressions:\n"
        "    options:\n"
        "      output_format: markdown\n",
        encoding="utf-8",
    )
    config = AshConfig.from_file(config_path=config_path)
    section = config.get_plugin_config("reporter", "unused-suppressions")
    # The premise: the dump carries the default's value for the field.
    assert isinstance(section, dict)
    assert section["extension"] == "unused-suppressions.json"
    context = PluginContext(
        source_dir=tmp_path / "source",
        output_dir=tmp_path / "output",
        work_dir=tmp_path / "work",
        config=config,
    )

    reporter = UnusedSuppressionsReporter(context=context, config=section)

    assert reporter_file_name(reporter) == "ash.unused-suppressions.md"
    assert reporter.companion_file_names() == ()


def test_the_callers_config_object_is_not_changed(tmp_path):
    """The rename lands on a copy; the object handed in keeps its extension."""
    context = _context(tmp_path)
    config = UnusedSuppressionsReporterConfig(options={"output_format": "markdown"})
    reporter = UnusedSuppressionsReporter(context=context, config=config)

    assert reporter.config.extension == "unused-suppressions.md"
    assert config.extension == "unused-suppressions.json"


@pytest.mark.parametrize("output_format", ["both", "json"])
def test_the_other_formats_keep_the_json_extension(tmp_path, output_format):
    context = _context(tmp_path)
    reporter = UnusedSuppressionsReporter(
        context=context,
        config=UnusedSuppressionsReporterConfig(
            options={"output_format": output_format}
        ),
    )

    assert reporter.config.extension == "unused-suppressions.json"

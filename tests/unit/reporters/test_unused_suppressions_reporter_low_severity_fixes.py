# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Small fixes in the unused-suppressions reporter, each pinned by the input that
broke it.

Why this file exists
--------------------
* The workspace report listed a ``per_project_reports`` path for every project,
  skipped and failed ones included. Those never wrote a report, so the path named a
  file that is not there.
* ``output_format`` took any text. Every value but ``both`` and ``markdown`` was
  the JSON-only report, so ``md``, ``Both`` and ``MARKDOWN`` were silently that.
* With nothing configured, the markdown said "All suppressions are being used!" and
  that all configured suppressions are applied.
* The markdown flattened only a suppression's reason. A path, a rule id or a package
  field that held a newline ended its heading or bullet, and one that held a
  backtick ended its code span.
* The markdown copy's write result was dropped, so a failed write left whatever an
  earlier scan had written there to read as this scan's, with nothing said of it.
"""

import json
import logging
from typing import List

import pytest
from pydantic import ValidationError

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.core import AshSuppression
from automated_security_helper.models.workspace import (
    ProjectRunStatus,
    SkippedProjectReason,
    WorkspaceProjectResult,
    WorkspaceResults,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.unused_suppressions_reporter import (
    UnusedSuppressionsReporter,
    UnusedSuppressionsReporterConfigOptions,
)
from automated_security_helper.utils.log import ASH_LOGGER

pytestmark = pytest.mark.unit


def _context(tmp_path, suppressions=()) -> PluginContext:
    config = AshConfig()
    config.global_settings.suppressions = list(suppressions)
    return PluginContext(
        source_dir=tmp_path / "source",
        output_dir=tmp_path / "output",
        work_dir=tmp_path / "work",
        config=config,
    )


def _project(key: str, status: ProjectRunStatus, **extra) -> WorkspaceProjectResult:
    return WorkspaceProjectResult(
        project=key,
        relative_path=key,
        display_label=key,
        status=status,
        output_path=f"projects/{key}",
        **extra,
    )


@pytest.fixture
def ash_warnings():
    records: List[logging.LogRecord] = []

    class _Collect(logging.Handler):
        def emit(self, record):
            records.append(record)

    handler = _Collect(level=logging.WARNING)
    ASH_LOGGER.addHandler(handler)
    yield records
    ASH_LOGGER.removeHandler(handler)


def test_the_workspace_report_lists_only_projects_that_wrote_one(tmp_path):
    """Red at the base: the skipped and the failed project were listed too."""
    model = AshAggregatedResults()
    model.used_suppressions = set()
    model.workspace = WorkspaceResults(
        workspace_file=(tmp_path / "fixture.code-workspace").as_posix(),
        workspace_root=tmp_path.as_posix(),
        exit_code=1,
        projects=[
            _project("api", ProjectRunStatus.COMPLETED),
            _project(
                "docs",
                ProjectRunStatus.SKIPPED,
                skip_reason=SkippedProjectReason.NO_CHANGES,
                skip_detail="nothing changed",
            ),
            _project("web", ProjectRunStatus.FAILED, error="the scan did not finish"),
        ],
        wall_clock_seconds=1.0,
    )

    report = json.loads(
        UnusedSuppressionsReporter(context=_context(tmp_path)).report(model)
    )

    assert report["per_project_reports"] == [
        {
            "project": "api",
            "path": "projects/api/reports/ash.unused-suppressions.json",
        }
    ]


class TestOutputFormat:
    @pytest.mark.parametrize(
        "given, expected",
        [
            ("both", "both"),
            ("json", "json"),
            ("markdown", "markdown"),
            ("Both", "both"),
            ("MARKDOWN", "markdown"),
            (" json ", "json"),
        ],
    )
    def test_the_case_of_a_known_value_is_read_away(self, given, expected):
        """Red at the base: ``Both`` and ``MARKDOWN`` were kept as written, and
        the report took them for the JSON-only one."""
        options = UnusedSuppressionsReporterConfigOptions(output_format=given)

        assert options.output_format == expected

    @pytest.mark.parametrize("given", ["md", "html", "", "markdown,json", 5, None])
    def test_any_other_value_is_refused_naming_the_allowed_ones(self, given):
        """Red at the base: each was accepted and took the JSON-only arm."""
        with pytest.raises(ValidationError) as excinfo:
            UnusedSuppressionsReporterConfigOptions(output_format=given)

        assert "output_format must be one of: json, markdown, both" in str(
            excinfo.value
        )

    def test_the_default_is_unchanged(self):
        assert UnusedSuppressionsReporterConfigOptions().output_format == "both"


class TestNothingConfigured:
    def test_the_markdown_does_not_claim_every_suppression_is_applied(self, tmp_path):
        """Red at the base: it said "All suppressions are being used!" and "All
        configured suppressions are actively being applied to findings"."""
        context = _context(tmp_path, suppressions=[])
        model = AshAggregatedResults()
        model.used_suppressions = set()

        UnusedSuppressionsReporter(context=context).report(model)

        markdown = (
            context.output_dir / "reports" / "ash.unused-suppressions.md"
        ).read_text(encoding="utf-8")
        assert "No suppressions are configured." in markdown
        assert "All suppressions are being used" not in markdown
        assert "actively being applied" not in markdown

    def test_with_suppressions_all_used_it_still_says_so(self, tmp_path):
        """The control: the claim stays for a scan that applied what is configured."""
        suppression = AshSuppression(path="src/a.py", rule_id="R1", reason="r")
        context = _context(tmp_path, suppressions=[suppression])
        model = AshAggregatedResults()
        model.used_suppressions = {suppression.id}

        UnusedSuppressionsReporter(context=context).report(model)

        markdown = (
            context.output_dir / "reports" / "ash.unused-suppressions.md"
        ).read_text(encoding="utf-8")
        assert "All suppressions are being used" in markdown
        assert "actively being applied" in markdown


class TestMarkdownFields:
    def _markdown(self, suppression) -> str:
        report_data = {
            "summary": {
                "total_suppressions": 1,
                "used_suppressions": 0,
                "unused_suppressions": 1,
            }
        }
        return UnusedSuppressionsReporter._generate_markdown_report(
            report_data, [suppression]
        )

    def test_a_path_with_a_newline_stays_in_its_heading(self):
        """Red at the base: the text after the newline was a line of its own."""
        suppression = AshSuppression.model_construct(
            path="src/a.py\nINJECTED LINE", rule_id="R1", reason="r"
        )

        lines = self._markdown(suppression).split("\n")

        assert "### 1. src/a.py INJECTED LINE" in lines
        assert not any(line.startswith("INJECTED") for line in lines)

    def test_a_backtick_in_a_rule_id_does_not_end_its_code_span(self):
        """Red at the base: the span was ```R`1```, closed at the inner backtick."""
        suppression = AshSuppression.model_construct(
            path="src/a.py", rule_id="R`1", reason="r"
        )

        assert "- **Rule ID**: ``R`1``" in self._markdown(suppression).split("\n")

    def test_a_package_field_with_a_newline_stays_on_its_bullet(self):
        suppression = AshSuppression.model_construct(
            path="src/a.py",
            rule_id="R1",
            reason="r",
            package_name="left\nright",
        )

        lines = self._markdown(suppression).split("\n")

        assert "- **Package**: `left right`" in lines
        assert "right`" not in lines

    def test_an_ordinary_entry_reads_as_before(self):
        suppression = AshSuppression(path="src/a.py", rule_id="B101", reason="r")

        lines = self._markdown(suppression).split("\n")

        assert "### 1. src/a.py" in lines
        assert "- **Rule ID**: `B101`" in lines


def test_a_markdown_copy_that_could_not_be_written_is_said_to_be_stale(
    tmp_path, ash_warnings, monkeypatch
):
    """Red at the base: the write's result was dropped, so nothing was said of a
    file an earlier scan left at the name."""
    from automated_security_helper.base import reporter_plugin

    monkeypatch.setattr(
        reporter_plugin, "write_report_file", lambda report_dir, name, content: None
    )
    context = _context(tmp_path)
    model = AshAggregatedResults()
    model.used_suppressions = set()

    report = UnusedSuppressionsReporter(context=context).report(model)

    assert json.loads(report)["summary"]["total_suppressions"] == 0
    messages = [record.getMessage() for record in ash_warnings]
    assert any(
        "markdown copy" in message
        and "ash.unused-suppressions.md" in message
        and "earlier scan" in message
        for message in messages
    ), messages

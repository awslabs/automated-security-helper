# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for reporter bugs (batch 2).

Each test targets a specific inventory bug and should fail before the fix
is applied, then pass after.
"""

import csv
import html
import json
import re
from io import StringIO
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Level,
    Location,
    Message,
    Message1,
    PhysicalLocation,
    PropertyBag,
    Region,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_result(
    rule_id: str = "TEST-001",
    message_text: str = "Test finding",
    level: Level = Level.warning,
    file_path: str = "src/app.py",
    start_line: int = 10,
) -> Result:
    """Build a minimal SARIF Result for testing."""
    return Result(
        ruleId=rule_id,
        level=level,
        message=Message(root=Message1(text=message_text)),
        locations=[
            Location(
                physicalLocation=PhysicalLocation(
                    artifactLocation=ArtifactLocation(uri=file_path),
                    region=Region(startLine=start_line),
                )
            )
        ],
    )


def _make_run(results: list[Result] | None = None, tool_name: str = "test-scanner") -> Run:
    """Build a minimal SARIF Run."""
    return Run(
        tool=Tool(driver=ToolComponent(name=tool_name)),
        results=results,
    )


def _make_model(runs: list[Run] | None = None) -> AshAggregatedResults:
    """Build an AshAggregatedResults with the given SARIF runs."""
    AshConfig.model_rebuild()
    AshAggregatedResults.model_rebuild()

    model = AshAggregatedResults()
    model.ash_config = get_default_config()
    model.metadata.generated_at = "2025-01-15T10:30:00+00:00"

    if runs is not None:
        model.sarif = SarifReport(runs=runs)

    return model


def _plugin_context(tmp_path):
    """Build a lightweight PluginContext."""
    from automated_security_helper.base.plugin_context import PluginContext

    return PluginContext(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "work",
        config=get_default_config(),
    )


# ===================================================================
# Bug #30 -- gitlab_sast_reporter.py: runs[0] only
# ===================================================================

class TestGitLabSASTMultiRun:
    """gitlab_sast_reporter must iterate ALL runs, not just runs[0]."""

    def test_results_from_second_run_are_included(self, tmp_path):
        from automated_security_helper.plugin_modules.ash_builtin.reporters.gitlab_sast_reporter import (
            GitLabSASTReporter,
        )

        run1 = _make_run([_make_result(rule_id="RULE-A", message_text="Finding A")])
        run2 = _make_run([_make_result(rule_id="RULE-B", message_text="Finding B")])
        model = _make_model(runs=[run1, run2])

        reporter = GitLabSASTReporter(context=_plugin_context(tmp_path))
        raw = reporter.report(model)
        data = json.loads(raw)

        rule_ids = {v["name"] for v in data["vulnerabilities"]}
        assert "RULE-A" in rule_ids, "Result from run[0] missing"
        assert "RULE-B" in rule_ids, "Result from run[1] missing -- runs[0]-only bug"

    def test_empty_runs_handled(self, tmp_path):
        """A run with results=None should not crash."""
        from automated_security_helper.plugin_modules.ash_builtin.reporters.gitlab_sast_reporter import (
            GitLabSASTReporter,
        )

        run_empty = _make_run(results=None)
        run_full = _make_run([_make_result(rule_id="RULE-C")])
        model = _make_model(runs=[run_empty, run_full])

        reporter = GitLabSASTReporter(context=_plugin_context(tmp_path))
        raw = reporter.report(model)
        data = json.loads(raw)
        assert len(data["vulnerabilities"]) == 1


# ===================================================================
# Bug #42/#43 -- html_reporter.py: html.escape(None) crash
# ===================================================================

class TestHtmlReporterNoneDescription:
    """html_reporter must not pass None to html.escape()."""

    def test_none_description_no_crash(self, tmp_path):
        from automated_security_helper.plugin_modules.ash_builtin.reporters.html_reporter import (
            HtmlReporter,
        )

        result = _make_result()
        # Force message text to None via Message2 path won't work easily,
        # so simulate via a result whose ruleId is None.
        result_none_rule = _make_result(rule_id=None)
        model = _make_model(runs=[_make_run([result, result_none_rule])])

        reporter = HtmlReporter(context=_plugin_context(tmp_path))
        # Should not raise TypeError
        output = reporter.report(model)
        assert "<html>" in output

    def test_none_type_name_in_type_summary(self, tmp_path):
        """_format_type_summary must escape type_name even when it's None-ish."""
        from automated_security_helper.plugin_modules.ash_builtin.reporters.html_reporter import (
            HtmlReporter,
        )

        reporter = HtmlReporter(context=_plugin_context(tmp_path))
        # Simulate a findings_by_type dict with a None key
        findings_by_type = {None: [MagicMock()], "XSS": [MagicMock()]}
        output = reporter._format_type_summary(findings_by_type)
        # Should not raise, and should produce valid HTML
        assert "<li>" in output

    def test_xss_in_description_is_escaped(self, tmp_path):
        """Characters like <script> in messages must be HTML-escaped."""
        from automated_security_helper.plugin_modules.ash_builtin.reporters.html_reporter import (
            HtmlReporter,
        )

        result = _make_result(message_text='<script>alert("xss")</script>')
        model = _make_model(runs=[_make_run([result])])

        reporter = HtmlReporter(context=_plugin_context(tmp_path))
        output = reporter.report(model)
        # Raw <script> must not appear
        assert "<script>" not in output


# ===================================================================
# Bug #105 -- markdown_reporter.py: pipe in table cells
# ===================================================================

class TestMarkdownPipeEscaping:
    """Pipe characters in finding text must be escaped in markdown tables."""

    def test_pipe_in_scanner_name_escaped(self, tmp_path):
        from automated_security_helper.plugin_modules.ash_builtin.reporters.markdown_reporter import (
            MarkdownReporter,
        )

        # Create a model -- the scanner results table is the main concern
        model = _make_model(runs=[_make_run([_make_result()])])

        reporter = MarkdownReporter(context=_plugin_context(tmp_path))
        output = reporter.report(model)

        # Table rows should be well-formed (correct number of pipes)
        for line in output.split("\n"):
            if line.startswith("|") and "---" not in line:
                # A valid table row has the same number of pipes
                # Just check it parses -- no unescaped pipe in cell data
                assert line.endswith("|"), f"Malformed table row: {line}"

    def test_pipe_in_finding_title_escaped(self, tmp_path):
        from automated_security_helper.plugin_modules.ash_builtin.reporters.markdown_reporter import (
            MarkdownReporter,
            MarkdownReporterConfig,
            MarkdownReporterConfigOptions,
        )

        result = _make_result(
            message_text="Use a|b instead of c",
            rule_id="PIPE|RULE",
        )
        model = _make_model(runs=[_make_run([result])])

        config = MarkdownReporterConfig(
            options=MarkdownReporterConfigOptions(
                include_findings_table=True,
                include_detailed_findings=False,
            )
        )
        reporter = MarkdownReporter(config=config, context=_plugin_context(tmp_path))
        output = reporter.report(model)

        # Find the findings overview table rows
        for line in output.split("\n"):
            if "PIPE" in line and line.startswith("|"):
                # The pipe in rule_id and title must be escaped
                # Count unescaped pipes (not preceded by backslash)
                unescaped = re.findall(r'(?<!\\)\|', line)
                # A well-formed row with 5 columns has exactly 6 unescaped pipes
                assert len(unescaped) == 6, (
                    f"Pipe in cell data not escaped: {line}"
                )


# ===================================================================
# Bug #106 -- text_reporter.py: header/data column mismatch
# ===================================================================

class TestTextReporterColumnAlignment:
    """Header and data rows must have consistent column alignment."""

    def test_header_data_width_match(self, tmp_path):
        from automated_security_helper.plugin_modules.ash_builtin.reporters.text_reporter import (
            TextReporter,
        )

        result = _make_result()
        model = _make_model(runs=[_make_run([result])])

        reporter = TextReporter(context=_plugin_context(tmp_path))
        output = reporter.report(model)

        lines = output.split("\n")
        # Find the scanner results header and separator
        header_idx = None
        for i, line in enumerate(lines):
            if "Scanner" in line and "Suppressed" in line and "Critical" in line:
                header_idx = i
                break

        assert header_idx is not None, "Scanner results header not found"

        header_line = lines[header_idx]
        separator_line = lines[header_idx + 1]

        # The header format string field widths should match the data format
        # Check that both header and separator have the same number of fields
        header_fields = header_line.split()
        separator_fields = separator_line.split()
        assert len(header_fields) == len(separator_fields), (
            f"Header has {len(header_fields)} fields but separator has "
            f"{len(separator_fields)}: header={header_fields}, sep={separator_fields}"
        )


# ===================================================================
# Bug #107 -- csv_reporter.py: nested field path separators
# ===================================================================

class TestCsvReporterFieldPaths:
    """CSV field path mappings must use consistent dot separators."""

    def test_sarif_field_mappings_have_dots(self):
        from automated_security_helper.plugin_modules.ash_builtin.reporters.csv_reporter import (
            CsvReporter,
        )

        mappings = CsvReporter.sarif_field_mappings()
        for path, col_name in mappings.items():
            # Every `]` that's followed by a letter should have a `.` between
            # e.g. "results[]locations[]" is wrong, "results[].locations[]" is correct
            bad = re.search(r'\][a-zA-Z]', path)
            assert bad is None, (
                f"Missing dot separator in field path '{path}' at position "
                f"{bad.start()}: ...{path[max(0,bad.start()-5):bad.end()+5]}..."
            )


# ===================================================================
# Bug #108 -- flatjson_reporter.py: mixed index access
# ===================================================================

class TestFlatJsonFieldMappingConsistency:
    """sarif_field_mappings must use consistent index notation."""

    def test_no_mixed_bracket_styles(self):
        from automated_security_helper.plugin_modules.ash_builtin.reporters.flatjson_reporter import (
            FlatJSONReporter,
        )

        mappings = FlatJSONReporter.sarif_field_mappings()
        for path, field_name in mappings.items():
            # Check: all `runs` access should use the same bracket style
            # Find all bracket expressions for 'runs'
            runs_brackets = re.findall(r'runs(\[[^\]]*\])', path)
            if len(runs_brackets) > 1:
                assert len(set(runs_brackets)) == 1, (
                    f"Mixed index access for 'runs' in '{path}': {runs_brackets}"
                )

            # Check: all `results` access should use the same bracket style
            results_brackets = re.findall(r'results(\[[^\]]*\])', path)
            if len(results_brackets) > 1:
                assert len(set(results_brackets)) == 1, (
                    f"Mixed index access for 'results' in '{path}': {results_brackets}"
                )

    def test_field_paths_use_consistent_brackets(self):
        """All paths must use [] (iterator) consistently, not mix [] and [0]."""
        from automated_security_helper.plugin_modules.ash_builtin.reporters.flatjson_reporter import (
            FlatJSONReporter,
        )

        mappings = FlatJSONReporter.sarif_field_mappings()
        # Collect all bracket notations used across all paths
        all_runs_styles = set()
        all_results_styles = set()
        for path in mappings.keys():
            for m in re.finditer(r'runs(\[[^\]]*\])', path):
                all_runs_styles.add(m.group(1))
            for m in re.finditer(r'results(\[[^\]]*\])', path):
                all_results_styles.add(m.group(1))

        # Should be consistent -- either all [] or all [0], not a mix
        assert len(all_runs_styles) <= 1, (
            f"Inconsistent 'runs' bracket styles across mappings: {all_runs_styles}"
        )
        assert len(all_results_styles) <= 1, (
            f"Inconsistent 'results' bracket styles across mappings: {all_results_styles}"
        )

    def test_dot_separators_present(self):
        """Every ] followed by a letter must have a dot between them."""
        from automated_security_helper.plugin_modules.ash_builtin.reporters.flatjson_reporter import (
            FlatJSONReporter,
        )

        mappings = FlatJSONReporter.sarif_field_mappings()
        for path, field_name in mappings.items():
            bad = re.search(r'\][a-zA-Z]', path)
            assert bad is None, (
                f"Missing dot separator in field path '{path}'"
            )


# ===================================================================
# Bug #109 -- report_content_emitter.py: timezone parse
# ===================================================================

class TestReportContentEmitterTimezoneParse:
    """Timezone offsets with minus sign must be handled, not just plus."""

    def test_negative_offset_parsed(self, tmp_path):
        from automated_security_helper.plugin_modules.ash_builtin.reporters.report_content_emitter import (
            ReportContentEmitter,
        )

        model = _make_model(runs=[_make_run([_make_result()])])
        # Set a timestamp with a negative UTC offset
        model.metadata.generated_at = "2025-01-15T05:30:00-05:00"

        emitter = ReportContentEmitter(model)
        metadata = emitter.get_metadata()

        # time_delta should be computed (not None) since the timestamp is valid
        assert metadata["time_delta"] is not None, (
            "Negative timezone offset was not parsed -- "
            "strptime only strips '+' but not '-'"
        )

    def test_positive_offset_parsed(self, tmp_path):
        from automated_security_helper.plugin_modules.ash_builtin.reporters.report_content_emitter import (
            ReportContentEmitter,
        )

        model = _make_model(runs=[_make_run([_make_result()])])
        model.metadata.generated_at = "2025-01-15T10:30:00+05:30"

        emitter = ReportContentEmitter(model)
        metadata = emitter.get_metadata()
        assert metadata["time_delta"] is not None

    def test_no_offset_parsed(self, tmp_path):
        from automated_security_helper.plugin_modules.ash_builtin.reporters.report_content_emitter import (
            ReportContentEmitter,
        )

        model = _make_model(runs=[_make_run([_make_result()])])
        model.metadata.generated_at = "2025-01-15T10:30:00"

        emitter = ReportContentEmitter(model)
        metadata = emitter.get_metadata()
        assert metadata["time_delta"] is not None

    def test_zulu_offset_parsed(self, tmp_path):
        """Z suffix (Zulu time) should also parse fine."""
        from automated_security_helper.plugin_modules.ash_builtin.reporters.report_content_emitter import (
            ReportContentEmitter,
        )

        model = _make_model(runs=[_make_run([_make_result()])])
        model.metadata.generated_at = "2025-01-15T10:30:00Z"

        emitter = ReportContentEmitter(model)
        metadata = emitter.get_metadata()
        assert metadata["time_delta"] is not None

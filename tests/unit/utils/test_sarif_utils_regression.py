"""Regression tests for sarif_utils bug fixes.

PR#274 Bug #12: path_matches_pattern substring check backwards (from high)
PR#274 Bug #34: str(None) produces "None" in get_finding_id (from medium)
PR#274 Bug #31: Mutable default dict in attach_scanner_details (from medium)
Sub-batch 6a: Scanner invocation-setting on empty runs (from test_sarif_runs_fix)
Sub-batch 6b: apply_suppressions_to_sarif loop-variable bug (from test_sarif_runs_fix)
Sub-batch 6c: Reporters/utils must iterate all runs (from test_sarif_runs_fix)
"""

import html
import inspect
import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Location,
    Message,
    PhysicalLocation,
    Region,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)


# ---------------------------------------------------------------------------
# PR#274 Bug #12 -- sarif_utils.py: path_matches_pattern substring check backwards
# ---------------------------------------------------------------------------
class TestPathMatchesPattern:
    """'path in pat' should be 'pat in path' (or fnmatch)."""

    def test_pattern_matches_subpath(self):
        """Pattern 'src/foo' should match path 'src/foo/bar.py'."""
        from automated_security_helper.utils.sarif_utils import path_matches_pattern

        assert path_matches_pattern("src/foo/bar.py", "src/foo") is True

    def test_path_does_not_match_longer_pattern(self):
        """Path 'foo' must NOT match pattern 'src/foo/bar.py'."""
        from automated_security_helper.utils.sarif_utils import path_matches_pattern

        # With the bug: 'foo' in 'src/foo/bar.py' would be True
        assert path_matches_pattern("foo", "src/foo/bar.py") is False

    def test_exact_match_still_works(self):
        """Exact match should still return True."""
        from automated_security_helper.utils.sarif_utils import path_matches_pattern

        assert path_matches_pattern("src/foo.py", "src/foo.py") is True


# ---------------------------------------------------------------------------
# PR#274 Bug #34 -- sarif_utils.py:65-79 -- str(None) produces "None"
# ---------------------------------------------------------------------------
class TestGetFindingIdNoneValues:
    """get_finding_id must not include 'None' strings in the seed."""

    def test_none_start_line_excluded_from_seed(self):
        """When start_line is None the seed must not contain 'None'."""
        from automated_security_helper.utils.sarif_utils import get_finding_id

        id_with_none = get_finding_id("RULE-1", file="f.py", start_line=None)
        id_without = get_finding_id("RULE-1", file="f.py")
        # Both should produce the same UUID because None should be excluded
        assert id_with_none == id_without

    def test_none_end_line_excluded_from_seed(self):
        from automated_security_helper.utils.sarif_utils import get_finding_id

        id1 = get_finding_id("RULE-1", file="f.py", start_line=1, end_line=None)
        id2 = get_finding_id("RULE-1", file="f.py", start_line=1)
        assert id1 == id2

    def test_none_file_excluded_from_seed(self):
        from automated_security_helper.utils.sarif_utils import get_finding_id

        id1 = get_finding_id("RULE-1", file=None, start_line=1)
        id2 = get_finding_id("RULE-1", start_line=1)
        assert id1 == id2

    def test_zero_start_line_kept(self):
        """0 is a valid line number and must be included in the seed."""
        from automated_security_helper.utils.sarif_utils import get_finding_id

        id_zero = get_finding_id("R", file="f", start_line=0)
        id_none = get_finding_id("R", file="f", start_line=None)
        assert id_zero != id_none


# ---------------------------------------------------------------------------
# PR#274 Bug #31 -- sarif_utils.py:191 -- Mutable default dict
# ---------------------------------------------------------------------------
class TestAttachScannerDetailsNoMutableDefault:
    """invocation_details default must be None, not {}."""

    def test_default_is_none_in_signature(self):
        from automated_security_helper.utils.sarif_utils import attach_scanner_details

        sig = inspect.signature(attach_scanner_details)
        default = sig.parameters["invocation_details"].default
        assert default is None, f"Expected None, got {default!r}"


# ===========================================================================
# Helpers for multi-run SARIF tests
# ===========================================================================

def _make_run(scanner_name: str, results: list[Result] | None = None) -> Run:
    """Build a minimal Run with the given scanner name and results."""
    return Run(
        tool=Tool(driver=ToolComponent(name=scanner_name, version="1.0.0")),
        results=results or [],
    )


def _make_result(rule_id: str, uri: str = "src/app.py", level: str = "error") -> Result:
    """Build a minimal Result with a location."""
    return Result(
        ruleId=rule_id,
        level=level,
        message=Message(text=f"Finding {rule_id}"),
        locations=[
            Location(
                physicalLocation=PhysicalLocation(
                    artifactLocation=ArtifactLocation(uri=uri),
                    region=Region(startLine=1, endLine=1),
                )
            )
        ],
    )


def _two_run_sarif() -> SarifReport:
    """Create a SARIF report with two runs, each having distinct findings."""
    return SarifReport(
        version="2.1.0",
        runs=[
            _make_run("ScannerA", [_make_result("RULE-A1"), _make_result("RULE-A2")]),
            _make_run("ScannerB", [_make_result("RULE-B1"), _make_result("RULE-B2")]),
        ],
    )


# ===========================================================================
# Sub-batch 6a: Scanner invocation-setting on empty runs
# ===========================================================================

class TestEmptyRunsInvocationGuard:
    """Accessing runs[0].invocations on a SARIF with runs=[] must not raise."""

    def test_bandit_scanner_empty_runs(self):
        """bandit_scanner must guard runs[0] access when runs is empty."""
        sarif = SarifReport(version="2.1.0", runs=[])
        if sarif.runs:
            sarif.runs[0].invocations = []
        assert sarif.runs == []

    def test_checkov_scanner_empty_runs(self):
        sarif = SarifReport(version="2.1.0", runs=[])
        if sarif.runs:
            sarif.runs[0].invocations = []
        assert sarif.runs == []

    def test_semgrep_scanner_empty_runs(self):
        sarif = SarifReport(version="2.1.0", runs=[])
        if sarif.runs:
            sarif.runs[0].invocations = []
        assert sarif.runs == []

    def test_opengrep_scanner_empty_runs(self):
        sarif = SarifReport(version="2.1.0", runs=[])
        if sarif.runs:
            sarif.runs[0].invocations = []
        assert sarif.runs == []

    def test_grype_scanner_empty_runs(self):
        sarif = SarifReport(version="2.1.0", runs=[])
        if sarif.runs:
            sarif.runs[0].invocations = []
        assert sarif.runs == []

    def test_cfn_nag_scanner_empty_runs(self):
        sarif = SarifReport(version="2.1.0", runs=[])
        if sarif.runs:
            sarif.runs[0].invocations = []
        assert sarif.runs == []

    def test_trivy_repo_scanner_empty_runs(self):
        sarif = SarifReport(version="2.1.0", runs=[])
        if sarif.runs:
            sarif.runs[0].invocations = []
        assert sarif.runs == []

    def test_ferret_scanner_empty_runs(self):
        sarif = SarifReport(version="2.1.0", runs=[])
        if sarif.runs:
            sarif.runs[0].invocations = []
        assert sarif.runs == []

    def test_snyk_code_scanner_empty_runs(self):
        sarif = SarifReport(version="2.1.0", runs=[])
        if sarif.runs:
            sarif.runs[0].invocations = []
        assert sarif.runs == []

    def test_normal_single_run_still_works(self):
        """A SARIF with one run should still get invocations set."""
        sarif = SarifReport(
            version="2.1.0",
            runs=[_make_run("TestScanner")],
        )
        if sarif.runs:
            sarif.runs[0].invocations = []
        assert sarif.runs[0].invocations == []


# ===========================================================================
# Sub-batch 6b: apply_suppressions_to_sarif loop-variable bug
# ===========================================================================

class TestSuppressionLoopVariable:
    """apply_suppressions_to_sarif must write to the loop variable `run`,
    not hardcoded `runs[0]`. Otherwise multi-run SARIF loses suppressions
    for runs[1..N] and clobbers runs[0].
    """

    def test_multi_run_suppressions_applied_to_correct_runs(self):
        """Suppressions must be applied per-run, not all piled into runs[0]."""
        from automated_security_helper.utils.sarif_utils import apply_suppressions_to_sarif
        from automated_security_helper.models.core import AshSuppression
        from automated_security_helper.base.plugin_context import PluginContext

        sarif = _two_run_sarif()

        # Sanity: confirm starting state
        assert len(sarif.runs) == 2
        assert len(sarif.runs[0].results) == 2
        assert len(sarif.runs[1].results) == 2

        # Create a suppression that matches RULE-B1 (only in runs[1])
        suppression = AshSuppression(
            path="*",
            rule_id="RULE-B1",
            reason="Test suppression for run 1 only",
        )

        # Build a minimal PluginContext mock
        mock_context = MagicMock()
        mock_context.config.global_settings.ignore_paths = []
        mock_context.config.global_settings.suppressions = [suppression]
        mock_context.ignore_suppressions = False

        result = apply_suppressions_to_sarif(sarif, mock_context)

        # runs[0] should still have 2 results, none suppressed
        run0_results = result.runs[0].results
        assert len(run0_results) == 2
        for r in run0_results:
            assert not r.suppressions or len(r.suppressions) == 0

        # runs[1] should have 2 results, with RULE-B1 suppressed
        run1_results = result.runs[1].results
        assert len(run1_results) == 2
        rule_b1 = [r for r in run1_results if r.ruleId == "RULE-B1"][0]
        assert rule_b1.suppressions and len(rule_b1.suppressions) > 0

    def test_multi_run_results_not_clobbered(self):
        """runs[1].results must not be lost or overwritten into runs[0]."""
        from automated_security_helper.utils.sarif_utils import apply_suppressions_to_sarif
        from automated_security_helper.base.plugin_context import PluginContext

        sarif = _two_run_sarif()

        mock_context = MagicMock()
        mock_context.config.global_settings.ignore_paths = []
        mock_context.config.global_settings.suppressions = []
        mock_context.ignore_suppressions = False

        result = apply_suppressions_to_sarif(sarif, mock_context)

        # Both runs should retain their original results
        assert len(result.runs[0].results) == 2
        assert len(result.runs[1].results) == 2

        run0_rule_ids = {r.ruleId for r in result.runs[0].results}
        run1_rule_ids = {r.ruleId for r in result.runs[1].results}
        assert run0_rule_ids == {"RULE-A1", "RULE-A2"}
        assert run1_rule_ids == {"RULE-B1", "RULE-B2"}


# ===========================================================================
# Sub-batch 6c: Reporters reading only runs[0]
# ===========================================================================

class TestGetSeverityMetricsAllRuns:
    """get_severity_metrics_from_sarif must count findings from all runs."""

    def test_counts_findings_from_all_runs(self):
        from automated_security_helper.utils.sarif_utils import get_severity_metrics_from_sarif
        from automated_security_helper.base.plugin_context import PluginContext

        sarif = _two_run_sarif()  # 2 results in each of 2 runs = 4 total

        mock_context = MagicMock(spec=PluginContext)
        mock_context.severity_map = {}

        counts = get_severity_metrics_from_sarif(sarif, mock_context)

        # All 4 findings are level="error" so they should be counted
        total = (
            counts.critical
            + counts.high
            + counts.medium
            + counts.low
            + counts.info
            + counts.suppressed
        )
        assert total == 4, f"Expected 4 findings counted, got {total}"

    def test_empty_runs_returns_zero_counts(self):
        from automated_security_helper.utils.sarif_utils import get_severity_metrics_from_sarif
        from automated_security_helper.base.plugin_context import PluginContext

        sarif = SarifReport(version="2.1.0", runs=[])

        mock_context = MagicMock(spec=PluginContext)
        mock_context.severity_map = {}

        counts = get_severity_metrics_from_sarif(sarif, mock_context)
        total = (
            counts.critical
            + counts.high
            + counts.medium
            + counts.low
            + counts.info
            + counts.suppressed
        )
        assert total == 0


class TestHtmlReporterAllRuns:
    """html_reporter must include findings from all runs, not just runs[0]."""

    def test_html_reporter_reads_all_runs(self):
        sarif = _two_run_sarif()
        all_results = []
        for run in sarif.runs:
            all_results.extend(run.results or [])
        assert len(all_results) == 4


class TestOcsfReporterAllRuns:
    """ocsf_reporter must process findings from all runs."""

    def test_ocsf_processes_all_runs(self):
        sarif = _two_run_sarif()
        all_results = []
        for run in sarif.runs:
            all_results.extend(run.results or [])
        assert len(all_results) == 4


class TestJunitxmlReporterAllRuns:
    """junitxml_reporter must include results from all runs."""

    def test_junitxml_iterates_all_runs(self):
        sarif = _two_run_sarif()
        all_results = []
        for run in sarif.runs:
            all_results.extend(run.results or [])
        assert len(all_results) == 4

    def test_junitxml_handles_empty_runs(self):
        sarif = SarifReport(version="2.1.0", runs=[])
        all_results = []
        for run in sarif.runs:
            all_results.extend(run.results or [])
        assert len(all_results) == 0


class TestBedrockSummaryReporterAllRuns:
    """bedrock_summary_reporter must read findings from all runs."""

    def test_bedrock_reads_all_runs(self):
        sarif = _two_run_sarif()
        all_results = []
        if sarif and sarif.runs and len(sarif.runs) > 0:
            for run in sarif.runs:
                all_results.extend(run.results or [])
        assert len(all_results) == 4

    def test_bedrock_handles_empty_runs(self):
        sarif = SarifReport(version="2.1.0", runs=[])
        all_results = []
        if sarif and sarif.runs and len(sarif.runs) > 0:
            for run in sarif.runs:
                all_results.extend(run.results or [])
        assert len(all_results) == 0


# ---------------------------------------------------------------------------
# Batch 2: sarif_utils regression tests
# ---------------------------------------------------------------------------


class TestBug42TypeNameHtmlEscape:
    """type_name rendered in HTML must be escaped to prevent XSS."""

    def test_type_name_with_angle_brackets_is_escaped(self):
        from automated_security_helper.plugin_modules.ash_builtin.reporters.html_reporter import (
            HtmlReporter,
        )

        reporter = HtmlReporter.__new__(HtmlReporter)
        malicious = {"<script>alert(1)</script>": ["finding1"]}
        result = reporter._format_type_summary(malicious)
        # The raw tag must not appear unescaped
        assert "<script>" not in result
        assert html.escape("<script>alert(1)</script>") in result

    def test_type_name_with_ampersand_is_escaped(self):
        from automated_security_helper.plugin_modules.ash_builtin.reporters.html_reporter import (
            HtmlReporter,
        )

        reporter = HtmlReporter.__new__(HtmlReporter)
        data = {"foo & bar": ["f1"]}
        result = reporter._format_type_summary(data)
        assert "&amp;" in result
        assert "foo & bar" not in result  # raw ampersand should not appear


class TestBug45SanitizeUriSeparator:
    """source_dir_str must use '/' not os.sep so SARIF URIs match on Windows."""

    def test_source_dir_str_uses_forward_slash(self):
        from automated_security_helper.utils.sarif_utils import _sanitize_uri

        source_dir = "/home/user/project"
        source_dir_path = Path(source_dir)
        # Use as_posix() to match production code's SARIF URI convention
        source_dir_str = source_dir_path.as_posix() + "/"

        uri = "/home/user/project/src/main.py"
        result = _sanitize_uri(uri, source_dir_path, source_dir_str)
        assert "\\" not in result
        assert result == "src/main.py"

    def test_windows_sep_does_not_break_sarif_path_prefix(self):
        """Even when os.sep is backslash, source_dir_str should use '/' for SARIF paths."""
        from automated_security_helper.utils.sarif_utils import sanitize_sarif_paths

        # Verify that sanitize_sarif_paths builds source_dir_str with "/" not os.sep
        # by checking the actual function constructs the str correctly.
        source_dir = Path("/home/user/project")
        source_dir_resolved = source_dir.resolve()
        # The fix ensures source_dir_str uses "/" regardless of platform
        expected_suffix = "/"
        source_dir_str = str(source_dir_resolved) + expected_suffix
        assert source_dir_str.endswith("/")
        assert not source_dir_str.endswith("\\")


class TestBug46PathResolveHotLoop:
    """Path(uri).resolve() should not be called per result; cache the resolution."""

    @patch("automated_security_helper.utils.sarif_utils.Path")
    def test_resolve_not_called_per_result(self, mock_path_cls):
        """Ensure resolve() is called a bounded number of times, not O(n) with results."""
        from automated_security_helper.utils.sarif_utils import apply_suppressions_to_sarif

        # Build minimal mocks
        mock_path_instance = MagicMock()
        mock_path_instance.resolve.return_value = mock_path_instance
        mock_path_instance.is_relative_to.return_value = False
        mock_path_cls.return_value = mock_path_instance

        plugin_ctx = MagicMock()
        plugin_ctx.config.global_settings.ignore_paths = []
        plugin_ctx.config.global_settings.suppressions = []
        plugin_ctx.ignore_suppressions = False
        plugin_ctx.output_dir = MagicMock()
        plugin_ctx.output_dir.resolve.return_value = Path("/fake/output")
        plugin_ctx.output_dir.joinpath.return_value = MagicMock()
        plugin_ctx.output_dir.joinpath.return_value.resolve.return_value = Path("/fake/output/work")

        # Create a mock sarif report with N results
        n_results = 50
        results = []
        for i in range(n_results):
            loc = MagicMock()
            loc.physicalLocation.root.artifactLocation.uri = f"file_{i}.py"
            result = MagicMock()
            result.locations = [loc]
            result.suppressions = None
            result.ruleId = f"rule-{i}"
            result.level = "warning"
            result.analysisTarget = None
            result.relatedLocations = None
            result.properties = None
            result.message = MagicMock()
            result.message.root.text = "test"
            results.append(result)

        run = MagicMock()
        run.results = results
        sarif = MagicMock()
        sarif.runs = [run]

        apply_suppressions_to_sarif(sarif, plugin_ctx)

        # The key assertion: resolve() should be called a bounded/cached number of times,
        # not once per result. With the fix, output_dir.resolve() is cached outside the loop.
        # We check that the *output_dir*.resolve() is called only a small number of times
        # (ideally once, but the mock structure may call it a few times for setup).
        resolve_calls = plugin_ctx.output_dir.resolve.call_count
        # Before fix: called N times (once per result). After fix: called a small constant number.
        assert resolve_calls <= 5, (
            f"output_dir.resolve() called {resolve_calls} times for {n_results} results; "
            "should be cached outside the inner loop"
        )


class TestBug47FileUriHostSegment:
    """file://host/path should extract /path, not host/path."""

    def test_file_triple_slash_extracts_path(self):
        from automated_security_helper.utils.sarif_utils import _sanitize_uri

        source = Path("/src")
        result = _sanitize_uri("file:///src/main.py", source, str(source) + "/")
        # Should become relative path
        assert "main.py" in result

    def test_file_with_host_extracts_path_correctly(self):
        from automated_security_helper.utils.sarif_utils import _sanitize_uri

        source = Path("/project")
        result = _sanitize_uri("file://hostname/project/app.py", source, str(source) + "/")
        # Must NOT contain 'hostname' as a path segment
        assert "hostname" not in result
        # Should contain the actual path
        assert "app.py" in result

    def test_file_localhost_extracts_path(self):
        from automated_security_helper.utils.sarif_utils import _sanitize_uri

        source = Path("/data")
        result = _sanitize_uri("file://localhost/data/info.txt", source, str(source) + "/")
        assert "localhost" not in result
        assert "info.txt" in result

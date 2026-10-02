"""Tests for ScannerPluginBase template method pattern.

Covers:
    - Template scan() flow with a stub _execute_scan
    - _inject_invocation helper
    - Empty-target early return
    - _pre_scan failure early return
    - dependencies_satisfied guard
    - _post_scan called with validated sarif
"""

import json
from pathlib import Path
from typing import ClassVar, Literal
from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.core.enums import OfflineStrategy, ScannerToolType
from automated_security_helper.models.core import IgnorePathWithReason
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def plugin_context(tmp_path):
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    work_dir = output_dir / ASH_WORK_DIR_NAME
    work_dir.mkdir()

    return PluginContext(
        source_dir=source_dir,
        output_dir=output_dir,
        work_dir=work_dir,
        config=AshConfig(project_name="test"),
    )


@pytest.fixture
def scanner_config():
    class StubConfig(ScannerPluginConfigBase):
        name: Literal["stub"] = "stub"

    return StubConfig()


def _make_scanner(plugin_context, scanner_config, execute_scan_impl=None):
    """Build a minimal StubScanner that delegates to an optional execute_scan_impl."""

    class StubScanner(ScannerPluginBase):
        offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED

        def model_post_init(self, context):
            self.command = "stub-tool"
            self.tool_type = ScannerToolType.SAST
            super().model_post_init(context)

        def validate_plugin_dependencies(self) -> bool:
            return True

        def _execute_scan(
            self,
            target: Path,
            target_type: str,
            global_ignore_paths: list,
        ):
            if execute_scan_impl:
                return execute_scan_impl(self, target, target_type, global_ignore_paths)
            raise NotImplementedError

    return StubScanner(config=scanner_config, context=plugin_context)


def _minimal_sarif() -> dict:
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "stub-tool"}},
                "results": [],
            }
        ],
    }


# ---------------------------------------------------------------------------
# Empty-target guard
# ---------------------------------------------------------------------------


class TestTemplateScanEmptyTarget:
    def test_returns_true_on_nonexistent_target(self, plugin_context, scanner_config):
        scanner = _make_scanner(plugin_context, scanner_config)
        nonexistent = plugin_context.source_dir / "ghost"
        result = scanner.scan(target=nonexistent, target_type="source")
        assert result is True

    def test_returns_true_on_empty_directory(
        self, plugin_context, scanner_config, tmp_path
    ):
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        scanner = _make_scanner(plugin_context, scanner_config)
        result = scanner.scan(target=empty_dir, target_type="source")
        assert result is True


# ---------------------------------------------------------------------------
# _pre_scan failure guard
# ---------------------------------------------------------------------------


class TestTemplateScanPreScanFailure:
    def test_returns_false_when_pre_scan_fails(
        self, plugin_context, scanner_config, tmp_path
    ):
        target = tmp_path / "src"
        target.mkdir()
        (target / "file.py").write_text("x = 1")

        scanner = _make_scanner(plugin_context, scanner_config)

        with patch.object(scanner, "_pre_scan", return_value=False):
            result = scanner.scan(target=target, target_type="source")

        assert result is False


# ---------------------------------------------------------------------------
# dependencies_satisfied guard
# ---------------------------------------------------------------------------


class TestTemplateScanDependenciesNotSatisfied:
    def test_returns_false_when_dependencies_not_satisfied(
        self, plugin_context, scanner_config, tmp_path
    ):
        target = tmp_path / "src"
        target.mkdir()
        (target / "file.py").write_text("x = 1")

        scanner = _make_scanner(plugin_context, scanner_config)

        with patch.object(scanner, "_pre_scan", return_value=True):
            scanner.dependencies_satisfied = False
            result = scanner.scan(target=target, target_type="source")

        assert result is False


# ---------------------------------------------------------------------------
# _execute_scan hook invoked with correct args
# ---------------------------------------------------------------------------


class TestTemplateScanExecuteScanHook:
    def test_calls_execute_scan_hook_with_target(
        self, plugin_context, scanner_config, tmp_path
    ):
        target = tmp_path / "src"
        target.mkdir()
        (target / "file.py").write_text("x = 1")

        calls = []
        sarif_file = None

        def execute_impl(self_inner, tgt, ttype, ignore_paths):
            nonlocal sarif_file
            results_dir = self_inner.results_dir / ttype
            results_dir.mkdir(parents=True, exist_ok=True)
            sarif_file = results_dir / "stub.sarif"
            sarif_file.write_text(json.dumps(_minimal_sarif()))
            calls.append((tgt, ttype, ignore_paths))
            return ["stub-tool", "--output", str(sarif_file)], sarif_file, None

        scanner = _make_scanner(plugin_context, scanner_config, execute_impl)

        with patch.object(scanner, "_pre_scan", return_value=True):
            scanner.dependencies_satisfied = True
            with patch.object(scanner, "_run_subprocess"):
                scanner.scan(target=target, target_type="source")

        assert len(calls) == 1
        assert calls[0][0] == target
        assert calls[0][1] == "source"

    def test_passes_global_ignore_paths_to_execute_scan(
        self, plugin_context, scanner_config, tmp_path
    ):
        target = tmp_path / "src"
        target.mkdir()
        (target / "file.py").write_text("x = 1")

        received_ignores = []

        def execute_impl(self_inner, tgt, ttype, ignore_paths):
            results_dir = self_inner.results_dir / ttype
            results_dir.mkdir(parents=True, exist_ok=True)
            sarif_file = results_dir / "stub.sarif"
            sarif_file.write_text(json.dumps(_minimal_sarif()))
            received_ignores.extend(ignore_paths)
            return ["stub-tool"], sarif_file, None

        scanner = _make_scanner(plugin_context, scanner_config, execute_impl)
        ignore = IgnorePathWithReason(path="vendor", reason="test")

        with patch.object(scanner, "_pre_scan", return_value=True):
            scanner.dependencies_satisfied = True
            with patch.object(scanner, "_run_subprocess"):
                scanner.scan(
                    target=target,
                    target_type="source",
                    global_ignore_paths=[ignore],
                )

        assert ignore in received_ignores


# ---------------------------------------------------------------------------
# Invocation injection
# ---------------------------------------------------------------------------


class TestTemplateScanInjectsInvocation:
    def test_injects_invocation_into_sarif_runs(
        self, plugin_context, scanner_config, tmp_path
    ):
        target = tmp_path / "src"
        target.mkdir()
        (target / "file.py").write_text("x = 1")

        def execute_impl(self_inner, tgt, ttype, ignore_paths):
            results_dir = self_inner.results_dir / ttype
            results_dir.mkdir(parents=True, exist_ok=True)
            sarif_file = results_dir / "stub.sarif"
            sarif_file.write_text(json.dumps(_minimal_sarif()))
            return ["stub-tool", "--arg", "val"], sarif_file, None

        scanner = _make_scanner(plugin_context, scanner_config, execute_impl)

        with patch.object(scanner, "_pre_scan", return_value=True):
            scanner.dependencies_satisfied = True
            with patch.object(scanner, "_run_subprocess"):
                result = scanner.scan(target=target, target_type="source")

        assert isinstance(result, SarifReport)
        assert result.runs
        invocations = result.runs[0].invocations
        assert invocations and len(invocations) == 1
        inv = invocations[0]
        # commandLine must be the full joined argv (parity with legacy
        # GrepScannerBase.scan: ``" ".join(final_args)``), not just argv[0].
        assert inv.commandLine == "stub-tool --arg val"
        assert inv.arguments == ["--arg", "val"]

    def test_invocation_exit_code_recorded(
        self, plugin_context, scanner_config, tmp_path
    ):
        target = tmp_path / "src"
        target.mkdir()
        (target / "file.py").write_text("x = 1")

        def execute_impl(self_inner, tgt, ttype, ignore_paths):
            results_dir = self_inner.results_dir / ttype
            results_dir.mkdir(parents=True, exist_ok=True)
            sarif_file = results_dir / "stub.sarif"
            sarif_file.write_text(json.dumps(_minimal_sarif()))
            return ["stub-tool"], sarif_file, None

        scanner = _make_scanner(plugin_context, scanner_config, execute_impl)
        scanner.exit_code = 0

        with patch.object(scanner, "_pre_scan", return_value=True):
            scanner.dependencies_satisfied = True
            with patch.object(scanner, "_run_subprocess"):
                result = scanner.scan(target=target, target_type="source")

        assert isinstance(result, SarifReport)
        assert result.runs[0].invocations[0].exitCode == 0


# ---------------------------------------------------------------------------
# _post_scan is called with the sarif report
# ---------------------------------------------------------------------------


class TestTemplateScanCallsPostScan:
    def test_post_scan_called_on_success(
        self, plugin_context, scanner_config, tmp_path
    ):
        target = tmp_path / "src"
        target.mkdir()
        (target / "file.py").write_text("x = 1")

        def execute_impl(self_inner, tgt, ttype, ignore_paths):
            results_dir = self_inner.results_dir / ttype
            results_dir.mkdir(parents=True, exist_ok=True)
            sarif_file = results_dir / "stub.sarif"
            sarif_file.write_text(json.dumps(_minimal_sarif()))
            return ["stub-tool"], sarif_file, None

        scanner = _make_scanner(plugin_context, scanner_config, execute_impl)
        post_scan_calls = []

        original_post = scanner._post_scan

        def tracking_post_scan(*a, **kw):
            post_scan_calls.append((a, kw))
            return original_post(*a, **kw)

        scanner._post_scan = tracking_post_scan

        with patch.object(scanner, "_pre_scan", return_value=True):
            scanner.dependencies_satisfied = True
            with patch.object(scanner, "_run_subprocess"):
                scanner.scan(target=target, target_type="source")

        assert len(post_scan_calls) >= 1

    def test_post_scan_called_on_empty_target(self, plugin_context, scanner_config):
        nonexistent = plugin_context.source_dir / "ghost"
        scanner = _make_scanner(plugin_context, scanner_config)
        post_scan_calls = []
        original_post = scanner._post_scan

        def tracking_post_scan(*a, **kw):
            post_scan_calls.append((a, kw))
            return original_post(*a, **kw)

        scanner._post_scan = tracking_post_scan
        scanner.scan(target=nonexistent, target_type="source")
        assert len(post_scan_calls) >= 1


# ---------------------------------------------------------------------------
# _inject_invocation helper
# ---------------------------------------------------------------------------


class TestInjectInvocationHelper:
    def test_attaches_per_result_scanner_details(self, plugin_context, scanner_config):
        """DA r7 #3 — migrated scanners must populate per-result scanner_details.

        Before this fix, the template-method path only injected
        runs[0].invocations[0]; per-result properties.scanner_details and
        tool.driver.properties.scanner_details were left empty for
        bandit/semgrep/opengrep. Downstream consumers reading
        ``result.properties.scanner_details.tool_invocation`` would see
        an empty dict.
        """
        scanner = _make_scanner(plugin_context, scanner_config)
        # Build a SARIF report with one result so we can verify per-result
        # attach reaches it.
        from datetime import datetime, timezone
        from automated_security_helper.schemas.sarif_schema_model import (
            Location,
            Message,
            PhysicalLocation,
            Result,
        )

        location = Location(
            physicalLocation=PhysicalLocation(
                artifactLocation=ArtifactLocation(uri="src/foo.py"),
            )
        )
        result = Result(message=Message(text="finding"), locations=[location])
        report = SarifReport(
            version="2.1.0",
            runs=[
                Run(
                    tool=Tool(driver=ToolComponent(name="stub")),
                    results=[result],
                )
            ],
        )
        scanner.start_time = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        scanner.end_time = datetime(2025, 1, 1, 12, 0, 5, tzinfo=timezone.utc)
        scanner.exit_code = 0
        scanner.errors = []

        final_args = ["stub-tool", "--flag", "val", "src"]
        target = plugin_context.source_dir
        scanner._inject_invocation(report, final_args, target)

        # Tool driver gets scanner_details.tool_invocation populated
        driver_props = report.runs[0].tool.driver.properties
        assert driver_props is not None
        sd = getattr(driver_props, "scanner_details", None)
        assert sd is not None, "tool.driver.properties.scanner_details missing"
        invocation = sd.get("tool_invocation")
        assert invocation is not None, "tool_invocation missing on tool driver"
        assert invocation["command_line"] == "stub-tool --flag val src"
        assert invocation["exit_code"] == 0

        # Per-result properties.scanner_details also populated
        first_result = report.runs[0].results[0]
        assert first_result.properties is not None
        per_result_sd = getattr(first_result.properties, "scanner_details", None)
        assert per_result_sd is not None, (
            "result.properties.scanner_details missing — DA r7 #3 regression"
        )
        per_result_invocation = per_result_sd.get("tool_invocation")
        assert per_result_invocation is not None
        assert per_result_invocation["command_line"] == "stub-tool --flag val src"

    def test_populates_command_line(self, plugin_context, scanner_config):
        scanner = _make_scanner(plugin_context, scanner_config)
        report = SarifReport(
            version="2.1.0",
            runs=[
                Run(
                    tool=Tool(driver=ToolComponent(name="stub")),
                    results=[],
                )
            ],
        )
        from datetime import datetime, timezone

        scanner.start_time = datetime.now(timezone.utc)
        scanner.end_time = datetime.now(timezone.utc)
        scanner.exit_code = 0
        scanner.errors = []

        final_args = ["stub-tool", "--flag", "val"]
        target = plugin_context.source_dir
        scanner._inject_invocation(report, final_args, target)

        inv = report.runs[0].invocations[0]
        # Match legacy GrepScannerBase.scan format: full joined argv.
        assert inv.commandLine == "stub-tool --flag val"

    def test_populates_arguments_list(self, plugin_context, scanner_config):
        scanner = _make_scanner(plugin_context, scanner_config)
        report = SarifReport(
            version="2.1.0",
            runs=[
                Run(
                    tool=Tool(driver=ToolComponent(name="stub")),
                    results=[],
                )
            ],
        )
        from datetime import datetime, timezone

        scanner.start_time = datetime.now(timezone.utc)
        scanner.end_time = datetime.now(timezone.utc)
        scanner.exit_code = 1
        scanner.errors = []

        final_args = ["stub-tool", "--flag", "val"]
        target = plugin_context.source_dir
        scanner._inject_invocation(report, final_args, target)

        inv = report.runs[0].invocations[0]
        assert inv.arguments == ["--flag", "val"]

    def test_execution_successful_for_success_exit_codes(
        self, plugin_context, scanner_config
    ):
        scanner = _make_scanner(plugin_context, scanner_config)
        report = SarifReport(
            version="2.1.0",
            runs=[
                Run(
                    tool=Tool(driver=ToolComponent(name="stub")),
                    results=[],
                )
            ],
        )
        from datetime import datetime, timezone

        scanner.start_time = datetime.now(timezone.utc)
        scanner.end_time = datetime.now(timezone.utc)
        scanner.errors = []

        for exit_code in (0, 1):
            scanner.exit_code = exit_code
            report.runs[0].invocations = []
            scanner._inject_invocation(report, ["stub-tool"], plugin_context.source_dir)
            assert report.runs[0].invocations[0].executionSuccessful is True

    def test_execution_unsuccessful_for_other_exit_codes(
        self, plugin_context, scanner_config
    ):
        scanner = _make_scanner(plugin_context, scanner_config)
        report = SarifReport(
            version="2.1.0",
            runs=[
                Run(
                    tool=Tool(driver=ToolComponent(name="stub")),
                    results=[],
                )
            ],
        )
        from datetime import datetime, timezone

        scanner.start_time = datetime.now(timezone.utc)
        scanner.end_time = datetime.now(timezone.utc)
        scanner.errors = []
        scanner.exit_code = 2

        scanner._inject_invocation(report, ["stub-tool"], plugin_context.source_dir)
        assert report.runs[0].invocations[0].executionSuccessful is False

    def test_custom_success_codes(self, plugin_context, scanner_config):
        scanner = _make_scanner(plugin_context, scanner_config)
        report = SarifReport(
            version="2.1.0",
            runs=[
                Run(
                    tool=Tool(driver=ToolComponent(name="stub")),
                    results=[],
                )
            ],
        )
        from datetime import datetime, timezone

        scanner.start_time = datetime.now(timezone.utc)
        scanner.end_time = datetime.now(timezone.utc)
        scanner.errors = []
        scanner.exit_code = 2

        scanner._inject_invocation(
            report, ["stub-tool"], plugin_context.source_dir, success_codes={0, 1, 2}
        )
        assert report.runs[0].invocations[0].executionSuccessful is True

    def test_noop_when_no_runs(self, plugin_context, scanner_config):
        scanner = _make_scanner(plugin_context, scanner_config)
        report = SarifReport(version="2.1.0", runs=[])
        from datetime import datetime, timezone

        scanner.start_time = datetime.now(timezone.utc)
        scanner.end_time = datetime.now(timezone.utc)
        scanner.errors = []
        scanner.exit_code = 0

        # Should not raise
        scanner._inject_invocation(report, ["stub-tool"], plugin_context.source_dir)
        assert report.runs == []

    def test_command_line_matches_legacy_grep_scanner_format(
        self, plugin_context, scanner_config
    ):
        """Regression: ``_inject_invocation`` MUST emit ``commandLine`` as the
        full joined argv to match the legacy ``GrepScannerBase.scan`` format
        (see ``_grep_scanner_base.py`` ~line 289: ``" ".join(final_args)``).

        Pre-fix the helper emitted only ``final_args[0]``, which made any
        scanner migrated to the new template (e.g. checkov, grype) produce
        SARIF that omitted the arguments from ``commandLine`` — diverging
        from the byte-for-byte parity claim of Track 2.1.
        """
        scanner = _make_scanner(plugin_context, scanner_config)
        report = SarifReport(
            version="2.1.0",
            runs=[
                Run(
                    tool=Tool(driver=ToolComponent(name="stub")),
                    results=[],
                )
            ],
        )
        from datetime import datetime, timezone

        scanner.start_time = datetime.now(timezone.utc)
        scanner.end_time = datetime.now(timezone.utc)
        scanner.exit_code = 0
        scanner.errors = []

        final_args = ["semgrep", "scan", "--config", "p/ci", "--json"]
        target = plugin_context.source_dir
        scanner._inject_invocation(report, final_args, target)

        inv = report.runs[0].invocations[0]
        # Mirror the legacy expression exactly.
        assert inv.commandLine == " ".join(final_args)
        # And, equivalently, the joined argv — NOT the binary alone.
        assert inv.commandLine == "semgrep scan --config p/ci --json"
        assert inv.commandLine != final_args[0]

    def test_command_line_simulates_checkov_grype_post_migration(
        self, plugin_context, scanner_config
    ):
        """Regression for migrated scanners (checkov, grype, commit 8c9c27e).

        Pre-fix, a checkov SARIF Invocation would emit only ``"checkov"``
        for ``commandLine`` and lose all argv context. Post-fix, the
        emission must be the full joined argv string — what the legacy
        per-scanner overrides would have produced.
        """
        scanner = _make_scanner(plugin_context, scanner_config)
        report = SarifReport(
            version="2.1.0",
            runs=[
                Run(
                    tool=Tool(driver=ToolComponent(name="checkov")),
                    results=[],
                )
            ],
        )
        from datetime import datetime, timezone

        scanner.start_time = datetime.now(timezone.utc)
        scanner.end_time = datetime.now(timezone.utc)
        scanner.exit_code = 0
        scanner.errors = []

        final_args = [
            "checkov",
            "-d",
            "/work/src",
            "--output",
            "sarif",
            "--output-file-path",
            "/work/out",
        ]
        target = plugin_context.source_dir
        scanner._inject_invocation(report, final_args, target)

        inv = report.runs[0].invocations[0]
        # Hardcoded legacy expectation (matches ``" ".join(final_args)``
        # that the pre-migration per-scanner _post_scan emitted).
        expected = "checkov -d /work/src --output sarif --output-file-path /work/out"
        assert inv.commandLine == expected


# ---------------------------------------------------------------------------
# A tool that failed hard, and wrote nothing
# ---------------------------------------------------------------------------


class TestNonZeroExitWithAnEmptyResultsFile:
    """The empty-results branch reads the exit code and then discards it.

    ``scan()`` at ``scanner_plugin.py:608-621`` handles an existing-but-empty
    results file by interpolating ``self.exit_code`` into a warning string and
    then ``return self._handle_empty_results()``. The exit code reaches human
    -readable text and nothing else: the return is a normal one rather than a
    raise, so ``_inject_invocation`` at ``:626`` -- the only place that computes
    ``executionSuccessful=(self.exit_code in success_codes)`` -- is never reached
    on this path.

    Measured on grype with an empty-but-writable cache and its update endpoint
    refused: grype logs ``failed to load vulnerability db``, exits 1 and writes a
    zero-byte report, and ASH grades it ``PASSED ... 0 findings`` and exits 0
    with ``--fail-on-incomplete-scanners`` already passed. The stub below
    reproduces the shape with grype's own ``success_exit_codes = {0, 2}``, so
    exit 1 is a failure code for it rather than the base class's accepted 1.

    The consequence for the completeness gate is pinned separately, in
    ``tests/unit/interactions/test_fail_on_incomplete_scanners.py``:
    ``TestTheGateCannotSeeAHardFailureGradedPassed``.
    """

    @staticmethod
    def _failed_tool_writing_an_empty_file(plugin_context, scanner_config, target):
        """A scanner whose tool exits 1 and leaves a zero-byte results file."""

        class FailedToolScanner(ScannerPluginBase):
            offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED
            # grype's own set, so 1 is genuinely not an accepted code here. With
            # the base class default of {0, 1} an exit of 1 would be a success and
            # the test would assert nothing.
            success_exit_codes: ClassVar[set] = {0, 2}

            def model_post_init(self, context):
                self.command = "failing-tool"
                self.tool_type = ScannerToolType.SAST
                super().model_post_init(context)

            def validate_plugin_dependencies(self) -> bool:
                return True

            def _execute_scan(self, target, target_type, global_ignore_paths):
                results_dir = self.results_dir / target_type
                results_dir.mkdir(parents=True, exist_ok=True)
                results_file = results_dir / "failing.sarif"
                results_file.write_text("", encoding="utf-8")
                return ["failing-tool", "--scan"], results_file, None

        scanner = FailedToolScanner(config=scanner_config, context=plugin_context)
        scanner.exit_code = 1
        scanner.errors = [
            "ERROR failed to load vulnerability db: database does not exist"
        ]
        return scanner

    def test_it_returns_a_report_rather_than_raising(
        self, plugin_context, scanner_config, tmp_path
    ):
        """CHARACTERIZATION: asserts the CURRENT behavior, which is wrong.

        A tool that exited with a code its own ``success_exit_codes`` excludes,
        having written no output, yields a valid empty SARIF and no exception.
        Asserted rather than corrected because correcting it is a change to the
        shared template every scanner inherits, not to this phase's flag.

        Reverse-reads as the alarm for the fix: when the empty-results branch
        starts consulting the exit code, this test reddens, and whoever is
        holding it should update it and drop the xfail below.
        """
        target = tmp_path / "src"
        target.mkdir()
        (target / "file.py").write_text("x = 1")
        scanner = self._failed_tool_writing_an_empty_file(
            plugin_context, scanner_config, target
        )

        with patch.object(scanner, "_pre_scan", return_value=True):
            scanner.dependencies_satisfied = True
            with patch.object(scanner, "_run_subprocess"):
                report = scanner.scan(target=target, target_type="source")

        assert isinstance(report, SarifReport), (
            "the empty-results branch returns _handle_empty_results(), so a hard "
            "tool failure produces a report rather than raising ScannerError"
        )
        assert report.runs == [], (
            "_handle_empty_results builds SarifReport(runs=[]). Note for whoever "
            "fixes this: moving _inject_invocation ahead of the early return is "
            "not sufficient on its own, because it no-ops on an empty runs list. "
            "There is no run to attach an invocation to. Grype overrides "
            "_ensure_runs to synthesize one, and that override is also only on "
            "the parse path."
        )

    def test_no_invocation_records_the_failure(
        self, plugin_context, scanner_config, tmp_path
    ):
        """CHARACTERIZATION: the exit code survives only as log text.

        Separate from the report-shape assertion above because this is the fact
        that makes the failure invisible to every downstream reader rather than
        merely unusual: ``executionSuccessful`` is the one field in the SARIF that
        would carry it, and no invocation is emitted at all.
        """
        target = tmp_path / "src"
        target.mkdir()
        (target / "file.py").write_text("x = 1")
        scanner = self._failed_tool_writing_an_empty_file(
            plugin_context, scanner_config, target
        )

        with patch.object(scanner, "_pre_scan", return_value=True):
            scanner.dependencies_satisfied = True
            with patch.object(scanner, "_run_subprocess"):
                report = scanner.scan(target=target, target_type="source")

        invocations = [inv for run in report.runs for inv in (run.invocations or [])]
        assert invocations == [], (
            "if an invocation now appears here the early return was changed -- "
            "check whether executionSuccessful is False, and drop the xfail on "
            "test_a_failed_tool_is_not_reported_as_a_successful_execution"
        )

    @pytest.mark.xfail(
        strict=True,
        reason=(
            "scan() returns _handle_empty_results() for an empty results file "
            "before reaching _inject_invocation, which is the only place "
            "executionSuccessful is computed from the exit code. So a tool that "
            "exited 1 with success_exit_codes={0, 2} produces a report that "
            "asserts nothing about its own failure, determine_status derives "
            "PASSED from its zero findings, and fail_on_incomplete_scanners has "
            "no ERROR or MISSING status to find. Remove this xfail once the "
            "empty-results branch consults the exit code."
        ),
    )
    def test_a_failed_tool_is_not_reported_as_a_successful_execution(
        self, plugin_context, scanner_config, tmp_path
    ):
        """The behavior this SHOULD have, recorded so the gap is not only prose.

        Either outcome would do: raising, or emitting an invocation with
        ``executionSuccessful=False``. This asserts the weaker of the two -- that
        the run does not read as successful -- so that whichever way the fix goes,
        this passes.
        """
        target = tmp_path / "src"
        target.mkdir()
        (target / "file.py").write_text("x = 1")
        scanner = self._failed_tool_writing_an_empty_file(
            plugin_context, scanner_config, target
        )

        with patch.object(scanner, "_pre_scan", return_value=True):
            scanner.dependencies_satisfied = True
            with patch.object(scanner, "_run_subprocess"):
                report = scanner.scan(target=target, target_type="source")

        invocations = [inv for run in report.runs for inv in (run.invocations or [])]
        assert invocations, "a scan that ran a tool should record an invocation"
        assert all(inv.executionSuccessful is False for inv in invocations)

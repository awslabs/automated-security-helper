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
from typing import ClassVar, List, Literal, Set
from unittest.mock import MagicMock, patch

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
    Invocation,
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

    def test_returns_true_on_empty_directory(self, plugin_context, scanner_config, tmp_path):
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        scanner = _make_scanner(plugin_context, scanner_config)
        result = scanner.scan(target=empty_dir, target_type="source")
        assert result is True


# ---------------------------------------------------------------------------
# _pre_scan failure guard
# ---------------------------------------------------------------------------


class TestTemplateScanPreScanFailure:
    def test_returns_false_when_pre_scan_fails(self, plugin_context, scanner_config, tmp_path):
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
    def test_calls_execute_scan_hook_with_target(self, plugin_context, scanner_config, tmp_path):
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
    def test_injects_invocation_into_sarif_runs(self, plugin_context, scanner_config, tmp_path):
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
        assert inv.commandLine == "stub-tool"
        assert inv.arguments == ["--arg", "val"]

    def test_invocation_exit_code_recorded(self, plugin_context, scanner_config, tmp_path):
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
    def test_post_scan_called_on_success(self, plugin_context, scanner_config, tmp_path):
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
        assert inv.commandLine == "stub-tool"

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

    def test_execution_successful_for_success_exit_codes(self, plugin_context, scanner_config):
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

    def test_execution_unsuccessful_for_other_exit_codes(self, plugin_context, scanner_config):
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
            report, ["stub-tool"], plugin_context.source_dir
        )
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

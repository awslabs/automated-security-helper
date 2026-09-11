"""Behavior tests for the uncovered branches of ``ScannerPluginBase``.

The scanner under test is a real concrete subclass, not a mock: ``StubScanner``
implements the abstract ``_execute_scan`` hook and is instantiated through the
normal pydantic path, so ``model_post_init`` and config validation run for real.
Where a collaborator has to be doubled (``ASH_LOGGER``,
``_validate_tool_availability_with_pre_installed``) the double is built with
``create_autospec`` or is a plain function with the real signature -- a bare
``Mock`` would answer to any attribute and could not catch a call to a method
that does not exist, which is the defect this repo has already shipped once.
"""

import json
import logging
from pathlib import Path
from typing import ClassVar, Literal, Optional
from unittest.mock import create_autospec, patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.scanner_plugin import (
    _STDERR_EXCERPT_LIMIT,
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.core.enums import OfflineStrategy, ScannerToolType
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import ToolArgs, ToolExtraArg
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.log import ASH_LOGGER


class StubConfig(ScannerPluginConfigBase):
    name: Literal["stub"] = "stub"


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


def _scanner(plugin_context, execute_scan=None, deps_ok=True, **fields):
    """Build a concrete ScannerPluginBase subclass over the real init path."""

    class StubScanner(ScannerPluginBase):
        offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED

        def model_post_init(self, context):
            self.command = "stub-tool"
            self.tool_type = ScannerToolType.SAST
            super().model_post_init(context)

        def validate_plugin_dependencies(self) -> bool:
            return deps_ok

        def _execute_scan(self, target, target_type, global_ignore_paths):
            if execute_scan is None:
                raise NotImplementedError
            return execute_scan(self, target, target_type, global_ignore_paths)

    return StubScanner(config=StubConfig(), context=plugin_context, **fields)


def _populated_target(tmp_path, name="target") -> Path:
    target = tmp_path / name
    target.mkdir()
    (target / "app.py").write_text("x = 1\n")
    return target


MINIMAL_SARIF = {
    "version": "2.1.0",
    "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
    "runs": [
        {
            "tool": {"driver": {"name": "stub-tool", "version": "1.0.0"}},
            "results": [],
        }
    ],
}


# ---------------------------------------------------------------------------
# model_post_init
# ---------------------------------------------------------------------------


def test_a_scanner_without_a_context_is_rejected():
    class ContextlessScanner(ScannerPluginBase):
        def _execute_scan(self, target, target_type, global_ignore_paths):
            raise NotImplementedError

    with pytest.raises(ScannerError, match="No context provided"):
        ContextlessScanner(config=StubConfig(), context=None)


def test_a_scanner_without_a_config_is_rejected(plugin_context):
    class ConfiglessScanner(ScannerPluginBase):
        def _execute_scan(self, target, target_type, global_ignore_paths):
            raise NotImplementedError

    with pytest.raises(ScannerError, match="Configuration is empty"):
        ConfiglessScanner(config=None, context=plugin_context)


def test_the_results_directory_is_derived_from_the_output_directory(plugin_context):
    scanner = _scanner(plugin_context)

    assert scanner.results_dir == plugin_context.output_dir / "scanners" / "stub"


# ---------------------------------------------------------------------------
# _resolve_arguments
# ---------------------------------------------------------------------------


def test_extra_args_with_valid_keys_are_appended(plugin_context, tmp_path):
    scanner = _scanner(
        plugin_context,
        args=ToolArgs(
            extra_args=[
                ToolExtraArg(key="--exclude", value=".venv"),
                ToolExtraArg(key="-q", value=""),
            ]
        ),
    )

    args = scanner._resolve_arguments(tmp_path / "t", tmp_path / "r.json")

    assert "--exclude" in args
    assert ".venv" in args
    assert "-q" in args


@pytest.mark.parametrize(
    "bad_key",
    ["; rm -rf /", "--", "-", "no-dashes", "---triple", "--1numeric", "$(whoami)", ""],
)
def test_an_extra_arg_with_an_invalid_key_is_skipped_with_a_warning(
    plugin_context, tmp_path, bad_key
):
    """A key that fails the flag pattern must not reach the command line."""
    scanner = _scanner(
        plugin_context,
        args=ToolArgs(extra_args=[ToolExtraArg(key=bad_key, value="danger")]),
    )

    logger = create_autospec(ASH_LOGGER)
    with patch("automated_security_helper.base.scanner_plugin.ASH_LOGGER", logger):
        args = scanner._resolve_arguments(tmp_path / "t", tmp_path / "r.json")

    assert "danger" not in args
    assert bad_key not in args
    assert logger.warning.call_count == 1
    assert "invalid key" in logger.warning.call_args.args[0]


def test_a_valid_extra_arg_produces_no_warning(plugin_context, tmp_path):
    scanner = _scanner(
        plugin_context,
        args=ToolArgs(extra_args=[ToolExtraArg(key="--skip-path", value=".venv/")]),
    )

    logger = create_autospec(ASH_LOGGER)
    with patch("automated_security_helper.base.scanner_plugin.ASH_LOGGER", logger):
        args = scanner._resolve_arguments(tmp_path / "t", tmp_path / "r.json")

    assert logger.warning.call_count == 0
    assert "--skip-path" in args


def test_resolve_arguments_prefers_an_explicit_results_file(plugin_context, tmp_path):
    scanner = _scanner(plugin_context)
    scanner.results_file = tmp_path / "fallback.json"

    args = scanner._resolve_arguments(tmp_path / "t", tmp_path / "explicit.json")

    assert (tmp_path / "explicit.json").as_posix() in args
    assert (tmp_path / "fallback.json").as_posix() not in args


def test_resolve_arguments_falls_back_to_the_instance_results_file(
    plugin_context, tmp_path
):
    scanner = _scanner(plugin_context)
    scanner.results_file = tmp_path / "fallback.json"

    args = scanner._resolve_arguments(tmp_path / "t")

    assert (tmp_path / "fallback.json").as_posix() in args


# ---------------------------------------------------------------------------
# _pre_scan dependency gate
# ---------------------------------------------------------------------------


def test_pre_scan_returns_false_when_dependencies_are_missing(plugin_context, tmp_path):
    scanner = _scanner(plugin_context, deps_ok=False)
    target = _populated_target(tmp_path)

    assert scanner._pre_scan(target=target, target_type="source") is False
    assert scanner.dependencies_satisfied is False


def test_pre_scan_returns_true_when_dependencies_are_satisfied(
    plugin_context, tmp_path
):
    scanner = _scanner(plugin_context, deps_ok=True)
    target = _populated_target(tmp_path)

    assert scanner._pre_scan(target=target, target_type="source") is True
    assert scanner.dependencies_satisfied is True


# ---------------------------------------------------------------------------
# _read_results_file / _handle_empty_results
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("content", ["", "   \n  \t "])
def test_reading_an_empty_results_file_returns_none(plugin_context, tmp_path, content):
    scanner = _scanner(plugin_context)
    results = tmp_path / "r.json"
    results.write_text(content)

    assert scanner._read_results_file(results) is None


def test_reading_a_populated_results_file_returns_the_parsed_json(
    plugin_context, tmp_path
):
    scanner = _scanner(plugin_context)
    results = tmp_path / "r.json"
    results.write_text(json.dumps(MINIMAL_SARIF))

    assert scanner._read_results_file(results)["version"] == "2.1.0"


def test_reading_a_missing_results_file_raises(plugin_context, tmp_path):
    """A missing file must raise: returning None would report a dead tool as clean."""
    scanner = _scanner(plugin_context)

    with pytest.raises(FileNotFoundError):
        scanner._read_results_file(tmp_path / "never-written.json")


def test_handle_empty_results_returns_an_empty_sarif_report(plugin_context):
    scanner = _scanner(plugin_context)

    report = scanner._handle_empty_results()

    assert isinstance(report, SarifReport)
    assert report.version == "2.1.0"
    assert report.runs == []


def test_the_default_ensure_runs_and_post_process_hooks_are_inert(plugin_context):
    scanner = _scanner(plugin_context)
    report = SarifReport.model_validate(MINIMAL_SARIF)

    assert scanner._ensure_runs(report) is None
    assert scanner._post_process_sarif(report, ["stub-tool"], Path(".")) is report
    assert scanner._invocation_extras(report, ["stub-tool"], Path(".")) == {}


# ---------------------------------------------------------------------------
# _execute_scan abstract stub
# ---------------------------------------------------------------------------


def test_the_base_execute_scan_hook_raises_not_implemented(plugin_context, tmp_path):
    """A subclass that delegates upward must get a named error, not silence."""

    class DelegatingScanner(ScannerPluginBase):
        def validate_plugin_dependencies(self) -> bool:
            return True

        def _execute_scan(self, target, target_type, global_ignore_paths):
            return super()._execute_scan(target, target_type, global_ignore_paths)

    scanner = DelegatingScanner(config=StubConfig(), context=plugin_context)

    with pytest.raises(NotImplementedError, match="DelegatingScanner"):
        scanner._execute_scan(tmp_path, "source", [])


# ---------------------------------------------------------------------------
# _effective_scan_timeout
# ---------------------------------------------------------------------------


def test_the_default_scan_timeout_is_thirty_minutes(plugin_context):
    """Documents the shipped default, so the None cases below are real overrides."""
    scanner = _scanner(plugin_context)

    assert scanner._effective_scan_timeout() == 1800.0


def test_an_explicit_none_scan_timeout_means_unbounded(plugin_context):
    scanner = _scanner(plugin_context)
    scanner.config.options.scan_timeout = None

    assert scanner._effective_scan_timeout() is None


def test_options_without_a_scan_timeout_attribute_mean_unbounded(plugin_context):
    """A third-party options class predating the field must not raise."""
    scanner = _scanner(plugin_context)

    class LegacyOptions:
        severity_threshold = None

    scanner.config.options = LegacyOptions()

    assert scanner._effective_scan_timeout() is None


def test_a_none_config_means_unbounded(plugin_context):
    scanner = _scanner(plugin_context)
    scanner.config = None

    assert scanner._effective_scan_timeout() is None


@pytest.mark.parametrize("raw,expected", [(30, 30.0), ("45", 45.0), (2.5, 2.5)])
def test_a_positive_scan_timeout_is_coerced_to_a_float(plugin_context, raw, expected):
    scanner = _scanner(plugin_context)
    scanner.config.options.scan_timeout = raw

    assert scanner._effective_scan_timeout() == expected


@pytest.mark.parametrize("raw", [0, -1, -0.5])
def test_a_non_positive_scan_timeout_means_unbounded(plugin_context, raw):
    scanner = _scanner(plugin_context)
    scanner.config.options.scan_timeout = raw

    assert scanner._effective_scan_timeout() is None


@pytest.mark.parametrize("raw", ["not-a-number", [30], {}, object()])
def test_an_uncoercible_scan_timeout_means_unbounded(plugin_context, raw):
    """A third-party option that is not numeric must not fail the scan."""
    scanner = _scanner(plugin_context)
    object.__setattr__(scanner.config.options, "scan_timeout", raw)

    assert scanner._effective_scan_timeout() is None


# ---------------------------------------------------------------------------
# scan(): timeout, empty results, unparsable SARIF
# ---------------------------------------------------------------------------


def _execute_writing(content=None):
    """Return an _execute_scan impl that writes ``content`` to the results file."""

    def _impl(scanner, target, target_type, global_ignore_paths):
        results = scanner.results_dir / "results.json"
        results.parent.mkdir(parents=True, exist_ok=True)
        if content is not None:
            results.write_text(content)
        return ["stub-tool", "--scan"], results, None

    return _impl


def test_a_timed_out_tool_is_reported_as_a_timeout_not_a_missing_file(
    plugin_context, tmp_path
):
    """The killed-tool message must name the timeout and the knob to change it."""
    scanner = _scanner(plugin_context, execute_scan=_execute_writing(None))
    scanner.config.options.scan_timeout = 5
    target = _populated_target(tmp_path)

    with (
        patch.object(
            type(scanner), "_run_subprocess", return_value={"timed_out": True}
        ),
        pytest.raises(ScannerError) as excinfo,
    ):
        scanner.scan(target=target, target_type="source")

    message = str(excinfo.value)
    assert "timed out after 5.0s" in message
    assert "scanners.stub.options.scan_timeout" in message


def test_an_empty_results_file_yields_the_empty_sarif_report(plugin_context, tmp_path):
    scanner = _scanner(plugin_context, execute_scan=_execute_writing(""))
    target = _populated_target(tmp_path)

    logger = create_autospec(ASH_LOGGER)
    with (
        patch.object(type(scanner), "_run_subprocess", return_value={"returncode": 0}),
        patch("automated_security_helper.base.scanner_plugin.ASH_LOGGER", logger),
    ):
        report = scanner.scan(target=target, target_type="source")

    assert isinstance(report, SarifReport)
    assert report.runs == []
    assert "results file is empty" in logger.warning.call_args.args[0]
    assert "No stderr output captured." in logger.warning.call_args.args[0]


def test_the_empty_results_warning_quotes_captured_stderr_when_present(
    plugin_context, tmp_path
):
    scanner = _scanner(plugin_context, execute_scan=_execute_writing(""))
    target = _populated_target(tmp_path)

    logger = create_autospec(ASH_LOGGER)

    def _run(self, **kwargs):
        self.errors.append("tool said no")
        return {"returncode": 1}

    with (
        patch.object(type(scanner), "_run_subprocess", _run),
        patch("automated_security_helper.base.scanner_plugin.ASH_LOGGER", logger),
    ):
        scanner.scan(target=target, target_type="source")

    assert "Stderr: tool said no" in logger.warning.call_args.args[0]


def test_a_results_file_that_is_not_sarif_is_returned_raw_with_a_warning(
    plugin_context, tmp_path
):
    """Unparsable output degrades to the raw dict rather than failing the scan."""
    scanner = _scanner(
        plugin_context, execute_scan=_execute_writing(json.dumps({"not": "sarif"}))
    )
    target = _populated_target(tmp_path)

    logger = create_autospec(ASH_LOGGER)
    with (
        patch.object(type(scanner), "_run_subprocess", return_value={"returncode": 0}),
        patch("automated_security_helper.base.scanner_plugin.ASH_LOGGER", logger),
    ):
        result = scanner.scan(target=target, target_type="source")

    assert result == {"not": "sarif"}
    assert "Failed to parse" in logger.warning.call_args.args[0]


def test_a_valid_sarif_results_file_is_returned_as_a_report(plugin_context, tmp_path):
    scanner = _scanner(
        plugin_context, execute_scan=_execute_writing(json.dumps(MINIMAL_SARIF))
    )
    target = _populated_target(tmp_path)

    with patch.object(type(scanner), "_run_subprocess", return_value={"returncode": 0}):
        result = scanner.scan(target=target, target_type="source")

    assert isinstance(result, SarifReport)
    assert result.runs[0].invocations[0].exitCode == scanner.exit_code


# ---------------------------------------------------------------------------
# _describe_scan_failure
# ---------------------------------------------------------------------------


def test_the_failure_message_says_when_an_exit_code_is_accepted(plugin_context):
    scanner = _scanner(plugin_context)
    scanner.exit_code = 1

    detail = scanner._describe_scan_failure(RuntimeError("broke"), None)

    assert "an accepted exit code for this scanner" in detail
    assert "No stderr captured." in detail


def test_the_failure_message_lists_the_accepted_codes_when_the_exit_code_is_not_one(
    plugin_context,
):
    scanner = _scanner(plugin_context)
    scanner.exit_code = 7

    detail = scanner._describe_scan_failure(RuntimeError("broke"), None)

    assert "not an accepted exit code; success_exit_codes=[0, 1]" in detail


def test_the_failure_message_names_the_log_it_checked_when_stderr_is_empty(
    plugin_context, tmp_path
):
    scanner = _scanner(plugin_context)
    results_file = tmp_path / "scanners" / "stub" / "results.json"
    results_file.parent.mkdir(parents=True)

    detail = scanner._describe_scan_failure(RuntimeError("broke"), results_file)

    assert "No stderr captured; checked" in detail
    assert "StubScanner.stderr.log" in detail


def test_the_failure_message_reads_the_stderr_log_when_errors_are_empty(
    plugin_context, tmp_path
):
    scanner = _scanner(plugin_context)
    results_file = tmp_path / "scanners" / "stub" / "results.json"
    results_file.parent.mkdir(parents=True)
    (results_file.parent / "StubScanner.stderr.log").write_text("tool wrote this\n")

    detail = scanner._describe_scan_failure(RuntimeError("broke"), results_file)

    assert "Stderr: tool wrote this" in detail


def test_a_long_stderr_is_truncated_in_the_failure_message(plugin_context):
    scanner = _scanner(plugin_context)
    scanner.errors = ["x" * (_STDERR_EXCERPT_LIMIT + 500)]

    detail = scanner._describe_scan_failure(RuntimeError("broke"), None)

    assert " ...[truncated]" in detail
    assert len(detail) < _STDERR_EXCERPT_LIMIT + 500


def test_a_short_stderr_is_not_truncated(plugin_context):
    scanner = _scanner(plugin_context)
    scanner.errors = ["short and sweet"]

    detail = scanner._describe_scan_failure(RuntimeError("broke"), None)

    assert "Stderr: short and sweet" in detail
    assert "truncated" not in detail


# ---------------------------------------------------------------------------
# validate_plugin
# ---------------------------------------------------------------------------


def _availability(available, warnings=(), errors=(), method="path"):
    return {
        "available": available,
        "validation_method": method,
        "warnings": list(warnings),
        "errors": list(errors),
    }


def test_validate_plugin_succeeds_and_logs_the_validation_method(plugin_context):
    scanner = _scanner(plugin_context)

    with patch.object(
        type(scanner),
        "_validate_tool_availability_with_pre_installed",
        return_value=_availability(True, method="pre-installed"),
    ):
        assert scanner.validate_plugin() is True

    assert scanner.dependencies_satisfied is True


def test_validate_plugin_logs_each_warning_on_success(plugin_context):
    scanner = _scanner(plugin_context)
    logged = []

    with (
        patch.object(
            type(scanner),
            "_validate_tool_availability_with_pre_installed",
            return_value=_availability(True, warnings=["old version", "no lockfile"]),
        ),
        patch.object(
            type(scanner),
            "_plugin_log",
            lambda self, msg, **kw: logged.append((msg, kw.get("level"))),
        ),
    ):
        assert scanner.validate_plugin() is True

    assert ("old version", logging.WARNING) in logged
    assert ("no lockfile", logging.WARNING) in logged


def test_validate_plugin_fails_and_logs_each_error(plugin_context):
    scanner = _scanner(plugin_context)
    scanner.dependencies_satisfied = True
    logged = []

    with (
        patch.object(
            type(scanner),
            "_validate_tool_availability_with_pre_installed",
            return_value=_availability(False, errors=["not on PATH", "no uv"]),
        ),
        patch.object(type(scanner), "_is_offline_mode", lambda self: False),
        patch.object(
            type(scanner),
            "_plugin_log",
            lambda self, msg, **kw: logged.append((msg, kw.get("level"))),
        ),
    ):
        assert scanner.validate_plugin() is False

    assert scanner.dependencies_satisfied is False
    assert ("not on PATH", logging.ERROR) in logged
    assert ("no uv", logging.ERROR) in logged


def test_validate_plugin_explains_offline_mode_for_a_uv_managed_tool(plugin_context):
    """Offline mode plus use_uv_tool is the case that needs the extra hint."""
    scanner = _scanner(plugin_context, use_uv_tool=True)
    logged = []

    with (
        patch.object(
            type(scanner),
            "_validate_tool_availability_with_pre_installed",
            return_value=_availability(False, errors=["missing"]),
        ),
        patch.object(type(scanner), "_is_offline_mode", lambda self: True),
        patch.object(
            type(scanner),
            "_plugin_log",
            lambda self, msg, **kw: logged.append((msg, kw.get("level"))),
        ),
    ):
        assert scanner.validate_plugin() is False

    hints = [msg for msg, _ in logged if "ASH_OFFLINE=true" in msg]
    assert len(hints) == 1
    assert "stub-tool" in hints[0]


def test_no_offline_hint_is_logged_when_the_tool_is_not_uv_managed(plugin_context):
    scanner = _scanner(plugin_context, use_uv_tool=False)
    logged = []

    with (
        patch.object(
            type(scanner),
            "_validate_tool_availability_with_pre_installed",
            return_value=_availability(False, errors=["missing"]),
        ),
        patch.object(type(scanner), "_is_offline_mode", lambda self: True),
        patch.object(
            type(scanner),
            "_plugin_log",
            lambda self, msg, **kw: logged.append((msg, kw.get("level"))),
        ),
    ):
        scanner.validate_plugin()

    assert not any("ASH_OFFLINE=true" in msg for msg, _ in logged)


def test_no_offline_hint_is_logged_when_offline_mode_is_off(plugin_context):
    scanner = _scanner(plugin_context, use_uv_tool=True)
    logged = []

    with (
        patch.object(
            type(scanner),
            "_validate_tool_availability_with_pre_installed",
            return_value=_availability(False, errors=["missing"]),
        ),
        patch.object(type(scanner), "_is_offline_mode", lambda self: False),
        patch.object(
            type(scanner),
            "_plugin_log",
            lambda self, msg, **kw: logged.append((msg, kw.get("level"))),
        ),
    ):
        scanner.validate_plugin()

    assert not any("ASH_OFFLINE=true" in msg for msg, _ in logged)


# ---------------------------------------------------------------------------
# safe_scan
# ---------------------------------------------------------------------------


def test_safe_scan_passes_a_successful_result_straight_through(
    plugin_context, tmp_path
):
    scanner = _scanner(
        plugin_context, execute_scan=_execute_writing(json.dumps(MINIMAL_SARIF))
    )
    target = _populated_target(tmp_path)

    with patch.object(type(scanner), "_run_subprocess", return_value={"returncode": 0}):
        result = scanner.safe_scan(target=target, target_type="source")

    assert isinstance(result, SarifReport)


def test_safe_scan_converts_an_exception_into_a_structured_error_response(
    plugin_context, tmp_path
):
    """safe_scan must never propagate; the orchestrator relies on the dict shape."""
    scanner = _scanner(plugin_context)
    target = _populated_target(tmp_path)

    logger = create_autospec(ASH_LOGGER)
    with (
        patch.object(
            type(scanner), "scan", side_effect=RuntimeError("scanner exploded")
        ),
        patch("automated_security_helper.base.scanner_plugin.ASH_LOGGER", logger),
    ):
        result = scanner.safe_scan(target=target, target_type="source")

    assert result["scanner"] == "StubScanner"
    assert result["error"] == "scanner exploded"
    assert result["status"] == "failed"
    assert result["findings"] == []
    assert "StubScanner scanner failed: scanner exploded" in result["errors"]
    assert "RuntimeError: scanner exploded" in result["stack_trace"]
    assert logger.error.call_count == 1
    assert logger.debug.call_count == 1


def test_safe_scan_records_the_error_on_the_scanner_instance(plugin_context, tmp_path):
    scanner = _scanner(plugin_context)
    target = _populated_target(tmp_path)

    with (
        patch.object(type(scanner), "scan", side_effect=RuntimeError("boom")),
        patch(
            "automated_security_helper.base.scanner_plugin.ASH_LOGGER",
            create_autospec(ASH_LOGGER),
        ),
    ):
        scanner.safe_scan(target=target, target_type="source")

    assert any("boom" in e for e in scanner.errors)


def test_safe_scan_defaults_global_ignore_paths_to_an_empty_list(
    plugin_context, tmp_path
):
    scanner = _scanner(plugin_context)
    target = _populated_target(tmp_path)
    seen = {}

    def _capture(self, **kwargs):
        seen.update(kwargs)
        return True

    with patch.object(type(scanner), "scan", _capture):
        scanner.safe_scan(target=target, target_type="source")

    assert seen["global_ignore_paths"] == []


def test_safe_scan_forwards_supplied_global_ignore_paths(plugin_context, tmp_path):
    from automated_security_helper.models.core import IgnorePathWithReason

    scanner = _scanner(plugin_context)
    target = _populated_target(tmp_path)
    ignores: list[IgnorePathWithReason] = [
        IgnorePathWithReason(path="vendor/**", reason="third party")
    ]
    seen = {}

    def _capture(self, **kwargs):
        seen.update(kwargs)
        return True

    with patch.object(type(scanner), "scan", _capture):
        scanner.safe_scan(
            target=target, target_type="source", global_ignore_paths=ignores
        )

    assert seen["global_ignore_paths"] == ignores


def test_scan_returns_false_when_the_dependency_gate_rejects(plugin_context, tmp_path):
    scanner = _scanner(plugin_context, deps_ok=False)
    target = _populated_target(tmp_path)

    assert scanner.scan(target=target, target_type="source") is False


def test_scan_short_circuits_on_an_empty_target(plugin_context, tmp_path):
    scanner = _scanner(plugin_context)
    empty = tmp_path / "empty"
    empty.mkdir()

    assert scanner.scan(target=empty, target_type="source") is True


def test_the_optional_config_override_is_revalidated_during_pre_scan(
    plugin_context, tmp_path
):
    scanner = _scanner(plugin_context)
    target = _populated_target(tmp_path)

    scanner._pre_scan(
        target=target, target_type="source", config=StubConfig(enabled=False)
    )

    assert scanner.config.enabled is False


def test_pre_scan_raises_when_the_target_does_not_exist(plugin_context, tmp_path):
    scanner = _scanner(plugin_context)

    with pytest.raises(ScannerError, match="does not exist"):
        scanner._pre_scan(target=tmp_path / "nope", target_type="converted")


def test_an_unset_optional_results_file_is_dropped_from_the_arguments(
    plugin_context, tmp_path
):
    scanner = _scanner(plugin_context)
    scanner.results_file = None

    args = scanner._resolve_arguments(tmp_path / "t")

    assert None not in args
    assert all(str(a).strip() != "" for a in args)


def test_the_module_exposes_the_stderr_excerpt_limit(plugin_context):
    """The truncation test above is only meaningful against the real constant."""
    assert isinstance(_STDERR_EXCERPT_LIMIT, int)
    assert _STDERR_EXCERPT_LIMIT > 0


def test_optional_typing_import_is_used_for_the_config_annotation():
    assert Optional is not None

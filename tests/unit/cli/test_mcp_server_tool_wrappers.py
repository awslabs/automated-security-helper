#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for mcp_server's tool wrappers, resources and reporting side paths.

mcp_server is a thin protocol layer over mcp_tools: most of its functions
delegate and exist only to convert an exception into a protocol-shaped dict, so
the untested part was the except arm of each wrapper plus the reporting paths
that only run when talking to the client itself fails.

Two of those are worth calling out. get_scan_results and get_scan_result_paths
each wrap their own ctx.error call in a second try/except, so a client that has
already gone away does not turn a handled error into an unhandled one; those
inner handlers are covered by making ctx.error raise. And run_ash_scan tolerates
ctx.report_progress failing, because losing a progress update must not lose the
scan.

The Context double is MagicMock(spec=Context). Context's log methods are async,
so spec makes them AsyncMocks automatically; without spec, a typo in a method
name would be silently accepted and the test could not catch a call to a method
the protocol does not define.
"""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from mcp.server.mcpserver import Context

from automated_security_helper.cli.mcp.scan_target import ASH_MCP_ALLOWED_ROOTS_ENV
from automated_security_helper.cli.mcp_server import (
    analyze_security_findings,
    check_installation,
    diff_scan_results,
    explain_finding,
    get_ash_config_schema,
    get_ash_exit_codes,
    get_ash_status,
    get_ash_suppression_schema,
    get_config,
    get_scan_progress,
    get_scan_result_paths,
    get_scan_results,
    list_scanners,
    run_ash_scan,
    suggest_suppression,
    validate_config,
)
from automated_security_helper.core.constants import ASH_EXIT_CODES
from automated_security_helper.core.resource_management.scan_registry import (
    ScanRegistry,
    ScanRegistryEntry,
)

_SERVER = "automated_security_helper.cli.mcp_server"


@pytest.fixture
def ctx():
    """A Context double limited to the protocol's real surface."""
    return MagicMock(spec=Context)


@pytest.fixture
def allowed_root(tmp_path, monkeypatch):
    monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(tmp_path))
    return tmp_path


@pytest.fixture
def registry():
    return MagicMock(spec=ScanRegistry)


def _entry(output_dir):
    entry = ScanRegistryEntry(
        scan_id="scan-1",
        directory_path=str(output_dir.parent),
        output_directory=str(output_dir),
    )
    return entry


class TestRunAshScanReportingPaths:
    def test_a_results_file_that_cannot_be_removed_is_warned_about(
        self, ctx, allowed_root
    ):
        output_dir = allowed_root / ".ash" / "ash_output"
        output_dir.mkdir(parents=True)
        (output_dir / "ash_aggregated_results.json").write_text("{}")

        with (
            patch(
                f"{_SERVER}.mcp_scan_directory",
                AsyncMock(return_value={"success": False, "error": "stopped here"}),
            ),
            patch(f"{_SERVER}.os.remove", side_effect=PermissionError("read-only")),
        ):
            result = asyncio.run(
                run_ash_scan(ctx=ctx, source_dir=str(allowed_root), clean_output=True)
            )

        warnings = [c.args[0] for c in ctx.warning.await_args_list]
        assert any("Failed to clean up results file" in w for w in warnings)
        assert any("read-only" in w for w in warnings)
        # The scan attempt still went ahead; the cleanup failure is not fatal.
        assert result["error_type"] == "scan_start_failure"

    def test_a_failed_initial_progress_update_does_not_fail_the_scan(
        self, ctx, allowed_root
    ):
        ctx.report_progress = AsyncMock(side_effect=RuntimeError("client went away"))

        async def _call():
            result = await run_ash_scan(ctx=ctx, source_dir=str(allowed_root))
            # Let the monitor task start and finish before the loop closes.
            await asyncio.sleep(0)
            return result

        with (
            patch(
                f"{_SERVER}.mcp_scan_directory",
                AsyncMock(return_value={"success": True, "scan_id": "scan-1"}),
            ),
            patch(f"{_SERVER}.monitor_scan_progress", AsyncMock()),
            patch(f"{_SERVER}.logger", MagicMock()) as logger,
        ):
            result = asyncio.run(_call())

        assert result["success"] is True
        assert result["scan_id"] == "scan-1"
        assert result["status"] == "running"
        assert (
            "Failed to send initial progress update" in logger.warning.call_args[0][0]
        )

    def test_a_refused_target_is_reported_before_any_cleanup_happens(
        self, ctx, tmp_path, monkeypatch
    ):
        permitted = tmp_path / "permitted"
        permitted.mkdir()
        refused = tmp_path / "elsewhere"
        (refused / ".ash" / "ash_output").mkdir(parents=True)
        results_file = refused / ".ash" / "ash_output" / "ash_aggregated_results.json"
        results_file.write_text("{}")
        monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(permitted))

        result = asyncio.run(run_ash_scan(ctx=ctx, source_dir=str(refused)))

        assert result["success"] is False
        assert result["error_type"] == "scan_target_not_permitted"
        assert result["error_category"] == "invalid_path"
        # The refusal must land before the clean_output branch deletes anything
        # inside the caller-named directory.
        assert results_file.exists()


class TestGetScanProgressFileWalk:
    def _run(self, ctx, registry, output_dir):
        with (
            patch(
                f"{_SERVER}.mcp_get_scan_progress",
                AsyncMock(return_value={"success": True, "status": "running"}),
            ),
            patch(f"{_SERVER}.get_scan_registry", return_value=registry),
        ):
            return asyncio.run(get_scan_progress(ctx=ctx, scan_id="scan-1"))

    def test_stray_files_in_the_scanners_tree_are_skipped(
        self, ctx, registry, tmp_path
    ):
        output_dir = tmp_path / "ash_output"
        target = output_dir / "scanners" / "bandit" / "source"
        target.mkdir(parents=True)
        (target / "ASH.ScanResults.json").write_text(
            json.dumps({"severity_counts": {"high": 2, "low": 1}})
        )
        (output_dir / "scanners" / "README.txt").write_text("not a scanner")
        (output_dir / "scanners" / "bandit" / "notes.txt").write_text("not a target")
        registry.get_scan.return_value = _entry(output_dir)

        result = self._run(ctx, registry, output_dir)

        assert set(result["scanners"]) == {"bandit"}
        assert set(result["scanners"]["bandit"]) == {"source"}
        assert result["severity_counts"]["high"] == 2
        assert result["severity_counts"]["low"] == 1

    def test_an_unreadable_result_file_is_warned_about_and_skipped(
        self, ctx, registry, tmp_path
    ):
        output_dir = tmp_path / "ash_output"
        target = output_dir / "scanners" / "bandit" / "source"
        target.mkdir(parents=True)
        (target / "ASH.ScanResults.json").write_text("{ not json")
        registry.get_scan.return_value = _entry(output_dir)

        result = self._run(ctx, registry, output_dir)

        assert result["scanners"]["bandit"] == {}
        assert result["severity_counts"]["high"] == 0
        warning = ctx.warning.await_args[0][0]
        assert "Error reading result file" in warning
        assert "ASH.ScanResults.json" in warning

    def test_scanner_statuses_come_from_the_aggregated_output(
        self, ctx, registry, tmp_path
    ):
        """The globbed `scanners` map cannot see a scanner that never ran."""
        output_dir = tmp_path / "ash_output"
        output_dir.mkdir(parents=True)
        (output_dir / "ash_aggregated_results.json").write_text(
            json.dumps(
                {
                    "scanner_results": {
                        "grype": {"status": "MISSING", "dependencies_satisfied": False}
                    }
                }
            )
        )
        registry.get_scan.return_value = _entry(output_dir)

        result = self._run(ctx, registry, output_dir)

        assert result["scanners"] == {}
        assert result["scanner_statuses"]["grype"]["status"] == "MISSING"
        assert result["skipped_scanners"] == [
            {
                "scanner": "grype",
                "status": "MISSING",
                "reason": "missing_dependencies",
            }
        ]


class TestGetScanResults:
    def test_severity_filter_is_named_in_the_progress_message(self, ctx, tmp_path):
        with patch(
            f"{_SERVER}.mcp_get_scan_results",
            AsyncMock(return_value={"success": True, "status": "completed"}),
        ):
            asyncio.run(
                get_scan_results(
                    ctx=ctx,
                    output_dir=str(tmp_path),
                    scanners="bandit",
                    severities="high,critical",
                )
            )

        message = ctx.info.await_args[0][0]
        assert "severities=high,critical" in message
        assert "scanners=bandit" in message
        assert "filter_level=full" in message

    def test_actionable_only_is_named_in_the_progress_message(self, ctx, tmp_path):
        with patch(
            f"{_SERVER}.mcp_get_scan_results",
            AsyncMock(return_value={"success": True, "status": "completed"}),
        ):
            asyncio.run(
                get_scan_results(
                    ctx=ctx, output_dir=str(tmp_path), actionable_only=True
                )
            )

        assert "actionable_only=True" in ctx.info.await_args[0][0]

    def test_a_client_that_cannot_be_told_about_the_error_is_logged_instead(
        self, ctx, tmp_path
    ):
        """The inner handler exists so a dead client does not escalate the failure."""
        ctx.error = AsyncMock(side_effect=RuntimeError("connection closed"))

        with (
            patch(
                f"{_SERVER}.mcp_get_scan_results",
                AsyncMock(side_effect=ValueError("corrupt results")),
            ),
            patch(f"{_SERVER}.logger", MagicMock()) as logger,
        ):
            result = asyncio.run(get_scan_results(ctx=ctx, output_dir=str(tmp_path)))

        assert result["success"] is False
        assert result["error_type"] == "ValueError"
        assert "corrupt results" in result["error"]
        assert "Failed to send error message to client" in logger.error.call_args[0][0]


class TestGetScanResultPaths:
    def test_a_relative_output_dir_is_resolved_against_the_working_directory(
        self, ctx, tmp_path, monkeypatch
    ):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(tmp_path))
        reports = tmp_path / "ash_output" / "reports"
        reports.mkdir(parents=True)
        (reports / "ash.sarif").write_text("{}")

        result = asyncio.run(get_scan_result_paths(ctx=ctx, output_dir="ash_output"))

        assert result["success"] is True
        assert result["output_dir"] == str(tmp_path / "ash_output")
        assert result["files"]["sarif"]["exists"] is True
        assert result["files"]["sarif"]["size_bytes"] == 2
        assert result["files"]["html"]["exists"] is False
        assert result["files"]["html"]["size_bytes"] == 0

    def test_a_refused_output_dir_is_reported_as_not_permitted(
        self, ctx, tmp_path, monkeypatch
    ):
        permitted = tmp_path / "permitted"
        permitted.mkdir()
        refused = tmp_path / "elsewhere"
        refused.mkdir()
        monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(permitted))

        result = asyncio.run(get_scan_result_paths(ctx=ctx, output_dir=str(refused)))

        assert result["success"] is False
        assert result["error_type"] == "scan_target_not_permitted"

    def test_a_client_that_cannot_be_told_about_the_error_is_logged_instead(
        self, ctx, allowed_root
    ):
        ctx.error = AsyncMock(side_effect=RuntimeError("connection closed"))

        with (
            patch(
                f"{_SERVER}.validate_scan_target",
                side_effect=ValueError("policy blew up"),
            ),
            patch(f"{_SERVER}.logger", MagicMock()) as logger,
        ):
            result = asyncio.run(
                get_scan_result_paths(ctx=ctx, output_dir=str(allowed_root))
            )

        assert result["success"] is False
        assert result["error_type"] == "ValueError"
        assert "Failed to send error message to client" in logger.error.call_args[0][0]


class TestDelegatingToolWrappers:
    """Each wrapper forwards its arguments, and converts a raise into a dict."""

    def test_explain_finding_forwards_its_arguments(self, tmp_path):
        with patch(
            f"{_SERVER}.mcp_explain_finding", return_value={"success": True}
        ) as inner:
            result = asyncio.run(
                explain_finding(finding_id="finding-1", results_path=str(tmp_path))
            )

        assert result == {"success": True}
        inner.assert_called_once_with(
            finding_id="finding-1", results_path=str(tmp_path)
        )

    def test_explain_finding_converts_a_raise_into_an_error_dict(self):
        with (
            patch(f"{_SERVER}.mcp_explain_finding", side_effect=RuntimeError("boom")),
            patch(f"{_SERVER}.logger", MagicMock()),
        ):
            result = asyncio.run(explain_finding(finding_id="finding-1"))

        assert result["success"] is False
        assert result["error"] == "Error explaining finding: boom"
        assert result["error_type"] == "RuntimeError"

    def test_get_config_forwards_its_arguments(self):
        with patch(
            f"{_SERVER}.mcp_get_config", return_value={"project_name": "demo"}
        ) as inner:
            result = asyncio.run(get_config(config_path=None, raw=True))

        assert result == {"project_name": "demo"}
        inner.assert_called_once_with(config_path=None, raw=True)

    def test_get_config_converts_a_raise_into_an_error_dict(self):
        with (
            patch(f"{_SERVER}.mcp_get_config", side_effect=OSError("unreadable")),
            patch(f"{_SERVER}.logger", MagicMock()),
        ):
            result = asyncio.run(get_config())

        assert result["success"] is False
        assert result["error"] == "Error getting config: unreadable"
        assert result["error_type"] == "OSError"

    def test_list_scanners_returns_the_inner_list(self):
        with patch(f"{_SERVER}.mcp_list_scanners", return_value=[{"name": "bandit"}]):
            assert list_scanners() == [{"name": "bandit"}]

    def test_list_scanners_wraps_a_raise_in_a_single_element_list(self):
        """The tool's return type is a list, so the error has to be one too."""
        with (
            patch(
                f"{_SERVER}.mcp_list_scanners", side_effect=RuntimeError("no plugins")
            ),
            patch(f"{_SERVER}.logger", MagicMock()),
        ):
            result = list_scanners()

        assert isinstance(result, list)
        assert len(result) == 1
        assert result[0]["success"] is False
        assert result[0]["error"] == "Error listing scanners: no plugins"
        assert result[0]["error_type"] == "RuntimeError"

    def test_diff_scan_results_forwards_its_arguments(self, tmp_path):
        before = str(tmp_path / "before.json")
        after = str(tmp_path / "after.json")

        with patch(
            f"{_SERVER}.mcp_diff_scan_results",
            return_value={"new": [], "resolved": [], "severity_changed": []},
        ) as inner:
            result = asyncio.run(
                diff_scan_results(before_path=before, after_path=after)
            )

        assert result["new"] == []
        inner.assert_called_once_with(before_path=before, after_path=after)

    def test_diff_scan_results_converts_a_raise_into_an_error_dict(self):
        with (
            patch(
                f"{_SERVER}.mcp_diff_scan_results", side_effect=RuntimeError("bad diff")
            ),
            patch(f"{_SERVER}.logger", MagicMock()),
        ):
            result = asyncio.run(diff_scan_results(before_path="a", after_path="b"))

        assert result["success"] is False
        assert result["error"] == "Error diffing scan results: bad diff"
        assert result["error_type"] == "RuntimeError"

    def test_validate_config_forwards_its_arguments(self):
        with patch(
            f"{_SERVER}.mcp_validate_config", return_value={"valid": True, "errors": []}
        ) as inner:
            result = validate_config(config_content="project_name: demo\n")

        assert result["valid"] is True
        inner.assert_called_once_with(
            config_content="project_name: demo\n", config_path=None
        )

    def test_validate_config_reports_a_raise_in_the_validation_error_shape(self):
        """The tool's contract is {valid, errors}, so the except arm keeps it."""
        with (
            patch(
                f"{_SERVER}.mcp_validate_config",
                side_effect=RuntimeError("validator gone"),
            ),
            patch(f"{_SERVER}.logger", MagicMock()),
        ):
            result = validate_config(config_path="ash.yaml")

        assert result["valid"] is False
        assert result["errors"] == [
            {
                "field": "",
                "message": "Unexpected error: validator gone",
                "type": "RuntimeError",
            }
        ]

    def test_suggest_suppression_forwards_its_arguments(self, tmp_path):
        with patch(
            f"{_SERVER}.mcp_suggest_suppression", return_value={"success": True}
        ) as inner:
            result = asyncio.run(
                suggest_suppression(
                    finding_id="finding-1",
                    results_path=str(tmp_path),
                    expiration="2030-01-01",
                    justification="accepted risk",
                )
            )

        assert result == {"success": True}
        inner.assert_called_once_with(
            finding_id="finding-1",
            results_path=str(tmp_path),
            expiration="2030-01-01",
            justification="accepted risk",
        )

    def test_suggest_suppression_converts_a_raise_into_an_error_dict(self):
        with (
            patch(
                f"{_SERVER}.mcp_suggest_suppression",
                side_effect=RuntimeError("no results"),
            ),
            patch(f"{_SERVER}.logger", MagicMock()),
        ):
            result = asyncio.run(suggest_suppression(finding_id="finding-1"))

        assert result["success"] is False
        assert result["error"] == "Error suggesting suppression: no results"
        assert result["error_type"] == "RuntimeError"

    def test_check_installation_converts_a_raise_into_an_error_dict(self, ctx):
        with (
            patch(
                f"{_SERVER}.mcp_check_installation",
                AsyncMock(side_effect=RuntimeError("no version")),
            ),
            patch(f"{_SERVER}.logger", MagicMock()),
        ):
            result = asyncio.run(check_installation(ctx=ctx))

        assert result["success"] is False
        assert result["error"] == "Error checking installation: no version"
        assert result["error_type"] == "RuntimeError"


class TestResources:
    def test_the_config_schema_resource_returns_the_ash_config_schema(self):
        """The generated schema is a $ref into $defs, not an inline object."""
        schema = json.loads(get_ash_config_schema())

        assert schema["$ref"] == "#/$defs/AshConfig"
        assert "project_name" in schema["$defs"]["AshConfig"]["properties"]

    def test_the_suppression_schema_resource_returns_the_suppression_schema(self):
        schema = json.loads(get_ash_suppression_schema())

        assert "properties" in schema
        assert "rule_id" in schema["properties"]

    def test_the_exit_codes_resource_mirrors_the_canonical_constant(self):
        codes = json.loads(get_ash_exit_codes())

        assert codes == {str(k): v for k, v in ASH_EXIT_CODES.items()}
        assert codes  # not an empty mapping

    def test_the_status_resource_reports_the_version_when_available(self):
        with patch(
            "automated_security_helper.utils.get_ash_version.get_ash_version",
            return_value="9.9.9",
        ):
            status = get_ash_status()

        assert "ASH version 9.9.9" in status
        assert "READY" in status

    def test_the_status_resource_reports_the_failure_when_the_version_is_unavailable(
        self,
    ):
        with (
            patch(
                "automated_security_helper.utils.get_ash_version.get_ash_version",
                side_effect=RuntimeError("no metadata"),
            ),
            patch(f"{_SERVER}.logger", MagicMock()),
        ):
            status = get_ash_status()

        assert "ERROR" in status
        assert "no metadata" in status
        assert "READY" not in status


class TestPrompts:
    def test_the_analysis_prompt_defaults_to_the_working_directory(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.chdir(tmp_path)

        prompt = analyze_security_findings(None)

        assert str(tmp_path.absolute()) in prompt
        assert "Risk Assessment" in prompt

    def test_the_analysis_prompt_uses_an_explicit_source_dir(self, tmp_path):
        prompt = analyze_security_findings(str(tmp_path / "project"))

        assert str(tmp_path / "project") in prompt

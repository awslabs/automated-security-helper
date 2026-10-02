#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The MCP tool wrappers are driven against the real producers, not stubs.

Why this file exists
--------------------
``mcp_server.get_scan_progress`` and ``mcp_server.get_scan_results`` each open
with a guard on ``success``, and no producer set that key on its success path.
Both guards were therefore true on both branches: every line after them was
dead, ``summarize_scanner_statuses`` ran zero times on a real poll, and
``filter_level`` was inert on a real scan.

The existing unit tests could not see any of it. Each one patches
``mcp_get_scan_progress`` or ``mcp_get_scan_results`` with an
``AsyncMock(return_value={"success": True, ...})``, which injects the key the
real producer omits -- so the guard fell through under test and returned early
in production. Those stubs have been corrected to the real shape in the same
change; this file adds the coverage they could not provide, by letting the real
producer build the payload and asserting on what the wrapper did with it.

The same defect class, on a different mechanism
-----------------------------------------------
``_run_scan_async`` wraps the scan in ``except Exception``. The local branch of
``run_ash_scan`` converts every failure into ``sys.exit``, and
``loop.run_in_executor`` re-raises whatever the worker raised, so a
``SystemExit`` arrives at that handler and is not caught: ``SystemExit`` derives
from ``BaseException``. Neither status update runs, the registry entry is
stranded at RUNNING, and the exception unwinds into the event loop.

``tests/unit/cli/mcp/test_workspace_exit_code_bypass.py`` names this exact
handler in its module docstring as the hazard it was written to avoid, and the
workspace tools avoid it by calling ``resolve_workspace`` and
``execute_workspace`` directly instead of the CLI entry point that exits. This
file pins the same guarantee for the async single-project path, which still goes
through ``run_ash_scan``: the exit must be recorded as a failure rather than
allowed to unwind.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, Dict
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from mcp.server.mcpserver import Context

from automated_security_helper.cli.mcp.scan_target import ASH_MCP_ALLOWED_ROOTS_ENV
from automated_security_helper.cli.mcp_server import (
    get_scan_progress,
    get_scan_results,
    get_scan_summary,
)
from automated_security_helper.core.resource_management.scan_registry import (
    MCScanStatus,
    ScanRegistry,
)

_SERVER = "automated_security_helper.cli.mcp_server"
_MANAGEMENT = "automated_security_helper.core.resource_management.scan_management"
_TOOLS = "automated_security_helper.cli.mcp_tools"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def ctx():
    """A Context double limited to the protocol's real surface.

    ``spec=Context`` makes the log methods AsyncMocks automatically and rejects
    a call to a method the protocol does not define, so a typo cannot pass.
    """
    return MagicMock(spec=Context)


@pytest.fixture
def allowed_root(tmp_path, monkeypatch):
    """Permit ``tmp_path`` so target confinement is not what these tests measure."""
    monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(tmp_path))
    return tmp_path


def _aggregated(output_dir: Path, scanner_results: Dict[str, Any]) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "ash_aggregated_results.json").write_text(
        json.dumps(
            {
                "metadata": {
                    "generated_at": "2026-01-01T00:00:00",
                    "summary_stats": {"actionable": 0, "total": 0},
                },
                "scanner_results": scanner_results,
            }
        ),
        encoding="utf-8",
    )


def _registered(source: Path, output: Path) -> tuple[ScanRegistry, str]:
    """A private registry holding one scan over *source*.

    Private rather than ``get_scan_registry()``: the global instance persists
    across tests in a process and refuses a second active scan on a directory
    that already has one.
    """
    registry = ScanRegistry()
    scan_id = registry.register_scan(
        directory_path=str(source),
        output_directory=str(output),
    )
    return registry, scan_id


# ---------------------------------------------------------------------------
# 1. get_scan_progress reaches the code after its guard
# ---------------------------------------------------------------------------


class TestTheProgressGuardDiscriminates:
    def _poll(self, ctx, source: Path, output: Path) -> Dict[str, Any]:
        """Call the tool with the real producer underneath it.

        Nothing between the tool and ``ScanRegistry`` is replaced; only the
        registry lookup is redirected to a private instance. Both
        ``mcp_server`` and ``scan_management`` resolve it by module-level name,
        so both bindings are patched -- patching one leaves the other reading
        the global registry, where the scan is not registered.
        """
        registry, scan_id = _registered(source, output)
        with (
            patch(f"{_SERVER}.get_scan_registry", return_value=registry),
            patch(f"{_MANAGEMENT}.get_scan_registry", return_value=registry),
        ):
            return asyncio.run(get_scan_progress(ctx=ctx, scan_id=scan_id))

    def test_a_real_successful_poll_reports_a_missing_scanner_as_skipped(
        self, ctx, tmp_path
    ):
        """The defect, stated as the thing a client could not learn.

        ``summarize_scanner_statuses`` is called after the guard, so on a real
        poll it ran zero times and ``skipped_scanners`` never left the server. A
        scanner that never ran was indistinguishable from one that ran clean,
        which for a security tool is the whole answer.
        """
        source = tmp_path / "proj"
        source.mkdir()
        output = source / ".ash" / "ash_output"
        _aggregated(
            output,
            {
                "bandit": {"status": "PASSED", "finding_count": 0},
                "semgrep": {"status": "MISSING", "dependencies_satisfied": False},
            },
        )

        progress = self._poll(ctx, source, output)

        assert progress["skipped_scanners"] == [
            {
                "scanner": "semgrep",
                "status": "MISSING",
                "reason": "missing_dependencies",
            }
        ]
        assert progress["scanner_statuses"]["semgrep"]["status"] == "MISSING"

    def test_a_real_successful_poll_still_walks_the_scanners_tree(self, ctx, tmp_path):
        """The other half of the dead region: the per-scanner file walk.

        Distinct from the summary above because the two come from different
        sources -- this one globs ``scanners/*/*/ASH.ScanResults.json`` -- and an
        implementation that reached only one of them would satisfy the other
        test.
        """
        source = tmp_path / "proj"
        source.mkdir()
        output = source / ".ash" / "ash_output"
        _aggregated(output, {"bandit": {"status": "PASSED", "finding_count": 5}})
        target = output / "scanners" / "bandit" / "source"
        target.mkdir(parents=True)
        (target / "ASH.ScanResults.json").write_text(
            json.dumps({"severity_counts": {"high": 5}}), encoding="utf-8"
        )

        progress = self._poll(ctx, source, output)

        assert progress["severity_counts"]["high"] == 5
        assert "bandit" in progress["scanners"]

    def test_an_upstream_failure_is_returned_untouched(self, ctx):
        """Negative control: the guard must still stop on a real failure.

        ``success: False`` is what ``create_error_response`` sets, so this is the
        shape every failing producer actually returns. If the guard were simply
        deleted, this test would see the wrapper continue past it and either add
        keys or raise on the absent registry entry.
        """
        failure = {"success": False, "error": "Registry unavailable"}

        with patch(f"{_SERVER}.mcp_get_scan_progress", AsyncMock(return_value=failure)):
            result = asyncio.run(get_scan_progress(ctx=ctx, scan_id="any-id"))

        assert result == failure

    def test_a_response_carrying_an_error_key_is_returned_untouched(self, ctx):
        """The second arm of the guard, exercised on its own.

        A producer can report a problem by including ``error`` without setting
        ``success`` at all. Tested separately from the ``success: False`` case so
        that a guard which checks only one of the two fails here.
        """
        failure = {"error": "half-written results", "error_category": "invalid_format"}

        with patch(f"{_SERVER}.mcp_get_scan_progress", AsyncMock(return_value=failure)):
            result = asyncio.run(get_scan_progress(ctx=ctx, scan_id="any-id"))

        assert result == failure


# ---------------------------------------------------------------------------
# 2. get_scan_results reaches its filters
# ---------------------------------------------------------------------------


class TestTheResultsGuardDiscriminates:
    def test_filter_level_summary_actually_filters_a_real_payload(
        self, ctx, allowed_root
    ):
        """``filter_level`` was inert on every real scan.

        ``filter_summary`` exists, is imported, and produces the documented
        shape when handed a real payload -- what was missing was the key that
        gates it. Asserting on the resolved shape (``_filter`` set,
        ``raw_results`` gone) rather than on the absence of an early return,
        because only the shape is what a client sees.
        """
        output = allowed_root / ".ash" / "ash_output"
        _aggregated(output, {"bandit": {"status": "PASSED", "finding_count": 0}})

        result = asyncio.run(
            get_scan_results(ctx=ctx, output_dir=str(output), filter_level="summary")
        )

        assert result["_filter"] == "summary"
        assert "raw_results" not in result
        assert "findings_summary" in result
        assert "scanner_summary" in result

    def test_filter_level_full_still_returns_the_whole_payload(self, ctx, allowed_root):
        """Positive control: falling through the guard is not "always filter"."""
        output = allowed_root / ".ash" / "ash_output"
        _aggregated(output, {"bandit": {"status": "PASSED", "finding_count": 0}})

        result = asyncio.run(
            get_scan_results(ctx=ctx, output_dir=str(output), filter_level="full")
        )

        assert result["success"] is True
        assert "raw_results" in result
        assert "_filter" not in result

    def test_get_scan_summary_tags_the_source_function(self, ctx, allowed_root):
        """``_source_function`` was conditioned on a key the producer never set.

        The tag distinguishes a summary obtained through ``get_scan_summary``
        from one obtained by calling ``get_scan_results`` directly, and it never
        got attached on a real scan.
        """
        output = allowed_root / ".ash" / "ash_output"
        _aggregated(output, {"bandit": {"status": "PASSED", "finding_count": 0}})

        result = asyncio.run(get_scan_summary(ctx=ctx, output_dir=str(output)))

        assert result["_source_function"] == "get_scan_summary"

    def test_an_error_payload_is_not_tagged_as_a_summary(self, ctx, allowed_root):
        """``_source_function`` must follow ``error``, not ``success``'s truthiness.

        The tag documents provenance: it says this payload came out of
        ``get_scan_summary`` rather than out of ``get_scan_results`` called
        directly. Attaching it to a payload the guard returned verbatim claims a
        summary was produced when none was -- ``filter_summary`` never ran.

        This is the only input that distinguishes ``summary.get("success")`` from
        ``"error" not in summary and summary.get("success") is not False``. Every
        other reachable payload agrees under both: ``filter_summary`` hardcodes
        ``success: True`` and carries no ``error``, and every early return either
        sets ``success: False`` or omits the key. So the distinguishing shape is
        ``error`` present *together with* a truthy ``success``, and that is why it
        is stubbed -- no producer emits it today. ``create_error_response`` pairs
        ``error`` with ``success: False``, and ``scan_tracking.get_scan_results``
        sets ``success: True`` with no ``error``.

        Pinned anyway because "``error`` is authoritative" is now the rule at
        three sibling call sites in this module, and an odd one out is what a
        future reader resolves by changing the wrong one.
        """
        payload = {
            "success": True,
            "error": "the results file was read but one scanner section was short",
            "scan_id": "scan-1",
            "status": "completed",
        }

        with patch(f"{_SERVER}.mcp_get_scan_results", AsyncMock(return_value=payload)):
            result = asyncio.run(
                get_scan_summary(ctx=ctx, output_dir=str(allowed_root))
            )

        assert "_source_function" not in result
        assert result["error"] == payload["error"]

    def test_a_producer_that_omits_the_key_is_not_read_as_a_failure(
        self, ctx, allowed_root
    ):
        """The guard must not depend on ``success`` being present.

        The mechanism this whole change is about is a producer that does not set
        the key, so the guard is written to stop on an explicit ``False`` rather
        than on absence. Nothing in production omits it now, which means a guard
        rewritten as ``not results.get("success")`` would pass every other test
        in this class: this is the only one that distinguishes the two forms, and
        it is what stops the defect returning through a third producer.

        Stubbed rather than driven, deliberately -- the shape being tested is one
        the fixed producers no longer emit.
        """
        payload = {
            "scan_id": "scan-1",
            "status": "completed",
            "is_complete": True,
            "summary_stats": {"total": 3, "actionable": 3},
            "raw_results": {"metadata": {}, "scanner_results": {}},
        }

        with patch(f"{_SERVER}.mcp_get_scan_results", AsyncMock(return_value=payload)):
            result = asyncio.run(
                get_scan_results(
                    ctx=ctx, output_dir=str(allowed_root), filter_level="summary"
                )
            )

        assert result["_filter"] == "summary"
        assert "raw_results" not in result

    def test_a_failed_read_is_returned_unfiltered(self, ctx, allowed_root):
        """Negative control: a refusal must not be reshaped into a summary.

        ``filter_summary`` would happily build a summary out of an error
        response, reporting zero findings across zero scanners -- a failed read
        rendered as a clean scan.
        """
        absent = allowed_root / "never-scanned" / ".ash" / "ash_output"

        result = asyncio.run(
            get_scan_results(ctx=ctx, output_dir=str(absent), filter_level="summary")
        )

        assert result["success"] is False
        assert result.get("_filter") is None


# ---------------------------------------------------------------------------
# 3. A scan that exits the process is recorded, not propagated
# ---------------------------------------------------------------------------


class TestAnExitingScanIsRecordedNotFatal:
    def _run(self, raised: BaseException, tmp_path) -> ScanRegistry:
        """Drive ``_run_scan_async`` with a scan that raises *raised*.

        ``run_ash_scan`` is patched on its defining module because
        ``_run_scan_async`` imports it lazily inside the function body, so the
        attribute is looked up at call time.

        ``except BaseException`` around the call and not ``except Exception``:
        the defect under test is precisely that ``SystemExit`` slips past an
        ``Exception`` handler, so a narrower clause here would reproduce it and
        the test would report the run's exit status instead of naming the bug.
        """
        from automated_security_helper.cli import mcp_tools
        from automated_security_helper.interactions import run_ash_scan as entry_point

        source = tmp_path / "proj"
        source.mkdir()
        output = source / ".ash" / "ash_output"
        output.mkdir(parents=True)
        registry, self.scan_id = _registered(source, output)

        def _raise(*args: Any, **kwargs: Any) -> None:
            raise raised

        with (
            patch.object(entry_point, "run_ash_scan", _raise),
            patch.object(mcp_tools, "get_scan_registry", return_value=registry),
        ):
            try:
                asyncio.run(
                    mcp_tools._run_scan_async(
                        scan_id=self.scan_id,
                        directory_path=str(source),
                        output_dir=str(output),
                        severity_threshold="MEDIUM",
                    )
                )
            except BaseException as exc:  # pragma: no cover -- the defect
                pytest.fail(
                    f"_run_scan_async let {type(exc).__name__}"
                    f"({getattr(exc, 'code', exc)!r}) escape. It runs as a bare "
                    f"asyncio task, and asyncio re-raises a BaseException out of "
                    f"Task.__step into the event loop: the MCP server would stop "
                    f"and every other session's in-flight scan would die with it."
                )
        return registry

    def test_a_scan_that_exits_the_process_does_not_unwind_the_loop(self, tmp_path):
        self._run(SystemExit(2), tmp_path)

    def test_a_scan_that_exits_is_recorded_as_failed(self, tmp_path):
        """Stranded at RUNNING was the observable symptom.

        A poll on a RUNNING entry reports an in-progress scan forever, so a
        client following the documented five-second loop never terminates.
        """
        registry = self._run(SystemExit(2), tmp_path)

        assert registry.get_scan(self.scan_id).status is MCScanStatus.FAILED

    def test_the_exit_code_is_named_in_the_error_message(self, tmp_path):
        """The code is the only thing the CLI communicated, so it must survive.

        ``fail_on_findings=False`` does not make this unreachable: the
        results-is-None arm of ``_compute_exit_code`` precedes the
        ``fail_on_findings`` resolution entirely, so an incomplete scan still
        exits non-zero.
        """
        registry = self._run(SystemExit(2), tmp_path)

        assert "2" in registry.get_scan(self.scan_id).error_message

    def test_an_ordinary_exception_is_still_recorded_as_failed(self, tmp_path):
        """Regression control on the handler that already worked.

        Replacing ``except Exception`` must not lose the case it was catching.
        """
        registry = self._run(RuntimeError("thread pool exploded"), tmp_path)

        entry = registry.get_scan(self.scan_id)
        assert entry.status is MCScanStatus.FAILED
        assert "thread pool exploded" in entry.error_message

    def test_a_successful_scan_is_still_recorded_as_completed(self, tmp_path):
        """Positive control: "always FAILED" satisfies everything above."""
        from automated_security_helper.cli import mcp_tools
        from automated_security_helper.interactions import run_ash_scan as entry_point

        source = tmp_path / "proj"
        source.mkdir()
        output = source / ".ash" / "ash_output"
        output.mkdir(parents=True)
        registry, scan_id = _registered(source, output)

        with (
            patch.object(entry_point, "run_ash_scan", lambda *a, **k: None),
            patch.object(mcp_tools, "get_scan_registry", return_value=registry),
        ):
            asyncio.run(
                mcp_tools._run_scan_async(
                    scan_id=scan_id,
                    directory_path=str(source),
                    output_dir=str(output),
                    severity_threshold="MEDIUM",
                )
            )

        assert registry.get_scan(scan_id).status is MCScanStatus.COMPLETED

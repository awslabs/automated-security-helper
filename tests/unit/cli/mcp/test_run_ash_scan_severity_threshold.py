# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``run_ash_scan(severity_threshold=...)`` can tighten the scan's threshold, never loosen it.

Why this file exists
--------------------
The tool validates ``severity_threshold`` and hands it to the scan, and
``get_scan_progress`` reports the threshold the scan applied, with the request
beside it. An MCP scan runs at the stricter of the request and its config
file's threshold (MEDIUM unless the repository sets one), and the client is
told which threshold applied.

What the tests measure is the threshold the scan's configuration resolves to in
the real orchestrator, which is what decides which findings are actionable and
whether a scanner FAILED or PASSED. Only the phases are replaced, by one that
records the configuration the engine was given.

Restrict-only, and why the default is not a value
-------------------------------------------------
The threshold a repository or operator configured is a policy. A client may
make it stricter (LOW over a configured HIGH: more findings gate) but not
looser (CRITICAL over a configured MEDIUM is ignored, and MEDIUM stays): the
scan runs at the stricter of the two, as a workspace project does against its
workspace's threshold. A client that names none gets the config's threshold,
which is why the parameter cannot default to "MEDIUM": a default always applied
would replace a repository's LOW or ALL. The value is case-insensitive.
"""

from __future__ import annotations

import asyncio
import threading
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock

import pytest
from mcp.server.mcpserver import Context

from automated_security_helper.cli import mcp_server
from automated_security_helper.core.resource_management.scan_registry import (
    ScanRegistry,
)
from tests.utils.tasks import drain

_LAUNCHER = "automated_security_helper.interactions.run_ash_scan.run_ash_scan"


@pytest.fixture(autouse=True)
def isolated_mcp_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from automated_security_helper.cli.mcp import profile_registry
    from automated_security_helper.cli.mcp.sessions import (
        reset_default_registry_for_tests,
    )
    from automated_security_helper.core.resource_management import scan_registry

    monkeypatch.setattr(scan_registry, "_scan_registry", ScanRegistry())
    profile_registry.clear_profile_registry()
    profile_registry.clear_session_state()
    reset_default_registry_for_tests()
    for name in ("ASH_MCP_ALLOWED_CONFIG_ROOTS", "ASH_MCP_TRANSPORT", "ASH_CONFIG"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path / "allowed"))
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "workspaces"))
    (tmp_path / "allowed").mkdir()
    monkeypatch.setattr(mcp_server, "monitor_scan_progress", AsyncMock())
    yield
    profile_registry.clear_profile_registry()
    profile_registry.clear_session_state()
    reset_default_registry_for_tests()


@pytest.fixture
def resolved_thresholds(monkeypatch) -> List[str]:
    """The threshold each launched scan's configuration resolved to, in the engine."""
    from automated_security_helper.core.execution_engine import ScanExecutionEngine
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    seen: List[str] = []

    def phases(engine, *args: Any, **kwargs: Any):
        seen.append(engine._context.config.global_settings.severity_threshold)
        return AshAggregatedResults(ash_config=engine._context.config)

    monkeypatch.setattr(ScanExecutionEngine, "execute_phases", phases)
    return seen


def _project(tmp_path: Path, configured: str | None = None) -> Path:
    project = tmp_path / "allowed" / "project"
    project.mkdir(parents=True)
    (project / "app.py").write_text("x = 1\n", encoding="utf-8")
    if configured is not None:
        (project / ".ash").mkdir()
        (project / ".ash" / ".ash.yaml").write_text(
            "project_name: project\n"
            "global_settings:\n"
            f"  severity_threshold: {configured}\n",
            encoding="utf-8",
        )
    return project


async def _scan(project: Path, **kwargs: Any) -> Dict[str, Any]:
    ctx = MagicMock(spec=Context)
    ctx.headers = {}
    result = await mcp_server.run_ash_scan(ctx, source_dir=str(project), **kwargs)
    await drain()
    return result


@pytest.mark.asyncio
class TestTheThresholdReachesTheScan:
    async def test_a_stricter_threshold_is_the_one_the_scan_uses(
        self, tmp_path, resolved_thresholds
    ):
        result = await _scan(_project(tmp_path), severity_threshold="LOW")

        assert result["success"] is True, result
        assert resolved_thresholds == ["LOW"]

    async def test_a_stricter_threshold_tightens_the_repository_config(
        self, tmp_path, resolved_thresholds
    ):
        result = await _scan(
            _project(tmp_path, configured="HIGH"), severity_threshold="LOW"
        )

        assert result["success"] is True, result
        assert resolved_thresholds == ["LOW"]

    async def test_all_is_accepted(self, tmp_path, resolved_thresholds):
        result = await _scan(_project(tmp_path), severity_threshold="ALL")

        assert result["success"] is True, result
        assert resolved_thresholds == ["ALL"]

    async def test_the_value_is_case_insensitive(self, tmp_path, resolved_thresholds):
        result = await _scan(_project(tmp_path), severity_threshold="low")

        assert result["success"] is True, result
        assert resolved_thresholds == ["LOW"]
        assert result.get("severity_threshold", "LOW") == "LOW"


@pytest.mark.asyncio
class TestAClientCannotLoosenTheThreshold:
    async def test_a_looser_threshold_leaves_the_repository_config_in_charge(
        self, tmp_path, resolved_thresholds
    ):
        result = await _scan(
            _project(tmp_path, configured="LOW"), severity_threshold="HIGH"
        )

        assert result["success"] is True, result
        assert resolved_thresholds == ["LOW"], (
            "a client loosened the repository's LOW threshold to HIGH"
        )

    async def test_a_looser_threshold_than_the_default_is_ignored(
        self, tmp_path, resolved_thresholds
    ):
        result = await _scan(_project(tmp_path), severity_threshold="CRITICAL")

        assert result["success"] is True, result
        assert resolved_thresholds == ["MEDIUM"]


@pytest.mark.asyncio
class TestWhatMustNotChange:
    async def test_no_threshold_leaves_the_repository_config_in_charge(
        self, tmp_path, resolved_thresholds
    ):
        """Guards the fix: an always-applied default would turn LOW into MEDIUM."""
        result = await _scan(_project(tmp_path, configured="LOW"))

        assert result["success"] is True, result
        assert resolved_thresholds == ["LOW"]

    async def test_an_unknown_threshold_is_refused_before_anything_runs(
        self, tmp_path, resolved_thresholds
    ):
        result = await _scan(_project(tmp_path), severity_threshold="SEVERE")

        assert result["success"] is False, result
        assert resolved_thresholds == []


@pytest.mark.asyncio
async def test_progress_reports_the_threshold_the_scan_was_judged_by(
    tmp_path, monkeypatch
):
    """With no threshold named, progress echoes the config's, not a default.

    The runner records the threshold from the config the scan resolved, not
    "MEDIUM", the tool's default, whatever the scan ran at.
    """
    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    def scan(**kwargs: Any):
        config = resolve_config(
            config_path=kwargs.get("config"),
            source_dir=kwargs["source_dir"],
            config_overrides=kwargs.get("config_overrides"),
        )
        return AshAggregatedResults(ash_config=config)

    monkeypatch.setattr(_LAUNCHER, scan)
    result = await _scan(_project(tmp_path, configured="LOW"))
    assert result["success"] is True, result

    ctx = MagicMock(spec=Context)
    ctx.headers = {}
    progress = await mcp_server.get_scan_progress(ctx, result["scan_id"])

    assert progress["severity_threshold"] == "LOW", progress


def _project_with_scanner_threshold(tmp_path: Path, threshold: str) -> Path:
    project = tmp_path / "allowed" / "project"
    project.mkdir(parents=True)
    (project / "app.py").write_text("x = 1\n", encoding="utf-8")
    (project / ".ash").mkdir()
    (project / ".ash" / ".ash.yaml").write_text(
        "project_name: project\n"
        "scanners:\n"
        "  bandit:\n"
        "    options:\n"
        f"      severity_threshold: {threshold}\n",
        encoding="utf-8",
    )
    return project


@pytest.fixture
def bandit_thresholds(monkeypatch) -> List[Dict[str, Any]]:
    """What decides bandit's verdict in each launched scan, read in the engine.

    Both readers of a scanner's own threshold: the scanner's plugin config, which
    the executor passes to determine_status, and the statistics calculator.
    """
    from automated_security_helper.core.execution_engine import ScanExecutionEngine
    from automated_security_helper.core.scanner_statistics_calculator import (
        ScannerStatisticsCalculator,
    )
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    seen: List[Dict[str, Any]] = []

    def phases(engine, *args: Any, **kwargs: Any):
        config = engine._context.config
        model = AshAggregatedResults(ash_config=config)
        # The dict the scan phase builds bandit's plugin config from.
        plugin = config.get_plugin_config(plugin_type="scanner", plugin_name="bandit")
        seen.append(
            {
                "plugin": (plugin or {}).get("options", {}).get("severity_threshold"),
                "statistics": ScannerStatisticsCalculator.get_scanner_threshold_info(
                    model, "bandit"
                )[0],
            }
        )
        return model

    monkeypatch.setattr(ScanExecutionEngine, "execute_phases", phases)
    return seen


@pytest.mark.asyncio
class TestTheRequestTightensAScannersOwnThreshold:
    """A scanner's own threshold decides its verdict over the global one.

    The request tightens a scanner's own threshold as well as global_settings,
    so when a repository sets bandit to CRITICAL and the client asks for HIGH, a
    HIGH finding makes bandit FAILED: the stricter of the two decides.
    """

    async def test_a_stricter_request_tightens_a_scanners_threshold(
        self, tmp_path, bandit_thresholds
    ):
        from automated_security_helper.utils.severity_ladder import (
            severity_fails_threshold,
        )

        result = await _scan(
            _project_with_scanner_threshold(tmp_path, "CRITICAL"),
            severity_threshold="HIGH",
        )

        assert result["success"] is True, result
        assert bandit_thresholds == [{"plugin": "HIGH", "statistics": "HIGH"}]
        assert severity_fails_threshold("HIGH", bandit_thresholds[0]["plugin"])

    async def test_a_looser_request_leaves_a_scanners_threshold_alone(
        self, tmp_path, bandit_thresholds
    ):
        result = await _scan(
            _project_with_scanner_threshold(tmp_path, "LOW"),
            severity_threshold="HIGH",
        )

        assert result["success"] is True, result
        assert bandit_thresholds == [{"plugin": "LOW", "statistics": "LOW"}]

    async def test_a_scanner_with_no_threshold_of_its_own_follows_the_global(
        self, tmp_path, bandit_thresholds
    ):
        """Not given one: it inherits the tightened global threshold."""
        result = await _scan(_project(tmp_path), severity_threshold="LOW")

        assert result["success"] is True, result
        assert bandit_thresholds == [{"plugin": None, "statistics": "LOW"}]


@pytest.fixture
def held_scan(monkeypatch):
    """A launcher that waits until released, then raises ``outcome["raise"]`` if set."""
    started = threading.Event()
    release = threading.Event()
    outcome: Dict[str, Any] = {"raise": None}

    def scan(**kwargs: Any):
        started.set()
        release.wait(30)
        if outcome["raise"] is not None:
            raise outcome["raise"]
        return None

    monkeypatch.setattr(_LAUNCHER, scan)
    return started, release, outcome


async def _progress_while_held(project: Path, held, **kwargs: Any):
    """Start a scan, read its progress while it runs, let it end, read it again."""
    started, release, _outcome = held
    ctx = MagicMock(spec=Context)
    ctx.headers = {}
    begun = await mcp_server.run_ash_scan(ctx, source_dir=str(project), **kwargs)
    assert begun["success"] is True, begun
    try:
        assert await asyncio.to_thread(started.wait, 30), "the scan never started"
        running = await mcp_server.get_scan_progress(ctx, begun["scan_id"])
    finally:
        release.set()
        await drain()
    ended = await mcp_server.get_scan_progress(ctx, begun["scan_id"])
    return running, ended


@pytest.mark.asyncio
async def test_progress_shows_the_requested_threshold_upper_cased_while_it_runs(
    tmp_path, held_scan
):
    """The request is reported as given, upper-cased, and kept apart from the applied value.

    The case test above passes whether or not the request is upper-cased: the
    scan's own config resolution accepts either case. This reads the request
    back while the scan is still pending.
    """
    running, _ended = await _progress_while_held(
        _project(tmp_path), held_scan, severity_threshold="low"
    )

    assert running["requested_severity_threshold"] == "LOW", running


@pytest.mark.asyncio
async def test_progress_never_reports_a_requested_threshold_the_scan_did_not_apply(
    tmp_path, held_scan
):
    """CRITICAL over the default MEDIUM is ignored, so nothing may say CRITICAL.

    A registry that recorded the request as the scan's threshold would have
    progress echo it until a COMPLETED or INCOMPLETE runner replaced it with the
    threshold the findings were judged by, so a scan still running, or one that
    failed, would be reported at CRITICAL although it ran at MEDIUM.
    """
    _started, _release, outcome = held_scan
    outcome["raise"] = RuntimeError("scanner orchestration crashed")

    running, ended = await _progress_while_held(
        _project(tmp_path), held_scan, severity_threshold="CRITICAL"
    )

    assert running["severity_threshold"] != "CRITICAL", running
    assert ended["status"] == "failed", ended
    assert ended["severity_threshold"] != "CRITICAL", ended
    assert ended["requested_severity_threshold"] == "CRITICAL", ended

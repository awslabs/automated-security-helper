# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A slow or failing uv version probe must not reach any snapshot.

Regression for unit-test (windows-latest, py3.14) in run 37632600207: the semgrep
probe (``uv tool run --from <spec> semgrep --version``, 15 s timeout) did not answer,
SemgrepScanner logged ``Could not determine UV tool semgrep version`` at WARNING
while the plugin registry loaded, and that line failed test_unknown_tool on all
three platforms and a test_snapshot_errors_scan case. The conftest fixture
``_pinned_uv_tool_probe`` answers the probe for every snapshot test; these tests
make the probe time out underneath it and check nothing changes, with a positive
control showing the same timeout produces the warning without the pin.
"""

from __future__ import annotations

import subprocess  # nosec B404 - TimeoutExpired only; nothing here spawns a process

import pytest

from automated_security_helper.plugin_modules.ash_builtin.scanners.semgrep_scanner import (
    SemgrepScanner,
)
from automated_security_helper.utils import uv_tool_runner
from automated_security_helper.utils.uv_tool_runner import UVToolRunner
from tests.snapshot.conftest import pinned_uv_tool_version

# Captured at import, before any fixture patches the class.
_REAL_GET_TOOL_VERSION = UVToolRunner.get_tool_version

_WARNING = "Could not determine UV tool semgrep version"


@pytest.fixture
def probe_times_out(monkeypatch):
    """Every uv subprocess in uv_tool_runner times out, as the slow runner's did."""

    def _timeout(cmd, *args, **kwargs):
        raise subprocess.TimeoutExpired(cmd, kwargs.get("timeout", 15))

    monkeypatch.setattr(uv_tool_runner.subprocess, "run", _timeout)
    monkeypatch.setattr(uv_tool_runner, "_uv_tool_version_cache", {})


def _construct_semgrep(monkeypatch, context) -> tuple[SemgrepScanner, list[str]]:
    logged: list[str] = []
    monkeypatch.setattr(
        SemgrepScanner,
        "_plugin_log",
        lambda self, message, *args, **kwargs: logged.append(str(message)),
    )
    return SemgrepScanner(context=context), logged


def test_a_timed_out_probe_does_not_reach_a_snapshot(
    monkeypatch, probe_times_out, test_plugin_context
):
    scanner, logged = _construct_semgrep(monkeypatch, test_plugin_context)
    assert scanner.tool_version == pinned_uv_tool_version("semgrep")
    assert not any(_WARNING in line for line in logged), logged


def test_the_unknown_tool_command_is_unchanged_under_a_timed_out_probe(
    run_cli, probe_times_out
):
    result = run_cli(["dependencies", "install", "--bin-path", "bin", "--tool", "gryp"])
    assert result["exit_code"] == 2
    assert _WARNING not in result["stdout"] + result["stderr"]


def test_without_the_pin_the_same_timeout_logs_the_warning(
    monkeypatch, probe_times_out, test_plugin_context
):
    """Positive control: the instrument above can see the failure it guards."""
    monkeypatch.setattr(UVToolRunner, "get_tool_version", _REAL_GET_TOOL_VERSION)
    scanner, logged = _construct_semgrep(monkeypatch, test_plugin_context)
    assert scanner.tool_version is None
    assert any(_WARNING in line for line in logged), logged

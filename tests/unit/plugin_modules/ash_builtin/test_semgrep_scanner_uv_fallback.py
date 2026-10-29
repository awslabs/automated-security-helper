# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Semgrep's dependency fallback runs the tool the way the resolver found it.

``get_uv_tool_command`` answers ``["uv", "tool", "run", "semgrep"]`` when uv runs the
tool and the path of a semgrep binary on PATH otherwise. Both fallback sites in
``_validate_tool_dependencies`` read any non-None answer as "the binary is on PATH"
and turned ``use_uv_tool`` off, so when uv was the only route (the explicit install
failed, or the runner reported uv unavailable while the probe answered) the scan
went on to exec a semgrep that is not on PATH.

The resolver and the install steps are stood in for; no process starts here.
"""

from __future__ import annotations

import pytest

from automated_security_helper.plugin_modules.ash_builtin.scanners import (
    semgrep_scanner as semgrep_module,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.semgrep_scanner import (
    SemgrepScanner,
    SemgrepScannerConfig,
    SemgrepScannerConfigOptions,
)

pytestmark = pytest.mark.unit


UV_FORM = ["uv", "tool", "run", "semgrep"]
DIRECT_FORM = ["/opt/tools/bin/semgrep"]


def _scanner(test_plugin_context, monkeypatch) -> SemgrepScanner:
    monkeypatch.delenv("SEMGREP_RULES_CACHE_DIR", raising=False)
    monkeypatch.setattr(SemgrepScanner, "_scanner_offline", lambda self: False)
    monkeypatch.setattr(
        SemgrepScanner, "unsupported_platform_reason", lambda self: None
    )
    scanner = SemgrepScanner(
        context=test_plugin_context,
        config=SemgrepScannerConfig(options=SemgrepScannerConfigOptions(offline=False)),
    )
    assert scanner.use_uv_tool is True, "premise: semgrep runs through uv by default"
    return scanner


def _install_fails(monkeypatch):
    """uv is available, semgrep is not installed, and the explicit install fails."""
    monkeypatch.setattr(
        SemgrepScanner, "_validate_uv_tool_availability", lambda self: True
    )
    monkeypatch.setattr(
        SemgrepScanner, "_get_tool_installation_info", lambda self: {"available": False}
    )
    monkeypatch.setattr(
        SemgrepScanner, "_install_uv_tool", lambda self, timeout=300: False
    )


@pytest.mark.parametrize(
    ("found", "uses_uv"),
    [
        pytest.param(UV_FORM, True, id="uv-runs-it"),
        pytest.param(DIRECT_FORM, False, id="binary"),
    ],
)
def test_the_install_fallback_runs_the_tool_as_the_resolver_found_it(
    test_plugin_context, monkeypatch, found, uses_uv
):
    """Fails at the base for the uv form: ``use_uv_tool`` was set False for any
    non-None answer, and the scan would exec a semgrep that is not on PATH."""
    scanner = _scanner(test_plugin_context, monkeypatch)
    _install_fails(monkeypatch)
    monkeypatch.setattr(semgrep_module, "get_uv_tool_command", lambda name: list(found))

    assert scanner._validate_tool_dependencies() is True
    assert scanner.dependencies_satisfied is True
    assert scanner.use_uv_tool is uses_uv


@pytest.mark.parametrize(
    ("found", "uses_uv"),
    [
        pytest.param(UV_FORM, True, id="uv-runs-it"),
        pytest.param(DIRECT_FORM, False, id="binary"),
    ],
)
def test_the_uv_unavailable_fallback_runs_the_tool_as_the_resolver_found_it(
    test_plugin_context, monkeypatch, found, uses_uv
):
    """The runner reporting uv unavailable is one reading; the resolver's probe is
    another. When the probe answers with the uv form, uv runs the tool."""
    scanner = _scanner(test_plugin_context, monkeypatch)
    monkeypatch.setattr(
        SemgrepScanner, "_validate_uv_tool_availability", lambda self: False
    )
    monkeypatch.setattr(semgrep_module, "get_uv_tool_command", lambda name: list(found))

    assert scanner._validate_tool_dependencies() is True
    assert scanner.dependencies_satisfied is True
    assert scanner.use_uv_tool is uses_uv


def test_no_route_at_all_is_still_a_failed_check(test_plugin_context, monkeypatch):
    """The control: a None answer leaves the dependency unsatisfied, as before."""
    scanner = _scanner(test_plugin_context, monkeypatch)
    _install_fails(monkeypatch)
    monkeypatch.setattr(semgrep_module, "get_uv_tool_command", lambda name: None)

    assert scanner._validate_tool_dependencies() is False

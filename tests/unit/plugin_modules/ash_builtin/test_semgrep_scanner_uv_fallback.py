# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Semgrep's dependency fallback runs the tool the way the resolver found it.

``get_uv_tool_command`` answers ``["uv", "tool", "run", "semgrep"]`` when uv runs the
tool and the path of a semgrep binary on PATH otherwise. Both fallback sites in
``_validate_tool_dependencies`` read any non-None answer as "the binary is on PATH"
and turned ``use_uv_tool`` off, so when uv was the only route (the runner reported
uv unavailable while the probe answered) the scan went on to exec a semgrep that is
not on PATH. The uv form is told by the first word's file name, so a uv named by its
full path counts as uv. After uv's own install of the tool failed, the uv form is
not an answer at all: ``uv tool run`` would repeat the failed install at scan time,
so only a semgrep binary on PATH satisfies the dependency there.

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
from automated_security_helper.utils import pre_installed_tool
from automated_security_helper.utils.pre_installed_tool import PreInstalledToolVerdict

pytestmark = pytest.mark.unit


UV_FORM = ["uv", "tool", "run", "semgrep"]
UV_BY_PATH = ["/usr/local/bin/uv", "tool", "run", "semgrep"]
DIRECT_FORM = ["/opt/tools/bin/semgrep"]


def _scanner(test_plugin_context, monkeypatch) -> SemgrepScanner:
    monkeypatch.delenv("SEMGREP_RULES_CACHE_DIR", raising=False)
    monkeypatch.setattr(SemgrepScanner, "_scanner_offline", lambda self: False)
    monkeypatch.setattr(
        SemgrepScanner, "unsupported_platform_reason", lambda self: None
    )
    # Both binary routes verify the binary they found against the scan's
    # requirement (test_semgrep_scanner_direct_binary_verified.py is about that
    # verification). Here the routes are the subject, so the verifier is stood in
    # for and answers "satisfied": the real one would probe a path that does not
    # exist, and could start uv or the binary, which this file's docstring rules out.
    monkeypatch.setattr(
        pre_installed_tool,
        "verify_pre_installed_tool",
        lambda executable, package, extras=None, version_constraint=None, **kw: (
            PreInstalledToolVerdict(
                "satisfied", executable, "semgrep>=1.125.0,<2.0.0", "stood in for"
            )
        ),
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


def test_the_install_fallback_runs_a_semgrep_binary_on_path(
    test_plugin_context, monkeypatch
):
    """After uv's install of semgrep failed, a semgrep binary on PATH is the
    fallback, run directly, found by a direct PATH lookup.

    The resolver is not the lookup: it probes ``uv tool run semgrep --version``
    first and answers the uv form whenever that probe succeeds, and it remembers
    the answer per process, so its answer here is the uv form while a binary sits
    on PATH. This test models exactly that: the resolver says uv, PATH has the
    binary. Red at the tip that read the resolver (the uv form was refused and
    semgrep reported MISSING with a binary on PATH); green with the direct lookup.
    At the base the resolver's answer was taken as the binary either way, so this
    is not a red-at-base test.
    """
    scanner = _scanner(test_plugin_context, monkeypatch)
    _install_fails(monkeypatch)
    monkeypatch.setattr(
        semgrep_module, "get_uv_tool_command", lambda name, **kwargs: list(UV_FORM)
    )
    monkeypatch.setattr(semgrep_module, "find_executable", lambda name: DIRECT_FORM[0])

    assert scanner._validate_tool_dependencies() is True
    assert scanner.dependencies_satisfied is True
    assert scanner.use_uv_tool is False


@pytest.mark.parametrize(
    "found",
    [
        pytest.param(UV_FORM, id="uv-runs-it"),
        pytest.param(UV_BY_PATH, id="uv-named-by-path"),
    ],
)
def test_the_install_fallback_does_not_accept_the_uv_form(
    test_plugin_context, monkeypatch, found
):
    """After the explicit install failed, ``uv tool run semgrep`` is no answer: the
    scan would repeat the install that just failed (offline, it fails again). With
    no semgrep binary on PATH the dependency is MISSING, as it was before the
    resolver fallback existed, whatever the resolver answers.

    Fails at the base: the uv form was accepted and the scanner recorded the
    dependency as satisfied.
    """
    scanner = _scanner(test_plugin_context, monkeypatch)
    _install_fails(monkeypatch)
    monkeypatch.setattr(
        semgrep_module, "get_uv_tool_command", lambda name, **kwargs: list(found)
    )
    monkeypatch.setattr(semgrep_module, "find_executable", lambda name: None)

    assert scanner._validate_tool_dependencies() is False
    assert scanner.dependencies_satisfied is not True


@pytest.mark.parametrize(
    ("found", "uses_uv"),
    [
        pytest.param(UV_FORM, True, id="uv-runs-it"),
        pytest.param(UV_BY_PATH, True, id="uv-named-by-path"),
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
    monkeypatch.setattr(
        semgrep_module, "get_uv_tool_command", lambda name, **kwargs: list(found)
    )

    assert scanner._validate_tool_dependencies() is True
    assert scanner.dependencies_satisfied is True
    assert scanner.use_uv_tool is uses_uv


def test_no_route_at_all_is_still_a_failed_check(test_plugin_context, monkeypatch):
    """The control: no binary on PATH and a None resolver answer leave the
    dependency unsatisfied, as before."""
    scanner = _scanner(test_plugin_context, monkeypatch)
    _install_fails(monkeypatch)
    monkeypatch.setattr(
        semgrep_module, "get_uv_tool_command", lambda name, **kwargs: None
    )
    monkeypatch.setattr(semgrep_module, "find_executable", lambda name: None)

    assert scanner._validate_tool_dependencies() is False

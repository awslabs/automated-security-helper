"""Semgrep's direct route records the version of the copy that runs.

A semgrep binary on PATH that runs directly (uv missing, or uv's install failed)
is the binary the scan runs, so the version the reports name is its own. A copy
that answered no version used to leave the value an earlier uv probe wrote, which
names uv's environment and not the binary that ran. And a return to the uv route
kept the direct copy's version with no probe owed.
"""

from __future__ import annotations

import pytest

from automated_security_helper.plugin_modules.ash_builtin.scanners import (
    semgrep_scanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.semgrep_scanner import (
    SemgrepScanner,
    SemgrepScannerConfig,
    SemgrepScannerConfigOptions,
)
from automated_security_helper.utils import pre_installed_tool
from automated_security_helper.utils.pre_installed_tool import PreInstalledToolVerdict

pytestmark = pytest.mark.unit

BINARY = "/opt/tools/bin/semgrep"
UV_PROBE_VERSION = "1.140.0"


@pytest.fixture(autouse=True)
def _no_tool_probe(monkeypatch):
    from tests.utils.tool_guard import stub_tool_probes

    stub_tool_probes(monkeypatch)


def _scanner(test_plugin_context, monkeypatch) -> SemgrepScanner:
    monkeypatch.delenv("SEMGREP_RULES_CACHE_DIR", raising=False)
    monkeypatch.setattr(SemgrepScanner, "_scanner_offline", lambda self: False)
    scanner = SemgrepScanner(
        context=test_plugin_context,
        config=SemgrepScannerConfig(options=SemgrepScannerConfigOptions(offline=False)),
    )
    monkeypatch.setattr(
        SemgrepScanner, "unsupported_platform_reason", lambda self: None
    )
    return scanner


def _verdict(status: str, version: str | None):
    return PreInstalledToolVerdict(
        status,
        BINARY,
        "semgrep>=1.125.0,<2.0.0",
        "semgrep answered",
        version=version,
    )


def _answer(monkeypatch, status: str, version: str | None):
    monkeypatch.setattr(
        pre_installed_tool,
        "verify_pre_installed_tool",
        lambda *args, **kwargs: _verdict(status, version),
    )


def test_a_satisfying_copy_with_no_version_leaves_the_record_empty(
    test_plugin_context, monkeypatch
):
    scanner = _scanner(test_plugin_context, monkeypatch)
    scanner.tool_version = UV_PROBE_VERSION
    _answer(monkeypatch, "satisfied", None)

    assert scanner._direct_binary_satisfies(BINARY) is True

    assert scanner.tool_version is None
    assert scanner._deferred_tool_version_probe is None


def test_a_satisfying_copy_records_the_version_it_answered(
    test_plugin_context, monkeypatch
):
    scanner = _scanner(test_plugin_context, monkeypatch)
    scanner.tool_version = UV_PROBE_VERSION
    _answer(monkeypatch, "satisfied", "1.130.0")

    assert scanner._direct_binary_satisfies(BINARY) is True

    assert scanner.tool_version == "1.130.0"


def test_an_unverifiable_copy_with_no_version_leaves_the_record_empty(
    test_plugin_context, monkeypatch
):
    scanner = _scanner(test_plugin_context, monkeypatch)
    scanner.tool_version = UV_PROBE_VERSION
    _answer(monkeypatch, "unverifiable", None)

    assert scanner._direct_binary_satisfies(BINARY) is True

    assert scanner.tool_version is None
    assert scanner._deferred_tool_version_probe is None


def test_an_unverifiable_copy_records_the_version_it_answered(
    test_plugin_context, monkeypatch
):
    scanner = _scanner(test_plugin_context, monkeypatch)
    scanner.tool_version = UV_PROBE_VERSION
    _answer(monkeypatch, "unverifiable", "1.131.0")

    assert scanner._direct_binary_satisfies(BINARY) is True

    assert scanner.tool_version == "1.131.0"


def test_the_last_resort_after_a_failed_install_records_no_probe_version(
    test_plugin_context, monkeypatch
):
    scanner = _scanner(test_plugin_context, monkeypatch)
    monkeypatch.setattr(semgrep_scanner, "find_executable", lambda name: BINARY)
    monkeypatch.setattr(
        SemgrepScanner, "_validate_uv_tool_availability", lambda self: True
    )
    monkeypatch.setattr(
        SemgrepScanner,
        "_get_tool_installation_info",
        lambda self: {"available": False},
    )
    monkeypatch.setattr(
        SemgrepScanner, "_install_uv_tool", lambda self, timeout=300: False
    )
    _answer(monkeypatch, "satisfied", None)
    scanner.use_uv_tool = True
    scanner.tool_version = UV_PROBE_VERSION

    assert scanner._validate_tool_dependencies() is True

    assert scanner.use_uv_tool is False
    assert scanner.tool_version is None


def test_the_resolver_returning_to_uv_takes_the_direct_copys_version_with_the_route(
    test_plugin_context, monkeypatch
):
    scanner = _scanner(test_plugin_context, monkeypatch)
    monkeypatch.setattr(
        semgrep_scanner,
        "get_uv_tool_command",
        lambda name, **kwargs: ["uv", "tool", "run", "semgrep"],
    )
    scanner.use_uv_tool = False
    scanner._deferred_tool_version_probe = None
    scanner.tool_version = "1.130.0"

    assert scanner._direct_or_uv_command_found() is True

    assert scanner.use_uv_tool is True
    assert scanner.tool_version is None
    assert scanner._deferred_tool_version_probe is not None
    assert scanner._deferred_tool_version_probe[0] == "semgrep"

"""Semgrep's direct route records the version of the copy that runs.

A semgrep binary on PATH that runs directly (uv missing, or uv's install failed)
is the binary the scan runs, so the version the reports name is its own. A copy
that answered no version used to leave the value an earlier uv probe wrote, which
names uv's environment and not the binary that ran. The record is made where the
route changes: asking whether a copy may run changes no route and no version
record, and a uv answer leaves the uv route's record as it is.
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


def _binary_on_path(monkeypatch):
    """The direct lookup of the install fallback (``direct_only``) finds the copy."""
    monkeypatch.setattr(semgrep_scanner, "find_executable", lambda name: BINARY)


def test_a_satisfying_copy_with_no_version_leaves_the_record_empty(
    test_plugin_context, monkeypatch
):
    scanner = _scanner(test_plugin_context, monkeypatch)
    scanner.tool_version = UV_PROBE_VERSION
    _answer(monkeypatch, "satisfied", None)

    _binary_on_path(monkeypatch)

    assert scanner._direct_or_uv_command_found(direct_only=True) is True

    assert scanner.use_uv_tool is False

    assert scanner.tool_version is None
    assert scanner._deferred_tool_version_probe is None


def test_a_satisfying_copy_records_the_version_it_answered(
    test_plugin_context, monkeypatch
):
    scanner = _scanner(test_plugin_context, monkeypatch)
    scanner.tool_version = UV_PROBE_VERSION
    _answer(monkeypatch, "satisfied", "1.130.0")

    _binary_on_path(monkeypatch)

    assert scanner._direct_or_uv_command_found(direct_only=True) is True

    assert scanner.use_uv_tool is False

    assert scanner.tool_version == "1.130.0"


def test_an_unverifiable_copy_with_no_version_leaves_the_record_empty(
    test_plugin_context, monkeypatch
):
    scanner = _scanner(test_plugin_context, monkeypatch)
    scanner.tool_version = UV_PROBE_VERSION
    _answer(monkeypatch, "unverifiable", None)

    _binary_on_path(monkeypatch)

    assert scanner._direct_or_uv_command_found(direct_only=True) is True

    assert scanner.use_uv_tool is False

    assert scanner.tool_version is None
    assert scanner._deferred_tool_version_probe is None


def test_an_unverifiable_copy_records_the_version_it_answered(
    test_plugin_context, monkeypatch
):
    scanner = _scanner(test_plugin_context, monkeypatch)
    scanner.tool_version = UV_PROBE_VERSION
    _answer(monkeypatch, "unverifiable", "1.131.0")

    _binary_on_path(monkeypatch)

    assert scanner._direct_or_uv_command_found(direct_only=True) is True

    assert scanner.use_uv_tool is False

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


def test_a_uv_answer_keeps_the_uv_routes_record(test_plugin_context, monkeypatch):
    """The resolver fallback (no ``direct_only``) is called only from the
    uv-absent branch of ``_validate_tool_dependencies``, entered only while
    ``use_uv_tool`` is True: ``_validate_uv_tool_availability`` answers True at
    once for a scanner off uv. A uv answer there leaves the uv route as it is,
    the version the uv probe recorded and a probe still owed included."""
    scanner = _scanner(test_plugin_context, monkeypatch)
    monkeypatch.setattr(
        semgrep_scanner,
        "get_uv_tool_command",
        lambda name, **kwargs: ["uv", "tool", "run", "semgrep"],
    )
    monkeypatch.setattr(
        pre_installed_tool,
        "verify_pre_installed_tool",
        lambda *args, **kwargs: pytest.fail("a uv answer is not verified as semgrep"),
    )
    scanner.use_uv_tool = True
    scanner.tool_version = UV_PROBE_VERSION
    scanner._deferred_tool_version_probe = ("semgrep", None)

    assert scanner._direct_or_uv_command_found() is True

    assert scanner.use_uv_tool is True
    assert scanner.tool_version == UV_PROBE_VERSION
    assert scanner._deferred_tool_version_probe == ("semgrep", None)


def test_a_uv_answer_reached_off_uv_takes_the_uv_route(
    test_plugin_context, monkeypatch
):
    """The test above enters on uv, which is where the one real caller is. Any other
    entry (an override of the availability check, a new caller, a test that patches
    it) must not leave a uv answer on a direct route, where the scan starts whatever
    semgrep PATH holds, unverified. A uv answer is the uv route: the scanner goes
    back to it with the record that route owes, the version of the direct copy
    dropped and the uv probe owed again.

    Without the fix the branch returned True with the route still direct."""
    scanner = _scanner(test_plugin_context, monkeypatch)
    monkeypatch.setattr(
        semgrep_scanner,
        "get_uv_tool_command",
        lambda name, **kwargs: ["uv", "tool", "run", "semgrep"],
    )
    monkeypatch.setattr(
        pre_installed_tool,
        "verify_pre_installed_tool",
        lambda *args, **kwargs: pytest.fail("a uv answer is not verified as semgrep"),
    )
    scanner.use_uv_tool = False
    scanner.tool_version = "1.130.0"  # a direct route's record
    scanner._deferred_tool_version_probe = None

    assert scanner._direct_or_uv_command_found() is True

    assert scanner.use_uv_tool is True
    assert scanner.tool_version is None
    assert scanner._deferred_tool_version_probe == ("semgrep", None)
    assert scanner.dependencies_satisfied is True


@pytest.mark.parametrize("status", ["satisfied", "unverifiable"])
def test_checking_a_copy_on_path_changes_no_record(
    test_plugin_context, monkeypatch, status
):
    """Asking whether the copy on PATH may run answers with the verifier's
    verdict and changes no route and no version record: the caller that takes the
    direct route records the copy's version beside its route change.

    Fails at the base: the check itself replaced the version the uv probe
    recorded and dropped the probe still owed."""
    scanner = _scanner(test_plugin_context, monkeypatch)
    scanner.use_uv_tool = True
    scanner.tool_version = UV_PROBE_VERSION
    scanner._deferred_tool_version_probe = ("semgrep", None)
    _answer(monkeypatch, status, "1.130.0")

    answer = scanner._direct_binary_verdict(BINARY)

    assert scanner.tool_version == UV_PROBE_VERSION
    assert scanner._deferred_tool_version_probe == ("semgrep", None)
    assert scanner.use_uv_tool is True
    assert answer is not None
    assert answer.version == "1.130.0"


@pytest.mark.parametrize(
    "direct_only", [True, False], ids=["install-fallback", "resolver-fallback"]
)
def test_a_copy_check_that_answers_false_refuses_the_copy(
    test_plugin_context, monkeypatch, direct_only
):
    """The check of a copy on PATH answers with a verdict, and a refusal is no
    verdict. A stand-in or an override still written to the old yes-or-no answer
    says False to refuse, and both callers (the install fallback and the resolver
    fallback) take that as a refusal: the copy does not run, the route and the
    record the uv route made stay, and the dependency is not satisfied.

    Without the fix a False answer was taken as a copy that may run: only None
    refused."""
    scanner = _scanner(test_plugin_context, monkeypatch)
    monkeypatch.setattr(
        SemgrepScanner, "_direct_binary_verdict", lambda self, executable: False
    )
    if direct_only:
        _binary_on_path(monkeypatch)
    else:
        monkeypatch.setattr(
            semgrep_scanner, "get_uv_tool_command", lambda name, **kwargs: [BINARY]
        )
    scanner.use_uv_tool = True
    scanner.tool_version = UV_PROBE_VERSION
    scanner._deferred_tool_version_probe = ("semgrep", None)

    assert scanner._direct_or_uv_command_found(direct_only=direct_only) is False

    assert scanner.use_uv_tool is True
    assert scanner.tool_version == UV_PROBE_VERSION
    assert scanner._deferred_tool_version_probe == ("semgrep", None)
    assert scanner.dependencies_satisfied is not True


def test_the_copy_check_is_named_for_the_verdict_it_returns():
    """The check returns the verifier's verdict for a copy that may run and None
    for one that may not, so it is not named as a yes-or-no question. No alias of
    the old name stays: an override of it would never be called by the base."""
    assert callable(getattr(SemgrepScanner, "_direct_binary_verdict", None))
    assert not hasattr(SemgrepScanner, "_direct_binary_satisfies")

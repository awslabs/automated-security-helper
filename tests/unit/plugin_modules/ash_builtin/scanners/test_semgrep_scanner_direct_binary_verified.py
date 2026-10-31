# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A semgrep binary found on PATH is verified before the scan runs it directly.

``_direct_or_uv_command_found`` is the dependency check's fallback: with uv missing,
or after uv's own install of semgrep failed, the resolver answers with a semgrep
binary on PATH and the scan runs it directly. It used to run whatever that binary
was, unverified against the scanner's version constraint, while the pre-installed
route (``_select_tool_execution``) verifies a binary before running it directly.

Now the binary is verified the same way (``utils/pre_installed_tool``): a copy that
does not satisfy the requirement is refused, with the reason recorded for the
MISSING row; one that cannot be verified runs, with a warning, since it is the only
route left.

The check's answer is stood in for: verifying runs ``semgrep --version``, and no tool starts
here. Building the scanner probes uv; the tool guard answers as a host without it. The
host is stood in for as one semgrep publishes a build for: on Windows the dependency
check refuses before it reaches the binary route these tests are about.
"""

from __future__ import annotations

import logging

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
    # A host semgrep publishes a build for; uv is missing, and PATH holds a semgrep binary.
    monkeypatch.setattr(
        SemgrepScanner, "unsupported_platform_reason", lambda self: None
    )
    monkeypatch.setattr(
        SemgrepScanner, "_validate_uv_tool_availability", lambda self: False
    )
    monkeypatch.setattr(
        semgrep_scanner, "get_uv_tool_command", lambda name, **kwargs: [BINARY]
    )
    return scanner


def _verdict(status: str, detail: str, version: str | None = None, summary: str = ""):
    return PreInstalledToolVerdict(
        status,
        BINARY,
        "semgrep>=1.125.0,<2.0.0",
        detail,
        version=version,
        summary=summary,
    )


def _answer(monkeypatch, answer, seen: list):
    def verify(executable, package, extras=None, version_constraint=None, **kwargs):
        seen.append((executable, package, version_constraint))
        return answer

    monkeypatch.setattr(pre_installed_tool, "verify_pre_installed_tool", verify)


def test_a_binary_that_does_not_satisfy_the_constraint_is_refused(
    test_plugin_context, monkeypatch, caplog
):
    """Verified unsatisfied: the dependency check says no and records why.

    Fails at the base: the binary was taken without a verification, so the check
    answered True and the scan ran it.
    """
    scanner = _scanner(test_plugin_context, monkeypatch)
    seen: list = []
    detail = "semgrep 1.100.0 at /home/someone/.local/bin/semgrep does not satisfy"
    _answer(
        monkeypatch,
        _verdict(
            "unsatisfied",
            detail,
            summary="the installed semgrep is older than required",
        ),
        seen,
    )

    with caplog.at_level(logging.ERROR):
        assert scanner._validate_tool_dependencies() is False
    assert seen and seen[0][0] == BINARY, seen
    assert seen[0][2] == scanner._get_tool_version_constraint()
    # The REASON reaches the results: the verifier's path-free summary, never the
    # copy's path or the full detail, which quotes the tool's own output.
    reason = scanner.dependency_unavailable_reason or ""
    assert "cannot be used" in reason, reason
    assert "older than required" in reason, reason
    assert BINARY not in reason, reason
    assert "1.100.0" not in reason and "/home/someone" not in reason, reason
    # The LOG keeps the full story: the path and the detail.
    logged = [r.getMessage() for r in caplog.records if r.levelno >= logging.ERROR]
    assert any(BINARY in line and "1.100.0" in line for line in logged), logged


def test_an_answer_without_a_summary_falls_back_to_its_detail_in_the_reason(
    test_plugin_context, monkeypatch
):
    """A verifier stand-in that carries no summary: the detail stands in, as the
    mixin's own MISSING line does, so the reason still says why."""
    scanner = _scanner(test_plugin_context, monkeypatch)
    _answer(monkeypatch, _verdict("unsatisfied", "semgrep 1.100.0 is too old"), [])

    assert scanner._validate_tool_dependencies() is False
    reason = scanner.dependency_unavailable_reason or ""
    assert "1.100.0" in reason and BINARY not in reason, reason


def test_a_binary_that_satisfies_the_constraint_runs_directly(
    test_plugin_context, monkeypatch
):
    """The control: verified satisfied, the scan runs the binary directly and the
    reports name its version."""
    scanner = _scanner(test_plugin_context, monkeypatch)
    _answer(
        monkeypatch, _verdict("satisfied", "semgrep 1.130.0", version="1.130.0"), []
    )

    assert scanner._validate_tool_dependencies() is True
    assert scanner.use_uv_tool is False
    assert scanner.dependencies_satisfied is True
    assert scanner.dependency_unavailable_reason is None
    assert scanner.tool_version == "1.130.0"


def test_a_binary_that_cannot_be_verified_still_runs(
    test_plugin_context, monkeypatch, caplog
):
    """Unverifiable (no uv to resolve the requirement with, say): the only route
    left is taken, with a warning rather than a refusal. The verifier was asked
    (``seen``), and the warning names the copy and says it is unverified."""
    scanner = _scanner(test_plugin_context, monkeypatch)
    seen: list = []
    _answer(monkeypatch, _verdict("unverifiable", "no uv to resolve against"), seen)

    with caplog.at_level(logging.WARNING):
        assert scanner._validate_tool_dependencies() is True
    assert scanner.use_uv_tool is False
    assert scanner.dependency_unavailable_reason is None
    assert seen and seen[0][0] == BINARY, seen
    warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert any(BINARY in line and "unverified" in line for line in warnings), warnings


def test_a_values_hook_that_raises_refuses_the_copy_on_path(
    test_plugin_context, monkeypatch, caplog
):
    """The values hook is overridable, and a raising one used to escape the
    dependency check; the first cure let the copy run unverified. Now the check
    answers False with a reason that names the hook's failure and no path, the
    warning carries no text the hook would have redacted, and the verifier is
    never asked: a copy whose records cannot be redacted does not run.

    Fails at the tip that returned True from the value-free arm (the check
    answered True and no reason was recorded), and at the base, where the
    exception escaped ``_validate_tool_dependencies``.

    The reason offers no uv remedy either: the mixin's run path refuses the uv
    route on the same hook failure, so installing uv would not make the scan run.
    That row fails at the previous tip, whose reason ended "or install uv so ASH
    can run a verified copy".
    """
    scanner = _scanner(test_plugin_context, monkeypatch)
    seen: list = []
    _answer(monkeypatch, _verdict("satisfied", "semgrep 1.130.0"), seen)

    def broken(self):
        raise RuntimeError("the hook is broken")

    monkeypatch.setattr(SemgrepScanner, "_values_to_redact", broken)

    with caplog.at_level(logging.WARNING):
        assert scanner._validate_tool_dependencies() is False
    assert seen == [], "the verify ran with values that could not be read"
    reason = scanner.dependency_unavailable_reason or ""
    assert "values hook" in reason and "RuntimeError" in reason, reason
    assert BINARY not in reason, reason
    assert "install uv" not in reason, reason
    warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert any(
        "RuntimeError" in line and "not verified" in line for line in warnings
    ), warnings
    assert not any(BINARY in line for line in warnings), warnings


def test_a_values_hook_answering_a_generator_is_read_once_and_redacts_every_line(
    test_plugin_context, monkeypatch, caplog
):
    """A generator answer used to be drained by the verify, so the lines after it
    were redacted against nothing and logged the requirement and the verifier's
    detail in clear. The guarded read turns it into a tuple once; the verifier
    gets that tuple and the reason is redacted with it.

    Fails at the base: the reason carried the secret value.
    """
    scanner = _scanner(test_plugin_context, monkeypatch)
    secret = "hunter2-token-value"
    seen_values: list = []

    def verify(executable, package, extras=None, version_constraint=None, **kwargs):
        seen_values.append(tuple(kwargs.get("values") or ()))
        return _verdict(
            "unsatisfied",
            f"semgrep at {BINARY} rejected {secret}",
            summary=f"rejected {secret}",
        )

    monkeypatch.setattr(pre_installed_tool, "verify_pre_installed_tool", verify)
    monkeypatch.setattr(
        SemgrepScanner, "_values_to_redact", lambda self: (v for v in [secret])
    )

    with caplog.at_level(logging.ERROR):
        assert scanner._validate_tool_dependencies() is False
    assert seen_values == [(secret,)], seen_values
    reason = scanner.dependency_unavailable_reason or ""
    assert secret not in reason, reason
    assert "rejected" in reason, reason
    logged = [r.getMessage() for r in caplog.records if r.levelno >= logging.ERROR]
    assert logged and all(secret not in line for line in logged), logged


def test_the_last_resort_after_a_failed_install_is_verified_too(
    test_plugin_context, monkeypatch
):
    """After uv's install of semgrep failed, the binary on PATH is the last resort,
    and an unsatisfying one is refused there as well. The last resort looks the
    binary up on PATH directly (``find_executable``), so that lookup is stood in
    for here; the resolver stub answers ANOTHER path, so the verified path tells
    which lookup the route used.

    Fails at the base: the last-resort binary was taken unverified.
    """
    scanner = _scanner(test_plugin_context, monkeypatch)
    monkeypatch.setattr(
        semgrep_scanner,
        "get_uv_tool_command",
        lambda name, **kwargs: ["/elsewhere/bin/semgrep"],
    )
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
    scanner.use_uv_tool = True
    seen: list = []
    _answer(monkeypatch, _verdict("unsatisfied", "semgrep 0.9.0 is too old"), seen)

    assert scanner._validate_tool_dependencies() is False
    assert seen and seen[0][0] == BINARY, seen
    assert "0.9.0" in (scanner.dependency_unavailable_reason or "")


def test_the_last_resort_after_a_failed_install_never_asks_the_resolver(
    test_plugin_context, monkeypatch
):
    """After uv's install of semgrep failed, the resolver is not consulted at all:
    it probes uv first and remembers a uv answer per process, so asking it could
    hide a binary that is on PATH now, or answer the uv route whose install has
    just failed. The last resort looks the binary up itself; with none on PATH
    the dependency is missing and the resolver was never asked.

    Pins the route the cross-scanner probe test leaves out for semgrep.
    """
    scanner = _scanner(test_plugin_context, monkeypatch)
    asked: list[str] = []

    def resolver(name, **kwargs):
        asked.append(name)
        return [BINARY]

    monkeypatch.setattr(semgrep_scanner, "get_uv_tool_command", resolver)
    monkeypatch.setattr(semgrep_scanner, "find_executable", lambda name: None)
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
    scanner.use_uv_tool = True

    assert scanner._validate_tool_dependencies() is False
    assert asked == []


@pytest.mark.parametrize("own_offline", [True, False])
def test_the_probe_runs_under_the_scanners_own_offline_mode(
    test_plugin_context, monkeypatch, own_offline
):
    """The resolver is asked with the scanner's own reading of offline, not left
    to ASH's mode alone: with ``options.offline: true`` and ASH online, the
    version probe runs offline like the scan, the version probe and the install
    already do. With the option off it is asked with False, which the resolver
    reads as "follow ASH".

    Fails at the base on both rows: the resolver was asked with no ``offline``
    at all, so an offline scanner's probe went to the network.
    """
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    monkeypatch.delenv("SEMGREP_RULES_CACHE_DIR", raising=False)
    scanner = SemgrepScanner(
        context=test_plugin_context,
        config=SemgrepScannerConfig(
            options=SemgrepScannerConfigOptions(offline=own_offline)
        ),
    )
    monkeypatch.setattr(
        SemgrepScanner, "unsupported_platform_reason", lambda self: None
    )
    monkeypatch.setattr(
        SemgrepScanner, "_validate_uv_tool_availability", lambda self: False
    )
    asked: list[dict] = []

    def resolver(name, **kwargs):
        asked.append(dict(kwargs))
        return [BINARY]

    monkeypatch.setattr(semgrep_scanner, "get_uv_tool_command", resolver)
    _answer(
        monkeypatch, _verdict("satisfied", "semgrep 1.130.0", version="1.130.0"), []
    )

    assert scanner._validate_tool_dependencies() is True
    assert len(asked) == 1
    assert asked[0].get("offline") is own_offline

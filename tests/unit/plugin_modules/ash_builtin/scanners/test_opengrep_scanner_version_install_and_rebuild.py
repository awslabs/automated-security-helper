# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Four small corrections to the opengrep scanner.

- ``options.version`` spelled without the leading ``v`` (``1.30.2`` for the pinned
  ``v1.30.2``; the validator accepts both) is the pinned release, installed through
  the verified pinned-tool commands. It used to take the custom-version branch and
  be refused for want of a digest.
- The ``--metrics`` rebuild on the first target runs the offline-cache validation
  again, after ``_execute_scan`` checked the reason construction recorded; a cache
  that became unusable since is refused, not scanned without.
- A copy of opengrep found only inside the scanned tree is refused by the lookup,
  and the refusal is now recorded for the MISSING row, as the base's dependency
  check records it; the row used to say "not installed".
- The install-command lookup reads the host's architecture from the machine name,
  not the pointer size, which read every 64-bit host as amd64.

Building the scanner probes ``opengrep --version``; the tool guard answers as a host
without opengrep would, so nothing starts here.
"""

from __future__ import annotations

import platform

import pytest

from automated_security_helper.base.plugin_base import CustomCommand
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules.ash_builtin.scanners import (
    opengrep_scanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.opengrep_scanner import (
    OpengrepScanner,
    OpengrepScannerConfig,
    OpengrepScannerConfigOptions,
)
from automated_security_helper.utils.download_utils import pinned_tool_install_commands
from automated_security_helper.utils.tool_downloads import TOOL_VERSIONS

pytestmark = pytest.mark.unit

RULE = "rules:\n  - id: placeholder\n    languages: [python]\n    message: m\n    severity: INFO\n    pattern: $X == $X\n"


@pytest.fixture(autouse=True)
def _no_tool_probe(monkeypatch):
    from tests.utils.tool_guard import stub_tool_probes

    stub_tool_probes(monkeypatch)


def _online_scanner(test_plugin_context, monkeypatch, **options) -> OpengrepScanner:
    monkeypatch.delenv("OPENGREP_RULES_CACHE_DIR", raising=False)
    monkeypatch.setattr(OpengrepScanner, "_scanner_offline", lambda self: False)
    return OpengrepScanner(
        context=test_plugin_context,
        config=OpengrepScannerConfig(
            options=OpengrepScannerConfigOptions(offline=False, **options)
        ),
    )


def _argv(commands: list[CustomCommand]) -> str:
    return " ".join(str(word) for command in commands for word in command.args)


def test_the_pinned_release_without_its_v_installs_the_pinned_binary(
    test_plugin_context, monkeypatch
):
    """``1.30.2`` for a pinned ``v1.30.2`` gets the verified pinned install commands.

    Fails at the base: the exact string compare read it as a custom version, and
    with no digest configured every platform got a command that refuses.
    """
    pinned = TOOL_VERSIONS["opengrep"]
    assert pinned.startswith("v"), "premise: the pinned release is spelled with a v"

    scanner = _online_scanner(test_plugin_context, monkeypatch, version=pinned[1:])

    expected = pinned_tool_install_commands("opengrep")
    for target_platform, arches in expected.items():
        for arch, commands in arches.items():
            installed = scanner.custom_install_commands[target_platform][arch]
            assert _argv(installed) == _argv(commands), (target_platform, arch)
            assert "Refusing to install" not in _argv(installed)


def test_a_custom_release_without_a_digest_is_still_refused(
    test_plugin_context, monkeypatch
):
    """The control: a release that is not the pinned one, with no digest, gets the
    refusing command on every platform."""
    scanner = _online_scanner(test_plugin_context, monkeypatch, version="v9.9.9")

    for arches in scanner.custom_install_commands.values():
        for commands in arches.values():
            assert "Refusing to install opengrep v9.9.9" in _argv(commands)


def test_a_cache_that_became_unusable_before_the_first_target_refuses_the_scan(
    test_plugin_context, tmp_path, monkeypatch
):
    """The ``--metrics`` rebuild re-validates the cache; a cache emptied since
    construction is refused with the recorded reason.

    Fails at the base: the rebuild recorded the reason and the arguments were
    resolved anyway, with no cache ``--config`` in them.
    """
    cache = tmp_path / "cache"
    cache.mkdir()
    rule = cache / "ci.yaml"
    rule.write_text(RULE, encoding="utf-8")
    monkeypatch.setenv("OPENGREP_RULES_CACHE_DIR", str(cache))
    scanner = OpengrepScanner(
        context=test_plugin_context,
        config=OpengrepScannerConfig(
            options=OpengrepScannerConfigOptions(offline=True)
        ),
    )
    assert scanner.dependency_unavailable_reason is None, "premise: the cache was valid"
    target = tmp_path / "src"
    target.mkdir()

    rule.unlink()
    # An older opengrep, whose --metrics decision was left for the first target.
    scanner._metrics_decision_pending = True
    scanner._metrics_flag = True

    with pytest.raises(ScannerError, match="OPENGREP_RULES_CACHE_DIR"):
        scanner._resolve_scan_arguments(target, tmp_path / "r.sarif")


def test_the_rebuild_with_a_usable_cache_carries_metrics_off(
    test_plugin_context, tmp_path, monkeypatch
):
    """The control: the cache still valid, the first target's command carries
    ``--metrics off`` and the cache as ``--config``."""
    cache = tmp_path / "cache"
    cache.mkdir()
    (cache / "ci.yaml").write_text(RULE, encoding="utf-8")
    monkeypatch.setenv("OPENGREP_RULES_CACHE_DIR", str(cache))
    scanner = OpengrepScanner(
        context=test_plugin_context,
        config=OpengrepScannerConfig(
            options=OpengrepScannerConfigOptions(offline=True)
        ),
    )
    target = tmp_path / "src"
    target.mkdir()
    scanner._metrics_decision_pending = True
    scanner._metrics_flag = True

    argv = [
        str(word) for word in scanner._resolve_scan_arguments(target, tmp_path / "r")
    ]

    assert "--metrics" in argv and argv[argv.index("--metrics") + 1] == "off", argv
    assert cache.as_posix() in argv, argv


def test_an_in_tree_copy_is_recorded_as_the_missing_reason(
    test_plugin_context, monkeypatch
):
    """The lookup's refusal of a copy inside the scanned tree becomes the recorded
    reason, so the MISSING row names the copy and how to allow it.

    Fails at the base: the check returned False and recorded nothing.
    """
    refusal = (
        "opengrep was found only inside the scanned tree, at /repo/bin/opengrep, and "
        "ASH does not run tools from the tree: install it outside the scanned tree"
    )
    scanner = _online_scanner(test_plugin_context, monkeypatch)
    monkeypatch.setattr(opengrep_scanner, "find_executable", lambda command: None)
    monkeypatch.setattr(opengrep_scanner, "in_tree_refusal", lambda command: refusal)

    assert scanner._validate_tool_dependencies() is False
    assert scanner.dependency_unavailable_reason == refusal
    assert scanner.missing_dependency_reason() == refusal


def test_a_plain_miss_records_no_reason(test_plugin_context, monkeypatch):
    """The control: not found, with no in-tree copy refused, records nothing."""
    scanner = _online_scanner(test_plugin_context, monkeypatch)
    monkeypatch.setattr(opengrep_scanner, "find_executable", lambda command: None)
    monkeypatch.setattr(opengrep_scanner, "in_tree_refusal", lambda command: None)

    assert scanner._validate_tool_dependencies() is False
    assert scanner.dependency_unavailable_reason is None


@pytest.mark.parametrize(
    ("machine", "registered", "expected"),
    [
        pytest.param("aarch64", "arm64", True, id="arm64-host-arm64-commands"),
        pytest.param("arm64", "arm64", True, id="darwin-arm64-host"),
        pytest.param("x86_64", "amd64", True, id="amd64-host-amd64-commands"),
        pytest.param("aarch64", "amd64", False, id="arm64-host-amd64-commands-only"),
        pytest.param("x86_64", "arm64", False, id="amd64-host-arm64-commands-only"),
    ],
)
def test_install_commands_are_looked_up_by_the_machines_architecture(
    test_plugin_context, monkeypatch, machine, registered, expected
):
    """The architecture key comes from ``platform.machine()``.

    Fails at the base on the arm64 rows: the pointer size read a 64-bit host as
    amd64, so an arm64 host found no commands under its own key and an amd64
    host's commands satisfied it.
    """
    scanner = _online_scanner(test_plugin_context, monkeypatch)
    scanner.custom_install_commands = {
        "linux": {registered: [CustomCommand(args=["true"], shell=False)]}
    }
    monkeypatch.setattr(platform, "system", lambda: "Linux")
    monkeypatch.setattr(platform, "machine", lambda: machine)

    assert scanner._has_install_commands() is expected

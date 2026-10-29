# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""semgrep's version check is off for ASH's runs, so no run reads its cache file.

The defect these tests pin
--------------------------
``semgrep scan`` and ``semgrep --version`` both end with a version check that opens
``~/.cache/semgrep_version``. Under a sandbox that does not grant the file (the
``sandbox-exec`` profile on macOS denies every undeclared path in the home), the
open raises ``PermissionError``. semgrep prints its findings, then exits 2, so the
scan is recorded as failed, and the version probe prints the version and exits 2,
so the scanner's version stays unknown.

semgrep's own switch for the check is ``--disable-version-check``, or the variable
``SEMGREP_ENABLE_VERSION_CHECK=0`` that the same option reads. The check only
shows upgrade banners, which ASH never reads. The scan gets the variable from
``extra_subprocess_env``, and the version probe, which ASH starts through uv and
cannot give an argument, gets it for the length of the probe. The probe is recorded
at construction and run by resolve_deferred_tool_version, which the dependency
check, the SARIF step and the inventory call, so the probe tests call it as those
readers do.

What stays as it was: the sandbox requirements (no ``~/.cache`` path is granted),
the ``metrics`` option and the exit codes the scanner accepts.

Negative control: removing the variable from ``extra_subprocess_env`` fails the
first three tests; removing the hold around the probe fails the probe tests.
"""

import os
from typing import List, Tuple

import pytest

from automated_security_helper.plugin_modules.ash_builtin.scanners.semgrep_scanner import (
    SemgrepScanner,
    SemgrepScannerConfig,
)
from automated_security_helper.utils.uv_tool_runner import UVToolRunner

pytestmark = pytest.mark.usefixtures("no_tool_probes")

VERSION_CHECK = "SEMGREP_ENABLE_VERSION_CHECK"


@pytest.fixture
def online(monkeypatch):
    """Online, with no rule cache and no version-check setting from the host."""
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    monkeypatch.delenv("SEMGREP_RULES_CACHE_DIR", raising=False)
    monkeypatch.delenv(VERSION_CHECK, raising=False)
    return monkeypatch


@pytest.fixture
def probes(online) -> List[Tuple[str, str | None]]:
    """Replace the runner's version probe with one that records what it ran under."""
    seen: List[Tuple[str, str | None]] = []

    def probe(self, tool_name, package_name=None, *args, **kwargs):
        seen.append((tool_name, os.environ.get(VERSION_CHECK)))
        return "1.2.3"

    online.setattr(UVToolRunner, "get_tool_version", probe)
    return seen


def test_scan_environment_turns_the_version_check_off(online, test_plugin_context):
    scanner = SemgrepScanner(context=test_plugin_context, config=SemgrepScannerConfig())

    assert scanner.extra_subprocess_env() == {VERSION_CHECK: "0"}


def test_offline_rules_are_added_beside_it(online, test_plugin_context, tmp_path):
    cache = tmp_path / "rules"
    cache.mkdir()
    (cache / "rule.yaml").write_text("rules: []\n", encoding="utf-8")
    online.setenv("SEMGREP_RULES_CACHE_DIR", str(cache))
    online.setenv("ASH_OFFLINE", "YES")

    scanner = SemgrepScanner(context=test_plugin_context, config=SemgrepScannerConfig())

    assert scanner.extra_subprocess_env() == {
        VERSION_CHECK: "0",
        "SEMGREP_RULES": f"{cache}/*",
    }


def test_exported_switch_does_not_win_over_the_scanner(online, test_plugin_context):
    online.setenv(VERSION_CHECK, "1")
    scanner = SemgrepScanner(context=test_plugin_context, config=SemgrepScannerConfig())

    assert scanner.extra_subprocess_env()[VERSION_CHECK] == "0"


def test_version_probe_runs_with_the_version_check_off(
    probes, online, test_plugin_context
):
    scanner = SemgrepScanner(context=test_plugin_context, config=SemgrepScannerConfig())
    # The probe construction recorded, run as the dependency check runs it.
    scanner.resolve_deferred_tool_version()

    assert probes == [("semgrep", "0")]
    assert scanner.tool_version == "1.2.3"


def test_version_probe_puts_the_environment_back(probes, online, test_plugin_context):
    scanner = SemgrepScanner(context=test_plugin_context, config=SemgrepScannerConfig())
    scanner.resolve_deferred_tool_version()

    assert VERSION_CHECK not in os.environ


def test_version_probe_puts_back_a_value_the_host_exported(
    probes, online, test_plugin_context
):
    online.setenv(VERSION_CHECK, "1")

    scanner = SemgrepScanner(context=test_plugin_context, config=SemgrepScannerConfig())
    scanner.resolve_deferred_tool_version()

    assert probes == [("semgrep", "0")]
    assert os.environ[VERSION_CHECK] == "1"


def test_failed_version_probe_puts_the_environment_back(online, test_plugin_context):
    def broken(self, tool_name, package_name=None, *args, **kwargs):
        raise RuntimeError("probe failed")

    online.setattr(UVToolRunner, "get_tool_version", broken)

    scanner = SemgrepScanner(context=test_plugin_context, config=SemgrepScannerConfig())
    # The mixin's probe catches the failure: no version, environment restored.
    scanner.resolve_deferred_tool_version()

    assert scanner.tool_version is None
    assert VERSION_CHECK not in os.environ


def test_control_sandbox_requirements_grant_no_cache_directory_read():
    """The fix is in the environment, not in the profile: no new path is declared."""
    requirements = SemgrepScanner.sandbox_requirements

    declared = (*requirements.cache_paths, *requirements.read_paths)
    assert declared == ("~/.semgrep",)
    assert requirements.read_path_env == ("SEMGREP_RULES_CACHE_DIR",)
    assert requirements.env_prefixes == ("SEMGREP_",)

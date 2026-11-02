# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The shared trivy base updates the database only for a scan that reads it, and
reads the online or offline mode when the scan runs.

Two readings that went wrong before, shared by ``trivy`` and ``trivy-repo``:

- Online, the vulnerability database was brought up to date before every scan,
  whatever the scan reads: a ``scanners: [secret]`` run downloaded the database
  it never opens, and a registry that was unreachable failed it. The update now
  runs only when the effective scanner set names ``vuln`` or ``misconfig`` (the
  checks bundle); the skip flags still go on every online command.
- The online flag (``--skip-version-check``) and the offline skip flags were
  chosen once, when the scanner was built, while the update and its skip flags
  were chosen at scan time. A scanner built online and run offline (ASH_OFFLINE
  set in between) then carried the online flag a trivy too old to know refuses,
  and lacked the offline skip flags; the scan-time reading now decides both.
  When the two readings agree, the command is unchanged.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.plugin_modules.ash_builtin.scanners import (
    _trivy_scanner_base as trivy_base,
)
from automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_repo_scanner import (
    TrivyRepoScanner,
    TrivyRepoScannerConfig,
    TrivyRepoScannerConfigOptions,
)

pytestmark = pytest.mark.unit

OFFLINE_FLAGS = ["--skip-db-update", "--skip-java-db-update", "--skip-check-update"]

#: What the host's shell may set that these tests would otherwise read: the files
#: trivy is pointed at, its scanner set, and the three settings that switch off or
#: reshape its database update (``TRIVY_SKIP_DB_UPDATE`` and ``TRIVY_SKIP_UPDATE``
#: suppress the update, ``TRIVY_EXIT_CODE`` changes the exit status), as the
#: update tests in test_trivy_scanner.py clear them.
HOST_TRIVY_VARIABLES = (
    "TRIVY_CONFIG",
    "TRIVY_IGNOREFILE",
    "TRIVY_SECRET_CONFIG",
    "TRIVY_SCANNERS",
    "TRIVY_SKIP_DB_UPDATE",
    "TRIVY_SKIP_UPDATE",
    "TRIVY_EXIT_CODE",
)


@pytest.fixture(autouse=True)
def _online_host(monkeypatch, tmp_path):
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    for name in HOST_TRIVY_VARIABLES:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("TRIVY_CACHE_DIR", str(tmp_path / "trivy-cache"))
    monkeypatch.setattr(trivy_base, "find_executable", lambda name: f"/bin/{name}")


@pytest.fixture
def updates(monkeypatch) -> List[Dict[str, Any]]:
    """Every database update the base asks for, instead of running one."""
    calls: List[Dict[str, Any]] = []

    def record(tool, cache_dir, offline, **kwargs):
        calls.append({"tool": tool, "offline": offline, **kwargs})

    monkeypatch.setattr(trivy_base, "prepare_content_db", record)
    return calls


@pytest.fixture
def ran(monkeypatch) -> List[List[str]]:
    """The command the base hands to the subprocess layer."""
    commands: List[List[str]] = []

    def run(self, command, *args, **kwargs):
        commands.append(list(command))
        return {"returncode": 0, "stdout": "", "stderr": ""}

    monkeypatch.setattr(trivy_base.ScannerPluginBase, "_run_subprocess", run)
    return commands


def _scanner(tmp_path: Path, **options) -> TrivyRepoScanner:
    context = PluginContext(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "work",
        config=get_default_config(),
    )
    for path in (context.source_dir, context.output_dir, context.work_dir):
        path.mkdir(parents=True, exist_ok=True)
    scanner = TrivyRepoScanner(
        context=context,
        config=TrivyRepoScannerConfig(options=TrivyRepoScannerConfigOptions(**options)),
    )
    scanner.results_dir = context.output_dir / "scanners" / "trivy-repo"
    scanner.results_dir.mkdir(parents=True, exist_ok=True)
    return scanner


@pytest.mark.parametrize(
    "name", ["TRIVY_SKIP_DB_UPDATE", "TRIVY_SKIP_UPDATE", "TRIVY_EXIT_CODE"]
)
def test_the_host_fixture_clears_trivys_update_settings_a_shell_may_hold(name):
    """A shell with ``TRIVY_SKIP_DB_UPDATE=true`` suppresses the update, so the
    update-count assertions below read zero where they expect one. The autouse
    fixture has run by now: the setting is named in its list and is gone."""
    assert name in HOST_TRIVY_VARIABLES
    assert name not in os.environ


# --- the update runs only for a scan that reads the database --------------------


def test_a_scan_of_secrets_alone_does_not_update_the_database(tmp_path, updates, ran):
    scanner = _scanner(tmp_path, scanners=["secret"])

    scanner._run_subprocess(
        ["trivy", "repository", "--scanners", "secret", "/src"],
        results_dir=scanner.results_dir,
    )

    assert updates == [], updates
    (command,) = ran
    assert "--skip-db-update" in command and "--skip-java-db-update" in command
    assert "--skip-check-update" not in command, command


def test_control_a_vulnerability_scan_updates_the_database_once(tmp_path, updates, ran):
    scanner = _scanner(tmp_path, scanners=["vuln"])

    scanner._run_subprocess(
        ["trivy", "repository", "--scanners", "vuln", "/src"],
        results_dir=scanner.results_dir,
    )

    assert [call["tool"] for call in updates] == ["trivy"]
    assert updates[0]["checks"] is False


def test_a_misconfiguration_scan_fetches_the_checks_bundle(tmp_path, updates, ran):
    scanner = _scanner(tmp_path, scanners=["misconfig"])

    scanner._run_subprocess(
        ["trivy", "repository", "--scanners", "misconfig", "/src"],
        results_dir=scanner.results_dir,
    )

    assert [call["checks"] for call in updates] == [True]
    (command,) = ran
    assert "--skip-check-update" in command


def test_a_scan_that_names_no_scanner_updates_for_trivys_default_set(
    tmp_path, updates, ran
):
    """trivy's own default is vuln and secret, so the database is read."""
    scanner = _scanner(tmp_path, scanners=[])

    scanner._run_subprocess(
        ["trivy", "repository", "/src"], results_dir=scanner.results_dir
    )

    assert len(updates) == 1


# --- the database counts as in use by the same reading the update is gated on ----


def test_the_database_is_not_in_use_when_trivys_settings_leave_out_vuln(
    tmp_path, monkeypatch
):
    """``scanners: []`` passes no ``--scanners``; with ``TRIVY_SCANNERS=secret`` trivy
    never opens the database and the update is skipped, so the age check must not
    then hold the scan to a database trivy did not read."""
    monkeypatch.setenv("TRIVY_SCANNERS", "secret")
    scanner = _scanner(tmp_path, scanners=[])

    assert scanner.content_databases_in_use() == []


def test_control_the_database_is_in_use_for_trivys_default_scanner_set(tmp_path):
    scanner = _scanner(tmp_path, scanners=[])

    assert scanner.content_databases_in_use() != []


# --- the mode is read when the scan runs ------------------------------------------


def test_a_scanner_built_online_and_run_offline_gets_the_offline_flags(
    tmp_path, monkeypatch, updates, ran
):
    scanner = _scanner(tmp_path, scanners=["vuln"])
    built = [arg.key for arg in scanner.args.extra_args]
    assert "--skip-version-check" in built and "--skip-db-update" not in built
    monkeypatch.setenv("ASH_OFFLINE", "YES")

    scanner._run_subprocess(
        ["trivy", "repository", "--skip-version-check", "/src"],
        results_dir=scanner.results_dir,
    )

    (command,) = ran
    assert "--skip-version-check" not in command, command
    for flag in OFFLINE_FLAGS:
        assert flag in command, command
    assert updates == []


def test_a_scanner_built_offline_and_run_online_updates_and_drops_the_offline_flags(
    tmp_path, monkeypatch, updates, ran
):
    monkeypatch.setenv("ASH_OFFLINE", "YES")
    scanner = _scanner(tmp_path, scanners=["vuln"])
    built = [arg.key for arg in scanner.args.extra_args]
    assert "--skip-db-update" in built and "--skip-version-check" not in built
    monkeypatch.delenv("ASH_OFFLINE")

    scanner._run_subprocess(
        ["trivy", "repository", *OFFLINE_FLAGS, "/src"],
        results_dir=scanner.results_dir,
    )

    (command,) = ran
    assert "--skip-version-check" in command, command
    # The skip flags present are the update's own set: the checks bundle was not
    # fetched, so trivy is not told to skip a check update either.
    assert command.count("--skip-db-update") == 1
    assert "--skip-check-update" not in command, command
    assert len(updates) == 1
    # The update was asked for in the mode the scan runs in, not the stale one
    # the scanner was built in.
    assert updates[0]["offline"] is False, updates


def test_control_a_consistent_online_command_keeps_its_shape(tmp_path, updates, ran):
    scanner = _scanner(tmp_path, scanners=["vuln"])

    scanner._run_subprocess(
        ["trivy", "repository", "--skip-version-check", "/src"],
        results_dir=scanner.results_dir,
    )

    (command,) = ran
    cache = [arg for arg in command if arg.startswith("--cache-dir=")]
    assert len(cache) == 1, command
    assert command == [
        "trivy",
        "repository",
        "--skip-db-update",
        "--skip-java-db-update",
        *cache,
        "--cache-backend=memory",
        "--exit-code=0",
        "--skip-version-check",
        "/src",
    ], command

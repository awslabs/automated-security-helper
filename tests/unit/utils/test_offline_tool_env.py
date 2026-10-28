# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Offline, every process ASH starts gets the variables that turn tool checks off.

``utils/offline_tool_env.py`` lists them; these tests check where they are applied:
every spawn through ``subprocess_utils`` (version probes included), and every
scanner command through ``PluginBase._run_subprocess``, including a scanner whose
own ``offline`` option is set while ASH runs online. Online nothing is added.
"""

import json
import os
import sys
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.plugin_modules.ash_builtin.scanners.syft_scanner import (
    SyftScanner,
    SyftScannerConfig,
    SyftScannerConfigOptions,
)
from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.offline_tool_env import (
    OFFLINE_TOOL_ENVIRONMENT,
    offline_tool_environment,
    with_offline_tool_environment,
)
from tests.utils.helpers import CHILD_TIMEOUT_SECONDS


@pytest.fixture
def offline(monkeypatch):
    monkeypatch.setenv("ASH_OFFLINE", "YES")
    return monkeypatch


@pytest.fixture
def online(monkeypatch):
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    for name in OFFLINE_TOOL_ENVIRONMENT:
        monkeypatch.delenv(name, raising=False)
    return monkeypatch


#: What offline mode must set, written out rather than read from the module, so that
#: dropping an entry there fails here. Each is a measured network contact or a
#: setting that can turn one on; see utils/offline_tool_env.py for which.
EXPECTED_OFFLINE_ENVIRONMENT = {
    "SEMGREP_ENABLE_VERSION_CHECK": "0",
    "SEMGREP_SEND_METRICS": "off",
    "CKV_SKIP_PACKAGE_UPDATE_CHECK": "true",
    "npm_config_update_notifier": "false",
    "TRIVY_SKIP_VERSION_CHECK": "true",
    "TRIVY_DISABLE_TELEMETRY": "true",
    "SYFT_CHECK_FOR_APP_UPDATE": "false",
    "SYFT_GOLANG_SEARCH_REMOTE_LICENSES": "false",
    "SYFT_JAVA_USE_NETWORK": "false",
    "SYFT_JAVASCRIPT_SEARCH_REMOTE_LICENSES": "false",
    "SYFT_PYTHON_SEARCH_REMOTE_LICENSES": "false",
    "SYFT_CPP_VCPKG_ALLOW_GIT_CLONE": "false",
    "SYFT_GOLANG_USE_PACKAGES_LIB": "false",
    "GRYPE_CHECK_FOR_APP_UPDATE": "false",
    "GRYPE_DB_AUTO_UPDATE": "false",
    "GRYPE_EXTERNAL_SOURCES_ENABLE": "false",
    "GOPROXY": "off",
    "GOTOOLCHAIN": "local",
    "GIT_ALLOW_PROTOCOL": "file",
}


def test_offline_adds_every_variable(offline):
    assert offline_tool_environment() == EXPECTED_OFFLINE_ENVIRONMENT


def test_online_adds_nothing(online):
    assert offline_tool_environment() == {}
    assert with_offline_tool_environment(None) is None
    assert with_offline_tool_environment({"A": "1"}) == {"A": "1"}


def test_offline_overrides_a_value_the_environment_sets(offline):
    """Offline wins over a variable that turns a check back on."""
    env = with_offline_tool_environment({"SEMGREP_ENABLE_VERSION_CHECK": "1"})

    assert env["SEMGREP_ENABLE_VERSION_CHECK"] == "0"


def _print_variables(names):
    """A ``python -c`` program that prints ``names`` from its environment as JSON."""
    return (
        "import json, os; "
        f"print(json.dumps({{n: os.environ.get(n) for n in {names!r}}}))"
    )


def test_every_spawn_gets_them_offline(offline, tmp_path):
    """A real child started through run_command_with_output_handling, the helper
    behind scanner commands, version probes and the detect-secrets worker."""
    names = sorted(EXPECTED_OFFLINE_ENVIRONMENT)
    response = subprocess_utils.run_command_with_output_handling(
        command=[
            sys.executable,
            "-c",
            _print_variables(names),
        ],
        stdout_preference="return",
        stderr_preference="return",
        cwd=tmp_path,
        # Windows starts no interpreter without SYSTEMROOT, so it is passed along.
        env={
            "PATH": os.environ.get("PATH", ""),
            **{k: v for k, v in os.environ.items() if k.upper() == "SYSTEMROOT"},
        },
        timeout=CHILD_TIMEOUT_SECONDS,
    )

    seen = json.loads(response["stdout"])
    assert seen == EXPECTED_OFFLINE_ENVIRONMENT


def test_spawn_run_gets_them_offline(offline, tmp_path):
    names = sorted(EXPECTED_OFFLINE_ENVIRONMENT)
    result = subprocess_utils.spawn_run(
        [
            sys.executable,
            "-c",
            _print_variables(names),
        ],
        capture_output=True,
        text=True,
        cwd=tmp_path,
        timeout=CHILD_TIMEOUT_SECONDS,
    )

    assert json.loads(result.stdout) == EXPECTED_OFFLINE_ENVIRONMENT


def test_spawns_are_unchanged_online(online, tmp_path):
    result = subprocess_utils.spawn_run(
        [
            sys.executable,
            "-c",
            "import os; print(os.environ.get('CKV_SKIP_PACKAGE_UPDATE_CHECK'))",
        ],
        capture_output=True,
        text=True,
        cwd=tmp_path,
        timeout=CHILD_TIMEOUT_SECONDS,
    )

    assert result.stdout.strip() == "None"


def _recorded_scanner_env(scanner, monkeypatch):
    recorded = {}

    def record(command, *args, **kwargs):
        recorded["env"] = kwargs.get("env")
        return {"returncode": 0, "stdout": "", "stderr": ""}

    monkeypatch.setattr(subprocess_utils, "run_command_with_output_handling", record)
    scanner._run_subprocess(command=["syft", "version"], results_dir=None)
    return recorded["env"]


def _syft(tmp_path, **options):
    context = PluginContext(
        source_dir=tmp_path / "repo",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "out" / "converted",
        config=get_default_config(),
    )
    Path(context.source_dir).mkdir(parents=True)
    return SyftScanner(
        context=context,
        config=SyftScannerConfig(options=SyftScannerConfigOptions(**options)),
    )


def test_a_scanner_forced_offline_by_its_own_option_gets_them(
    online, tmp_path, monkeypatch
):
    env = _recorded_scanner_env(_syft(tmp_path, offline=True), monkeypatch)

    assert env is not None
    for name, value in EXPECTED_OFFLINE_ENVIRONMENT.items():
        assert env.get(name) == value, name


def test_an_online_scanner_gets_none_of_them(online, tmp_path, monkeypatch):
    env = _recorded_scanner_env(_syft(tmp_path), monkeypatch)

    assert env is None or not any(name in env for name in OFFLINE_TOOL_ENVIRONMENT)

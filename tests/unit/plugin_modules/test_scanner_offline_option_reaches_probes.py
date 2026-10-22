# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scanner's own ``offline: true`` also keeps its version probes off the network.

With ASH online and ``scanners.<name>.options.offline: true``, the scan command got
the offline tool variables (``PluginBase._run_subprocess`` asks the scanner), but the
probes the dependency check runs before it (``<tool> --version``, ``uv tool run <tool>
--version``) go through ``subprocess_utils._spawn_env``, which read only ASH's own
offline mode. ``semgrep --version`` contacts semgrep.dev and ``checkov --version``
pypi.org without the variables.

``plugin_probe_scope``, which already wraps a scanner's construction and its dependency
check, now marks the spawns inside it as offline when the scanner runs offline.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
    CheckovScanner,
    CheckovScannerConfig,
    CheckovScannerConfigOptions,
)
from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.offline_tool_env import (
    OFFLINE_TOOL_ENVIRONMENT,
    offline_tool_environment,
)
from automated_security_helper.utils.sandbox.scope import plugin_probe_scope


@pytest.fixture
def context(tmp_path: Path, monkeypatch) -> PluginContext:
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    source = tmp_path / "src"
    source.mkdir()
    return PluginContext(
        source_dir=source,
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "out" / "converted",
        config=get_default_config(),
    )


def _checkov(context: PluginContext, offline: bool) -> CheckovScanner:
    return CheckovScanner(
        context=context,
        config=CheckovScannerConfig(
            options=CheckovScannerConfigOptions(offline=offline)
        ),
    )


def test_the_scope_adds_the_variables_while_ash_is_online(context):
    from automated_security_helper.utils.offline_tool_env import offline_tool_scope

    assert offline_tool_environment() == {}

    with offline_tool_scope(True):
        assert offline_tool_environment() == dict(OFFLINE_TOOL_ENVIRONMENT)

    assert offline_tool_environment() == {}


def test_a_scope_that_is_not_offline_adds_nothing(context):
    from automated_security_helper.utils.offline_tool_env import offline_tool_scope

    with offline_tool_scope(False):
        assert offline_tool_environment() == {}


def test_the_probe_scope_of_an_offline_scanner_marks_its_spawns(context):
    scanner = _checkov(context, offline=True)

    with plugin_probe_scope(scanner, context):
        env = subprocess_utils._spawn_env({})

    assert env.get("CKV_SKIP_PACKAGE_UPDATE_CHECK") == "true"
    assert env.get("SEMGREP_ENABLE_VERSION_CHECK") == "0"


def test_control_the_probe_scope_of_an_online_scanner_adds_nothing(context):
    scanner = _checkov(context, offline=False)

    with plugin_probe_scope(scanner, context):
        env = subprocess_utils._spawn_env({})

    assert "CKV_SKIP_PACKAGE_UPDATE_CHECK" not in env


def test_the_probe_scope_of_a_class_reads_its_configured_option(context):
    """Before construction (ScanPhase probes the class), from the run's config."""
    context.config.scanners.checkov.options.offline = True

    with plugin_probe_scope(CheckovScanner, context):
        env = subprocess_utils._spawn_env({})

    assert env.get("CKV_SKIP_PACKAGE_UPDATE_CHECK") == "true"


def test_the_dependency_check_probes_of_an_offline_scanner_get_the_variables(
    context, monkeypatch
):
    """The real dependency check, every spawn it makes captured."""
    scanner = _checkov(context, offline=True)
    seen = []

    def run(args, **kwargs):
        seen.append((list(map(str, args)), dict(kwargs.get("env") or {})))
        return subprocess.CompletedProcess(args, 0, stdout="checkov 3.2.0\n", stderr="")

    monkeypatch.setattr(subprocess_utils.subprocess, "run", run)
    monkeypatch.setattr(subprocess_utils, "_run_stoppable", run)

    with plugin_probe_scope(scanner, context):
        scanner.validate_plugin_dependencies()

    assert seen, "the dependency check started no process"
    missing = [
        args for args, env in seen if env.get("CKV_SKIP_PACKAGE_UPDATE_CHECK") != "true"
    ]
    assert missing == [], f"probes started without the offline variables: {missing}"

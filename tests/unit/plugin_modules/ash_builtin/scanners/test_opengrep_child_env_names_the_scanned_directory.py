# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The opengrep child may read git's view of the one directory it scans.

opengrep 2.0.0 runs ``git ls-files`` itself and exits 2 ("Could not get files from
git ls-files") when git refuses the directory as owned by another user, which is the
case for the mount the container scans read. 1.33.1 tolerated that. The scanner
therefore hands its child a ``safe.directory`` entry through ``GIT_CONFIG_*``: only
for the directory the scan was pointed at, only in that child's environment, and
never the ``*`` that would trust every directory.
"""

import os

import pytest

from automated_security_helper.plugin_modules.ash_builtin.scanners.opengrep_scanner import (
    OpengrepScanner,
    OpengrepScannerConfig,
    OpengrepScannerConfigOptions,
)
from tests.utils.tool_guard import stub_tool_probes

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _no_tool_probe(monkeypatch):
    stub_tool_probes(monkeypatch)


def _scanner(test_plugin_context):
    config = OpengrepScannerConfig(options=OpengrepScannerConfigOptions())
    scanner = OpengrepScanner(context=test_plugin_context, config=config)
    scanner.dependencies_satisfied = True
    return scanner


def _child_env(scanner, target):
    _args, _results, env = scanner._execute_scan(
        target=target, target_type="source", global_ignore_paths=[]
    )
    return env


def test_the_child_env_names_the_real_path_of_the_scanned_directory(
    test_plugin_context, monkeypatch, tmp_path
):
    monkeypatch.delenv("GIT_CONFIG_COUNT", raising=False)
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    try:
        link.symlink_to(real, target_is_directory=True)
    except OSError:  # pragma: no cover - no symlinks on this platform
        link = real

    env = _child_env(_scanner(test_plugin_context), link)

    assert env["GIT_CONFIG_COUNT"] == "1"
    assert env["GIT_CONFIG_KEY_0"] == "safe.directory"
    assert env["GIT_CONFIG_VALUE_0"] == os.path.realpath(real)


def test_the_child_env_never_trusts_every_directory(
    test_plugin_context, monkeypatch, tmp_path
):
    monkeypatch.delenv("GIT_CONFIG_COUNT", raising=False)

    env = _child_env(_scanner(test_plugin_context), tmp_path)

    values = [v for k, v in env.items() if k.startswith("GIT_CONFIG_VALUE_")]
    assert values and "*" not in values


def test_an_entry_the_caller_already_set_keeps_its_place(
    test_plugin_context, monkeypatch, tmp_path
):
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "core.pager")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", "cat")

    env = _child_env(_scanner(test_plugin_context), tmp_path)

    assert env["GIT_CONFIG_COUNT"] == "2"
    assert env["GIT_CONFIG_KEY_1"] == "safe.directory"
    assert env["GIT_CONFIG_VALUE_1"] == os.path.realpath(tmp_path)
    assert env["GIT_CONFIG_KEY_0"] == "core.pager"
    assert env["GIT_CONFIG_VALUE_0"] == "cat"


def test_the_parent_process_environment_is_not_changed(
    test_plugin_context, monkeypatch, tmp_path
):
    monkeypatch.delenv("GIT_CONFIG_COUNT", raising=False)

    _child_env(_scanner(test_plugin_context), tmp_path)

    assert "GIT_CONFIG_COUNT" not in os.environ

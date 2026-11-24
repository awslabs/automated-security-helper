# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A run that cannot download a registry ruleset is repeated on the local rules.

opengrep 2.0.0 exits 2 ("Error: fatal error") when a ruleset named by a registry
reference such as ``p/ci`` cannot be fetched, which is what a run with no network
(a sandbox) meets. The command also names ASH's bundled rules by path, so the
scanner repeats the run once without the registry references and says so in one
warning. Any other failure, a run that did fetch, and a command with no local
ruleset left keep their first result.
"""

from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_base import PluginBase
from automated_security_helper.plugin_modules.ash_builtin.scanners.opengrep_scanner import (
    OpengrepScanner,
    OpengrepScannerConfig,
    OpengrepScannerConfigOptions,
    without_registry_configs,
)
from tests.utils.tool_guard import stub_tool_probes

pytestmark = pytest.mark.unit

FETCH_FAILURE = (
    "[00.80][INFO]: trying to download from https://semgrep.dev/c/p/ci\n"
    "[01.27][INFO]: Error: fatal error\n"
)


@pytest.fixture(autouse=True)
def _no_tool_probe(monkeypatch):
    stub_tool_probes(monkeypatch)


def _scanner(test_plugin_context):
    config = OpengrepScannerConfig(options=OpengrepScannerConfigOptions())
    scanner = OpengrepScanner(context=test_plugin_context, config=config)
    scanner.dependencies_satisfied = True
    return scanner


class _Child:
    """Stands in for PluginBase._run_subprocess: answers each run in turn."""

    def __init__(self, results_dir, answers):
        self.results_dir = results_dir
        self.answers = list(answers)
        self.commands = []

    @property
    def run(self):
        def run(scanner, command, *args, **kwargs):
            self.commands.append(list(command))
            returncode, stderr = self.answers.pop(0)
            (self.results_dir / "OpengrepScanner.stderr.log").write_text(stderr)
            return {"returncode": returncode}

        return run


def _run(scanner, results_dir, rules, answers):
    child = _Child(results_dir, answers)
    command = ["opengrep", "scan", "--config", str(rules), "--config", "p/ci", "src"]
    with patch.object(PluginBase, "_run_subprocess", child.run):
        response = scanner._run_subprocess(
            command=command, results_dir=results_dir, cwd=results_dir
        )
    return child, command, response


def test_a_failed_registry_download_repeats_the_run_on_the_local_rules(
    test_plugin_context, tmp_path
):
    rules = tmp_path / "appsec.yaml"
    rules.write_text("rules: []")

    child, command, response = _run(
        _scanner(test_plugin_context),
        tmp_path,
        rules,
        [(2, FETCH_FAILURE), (0, "")],
    )

    assert len(child.commands) == 2
    assert "p/ci" in child.commands[0]
    assert "p/ci" not in child.commands[1]
    assert str(rules) in child.commands[1]
    # The command the invocation record shows is the one that ran.
    assert command == child.commands[1]
    assert response == {"returncode": 0}


def test_a_run_that_fetched_its_rules_is_not_repeated(test_plugin_context, tmp_path):
    rules = tmp_path / "appsec.yaml"
    rules.write_text("rules: []")

    child, command, response = _run(
        _scanner(test_plugin_context), tmp_path, rules, [(0, "")]
    )

    assert len(child.commands) == 1
    assert "p/ci" in command
    assert response == {"returncode": 0}


def test_another_exit_2_is_not_repeated(test_plugin_context, tmp_path):
    rules = tmp_path / "appsec.yaml"
    rules.write_text("rules: []")

    child, _command, response = _run(
        _scanner(test_plugin_context),
        tmp_path,
        rules,
        [(2, "[00.10][INFO]: Error: invalid pattern\n")],
    )

    assert len(child.commands) == 1
    assert response == {"returncode": 2}


def test_no_local_ruleset_keeps_the_failure(test_plugin_context, tmp_path):
    child = _Child(tmp_path, [(2, FETCH_FAILURE)])
    command = ["opengrep", "scan", "--config", "p/ci", "src"]
    with patch.object(PluginBase, "_run_subprocess", child.run):
        response = _scanner(test_plugin_context)._run_subprocess(
            command=command, results_dir=tmp_path, cwd=tmp_path
        )

    assert len(child.commands) == 1
    assert "p/ci" in command
    assert response == {"returncode": 2}


@pytest.mark.parametrize(
    ("value", "removed"),
    [
        ("p/ci", True),
        ("r/python.lang", True),
        ("auto", True),
        ("https://example.test/rules.yaml", True),
        ("rules/local.yaml", False),
    ],
)
def test_only_registry_references_are_removed(value, removed):
    separate = ["opengrep", "scan", "--config", value, "src"]
    joined = ["opengrep", "scan", f"--config={value}", "src"]
    if removed:
        assert without_registry_configs(separate) == ["opengrep", "scan", "src"]
        assert without_registry_configs(joined) == ["opengrep", "scan", "src"]
    else:
        assert without_registry_configs(separate) == separate
        assert without_registry_configs(joined) == joined

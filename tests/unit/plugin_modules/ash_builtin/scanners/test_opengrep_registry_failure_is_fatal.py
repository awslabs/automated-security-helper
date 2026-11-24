# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A registry ruleset that opengrep cannot download or parse fails the scan.

opengrep 2.0.0 exits 2 ("Error: fatal error") when a ruleset named by a registry
reference such as ``p/ci`` cannot be downloaded, and exits 7 ("Invalid YAML ...")
when one it downloaded is not rules YAML it accepts. Neither is retried on the
local rules: the scanner runs opengrep once, with the command it was given, and
the exit code is refused as a scanner error because it is outside the scanner's
accepted set.
"""

from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_base import PluginBase
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules.ash_builtin.scanners.opengrep_scanner import (
    OpengrepScanner,
    OpengrepScannerConfig,
    OpengrepScannerConfigOptions,
)
from tests.utils.tool_guard import stub_tool_probes

pytestmark = pytest.mark.unit

FETCH_FAILURE = (
    "[00.80][INFO]: trying to download from https://semgrep.dev/c/p/ci\n"
    "[01.27][INFO]: Error: fatal error\n"
)
INVALID_YAML = (
    "[00.90][INFO]: trying to download from https://semgrep.dev/c/p/ci\n"
    "[01.10][ERROR]: Invalid YAML in rules: Unknown or duplicate properties "
    "found in YAML object: missed\n"
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


@pytest.mark.parametrize(
    ("returncode", "stderr"),
    [(2, FETCH_FAILURE), (7, INVALID_YAML)],
    ids=["download failed, exit 2", "downloaded ruleset invalid YAML, exit 7"],
)
def test_a_registry_ruleset_failure_is_one_run_and_a_scanner_error(
    test_plugin_context, tmp_path, returncode, stderr
):
    rules = tmp_path / "appsec.yaml"
    rules.write_text("rules: []")
    command = ["opengrep", "scan", "--config", str(rules), "--config", "p/ci", "src"]
    recorded = list(command)
    # A second run would find no answer left and fail the test with IndexError.
    child = _Child(tmp_path, [(returncode, stderr)])
    scanner = _scanner(test_plugin_context)

    with patch.object(PluginBase, "_run_subprocess", child.run):
        response = scanner._run_subprocess(
            command=command, results_dir=tmp_path, cwd=tmp_path
        )

    # Exactly one invocation, with the registry reference and the recorded argv intact.
    assert child.commands == [recorded]
    assert command == recorded
    assert response == {"returncode": returncode}

    scanner._record_target_exit_code(response)
    with pytest.raises(ScannerError):
        scanner._refuse_rejected_exit_code()

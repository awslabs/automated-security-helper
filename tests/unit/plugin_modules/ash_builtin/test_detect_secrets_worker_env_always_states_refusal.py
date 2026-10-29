# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The scanner always tells the worker whether HTTP is refused, "0" or "1".

The worker refuses detect-secrets' verification requests unless its environment
says, in so many words, that this scan may verify. The scanner used to set the
variable only when refusing and to leave it out when verifying, so the two
processes agreed only while nothing between them touched the variable: an
executor or environment filter that dropped it turned "refuse" into "send"
without a trace. Now the variable is always present, "0" when the scan may
verify and "1" otherwise, and a value inherited from ASH's own environment is
replaced rather than passed through. The worker's half of the contract (refuse
unless exactly "0") is tested beside the worker.

The runner is replaced by a stand-in that records the environment it was handed
and then answers as a killed worker does; no process starts.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
    DetectSecretsScanner,
    DetectSecretsScannerConfig,
    DetectSecretsScannerConfigOptions,
    DetectSecretsScanSettings,
)
from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.detect_secrets_worker import REFUSE_HTTP_ENV

pytestmark = [pytest.mark.unit, pytest.mark.usefixtures("no_tool_probes")]

VERIFICATION_FILTER = (
    "detect_secrets.filters.common.is_ignored_due_to_verification_policies"
)


def _scanner(tmp_path: Path, filters: list) -> DetectSecretsScanner:
    context = PluginContext(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "out" / "converted",
        config=get_default_config(),
    )
    context.source_dir.mkdir(parents=True)
    context.output_dir.mkdir(parents=True)
    (context.source_dir / "settings.py").write_text("value = 1\n", encoding="utf-8")
    return DetectSecretsScanner(
        context=context,
        config=DetectSecretsScannerConfig(
            options=DetectSecretsScannerConfigOptions(
                scan_timeout=5,
                scan_settings=DetectSecretsScanSettings(
                    plugins_used=[{"name": "AWSKeyDetector"}], filters_used=filters
                ),
            )
        ),
    )


def _runner_recording_env(monkeypatch) -> list:
    seen: list = []

    def fake(command, **kwargs):
        seen.append(dict(kwargs.get("env") or {}))
        return {"timed_out": True, "returncode": 124}

    monkeypatch.setattr(subprocess_utils, "run_command_with_output_handling", fake)
    return seen


def _worker_env(scanner: DetectSecretsScanner, seen: list) -> dict:
    with pytest.raises(ScannerError, match="timed out"):
        scanner.scan(target=scanner.context.source_dir, target_type="source")
    assert seen, "the worker was not started"
    return seen[-1]


def test_a_scan_that_may_not_verify_states_one(tmp_path, monkeypatch):
    # An inherited "0" (a parent shell that verified) must not reach a scan that
    # does not verify: the scanner's own decision replaces it.
    monkeypatch.setenv(REFUSE_HTTP_ENV, "0")
    scanner = _scanner(tmp_path, [])
    seen = _runner_recording_env(monkeypatch)

    env = _worker_env(scanner, seen)

    assert env.get(REFUSE_HTTP_ENV) == "1"


def test_a_scan_that_may_verify_states_zero(tmp_path, monkeypatch):
    # The inherited "1" is replaced the same way: the worker reads this scan's
    # decision, never ASH's environment.
    monkeypatch.setenv(REFUSE_HTTP_ENV, "1")
    monkeypatch.setattr(DetectSecretsScanner, "_scanner_offline", lambda self: False)
    scanner = _scanner(tmp_path, [{"path": VERIFICATION_FILTER, "min_level": 2}])
    assert scanner._verification_permitted is True, (
        "precondition: the operator's own filter turns verification on"
    )
    seen = _runner_recording_env(monkeypatch)

    env = _worker_env(scanner, seen)

    # The variable is present, with the one value the worker reads as "send".
    assert env.get(REFUSE_HTTP_ENV) == "0"


def test_offline_turns_the_statement_back_to_one(tmp_path, monkeypatch):
    # Control: the same settings under --offline refuse, so the "0" above comes
    # from the verification decision and not from the filter's presence alone.
    monkeypatch.delenv(REFUSE_HTTP_ENV, raising=False)
    monkeypatch.setattr(DetectSecretsScanner, "_scanner_offline", lambda self: True)
    scanner = _scanner(tmp_path, [{"path": VERIFICATION_FILTER, "min_level": 2}])
    seen = _runner_recording_env(monkeypatch)

    env = _worker_env(scanner, seen)

    assert env.get(REFUSE_HTTP_ENV) == "1"

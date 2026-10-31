# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A detect-secrets worker ASH could not stop is recorded as such.

The scanner runs its worker through ``run_command_with_output_handling``
itself, not through the base class's ``_run_subprocess``, so the base class's
recorders do not run for it. At the timeout it recorded the timeout
(``_record_timeout``) and raised, but never recorded a stop that failed, the
shape ``response_could_not_stop`` reads: ``timed_out`` with no exit code, or the
runner's ``could_not_stop`` key. ``scan_could_not_stop`` stayed None, so the
executor graded the scanner as timed out and ``run_ash_scan`` did not fail the
run for a worker that may still be writing its raw findings into the results
directory after cleanup.

The runner is replaced by a stand-in that answers as the real one does for each
ending; no process starts.
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
)
from automated_security_helper.utils import subprocess_utils

pytestmark = [pytest.mark.unit, pytest.mark.usefixtures("no_tool_probes")]


def _scanner(tmp_path: Path) -> DetectSecretsScanner:
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
            options=DetectSecretsScannerConfigOptions(scan_timeout=5)
        ),
    )


def _runner_answering(monkeypatch, response: dict) -> list:
    calls: list = []

    def fake(command, **kwargs):
        calls.append(list(command))
        return dict(response)

    monkeypatch.setattr(subprocess_utils, "run_command_with_output_handling", fake)
    return calls


def test_a_worker_that_could_not_be_stopped_is_recorded(tmp_path, monkeypatch):
    """``timed_out`` with no exit code is the runner's shape for a stop that failed."""
    scanner = _scanner(tmp_path)
    calls = _runner_answering(
        monkeypatch,
        {"timed_out": True, "returncode": None, "error": "the worker kept running"},
    )

    with pytest.raises(ScannerError, match="timed out"):
        scanner.scan(target=scanner.context.source_dir, target_type="source")

    assert calls, "the worker was not started"
    assert scanner.scan_could_not_stop is not None
    assert "the worker kept running" in scanner.scan_could_not_stop


def test_the_runners_could_not_stop_key_is_recorded(tmp_path, monkeypatch):
    scanner = _scanner(tmp_path)
    _runner_answering(
        monkeypatch,
        {
            "timed_out": True,
            "returncode": 124,
            "could_not_stop": True,
            "could_not_stop_pid": 4242,
        },
    )

    with pytest.raises(ScannerError, match="timed out"):
        scanner.scan(target=scanner.context.source_dir, target_type="source")

    assert scanner.scan_could_not_stop is not None


def test_a_timeout_whose_stop_worked_is_a_plain_timeout(tmp_path, monkeypatch):
    """Control: a killed worker has an exit code, and is not a stop that failed."""
    scanner = _scanner(tmp_path)
    _runner_answering(monkeypatch, {"timed_out": True, "returncode": 124})

    with pytest.raises(ScannerError, match="timed out"):
        scanner.scan(target=scanner.context.source_dir, target_type="source")

    assert scanner.scan_could_not_stop is None

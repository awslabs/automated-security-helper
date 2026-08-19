# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for semgrep offline mode cache-miss hard-fail behaviour.

When offline=True and SEMGREP_RULES_CACHE_DIR is unset or points to a
directory with no .yaml/.yml files, _process_config_options must raise
ScannerError with an actionable message — and must never invoke subprocess.

Note: _process_config_options is called during model_post_init (scanner
construction), so env vars must be set before instantiation.
"""

import pytest
from unittest.mock import patch

from automated_security_helper.plugin_modules.ash_builtin.scanners.semgrep_scanner import (
    SemgrepScanner,
    SemgrepScannerConfig,
    SemgrepScannerConfigOptions,
)
from automated_security_helper.core.exceptions import ScannerError


def _make_scanner(test_plugin_context):
    config = SemgrepScannerConfig(
        options=SemgrepScannerConfigOptions(offline=True)
    )
    scanner = SemgrepScanner(context=test_plugin_context, config=config)
    scanner.dependencies_satisfied = True
    return scanner


def test_semgrep_offline_missing_cache_raises_actionable_error(test_plugin_context, monkeypatch):
    """No SEMGREP_RULES_CACHE_DIR → ScannerError with guidance."""
    monkeypatch.delenv("SEMGREP_RULES_CACHE_DIR", raising=False)

    with pytest.raises(ScannerError) as exc_info:
        _make_scanner(test_plugin_context)

    msg = str(exc_info.value)
    assert "SEMGREP_RULES_CACHE_DIR" in msg
    assert "ash build-image --offline" in msg


def test_semgrep_offline_empty_cache_raises_actionable_error(test_plugin_context, monkeypatch, tmp_path):
    """SEMGREP_RULES_CACHE_DIR set but empty → ScannerError with guidance."""
    monkeypatch.setenv("SEMGREP_RULES_CACHE_DIR", str(tmp_path))

    with pytest.raises(ScannerError) as exc_info:
        _make_scanner(test_plugin_context)

    msg = str(exc_info.value)
    assert "SEMGREP_RULES_CACHE_DIR" in msg
    assert "ash build-image --offline" in msg


def test_semgrep_offline_with_cache_does_not_raise(test_plugin_context, monkeypatch, tmp_path):
    """SEMGREP_RULES_CACHE_DIR set with a .yaml file → no error, --config appended."""
    rule_file = tmp_path / "rules.yaml"
    rule_file.write_text("rules: []")
    monkeypatch.setenv("SEMGREP_RULES_CACHE_DIR", str(tmp_path))

    scanner = _make_scanner(test_plugin_context)

    config_args = [a for a in scanner.args.extra_args if a.key == "--config"]
    cache_configs = [a for a in config_args if str(tmp_path) in a.value]
    assert cache_configs, "Expected --config pointing to cache dir"


def test_semgrep_offline_no_subprocess_on_failure(test_plugin_context, monkeypatch):
    """_run_subprocess (the actual scan) must never be called when cache is missing."""
    monkeypatch.delenv("SEMGREP_RULES_CACHE_DIR", raising=False)

    with patch(
        "automated_security_helper.plugin_modules.ash_builtin.scanners.semgrep_scanner.SemgrepScanner._run_subprocess"
    ) as mock_run_subprocess:
        with pytest.raises(ScannerError):
            _make_scanner(test_plugin_context)

        mock_run_subprocess.assert_not_called()

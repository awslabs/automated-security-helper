# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for opengrep offline mode cache-miss behaviour.

When offline=True and OPENGREP_RULES_CACHE_DIR is unset or points to a directory
with no .yaml/.yml rule files, opengrep cannot run. It must say so in a way the
scan phase can record, and it must never invoke subprocess.

The assertions here inverted for the reason set out in
``test_semgrep_offline_fallback``: the verdict used to be raised from
``_process_config_options``, which runs inside ``model_post_init``, so the
scanner never became an instance and never reached the hooks that turn "cannot
run here" into a recorded MISSING row. Both scanners are covered because both
inherit the single implementation in ``_grep_scanner_base``; the shared-base
control lives in ``tests/unit/plugin_modules/scanners/test_grep_scanner_base.py``.
"""

import pytest
from unittest.mock import patch

from automated_security_helper.plugin_modules.ash_builtin.scanners.opengrep_scanner import (
    OpengrepScanner,
    OpengrepScannerConfig,
    OpengrepScannerConfigOptions,
)
from automated_security_helper.core.exceptions import ScannerError


def _make_scanner(test_plugin_context):
    config = OpengrepScannerConfig(options=OpengrepScannerConfigOptions(offline=True))
    scanner = OpengrepScanner(context=test_plugin_context, config=config)
    scanner.dependencies_satisfied = True
    return scanner


def test_opengrep_offline_missing_cache_records_actionable_reason(
    test_plugin_context, monkeypatch
):
    """No OPENGREP_RULES_CACHE_DIR -> constructed, declines, keeps the guidance."""
    monkeypatch.delenv("OPENGREP_RULES_CACHE_DIR", raising=False)

    scanner = _make_scanner(test_plugin_context)

    assert scanner.validate_plugin_dependencies() is False
    msg = scanner.dependency_unavailable_reason
    assert msg is not None
    assert "OPENGREP_RULES_CACHE_DIR" in msg
    assert "ash build-image --offline" in msg


def test_opengrep_offline_empty_cache_records_actionable_reason(
    test_plugin_context, monkeypatch, tmp_path
):
    """OPENGREP_RULES_CACHE_DIR set but empty -> same verdict, same guidance."""
    monkeypatch.setenv("OPENGREP_RULES_CACHE_DIR", str(tmp_path))

    scanner = _make_scanner(test_plugin_context)

    assert scanner.validate_plugin_dependencies() is False
    msg = scanner.dependency_unavailable_reason
    assert msg is not None
    assert "OPENGREP_RULES_CACHE_DIR" in msg
    assert "ash build-image --offline" in msg


def test_opengrep_offline_with_cache_does_not_decline(
    test_plugin_context, monkeypatch, tmp_path
):
    """OPENGREP_RULES_CACHE_DIR set with a .yaml file -> no reason, --config appended."""
    rule_file = tmp_path / "rules.yaml"
    rule_file.write_text("rules: []")
    monkeypatch.setenv("OPENGREP_RULES_CACHE_DIR", str(tmp_path))

    scanner = _make_scanner(test_plugin_context)

    assert scanner.dependency_unavailable_reason is None
    config_args = [a for a in scanner.args.extra_args if a.key == "--config"]
    cache_configs = [a for a in config_args if str(tmp_path) in a.value]
    assert cache_configs, "Expected --config pointing to cache dir"


def test_opengrep_offline_no_subprocess_on_failure(test_plugin_context, monkeypatch):
    """_run_subprocess (the actual scan) must never be called when cache is missing.

    Note: subprocess.run may be called for version detection (_get_opengrep_version),
    which is acceptable.  What must NOT happen is the scan itself being launched.
    """
    monkeypatch.delenv("OPENGREP_RULES_CACHE_DIR", raising=False)

    with patch(
        "automated_security_helper.plugin_modules.ash_builtin.scanners.opengrep_scanner.OpengrepScanner._run_subprocess"
    ) as mock_run_subprocess:
        _make_scanner(test_plugin_context)
        mock_run_subprocess.assert_not_called()


def test_opengrep_offline_execute_scan_still_fails_closed(
    test_plugin_context, monkeypatch
):
    """A declined scanner must refuse to execute, not run against no rules."""
    monkeypatch.delenv("OPENGREP_RULES_CACHE_DIR", raising=False)
    scanner = _make_scanner(test_plugin_context)

    with pytest.raises(ScannerError, match="OPENGREP_RULES_CACHE_DIR"):
        scanner._execute_scan(
            target=test_plugin_context.source_dir,
            target_type="source",
            global_ignore_paths=[],
        )

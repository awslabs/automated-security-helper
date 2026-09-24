# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for semgrep offline mode cache-miss behaviour.

When offline=True and SEMGREP_RULES_CACHE_DIR is unset or points to a directory
with no .yaml/.yml rule files, semgrep cannot run. It must say so in a way the
scan phase can record, and it must never invoke subprocess.

Why these assertions inverted
-----------------------------
This module used to assert that ``_process_config_options`` RAISES ScannerError
for a missing cache. It does not any more, and the old assertions were pinning
the defect rather than the behaviour.

``_process_config_options`` is called from ``model_post_init``, so raising there
killed the constructor. ``ScanPhase`` builds every scanner inside a
``try/except Exception`` that logs one line and does not append to
``scanner_instances`` -- so the instance never existed to be asked
``validate_plugin_dependencies()`` or ``unsupported_platform_reason()``, the two
hooks that exist precisely so "cannot run here" lands as MISSING or SKIPPED.
The scanner vanished from the run instead: absent from ``scanner_results``,
absent from ``summary_stats`` (whose five counters still summed correctly over
the scanners that remained), and therefore invisible to both completeness gates.

The remediation text is the part that must survive the move, because it is what
an operator sees for a real misconfiguration. It is asserted here on the
recorded reason instead of on an exception message.
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
    config = SemgrepScannerConfig(options=SemgrepScannerConfigOptions(offline=True))
    scanner = SemgrepScanner(context=test_plugin_context, config=config)
    scanner.dependencies_satisfied = True
    return scanner


def test_semgrep_offline_missing_cache_records_actionable_reason(
    test_plugin_context, monkeypatch
):
    """No SEMGREP_RULES_CACHE_DIR -> constructed, declines, keeps the guidance."""
    monkeypatch.delenv("SEMGREP_RULES_CACHE_DIR", raising=False)

    scanner = _make_scanner(test_plugin_context)

    assert scanner.validate_plugin_dependencies() is False, (
        "a scanner that cannot run has to answer the dependency check, which is "
        "the only route to a MISSING row; raising from the constructor skipped it"
    )
    msg = scanner.dependency_unavailable_reason
    assert msg is not None
    assert "SEMGREP_RULES_CACHE_DIR" in msg
    assert "ash build-image --offline" in msg


def test_semgrep_offline_empty_cache_records_actionable_reason(
    test_plugin_context, monkeypatch, tmp_path
):
    """SEMGREP_RULES_CACHE_DIR set but empty -> same verdict, same guidance."""
    monkeypatch.setenv("SEMGREP_RULES_CACHE_DIR", str(tmp_path))

    scanner = _make_scanner(test_plugin_context)

    assert scanner.validate_plugin_dependencies() is False
    msg = scanner.dependency_unavailable_reason
    assert msg is not None
    assert "SEMGREP_RULES_CACHE_DIR" in msg
    assert "ash build-image --offline" in msg


def test_semgrep_offline_with_cache_does_not_decline(
    test_plugin_context, monkeypatch, tmp_path
):
    """SEMGREP_RULES_CACHE_DIR set with a .yaml file -> no reason, --config appended."""
    rule_file = tmp_path / "rules.yaml"
    rule_file.write_text("rules: []")
    monkeypatch.setenv("SEMGREP_RULES_CACHE_DIR", str(tmp_path))

    scanner = _make_scanner(test_plugin_context)

    assert scanner.dependency_unavailable_reason is None
    config_args = [a for a in scanner.args.extra_args if a.key == "--config"]
    cache_configs = [a for a in config_args if str(tmp_path) in a.value]
    assert cache_configs, "Expected --config pointing to cache dir"


def test_semgrep_offline_no_subprocess_on_failure(test_plugin_context, monkeypatch):
    """_run_subprocess (the actual scan) must never be called when cache is missing."""
    monkeypatch.delenv("SEMGREP_RULES_CACHE_DIR", raising=False)

    with patch(
        "automated_security_helper.plugin_modules.ash_builtin.scanners.semgrep_scanner.SemgrepScanner._run_subprocess"
    ) as mock_run_subprocess:
        _make_scanner(test_plugin_context)
        mock_run_subprocess.assert_not_called()


def test_semgrep_offline_execute_scan_still_fails_closed(
    test_plugin_context, monkeypatch
):
    """Moving the verdict out of the constructor must not make a scan runnable.

    ``_configure_offline_mode`` no longer appends the cache ``--config``, so a
    scanner that reached execution anyway would run against whatever rules it
    happened to have -- online defaults, or none -- and report the result as an
    offline scan. Nothing routes here today, because ``ScanPhase`` asks the
    dependency check first, but "nothing routes here today" is a property of a
    caller rather than of this class.
    """
    monkeypatch.delenv("SEMGREP_RULES_CACHE_DIR", raising=False)
    scanner = _make_scanner(test_plugin_context)

    with pytest.raises(ScannerError, match="SEMGREP_RULES_CACHE_DIR"):
        scanner._execute_scan(
            target=test_plugin_context.source_dir,
            target_type="source",
            global_ignore_paths=[],
        )

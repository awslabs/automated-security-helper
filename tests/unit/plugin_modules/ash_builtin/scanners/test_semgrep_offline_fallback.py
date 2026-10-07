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


def test_semgrep_offline_missing_cache_guidance_is_a_command_that_seeds_it(
    test_plugin_context, monkeypatch
):
    """The guidance must name a way to fill the cache that actually writes rules.

    It used to suggest ``semgrep --config p/ci --dryrun``, which fetches the ruleset
    and prints a plan but writes no rule file, so following it left the cache empty
    and the scanner MISSING on the next run.
    """
    monkeypatch.delenv("SEMGREP_RULES_CACHE_DIR", raising=False)

    scanner = _make_scanner(test_plugin_context)
    scanner.validate_plugin_dependencies()
    msg = scanner.dependency_unavailable_reason or ""

    assert "--dryrun" not in msg
    assert "https://semgrep.dev/c/" in msg
    assert ".ash-rules-fetched-at" in msg
    assert "advanced-usage.md" in msg


def test_following_the_missing_cache_guidance_seeds_the_cache(
    test_plugin_context, monkeypatch, tmp_path
):
    """Do what the guidance says, then the same scanner no longer declines.

    The guidance names three things: set the cache variable to a directory,
    download a ruleset from https://semgrep.dev/c/<ruleset> into it as a rule
    file, and record the time in .ash-rules-fetched-at. The download is stood in
    for by writing the YAML a ruleset URL returns, since unit tests do not reach
    the network.
    """
    monkeypatch.delenv("SEMGREP_RULES_CACHE_DIR", raising=False)
    declined = _make_scanner(test_plugin_context)
    assert declined.validate_plugin_dependencies() is False
    guidance = declined.dependency_unavailable_reason or ""
    assert "SEMGREP_RULES_CACHE_DIR" in guidance
    assert "https://semgrep.dev/c/" in guidance
    assert ".ash-rules-fetched-at" in guidance

    (tmp_path / "ci.yml").write_text("rules: []\n")
    (tmp_path / ".ash-rules-fetched-at").write_text("2026-10-07T00:00:00Z\n")
    monkeypatch.setenv("SEMGREP_RULES_CACHE_DIR", str(tmp_path))

    seeded = _make_scanner(test_plugin_context)
    assert seeded.dependency_unavailable_reason is None
    assert any(
        a.key == "--config" and str(tmp_path) in a.value for a in seeded.args.extra_args
    ), "the seeded cache directory is what the scanner is configured to read"


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

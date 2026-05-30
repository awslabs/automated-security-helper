# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for GrepScannerBase shared logic.

Covers:
- arg-building (--config, --metrics, --exclude, --severity, --sarif)
- offline-mode picks bundled cache via env var
- default ruleset fallthrough when no offline cache and no stargrep rules
- SARIF post-processing parity for both semgrep and opengrep subclasses
  (regression against the pre-refactor scanner output shape)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Literal
from unittest.mock import patch

import pytest

from automated_security_helper.plugin_modules.ash_builtin.scanners._grep_scanner_base import (
    GrepScannerBase,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.semgrep_scanner import (
    SemgrepScanner,
    SemgrepScannerConfig,
    SemgrepScannerConfigOptions,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.opengrep_scanner import (
    OpengrepScanner,
    OpengrepScannerConfig,
    OpengrepScannerConfigOptions,
)


# ---------------------------------------------------------------------------
# A minimal test stub. Real subclasses live in semgrep_scanner /
# opengrep_scanner; this stub is just enough to exercise the shared
# arg-building + offline-cache logic without a real binary.
# ---------------------------------------------------------------------------


def _extra_arg_pairs(scanner) -> list[tuple[str, str]]:
    """Return [(key, value), ...] for inspection."""
    return [(a.key, a.value) for a in scanner.args.extra_args]


# ---------------------------------------------------------------------------
# Shared arg-building
# ---------------------------------------------------------------------------


class TestSharedArgBuilding:
    def test_semgrep_online_emits_default_ruleset_and_metrics(
        self, test_plugin_context, monkeypatch
    ):
        """Online: --config p/ci, --metrics auto, --sarif must all be present."""
        monkeypatch.delenv("SEMGREP_RULES_CACHE_DIR", raising=False)
        config = SemgrepScannerConfig(
            options=SemgrepScannerConfigOptions(offline=False)
        )
        scanner = SemgrepScanner(context=test_plugin_context, config=config)

        pairs = _extra_arg_pairs(scanner)
        assert ("--config", "p/ci") in pairs, pairs
        assert ("--metrics", "auto") in pairs, pairs
        assert any(k == "--sarif" for k, _ in pairs), pairs

    def test_opengrep_online_emits_default_ruleset(
        self, test_plugin_context, monkeypatch
    ):
        """Online: --config p/ci, --sarif must all be present."""
        monkeypatch.delenv("OPENGREP_RULES_CACHE_DIR", raising=False)
        config = OpengrepScannerConfig(
            options=OpengrepScannerConfigOptions(offline=False)
        )
        scanner = OpengrepScanner(context=test_plugin_context, config=config)

        pairs = _extra_arg_pairs(scanner)
        assert ("--config", "p/ci") in pairs, pairs
        assert any(k == "--sarif" for k, _ in pairs), pairs

    def test_exclude_patterns_are_emitted(self, test_plugin_context, monkeypatch):
        monkeypatch.delenv("SEMGREP_RULES_CACHE_DIR", raising=False)
        config = SemgrepScannerConfig(
            options=SemgrepScannerConfigOptions(
                offline=False, exclude=["foo.py", "bar/*"]
            )
        )
        scanner = SemgrepScanner(context=test_plugin_context, config=config)

        pairs = _extra_arg_pairs(scanner)
        excludes = [v for k, v in pairs if k == "--exclude"]
        assert "foo.py" in excludes
        assert "bar/*" in excludes

    def test_severity_filter_emitted(self, test_plugin_context, monkeypatch):
        monkeypatch.delenv("SEMGREP_RULES_CACHE_DIR", raising=False)
        config = SemgrepScannerConfig(
            options=SemgrepScannerConfigOptions(
                offline=False, severity=["ERROR", "WARNING"]
            )
        )
        scanner = SemgrepScanner(context=test_plugin_context, config=config)

        pairs = _extra_arg_pairs(scanner)
        sev = [v for k, v in pairs if k == "--severity"]
        assert "ERROR" in sev
        assert "WARNING" in sev


# ---------------------------------------------------------------------------
# Offline-mode cache discovery
# ---------------------------------------------------------------------------


class TestOfflineCacheDiscovery:
    def test_semgrep_offline_picks_bundled_cache_from_env(
        self, test_plugin_context, monkeypatch, tmp_path
    ):
        """When SEMGREP_RULES_CACHE_DIR points at a populated dir, that dir
        becomes a --config target and --no-rewrite-rule-ids is set."""
        rule_file = tmp_path / "rules.yaml"
        rule_file.write_text("rules: []")
        monkeypatch.setenv("SEMGREP_RULES_CACHE_DIR", str(tmp_path))

        config = SemgrepScannerConfig(
            options=SemgrepScannerConfigOptions(offline=True)
        )
        scanner = SemgrepScanner(context=test_plugin_context, config=config)

        pairs = _extra_arg_pairs(scanner)
        cache_configs = [v for k, v in pairs if k == "--config" and str(tmp_path) in v]
        assert cache_configs, f"Expected --config pointing to cache dir, got {pairs}"
        assert any(k == "--no-rewrite-rule-ids" for k, _ in pairs)
        # Default registry entry must NOT be present in offline mode.
        assert ("--config", "p/ci") not in pairs

    def test_opengrep_offline_picks_bundled_cache_from_env(
        self, test_plugin_context, monkeypatch, tmp_path
    ):
        rule_file = tmp_path / "rules.yaml"
        rule_file.write_text("rules: []")
        monkeypatch.setenv("OPENGREP_RULES_CACHE_DIR", str(tmp_path))

        config = OpengrepScannerConfig(
            options=OpengrepScannerConfigOptions(offline=True)
        )
        scanner = OpengrepScanner(context=test_plugin_context, config=config)

        pairs = _extra_arg_pairs(scanner)
        cache_configs = [v for k, v in pairs if k == "--config" and str(tmp_path) in v]
        assert cache_configs, f"Expected --config pointing to cache dir, got {pairs}"
        assert any(k == "--no-rewrite-rule-ids" for k, _ in pairs)
        assert ("--config", "p/ci") not in pairs


# ---------------------------------------------------------------------------
# Default ruleset fallthrough
# ---------------------------------------------------------------------------


class TestDefaultRulesetFallthrough:
    def test_semgrep_falls_through_to_p_ci_when_online(
        self, test_plugin_context, monkeypatch
    ):
        """Online mode must use the configured `config` field (default p/ci)."""
        monkeypatch.delenv("SEMGREP_RULES_CACHE_DIR", raising=False)
        config = SemgrepScannerConfig(
            options=SemgrepScannerConfigOptions(offline=False)
        )
        scanner = SemgrepScanner(context=test_plugin_context, config=config)

        configs = [v for k, v in _extra_arg_pairs(scanner) if k == "--config"]
        assert "p/ci" in configs

    def test_opengrep_falls_through_to_p_ci_when_online(
        self, test_plugin_context, monkeypatch
    ):
        monkeypatch.delenv("OPENGREP_RULES_CACHE_DIR", raising=False)
        config = OpengrepScannerConfig(
            options=OpengrepScannerConfigOptions(offline=False)
        )
        scanner = OpengrepScanner(context=test_plugin_context, config=config)

        configs = [v for k, v in _extra_arg_pairs(scanner) if k == "--config"]
        assert "p/ci" in configs


# ---------------------------------------------------------------------------
# SARIF post-processing parity (regression)
# ---------------------------------------------------------------------------


_SAMPLE_SARIF: dict = {
    "version": "2.1.0",
    "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
    "runs": [
        {
            "tool": {
                "driver": {
                    "name": "semgrep",
                    "rules": [
                        {
                            "id": "test.rule",
                            "name": "test.rule",
                            "shortDescription": {"text": "test rule"},
                        }
                    ],
                }
            },
            "results": [],
        }
    ],
}


def _run_post_scan_pipeline(scanner, target: Path, sarif_dict: dict) -> dict:
    """Run scan() with _run_subprocess monkey-patched to drop a SARIF file
    on disk, then return the resulting SarifReport as a dict."""
    target.mkdir(parents=True, exist_ok=True)
    (target / "x.py").write_text("# placeholder\n")

    captured: dict = {}

    def fake_run_subprocess(self, command, results_dir, env=None):
        captured["command"] = command
        results_file = Path(results_dir) / "results_sarif.sarif"
        results_file.write_text(json.dumps(sarif_dict))
        self.exit_code = 0
        return None

    with (
        patch.object(
            scanner.__class__,
            "_run_subprocess",
            fake_run_subprocess,
        ),
        patch.object(scanner, "validate_plugin_dependencies", return_value=True),
    ):
        scanner.dependencies_satisfied = True
        report = scanner.scan(target=target, target_type="source")

    if hasattr(report, "model_dump"):
        return report.model_dump(by_alias=True, exclude_none=True)
    return report  # already a dict


class TestSarifPostProcessingParity:
    def test_semgrep_post_scan_attaches_invocation(
        self, test_plugin_context, monkeypatch, tmp_path
    ):
        monkeypatch.delenv("SEMGREP_RULES_CACHE_DIR", raising=False)
        target = tmp_path / "src"

        config = SemgrepScannerConfig(
            options=SemgrepScannerConfigOptions(offline=False)
        )
        scanner = SemgrepScanner(context=test_plugin_context, config=config)

        out = _run_post_scan_pipeline(scanner, target, _SAMPLE_SARIF)
        run0 = out["runs"][0]
        assert run0.get("invocations"), "expected invocations populated"
        inv = run0["invocations"][0]
        assert "commandLine" in inv
        assert inv["exitCode"] == 0

    def test_opengrep_post_scan_attaches_invocation(
        self, test_plugin_context, monkeypatch, tmp_path
    ):
        monkeypatch.delenv("OPENGREP_RULES_CACHE_DIR", raising=False)
        target = tmp_path / "src"

        config = OpengrepScannerConfig(
            options=OpengrepScannerConfigOptions(offline=False)
        )
        scanner = OpengrepScanner(context=test_plugin_context, config=config)

        out = _run_post_scan_pipeline(scanner, target, _SAMPLE_SARIF)
        run0 = out["runs"][0]
        assert run0.get("invocations"), "expected invocations populated"
        inv = run0["invocations"][0]
        assert "commandLine" in inv
        assert inv["exitCode"] == 0

    def test_byte_identical_run_structure_between_scanners(
        self, test_plugin_context, monkeypatch, tmp_path
    ):
        """Both semgrep and opengrep scanners process the same input SARIF
        through identical shared post-scan logic (modulo scanner name)."""
        monkeypatch.delenv("SEMGREP_RULES_CACHE_DIR", raising=False)
        monkeypatch.delenv("OPENGREP_RULES_CACHE_DIR", raising=False)
        target = tmp_path / "src"

        sg = SemgrepScanner(
            context=test_plugin_context,
            config=SemgrepScannerConfig(
                options=SemgrepScannerConfigOptions(offline=False)
            ),
        )
        og = OpengrepScanner(
            context=test_plugin_context,
            config=OpengrepScannerConfig(
                options=OpengrepScannerConfigOptions(offline=False)
            ),
        )

        out_sg = _run_post_scan_pipeline(sg, target, _SAMPLE_SARIF)
        target2 = tmp_path / "src2"
        out_og = _run_post_scan_pipeline(og, target2, _SAMPLE_SARIF)

        # Both must have a populated invocations array and the same
        # SARIF top-level shape (version, $schema, runs[*].results).
        assert out_sg["version"] == out_og["version"]
        assert out_sg.get("$schema") == out_og.get("$schema")
        assert out_sg["runs"][0]["results"] == out_og["runs"][0]["results"]
        assert len(out_sg["runs"][0]["invocations"]) == 1
        assert len(out_og["runs"][0]["invocations"]) == 1


# ---------------------------------------------------------------------------
# Sanity — both scanners actually inherit from GrepScannerBase post-refactor
# ---------------------------------------------------------------------------


def test_semgrep_inherits_from_grep_base():
    assert issubclass(SemgrepScanner, GrepScannerBase)


def test_opengrep_inherits_from_grep_base():
    assert issubclass(OpengrepScanner, GrepScannerBase)

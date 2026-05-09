# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for trivy_repo_scanner offline mode wiring."""

import os
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_repo_scanner import (
    TrivyRepoScanner,
    TrivyRepoScannerConfig,
    TrivyRepoScannerConfigOptions,
)
from automated_security_helper.utils.offline_mode_validator import (
    validate_trivy_offline_mode,
)

AshConfig.model_rebuild()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_context(tmp_path: Path) -> MagicMock:
    ctx = MagicMock(spec=PluginContext)
    ctx.source_dir = tmp_path / "source"
    ctx.output_dir = tmp_path / "output"
    ctx.source_dir.mkdir(exist_ok=True)
    ctx.output_dir.mkdir(exist_ok=True)
    ctx.global_ignore_paths = []
    return ctx


def _make_scanner(offline: bool, tmp_path: Path) -> TrivyRepoScanner:
    options = TrivyRepoScannerConfigOptions(offline=offline)
    config = TrivyRepoScannerConfig(options=options)
    return TrivyRepoScanner(context=_make_context(tmp_path), config=config)


OFFLINE_FLAGS = [
    "--skip-db-update",
    "--skip-java-db-update",
    "--offline-scan",
    "--skip-check-update",
]


# ---------------------------------------------------------------------------
# Flag injection tests
# ---------------------------------------------------------------------------

class TestTrivyOfflineFlagInjection:
    def test_offline_appends_flags(self, tmp_path):
        scanner = _make_scanner(offline=True, tmp_path=tmp_path)
        scanner._process_config_options()
        arg_keys = [a.key for a in scanner.args.extra_args]
        for flag in OFFLINE_FLAGS:
            assert flag in arg_keys, f"Expected {flag} in args when offline=True"

    def test_online_does_not_append_flags(self, tmp_path):
        scanner = _make_scanner(offline=False, tmp_path=tmp_path)
        scanner._process_config_options()
        arg_keys = [a.key for a in scanner.args.extra_args]
        for flag in OFFLINE_FLAGS:
            assert flag not in arg_keys, f"Unexpected {flag} in args when offline=False"


# ---------------------------------------------------------------------------
# Subprocess env passthrough test
# ---------------------------------------------------------------------------

class TestTrivySubprocessEnvPassthrough:
    def test_subprocess_receives_merged_env(self, tmp_path):
        scanner = _make_scanner(offline=True, tmp_path=tmp_path)
        scanner.extra_env = {"TRIVY_OFFLINE_TEST": "yes"}

        captured_env = {}

        def _fake_run_subprocess(command, results_dir, env=None, **kwargs):
            captured_env.update(env or {})
            scanner.exit_code = 0
            scanner.errors = []
            scanner.start_time = None
            scanner.end_time = None

        source_dir = tmp_path / "source"
        # Put a file in source_dir so the empty-dir check doesn't short-circuit
        (source_dir / "dummy.txt").write_text("x")
        # Ensure results file exists so scan() doesn't fail on file read
        results_file = scanner.results_dir / "source" / "results_sarif.sarif"
        results_file.parent.mkdir(parents=True, exist_ok=True)
        results_file.write_text('{"version":"2.1.0","runs":[]}')

        scanner.dependencies_satisfied = True
        with patch.object(scanner, "_run_subprocess", side_effect=_fake_run_subprocess):
            with patch.object(scanner, "_pre_scan", return_value=True):
                with patch.object(scanner, "_post_scan"):
                    scanner.scan(target=source_dir, target_type="source")

        assert "TRIVY_OFFLINE_TEST" in captured_env
        assert len(captured_env) > 1  # merged with os.environ


# ---------------------------------------------------------------------------
# validate_trivy_offline_mode tests
# ---------------------------------------------------------------------------

class TestValidateTrivyOfflineMode:
    def test_missing_cache_env_returns_false(self, monkeypatch):
        monkeypatch.delenv("TRIVY_CACHE_DIR", raising=False)
        valid, messages = validate_trivy_offline_mode()
        assert valid is False
        assert any("TRIVY_CACHE_DIR" in m for m in messages)

    def test_old_db_returns_true_with_warning(self, tmp_path, monkeypatch):
        cache_dir = tmp_path / "trivy-cache"
        cache_dir.mkdir()
        db_file = cache_dir / "db.db"
        db_file.write_bytes(b"fake")
        # Make the file appear 8 days old
        old_mtime = time.time() - (8 * 24 * 3600)
        os.utime(db_file, (old_mtime, old_mtime))

        monkeypatch.setenv("TRIVY_CACHE_DIR", str(cache_dir))
        valid, messages = validate_trivy_offline_mode()
        assert valid is True
        assert any("days old" in m for m in messages)

    def test_fresh_db_returns_true_no_staleness_warning(self, tmp_path, monkeypatch):
        cache_dir = tmp_path / "trivy-cache"
        cache_dir.mkdir()
        db_file = cache_dir / "trivy.db"
        db_file.write_bytes(b"fake")
        # File is brand new — mtime is current

        monkeypatch.setenv("TRIVY_CACHE_DIR", str(cache_dir))
        valid, messages = validate_trivy_offline_mode()
        assert valid is True
        # No staleness warning should appear for a fresh DB
        stale_msgs = [m for m in messages if "consider updating" in m]
        assert stale_msgs == []

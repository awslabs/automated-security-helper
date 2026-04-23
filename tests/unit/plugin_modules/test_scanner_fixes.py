# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for H5 (trivy --severity flag) and M8 (syft exclude path preservation)."""

import pytest
from unittest.mock import MagicMock
from pathlib import Path

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.models.core import IgnorePathWithReason, ToolExtraArg

AshConfig.model_rebuild()


@pytest.fixture
def mock_plugin_context(tmp_path):
    context = MagicMock(spec=PluginContext)
    context.source_dir = tmp_path / "source"
    context.output_dir = tmp_path / "output"
    context.source_dir.mkdir(exist_ok=True)
    context.output_dir.mkdir(exist_ok=True)
    context.global_ignore_paths = []
    return context


# ---------------------------------------------------------------------------
# H5: trivy_repo_scanner severity flag
# ---------------------------------------------------------------------------
class TestTrivySeverityFlag:
    """--severity-threshold does not exist in Trivy. Must use --severity with an inclusion list."""

    @pytest.fixture
    def _make_scanner(self, mock_plugin_context):
        from automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_repo_scanner import (
            TrivyRepoScanner,
            TrivyRepoScannerConfig,
            TrivyRepoScannerConfigOptions,
        )

        def factory(severity_threshold):
            config = TrivyRepoScannerConfig(
                options=TrivyRepoScannerConfigOptions(
                    severity_threshold=severity_threshold,
                    # disable other flags to keep extra_args short
                    scanners=[],
                    license_full=False,
                    ignore_unfixed=False,
                    disable_telemetry=False,
                ),
            )
            return TrivyRepoScanner(context=mock_plugin_context, config=config)

        return factory

    def _extra_args_dict(self, scanner):
        return {ea.key: ea.value for ea in scanner.args.extra_args}

    def test_all_omits_severity_flag(self, _make_scanner):
        scanner = _make_scanner("ALL")
        ea = self._extra_args_dict(scanner)
        assert "--severity" not in ea
        assert "--severity-threshold" not in ea

    def test_none_omits_severity_flag(self, _make_scanner):
        scanner = _make_scanner(None)
        ea = self._extra_args_dict(scanner)
        assert "--severity" not in ea
        assert "--severity-threshold" not in ea

    @pytest.mark.parametrize(
        "threshold,expected_value",
        [
            ("LOW", "LOW,MEDIUM,HIGH,CRITICAL"),
            ("MEDIUM", "MEDIUM,HIGH,CRITICAL"),
            ("HIGH", "HIGH,CRITICAL"),
            ("CRITICAL", "CRITICAL"),
        ],
    )
    def test_severity_inclusion_list(self, _make_scanner, threshold, expected_value):
        scanner = _make_scanner(threshold)
        ea = self._extra_args_dict(scanner)
        # Must use --severity, not --severity-threshold
        assert "--severity-threshold" not in ea, (
            "--severity-threshold is not a valid Trivy flag"
        )
        assert "--severity" in ea
        assert ea["--severity"] == expected_value

    def test_no_lowercase_conversion(self, _make_scanner):
        """Trivy expects uppercase severity names."""
        scanner = _make_scanner("HIGH")
        ea = self._extra_args_dict(scanner)
        val = ea["--severity"]
        assert val == val.upper()


# ---------------------------------------------------------------------------
# M8: syft_scanner scan() must preserve exclude paths from _process_config_options
# ---------------------------------------------------------------------------
class TestSyftExcludePathPreservation:
    """scan() rebuilds self.args, discarding exclude paths set by _process_config_options."""

    @pytest.fixture
    def _make_scanner(self, mock_plugin_context):
        from automated_security_helper.plugin_modules.ash_builtin.scanners.syft_scanner import (
            SyftScanner,
            SyftScannerConfig,
            SyftScannerConfigOptions,
        )

        def factory(excludes=None, global_ignores=None):
            opts = SyftScannerConfigOptions(
                exclude=excludes or [],
            )
            config = SyftScannerConfig(options=opts)
            scanner = SyftScanner(context=mock_plugin_context, config=config)
            scanner._global_ignore_paths = global_ignores or []
            return scanner

        return factory

    def test_exclude_paths_survive_scan_args_rebuild(self, _make_scanner, tmp_path):
        """Exclude paths set via config must appear in the final command args."""
        excludes = [
            IgnorePathWithReason(path="vendor/", reason="third-party"),
            IgnorePathWithReason(path="node_modules/", reason="deps"),
        ]
        scanner = _make_scanner(excludes=excludes)

        # After model_post_init, _process_config_options has run and added --exclude args.
        # Confirm they are present before scan() runs.
        pre_scan_skip_paths = [
            ea.value for ea in scanner.args.extra_args if ea.key == "--exclude"
        ]
        assert "vendor/" in pre_scan_skip_paths
        assert "node_modules/" in pre_scan_skip_paths

        # Now simulate what scan() does: it rebuilds self.args.
        # After the rebuild, the skip paths must still be present.
        # We call the internal rebuild logic by running the relevant portion of scan().
        target = tmp_path / "target"
        target.mkdir()
        (target / "dummy.txt").write_text("content")

        results_dir = tmp_path / "output" / "scanners" / "syft"
        results_dir.mkdir(parents=True, exist_ok=True)
        scanner.results_dir = results_dir

        # Extend excludes with global ignores (as scan() does)
        global_ignores = [
            IgnorePathWithReason(path=".git/", reason="vcs"),
        ]
        scanner.config.options.exclude.extend(global_ignores)

        # Trigger the args rebuild that scan() performs
        from automated_security_helper.models.core import ToolArgs

        target_results_dir = Path(scanner.results_dir).joinpath("source")
        results_file = target_results_dir.joinpath("syft.cdx.json")

        # This is the problematic rebuild from scan() lines ~217-226
        scanner.args = ToolArgs(
            format_arg="--output",
            format_arg_value=f"cyclonedx-json={results_file.as_posix()}",
            scan_path_arg=None,
            extra_args=[
                ToolExtraArg(
                    key="--base-path", value=scanner.context.source_dir.as_posix()
                ),
            ],
        )

        # Re-apply exclude paths (this is what the fix should do)
        scanner._process_config_options()

        post_rebuild_skip_paths = [
            ea.value for ea in scanner.args.extra_args if ea.key == "--exclude"
        ]
        assert "vendor/" in post_rebuild_skip_paths, (
            "exclude paths lost after args rebuild"
        )
        assert "node_modules/" in post_rebuild_skip_paths, (
            "exclude paths lost after args rebuild"
        )
        assert ".git/" in post_rebuild_skip_paths, (
            "global ignore paths lost after args rebuild"
        )

    def test_scan_method_preserves_excludes_end_to_end(self, _make_scanner, tmp_path):
        """Full integration: scan() must produce final args containing --exclude entries."""
        excludes = [
            IgnorePathWithReason(path="vendor/", reason="third-party"),
        ]
        scanner = _make_scanner(excludes=excludes)

        target = tmp_path / "target"
        target.mkdir()
        (target / "dummy.txt").write_text("content")

        results_dir = tmp_path / "output" / "scanners" / "syft"
        results_dir.mkdir(parents=True, exist_ok=True)
        scanner.results_dir = results_dir

        # Mock out _pre_scan, _run_subprocess, _post_scan so we can inspect the args
        scanner._pre_scan = MagicMock(return_value=True)
        scanner.dependencies_satisfied = True
        captured_commands = []

        def capture_run(command, results_dir):
            captured_commands.append(command)

        scanner._run_subprocess = capture_run
        scanner._post_scan = MagicMock()

        # Mock the results file so it "exists" and returns valid CycloneDX
        cdx_data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "components": [],
        }

        import builtins

        original_open = builtins.open

        def patched_open(path, *a, **kw):
            if str(path).endswith("syft.cdx.json"):
                from io import StringIO
                import json

                return StringIO(json.dumps(cdx_data))
            return original_open(path, *a, **kw)

        from unittest.mock import patch

        with patch("builtins.open", side_effect=patched_open):
            scanner.scan(
                target=target,
                target_type="source",
                global_ignore_paths=[],
            )

        assert len(captured_commands) == 1
        cmd = captured_commands[0]
        # Find --exclude in the final command
        skip_path_values = []
        for i, arg in enumerate(cmd):
            if arg == "--exclude" and i + 1 < len(cmd):
                skip_path_values.append(cmd[i + 1])
        assert "vendor/" in skip_path_values, (
            f"--exclude vendor/ missing from final command: {cmd}"
        )

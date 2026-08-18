# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Regression tests: checkov config discovery must key off source_dir, not process cwd.

checkov's subprocess runs with cwd=context.source_dir (PluginBase._run_subprocess
defaults working_dir to it). The config probe previously used a bare
Path(".ash/.checkov.yaml").exists(), which tests whatever directory ASH was invoked
from, and then passed the match through get_shortest_name, which relativises against
that same process cwd. So the probe and the consumer disagreed about the base
directory.

When ASH was invoked from its own checkout, the probe matched ASH's committed
.ash/.checkov.yaml and handed checkov a path it could not open. checkov exited
without writing results_sarif.sarif, the scanner raised FileNotFoundError, and every
scan reported checkov as ERROR with zero findings.

This lined up by accident before run_ash_scan was decomposed: that version chdir'd
the whole process into source_dir, so process cwd and subprocess cwd were the same
directory. Restoring the global chdir is not the fix - it destabilised 107 tests
across the CWD-sensitive suites, because the decomposition deliberately removed
process-wide cwd dependence (see tests/unit/test_cwd_defaults_fix.py). Resolving the
probe explicitly is, and it is also what scanning several projects in one process
requires.
"""

from pathlib import Path

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.base.plugin_context import PluginContext

PluginContext.model_rebuild()

from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (  # noqa: E402
    CheckovScanner,
    CheckovScannerConfig,
    CheckovScannerConfigOptions,
)


def _scanner(source_dir: Path, output_dir: Path, **opts) -> CheckovScanner:
    ctx = PluginContext(
        source_dir=source_dir, output_dir=output_dir, config=AshConfig()
    )
    return CheckovScanner(
        context=ctx,
        config=CheckovScannerConfig(options=CheckovScannerConfigOptions(**opts)),
    )


def _config_args(scanner: CheckovScanner) -> list[str]:
    return [
        ea.value for ea in scanner.args.extra_args if ea.key == "--config-file"
    ]


@pytest.fixture
def dirs(tmp_path):
    src = tmp_path / "target"
    (src / ".ash").mkdir(parents=True)
    out = tmp_path / "out"
    out.mkdir()
    return src, out


class TestConfigResolvedAgainstSourceDir:
    def test_finds_config_in_source_dir(self, dirs):
        src, out = dirs
        cfg = src / ".ash" / ".checkov.yaml"
        cfg.write_text("skip-check:\n  - CKV_AWS_18\n")

        args = _config_args(_scanner(src, out))
        assert args, "config in source_dir was not discovered"
        assert Path(args[0]) == cfg.resolve(), args

    def test_config_arg_is_absolute(self, dirs):
        """The subprocess cwd is source_dir; a cwd-relative arg is ambiguous."""
        src, out = dirs
        (src / ".ash" / ".checkov.yaml").write_text("skip-check: []\n")

        args = _config_args(_scanner(src, out))
        assert args and Path(args[0]).is_absolute(), args

    def test_ignores_config_that_only_exists_in_process_cwd(self, dirs, monkeypatch):
        """A config next to ASH's own checkout must not leak into a scan of elsewhere.

        This is the exact failure: the probe found a file relative to the process
        working directory that checkov, running from source_dir, could not open.
        """
        src, out = dirs
        elsewhere = out / "cwd-with-config"
        (elsewhere / ".ash").mkdir(parents=True)
        (elsewhere / ".ash" / ".checkov.yaml").write_text("skip-check: []\n")
        monkeypatch.chdir(elsewhere)

        assert _config_args(_scanner(src, out)) == [], (
            "picked up a config from the process working directory; checkov runs "
            "from source_dir and cannot open it"
        )

    def test_no_config_anywhere_adds_no_arg(self, dirs, monkeypatch):
        src, out = dirs
        monkeypatch.chdir(out)
        assert _config_args(_scanner(src, out)) == []

    def test_explicit_relative_config_file_resolves_against_source_dir(self, dirs):
        src, out = dirs
        cfg = src / "custom.yaml"
        cfg.write_text("skip-check: []\n")

        args = _config_args(_scanner(src, out, config_file="custom.yaml"))
        assert args and Path(args[0]) == cfg.resolve(), args

    def test_explicit_absolute_config_file_is_used_as_given(self, dirs):
        src, out = dirs
        cfg = out / "abs.yaml"
        cfg.write_text("skip-check: []\n")

        args = _config_args(_scanner(src, out, config_file=str(cfg)))
        assert args and Path(args[0]) == cfg.resolve(), args

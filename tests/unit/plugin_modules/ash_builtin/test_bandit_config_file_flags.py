# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The flags bandit runs with for each ``config_file``, as its description states.

``BanditScannerConfigOptions.config_file`` says: a file named ``.bandit`` is
passed with ``bandit --ini`` and any other with ``bandit --configfile``; unless
``config_file`` names a ``.bandit`` file that exists, ASH passes an empty config
file with ``bandit --ini``; a path that does not exist is logged as a warning
and ignored. ``test_bandit_scanner_behavior.py`` checks the flags recorded when
the options are processed; these check the argv of the scan.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import List, Optional

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner import (
    BanditScanner,
    BanditScannerConfig,
    BanditScannerConfigOptions,
)


@pytest.fixture
def plugin_context(tmp_path: Path) -> PluginContext:
    context = PluginContext(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "work",
        config=get_default_config(),
    )
    for directory in (context.source_dir, context.output_dir, context.work_dir):
        directory.mkdir(parents=True)
    return context


def _argv(context: PluginContext, config_file: Optional[Path]) -> tuple:
    scanner = BanditScanner(
        context=context,
        config=BanditScannerConfig(
            options=BanditScannerConfigOptions(config_file=config_file)
        ),
    )
    final_args, _, _ = scanner._execute_scan(context.source_dir, "source", [])
    return [str(arg) for arg in final_args], Path(scanner.results_dir)


def _after(argv: List[str], flag: str) -> List[str]:
    return [argv[i + 1] for i, arg in enumerate(argv[:-1]) if arg == flag]


def _is_the_empty_ini(value: str, results_dir: Path) -> bool:
    path = Path(value)
    return (
        path.parent == results_dir and path.read_text(encoding="utf-8") == "[bandit]\n"
    )


def test_a_dot_bandit_file_is_the_only_ini(plugin_context, tmp_path) -> None:
    config_file = tmp_path / "operator" / ".bandit"
    config_file.parent.mkdir()
    config_file.write_text("[bandit]\nskips = B101\n", encoding="utf-8")

    argv, _ = _argv(plugin_context, config_file)

    assert _after(argv, "--ini") == [config_file.as_posix()]
    assert _after(argv, "--configfile") == []


@pytest.mark.parametrize("name", ["bandit.yaml", "bandit.toml"])
def test_another_file_is_a_configfile_beside_the_empty_ini(
    plugin_context, tmp_path, name: str
) -> None:
    config_file = tmp_path / "operator" / name
    config_file.parent.mkdir()
    config_file.write_text("skips: []\n", encoding="utf-8")

    argv, results_dir = _argv(plugin_context, config_file)

    assert _after(argv, "--configfile") == [config_file.as_posix()]
    (ini,) = _after(argv, "--ini")
    assert _is_the_empty_ini(ini, results_dir), ini


@pytest.mark.parametrize("named", [False, True], ids=["unset", "missing"])
def test_without_a_usable_file_only_the_empty_ini_is_passed(
    plugin_context, tmp_path, named: bool, caplog
) -> None:
    missing = tmp_path / "nowhere" / ".bandit"
    with caplog.at_level(logging.WARNING):
        argv, results_dir = _argv(plugin_context, missing if named else None)

    assert _after(argv, "--configfile") == []
    (ini,) = _after(argv, "--ini")
    assert _is_the_empty_ini(ini, results_dir), ini
    if named:
        (warning,) = [
            r.getMessage() for r in caplog.records if str(missing) in r.getMessage()
        ]
        assert "is ignored" in warning and "empty config file" in warning, warning

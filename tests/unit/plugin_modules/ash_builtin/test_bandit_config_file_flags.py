# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The flags bandit runs with for each ``config_file``, as its description states.

``BanditScannerConfigOptions.config_file`` says: a file named exactly ``.bandit``
is passed with ``bandit --ini`` and any other file with ``bandit --configfile``;
unless ``config_file`` names a ``.bandit`` file, ASH passes an empty config file
with ``bandit --ini``; a path that is not a file is logged as a warning and
ignored. ``test_bandit_scanner_behavior.py`` checks the flags recorded when the
options are processed; these check the argv of the scan, and that a scanner run
twice (the source and the converted tree) passes one ``--ini`` each time.

A relative path an operator writes is made absolute by ``resolve_config``,
against the directory of the config file that sets it
(``test_operator_paths_resolve_from_their_config.py``). The scanner joins a value
that still reaches it relative to the source directory, which is what the
relative-path test here pins.
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

pytestmark = pytest.mark.unit


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


def _scanner(context: PluginContext, config_file: Optional[Path]) -> BanditScanner:
    return BanditScanner(
        context=context,
        config=BanditScannerConfig(
            options=BanditScannerConfigOptions(config_file=config_file)
        ),
    )


def _scan_argv(
    scanner: BanditScanner, target: Path, target_type: str = "source"
) -> List[str]:
    final_args, _, _ = scanner._execute_scan(target, target_type, [])
    return [str(arg) for arg in final_args]


def _argv(context: PluginContext, config_file: Optional[Path]) -> tuple:
    scanner = _scanner(context, config_file)
    return _scan_argv(scanner, context.source_dir), Path(scanner.results_dir)


def _after(argv: List[str], flag: str) -> List[str]:
    return [argv[i + 1] for i, arg in enumerate(argv[:-1]) if arg == flag]


def _is_the_empty_ini(value: str, results_dir: Path, source_dir: Path) -> bool:
    """ASH's empty config: in its private directory, outside the results and the tree."""
    from automated_security_helper.config.path_trust import in_scanned_tree
    from automated_security_helper.utils.tool_config_dir import TOOL_CONFIG_DIR_PREFIX

    path = Path(value)
    return (
        path.parent.name.startswith(TOOL_CONFIG_DIR_PREFIX)
        and results_dir not in path.parents
        and not in_scanned_tree(path, source_dir)
        and path.read_text(encoding="utf-8") == "[bandit]\n"
    )


def test_a_dot_bandit_file_is_the_only_ini(plugin_context, tmp_path) -> None:
    config_file = tmp_path / "operator" / ".bandit"
    config_file.parent.mkdir()
    config_file.write_text("[bandit]\nskips = B101\n", encoding="utf-8")

    argv, _ = _argv(plugin_context, config_file)

    assert _after(argv, "--ini") == [config_file.as_posix()]
    assert _after(argv, "--configfile") == []


@pytest.mark.parametrize("name", ["bandit.yaml", "bandit.toml", "ops.bandit"])
def test_another_file_is_a_configfile_beside_the_empty_ini(
    plugin_context, tmp_path, name: str
) -> None:
    config_file = tmp_path / "operator" / name
    config_file.parent.mkdir()
    config_file.write_text("skips: []\n", encoding="utf-8")

    argv, results_dir = _argv(plugin_context, config_file)

    assert _after(argv, "--configfile") == [config_file.as_posix()]
    (ini,) = _after(argv, "--ini")
    assert _is_the_empty_ini(ini, results_dir, plugin_context.source_dir), ini


@pytest.mark.parametrize("named", [False, True], ids=["unset", "missing"])
def test_without_a_usable_file_only_the_empty_ini_is_passed(
    plugin_context, tmp_path, named: bool, caplog
) -> None:
    missing = tmp_path / "nowhere" / ".bandit"
    with caplog.at_level(logging.WARNING):
        argv, results_dir = _argv(plugin_context, missing if named else None)

    assert _after(argv, "--configfile") == []
    (ini,) = _after(argv, "--ini")
    assert _is_the_empty_ini(ini, results_dir, plugin_context.source_dir), ini
    if named:
        (warning,) = [
            r.getMessage() for r in caplog.records if str(missing) in r.getMessage()
        ]
        assert "does not exist or is not a file" in warning, warning
        assert "empty ini file" in warning, warning


def test_a_directory_is_not_passed_as_a_config_file(
    plugin_context, tmp_path, caplog
) -> None:
    """``is_file``, not ``exists``: a directory named ``.bandit`` is ignored too."""
    directory = tmp_path / "operator" / ".bandit"
    directory.mkdir(parents=True)

    with caplog.at_level(logging.WARNING):
        argv, results_dir = _argv(plugin_context, directory)

    assert _after(argv, "--configfile") == []
    (ini,) = _after(argv, "--ini")
    assert _is_the_empty_ini(ini, results_dir, plugin_context.source_dir), ini
    (warning,) = [
        r.getMessage() for r in caplog.records if str(directory) in r.getMessage()
    ]
    assert "is not a file" in warning and "empty ini file" in warning, warning


def test_a_path_still_relative_at_the_scanner_is_joined_to_the_source_directory(
    plugin_context,
) -> None:
    """resolve_config has already anchored an operator's relative path; one set
    on the options directly reaches the scanner relative."""
    in_source = plugin_context.source_dir / "ops" / "bandit.yaml"
    in_source.parent.mkdir()
    in_source.write_text("skips: []\n", encoding="utf-8")

    argv, _ = _argv(plugin_context, Path("ops/bandit.yaml"))

    assert _after(argv, "--configfile") == [in_source.as_posix()]


@pytest.mark.parametrize("name", [None, ".bandit", "bandit.yaml"])
def test_each_scan_passes_one_ini(plugin_context, tmp_path, name) -> None:
    """One scanner scans the source tree, then the converted tree: one ``--ini``
    on each scan, the same config file on both, and the second scan names the
    converted target (both scans used to run on the source tree)."""
    config_file = None
    if name is not None:
        config_file = tmp_path / "operator" / name
        config_file.parent.mkdir()
        config_file.write_text("[bandit]\n", encoding="utf-8")
    scanner = _scanner(plugin_context, config_file)

    first = _scan_argv(scanner, plugin_context.source_dir)
    second = _scan_argv(scanner, plugin_context.work_dir, "converted")

    assert plugin_context.source_dir.as_posix() in first, first
    assert plugin_context.work_dir.as_posix() in second, second
    assert len(_after(first, "--ini")) == 1, first
    assert len(_after(second, "--ini")) == 1, second
    assert _after(first, "--configfile") == _after(second, "--configfile")

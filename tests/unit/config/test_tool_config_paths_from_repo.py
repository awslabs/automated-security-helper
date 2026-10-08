# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tool config and plugin file paths inside the scanned tree are not passed on.

Each test plants an empty file in a tmp source tree and points a scanner option at
it, or puts it where the scanner looks for one by name. The assertion is that its
path does not appear in what ASH hands the tool, and that a file outside the tree
named the operator's way does. See config/path_trust.py.
"""

from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.path_trust import reset_path_refusal_warnings
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.utils.uv_tool_runner import UVToolRunner


@pytest.fixture(autouse=True)
def _fresh_warnings():
    reset_path_refusal_warnings()
    yield
    reset_path_refusal_warnings()


@pytest.fixture(autouse=True)
def _no_uv_probe():
    with patch.object(UVToolRunner, "is_uv_available", return_value=False):
        yield


def _tree(tmp_path: Path, config: str) -> Path:
    source = tmp_path / "repo"
    (source / ".ash").mkdir(parents=True)
    (source / ".ash" / ".ash.yaml").write_text(f"project_name: scanned\n{config}")
    (source / "app.py").write_text("x = 1\n")
    return source


def _context(source: Path, tmp_path: Path, config) -> PluginContext:
    output = tmp_path / "out"
    (output / ASH_WORK_DIR_NAME).mkdir(parents=True, exist_ok=True)
    return PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / ASH_WORK_DIR_NAME,
        config=config,
    )


def _outside(tmp_path: Path, name: str) -> Path:
    path = tmp_path / "operator" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("")
    return path


def _checkov_argv(source: Path, tmp_path: Path, **resolve):
    from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
        CheckovScanner,
    )

    config = resolve_config(source_dir=source, **resolve)
    scanner = CheckovScanner(
        config=config.get_plugin_config("scanner", "checkov"),
        context=_context(source, tmp_path, config),
    )
    return scanner._resolve_arguments(source, tmp_path / "results.sarif")


def test_checkov_config_file_option_inside_the_tree_is_not_passed(tmp_path):
    source = _tree(
        tmp_path,
        "scanners:\n  checkov:\n    options:\n      config_file: settings.yaml\n",
    )
    (source / "settings.yaml").write_text("")
    argv = _checkov_argv(source, tmp_path)
    assert "--config-file" not in argv
    assert not any((source / "settings.yaml").as_posix() in a for a in argv)


@pytest.mark.parametrize("name", [".checkov.yaml", ".ash/.checkov.yaml"])
def test_a_discovered_checkov_config_inside_the_tree_is_not_passed(tmp_path, name):
    source = _tree(tmp_path, "")
    (source / name).write_text("")
    argv = _checkov_argv(source, tmp_path)
    assert "--config-file" not in argv


def test_an_operator_checkov_config_outside_the_tree_is_passed(tmp_path):
    source = _tree(tmp_path, "")
    (source / ".checkov.yaml").write_text("")
    operator = _outside(tmp_path, "checkov.yaml")
    argv = _checkov_argv(
        source,
        tmp_path,
        config_overrides=[f"scanners.checkov.options.config_file={operator}"],
    )
    assert argv[argv.index("--config-file") + 1] == operator.resolve().as_posix()


def _ferret_config_file(source: Path, tmp_path: Path, options: dict):
    from automated_security_helper.plugin_modules.ash_ferret_plugins.ferret_scanner import (
        FerretScanScanner,
        FerretScannerConfig,
    )

    config = resolve_config(source_dir=source)
    scanner = FerretScanScanner(
        config=FerretScannerConfig(options=options),
        context=_context(source, tmp_path, config),
    )
    return scanner._find_config_file(scanner.config.options.config_file)


def test_ferret_config_file_option_inside_the_tree_is_not_passed(tmp_path):
    source = _tree(tmp_path, "")
    (source / "f.yaml").write_text("")
    found = _ferret_config_file(source, tmp_path, {"config_file": "f.yaml"})
    assert found is None or not found.resolve().is_relative_to(source.resolve())


def test_a_discovered_ferret_config_inside_the_tree_is_not_passed(tmp_path):
    source = _tree(tmp_path, "")
    (source / "ferret.yaml").write_text("")
    found = _ferret_config_file(source, tmp_path, {})
    assert found is None or not found.resolve().is_relative_to(source.resolve())


def test_an_operator_ferret_config_outside_the_tree_is_passed(tmp_path):
    source = _tree(tmp_path, "")
    operator = _outside(tmp_path, "ferret.yaml")
    found = _ferret_config_file(source, tmp_path, {"config_file": str(operator)})
    assert found == operator


def _detect_secrets_settings(source: Path, tmp_path: Path, scan_settings: dict):
    from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
        DetectSecretsScanner,
        DetectSecretsScannerConfig,
    )

    config = resolve_config(source_dir=source)
    scanner = DetectSecretsScanner(
        config=DetectSecretsScannerConfig(options={"scan_settings": scan_settings}),
        context=_context(source, tmp_path, config),
    )
    return scanner.config.options.scan_settings.model_dump()


def test_detect_secrets_plugin_and_filter_files_inside_the_tree_are_dropped(
    tmp_path,
):
    source = _tree(tmp_path, "")
    (source / "plugin.py").write_text("")
    (source / "filters.py").write_text("")
    settings = _detect_secrets_settings(
        source,
        tmp_path,
        {
            "plugins_used": [
                {"name": "AWSKeyDetector"},
                {"name": "StandIn", "path": f"file://{source / 'plugin.py'}"},
            ],
            "filters_used": [
                {"path": "detect_secrets.filters.heuristic.is_sequential_string"},
                {"path": f"file://{source / 'filters.py'}::check"},
            ],
        },
    )
    assert source.as_posix() not in repr(settings)
    assert {"name": "AWSKeyDetector"}.items() <= settings["plugins_used"][0].items()
    assert [f["path"] for f in settings["filters_used"]] == [
        "detect_secrets.filters.heuristic.is_sequential_string"
    ]


def test_detect_secrets_operator_files_outside_the_tree_are_kept(tmp_path):
    source = _tree(tmp_path, "")
    plugin = _outside(tmp_path, "plugin.py")
    settings = _detect_secrets_settings(
        source,
        tmp_path,
        {"plugins_used": [{"name": "StandIn", "path": f"file://{plugin}"}]},
    )
    assert f"file://{plugin}" in repr(settings)

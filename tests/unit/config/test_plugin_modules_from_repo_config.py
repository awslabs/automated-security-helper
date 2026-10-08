# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""ash_plugin_modules from a config file in the scanned tree name installed modules only.

Each test builds a tmp source tree that holds a stand-in package, ``standin_plugins``,
whose ``__init__`` only defines a constant, and puts the tree on ``sys.path`` the way
a ``python -m`` launch from inside it would. The in-tree config names the package.
The assertions are that the name is gone from the resolved config and that the
package is not in ``sys.modules`` after the loaders the scan engine calls have run.
See config/plugin_module_trust.py.
"""

import logging
import sys
from pathlib import Path
from typing import List

import pytest

from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.plugins.discovery import discover_plugins
from automated_security_helper.plugins.loader import load_additional_plugin_modules
from automated_security_helper.utils.log import ASH_LOGGER

STANDIN = "standin_plugins"
INSTALLED = "automated_security_helper.plugin_modules.ash_trivy_plugins"


@pytest.fixture
def ash_log():
    records: List[logging.LogRecord] = []

    class _Collect(logging.Handler):
        def emit(self, record):
            records.append(record)

    handler = _Collect(level=logging.DEBUG)
    previous_level = ASH_LOGGER.level
    ASH_LOGGER.addHandler(handler)
    ASH_LOGGER.setLevel(logging.DEBUG)
    try:
        yield records
    finally:
        ASH_LOGGER.removeHandler(handler)
        ASH_LOGGER.setLevel(previous_level)


@pytest.fixture(autouse=True)
def _forget_standin():
    yield
    for name in [n for n in sys.modules if n == STANDIN or n.startswith(STANDIN + ".")]:
        del sys.modules[name]


def _tree(tmp_path: Path, monkeypatch, modules: List[str]) -> Path:
    source = tmp_path / "repo"
    package = source / STANDIN
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("STANDIN_LOADED = True\n")
    (source / ".ash").mkdir()
    listed = "".join(f"  - {name}\n" for name in modules)
    (source / ".ash" / ".ash.yaml").write_text(
        f"project_name: scanned\nash_plugin_modules:\n{listed}"
    )
    monkeypatch.syspath_prepend(str(source))
    monkeypatch.chdir(source)
    return source


def _import_like_the_engine(config) -> None:
    modules = list(config.ash_plugin_modules)
    load_additional_plugin_modules(modules)
    discover_plugins(plugin_modules=modules)


def test_an_in_tree_module_named_by_an_in_tree_config_is_not_imported(
    tmp_path, monkeypatch, ash_log
):
    source = _tree(tmp_path, monkeypatch, [STANDIN])
    config = resolve_config(source_dir=source)
    assert STANDIN not in config.ash_plugin_modules
    _import_like_the_engine(config)
    assert STANDIN not in sys.modules
    warnings = [
        r.getMessage()
        for r in ash_log
        if r.levelno == logging.WARNING and "ash_plugin_modules" in r.getMessage()
    ]
    assert len(warnings) == 1
    assert STANDIN in warnings[0]


def test_a_submodule_of_an_in_tree_package_is_refused_without_importing_it(
    tmp_path, monkeypatch
):
    source = _tree(tmp_path, monkeypatch, [f"{STANDIN}.sub"])
    (source / STANDIN / "sub.py").write_text("SUB_LOADED = True\n")
    config = resolve_config(source_dir=source)
    assert config.ash_plugin_modules == []
    assert STANDIN not in sys.modules


def test_a_comma_joined_entry_is_checked_name_by_name(tmp_path, monkeypatch):
    source = _tree(tmp_path, monkeypatch, [f"{INSTALLED},{STANDIN}"])
    config = resolve_config(source_dir=source)
    assert config.ash_plugin_modules == [INSTALLED]


def test_a_module_that_is_not_importable_is_refused(tmp_path, monkeypatch):
    source = _tree(tmp_path, monkeypatch, ["no_such_module_anywhere"])
    assert resolve_config(source_dir=source).ash_plugin_modules == []


def test_an_installed_module_named_by_an_in_tree_config_is_kept(tmp_path, monkeypatch):
    source = _tree(tmp_path, monkeypatch, [INSTALLED])
    config = resolve_config(source_dir=source)
    assert config.ash_plugin_modules == [INSTALLED]


def test_ash_community_plugins_config_keeps_its_modules(tmp_path, monkeypatch):
    repo_config = (
        Path(__file__).resolve().parents[3] / ".ash" / ".ash_community_plugins.yaml"
    )
    source = tmp_path / "repo"
    (source / ".ash").mkdir(parents=True)
    copied = source / ".ash" / ".ash_community_plugins.yaml"
    copied.write_text(repo_config.read_text())
    expected = resolve_config(config_path=repo_config, source_dir=tmp_path / "x")
    config = resolve_config(config_path=copied, source_dir=source)
    assert config.ash_plugin_modules == expected.ash_plugin_modules
    assert config.ash_plugin_modules


def test_an_operator_override_naming_the_module_is_honored(tmp_path, monkeypatch):
    source = _tree(tmp_path, monkeypatch, [STANDIN])
    config = resolve_config(
        source_dir=source,
        config_overrides=[f'ash_plugin_modules+=["{STANDIN}"]'],
    )
    assert STANDIN in config.ash_plugin_modules


def test_a_config_outside_the_tree_naming_the_module_is_honored(tmp_path, monkeypatch):
    source = _tree(tmp_path, monkeypatch, [])
    outside = tmp_path / "operator.yaml"
    outside.write_text(f"project_name: op\nash_plugin_modules:\n  - {STANDIN}\n")
    config = resolve_config(config_path=outside, source_dir=source)
    assert config.ash_plugin_modules == [STANDIN]


def test_a_workspace_project_cannot_add_a_module_from_elsewhere_in_the_workspace(
    tmp_path, monkeypatch
):
    import json

    from automated_security_helper.workspace.resolver import resolve_workspace

    workspace = tmp_path / "ws"
    project = workspace / "app"
    (project / ".ash").mkdir(parents=True)
    (project / ".ash" / ".ash.yaml").write_text(
        f"project_name: app\nash_plugin_modules:\n  - {STANDIN}\n"
    )
    shared = workspace / "shared"
    (shared / STANDIN).mkdir(parents=True)
    (shared / STANDIN / "__init__.py").write_text("STANDIN_LOADED = True\n")
    monkeypatch.syspath_prepend(str(shared))
    definition = workspace / "dev.code-workspace"
    definition.write_text(json.dumps({"folders": [{"path": "app"}]}))

    plan = resolve_workspace(definition)

    assert [p.ash_plugin_modules for p in plan.projects] == [[]]
    assert STANDIN not in sys.modules

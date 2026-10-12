# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Which release of a scanner's tool runs is the operator's choice.

``tool_version`` decides which release uv installs and which one already on PATH
is accepted. A config file inside the scanned tree, or one an MCP client
delivered, does not set it: the value comes from the defaults, a config file
outside the tree, or ``--config-overrides`` (``config/tool_config_trust.py``,
``confine_tool_versions``). A repository config that repeats the operator's value
is kept as it is.

Each plugin that reads ``tool_version`` is checked through the method that hands
the constraint to the install and the PATH check (``_get_tool_version_constraint``),
on the two routes a repository config reaches a scan by: a scan of the repository
(``resolve_config`` with the source directory), and a workspace project (the
operator's ``--config`` layered over the project's own config).
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Callable, Dict, List, NamedTuple, Optional
from unittest.mock import patch

import pytest
import yaml

from automated_security_helper.base.options import (
    reset_refused_tool_version_warnings,
)
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.plugin_modules.ash_builtin.converters.jupyter_converter import (
    JupyterConverter,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner import (
    BanditScanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.cfn_lint_scanner import (
    CfnLintScanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
    CheckovScanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.semgrep_scanner import (
    SemgrepScanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.zizmor_scanner import (
    ZizmorScanner,
)
from automated_security_helper.plugin_modules.ash_ferret_plugins.ferret_scanner import (
    FerretScanScanner,
)
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.uv_tool_runner import UVToolRunner
from automated_security_helper.workspace.resolver import resolve_workspace


class Plugin(NamedTuple):
    kind: str
    section: str
    name: str
    factory: Callable[..., Any]
    pin: str

    @property
    def key(self) -> str:
        return f"{self.section}.{self.name}.options.tool_version"


PLUGINS = [
    Plugin("scanner", "scanners", "bandit", BanditScanner, "==1.7.9"),
    Plugin("scanner", "scanners", "checkov", CheckovScanner, "==3.2.100"),
    Plugin("scanner", "scanners", "semgrep", SemgrepScanner, "==1.125.0"),
    Plugin("converter", "converters", "jupyter", JupyterConverter, "==7.16.1"),
    Plugin("scanner", "scanners", "ferret-scan", FerretScanScanner, "==1.0.1"),
    Plugin("scanner", "scanners", "cfn-lint", CfnLintScanner, "==1.43.3"),
    Plugin("scanner", "scanners", "zizmor", ZizmorScanner, "==1.29.0"),
]


@pytest.fixture(autouse=True)
def _no_operator_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.delenv("ASH_MCP_WORKSPACE_ROOT", raising=False)


@pytest.fixture(autouse=True)
def _no_uv_probe():
    with patch.object(UVToolRunner, "is_uv_available", return_value=False):
        yield


@pytest.fixture(autouse=True)
def _fresh_warnings():
    reset_refused_tool_version_warnings()
    yield
    reset_refused_tool_version_warnings()


@pytest.fixture
def ash_log():
    """ASH_LOGGER's records; it does not propagate, so caplog would see nothing."""
    records: List[logging.LogRecord] = []

    class _Collect(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
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


def _warnings_naming(records: List[logging.LogRecord], key: str) -> List[str]:
    return [
        r.getMessage()
        for r in records
        if r.levelno == logging.WARNING and key in r.getMessage()
    ]


def _write(path: Path, document: Dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    return path


def _section(plugin: Plugin, pin: Optional[str]) -> Dict[str, Any]:
    options = {} if pin is None else {"tool_version": pin}
    return {plugin.section: {plugin.name: {"options": options}}}


def _repo(tmp_path: Path, plugin: Plugin, pin: Optional[str]) -> Path:
    """A checkout whose own .ash/.ash.yaml sets the plugin's ``tool_version``."""
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    _write(repo / ".ash" / ".ash.yaml", _section(plugin, pin))
    return repo


def _operator(tmp_path: Path, plugin: Plugin, pin: Optional[str]) -> Path:
    """The operator's config file, outside the scanned tree."""
    return _write(tmp_path / "operator" / "ash.yaml", _section(plugin, pin))


def _constraint(plugin: Plugin, config: AshConfig, source: Path, tmp_path: Path):
    """What the plugin hands the install and the PATH check."""
    output = tmp_path / "out"
    (output / ASH_WORK_DIR_NAME).mkdir(parents=True, exist_ok=True)
    instance = plugin.factory(
        config=config.get_plugin_config(plugin.kind, plugin.name),
        context=PluginContext(
            source_dir=source,
            output_dir=output,
            work_dir=output / ASH_WORK_DIR_NAME,
            config=config,
        ),
    )
    return instance._get_tool_version_constraint()


def _default(plugin: Plugin, tmp_path: Path) -> Optional[str]:
    """The constraint the plugin uses when nobody sets ``tool_version``."""
    empty = tmp_path / "empty"
    empty.mkdir(exist_ok=True)
    return _constraint(plugin, AshConfig(), empty, tmp_path)


@pytest.mark.parametrize("plugin", PLUGINS, ids=lambda p: p.name)
def test_a_repository_config_does_not_choose_the_tool_version(
    plugin: Plugin, tmp_path: Path, ash_log
) -> None:
    repo = _repo(tmp_path, plugin, plugin.pin)

    config = resolve_config(source_dir=repo)

    assert _constraint(plugin, config, repo, tmp_path) == _default(plugin, tmp_path)
    assert _default(plugin, tmp_path) != plugin.pin
    assert _warnings_naming(ash_log, plugin.key)


@pytest.mark.parametrize("plugin", PLUGINS, ids=lambda p: p.name)
def test_a_repository_config_repeating_the_operators_override_is_kept(
    plugin: Plugin, tmp_path: Path, ash_log
) -> None:
    repo = _repo(tmp_path, plugin, plugin.pin)

    config = resolve_config(
        source_dir=repo, config_overrides=[f"{plugin.key}={plugin.pin}"]
    )

    assert _constraint(plugin, config, repo, tmp_path) == plugin.pin
    assert not _warnings_naming(ash_log, plugin.key)


@pytest.mark.parametrize("plugin", PLUGINS, ids=lambda p: p.name)
def test_an_operator_config_outside_the_tree_chooses_the_tool_version(
    plugin: Plugin, tmp_path: Path
) -> None:
    repo = _repo(tmp_path, plugin, None)
    operator = _operator(tmp_path, plugin, plugin.pin)

    config = resolve_config(config_path=operator, source_dir=repo)

    assert _constraint(plugin, config, repo, tmp_path) == plugin.pin


@pytest.mark.parametrize("plugin", PLUGINS, ids=lambda p: p.name)
def test_a_workspace_projects_config_does_not_choose_the_tool_version(
    plugin: Plugin, tmp_path: Path, ash_log
) -> None:
    repo = _repo(tmp_path, plugin, plugin.pin)
    operator = _operator(tmp_path, plugin, None)

    config = resolve_config(
        config_path=repo / ".ash" / ".ash.yaml",
        source_dir=repo,
        trusted_config_path=operator,
        overlay_config_path=operator,
    )

    assert _constraint(plugin, config, repo, tmp_path) == _default(plugin, tmp_path)
    assert _warnings_naming(ash_log, plugin.key)


@pytest.mark.parametrize("plugin", PLUGINS, ids=lambda p: p.name)
def test_a_workspace_project_repeating_the_operators_value_is_kept(
    plugin: Plugin, tmp_path: Path, ash_log
) -> None:
    repo = _repo(tmp_path, plugin, plugin.pin)
    operator = _operator(tmp_path, plugin, plugin.pin)

    config = resolve_config(
        config_path=repo / ".ash" / ".ash.yaml",
        source_dir=repo,
        trusted_config_path=operator,
        overlay_config_path=operator,
    )

    assert _constraint(plugin, config, repo, tmp_path) == plugin.pin
    assert not _warnings_naming(ash_log, plugin.key)


def test_a_workspace_names_the_project_and_the_key_it_ignored(
    tmp_path: Path, ash_log
) -> None:
    """Through resolve_workspace: the warning names the project's own config file."""
    for key, pin in (("api", "==1.125.0"), ("web", ">=1.130.0")):
        _write(
            tmp_path / key / ".ash" / "ash.yaml",
            {"scanners": {"semgrep": {"options": {"tool_version": pin}}}},
        )
    workspace = tmp_path / "dev.code-workspace"
    workspace.write_text(
        json.dumps({"folders": [{"path": "api"}, {"path": "web"}]}), encoding="utf-8"
    )

    plan = resolve_workspace(workspace)

    assert all("semgrep" not in project.scanner_pins for project in plan.projects)
    for key in ("api", "web"):
        named = [
            message
            for message in _warnings_naming(
                ash_log, "scanners.semgrep.options.tool_version"
            )
            if f"/{key}/.ash/ash.yaml" in message
        ]
        assert named, f"no warning names project {key}'s config"


def test_the_repositorys_other_options_still_apply(tmp_path: Path) -> None:
    """Only tool_version is replaced; the rest of the section is the repository's."""
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    _write(
        repo / ".ash" / ".ash.yaml",
        {
            "scanners": {
                "bandit": {
                    "options": {"tool_version": "==1.7.9", "confidence_level": "high"}
                }
            }
        },
    )

    config = resolve_config(source_dir=repo)

    options = config.scanners.bandit.options
    assert options.confidence_level == "high"
    assert options.tool_version == type(options).model_fields["tool_version"].default

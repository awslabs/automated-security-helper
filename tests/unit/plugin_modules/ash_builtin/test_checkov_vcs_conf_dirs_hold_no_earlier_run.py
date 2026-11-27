# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""checkov's VCS configuration frameworks never check settings an earlier run fetched.

checkov's GitLab and Bitbucket frameworks check the files their conf directory
holds, and write one only when a fetch of the repository host's settings returns
data. An offline scan turns that fetch off, so on an output directory an earlier
online run had filled, the framework reported that run's settings as this scan's,
and on a fresh one it reported nothing. Neither was logged. ASH now empties the conf
directories it names before each run, leaves a directory the operator named as it
is, and warns in an offline scan for each VCS configuration framework that runs.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.plugin_modules.ash_builtin.scanners import (
    checkov_scanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
    _CHECKOV_VCS_CONF_DIR_ENV,
    _VCS_CONFIG_FETCH_ENV_VARS,
    _VCS_CONFIGURATION_FRAMEWORKS,
    CheckovScanner,
    CheckovScannerConfig,
    CheckovScannerConfigOptions,
)

pytestmark = pytest.mark.unit

PluginContext.model_rebuild()

#: The per-framework variable and directory name checkov's naming rule gives.
_CONF_DIR = {
    "bitbucket_configuration": ("CKV_BITBUCKET_CONF_DIR_NAME", "bitbucket_conf"),
    "github_configuration": ("CKV_GITHUB_CONF_DIR_NAME", "github_conf"),
    "gitlab_configuration": ("CKV_GITLAB_CONF_DIR_NAME", "gitlab_conf"),
}

#: The words each offline warning of a framework that runs starts with.
_RUNS_OFFLINE = "framework runs in this offline scan"


@pytest.fixture(autouse=True)
def _no_operator_values(monkeypatch):
    for variable in (*_CHECKOV_VCS_CONF_DIR_ENV, *_VCS_CONFIG_FETCH_ENV_VARS):
        monkeypatch.delenv(variable, raising=False)


def _scanner(tmp_path: Path, **opts) -> CheckovScanner:
    source = tmp_path / "src"
    source.mkdir(exist_ok=True)
    output = tmp_path / "out"
    context = PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "converted",
        config=AshConfig(),
    )
    return CheckovScanner(
        context=context,
        config=CheckovScannerConfig(options=CheckovScannerConfigOptions(**opts)),
    )


def _ash_conf_dir(scanner: CheckovScanner, framework: str) -> Path:
    """The conf directory ASH names for ``framework`` on the source target."""
    results_dir = Path(os.path.abspath(scanner.results_dir.joinpath("source")))
    return results_dir / "vcs-config" / _CONF_DIR[framework][1]


def _plant_earlier_fetch(conf_dir: Path) -> Path:
    """A settings file as checkov writes one when a fetch returns data."""
    fetched = conf_dir / "project_approvals.json"
    fetched.parent.mkdir(parents=True, exist_ok=True)
    fetched.write_text('{"approvals_before_merge": 0}', encoding="utf-8")
    return fetched


def _execute(scanner: CheckovScanner, *, offline: bool) -> dict:
    with patch.object(CheckovScanner, "_scanner_offline", return_value=offline):
        _, _, env = scanner._execute_scan(scanner.context.source_dir, "source", [])
    assert env is not None
    return env


def _warnings(caplog) -> list[str]:
    return [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]


def _symlink_or_skip(link: Path, target: Path) -> None:
    link.parent.mkdir(parents=True, exist_ok=True)
    try:
        link.symlink_to(target, target_is_directory=True)
    except (OSError, NotImplementedError) as exc:  # pragma: no cover - Windows
        pytest.skip(f"symlink creation unavailable: {exc}")


@pytest.mark.parametrize("vcs_fw", _VCS_CONFIGURATION_FRAMEWORKS)
def test_an_offline_scan_checks_nothing_an_earlier_run_fetched(
    tmp_path, caplog, vcs_fw
):
    scanner = _scanner(tmp_path, frameworks=["all", vcs_fw], offline=True)
    conf_dir = _ash_conf_dir(scanner, vcs_fw)
    fetched = _plant_earlier_fetch(conf_dir)

    with caplog.at_level(logging.WARNING, logger="ash"):
        env = _execute(scanner, offline=True)

    variable = _CONF_DIR[vcs_fw][0]
    assert Path(env[variable]) == conf_dir
    assert not fetched.exists()
    assert not conf_dir.exists()
    said = [m for m in _warnings(caplog) if _RUNS_OFFLINE in m]
    assert len(said) == 1
    assert said[0].startswith(f"checkov's {vcs_fw} {_RUNS_OFFLINE}")
    assert "reports nothing" in said[0]
    assert variable in said[0]


def test_an_online_scan_checks_no_file_an_earlier_run_fetched(tmp_path, caplog):
    # A fetch that returns nothing writes no file, so the earlier run's would be
    # checked as this scan's online too.
    scanner = _scanner(tmp_path, frameworks=["gitlab_configuration"])
    conf_dir = _ash_conf_dir(scanner, "gitlab_configuration")
    fetched = _plant_earlier_fetch(conf_dir)

    with caplog.at_level(logging.WARNING, logger="ash"):
        env = _execute(scanner, offline=False)

    assert Path(env["CKV_GITLAB_CONF_DIR_NAME"]) == conf_dir
    assert not fetched.exists()
    for fetch_var in _VCS_CONFIG_FETCH_ENV_VARS:
        assert fetch_var not in env
    assert not [m for m in _warnings(caplog) if _RUNS_OFFLINE in m]


def test_a_directory_the_operator_named_is_left_as_it_is(tmp_path, monkeypatch, caplog):
    operator_dir = tmp_path / "operator-conf"
    fetched = _plant_earlier_fetch(operator_dir)
    monkeypatch.setenv("CKV_GITLAB_CONF_DIR_NAME", str(operator_dir))
    scanner = _scanner(tmp_path, frameworks=["gitlab_configuration"], offline=True)

    with caplog.at_level(logging.WARNING, logger="ash"):
        env = _execute(scanner, offline=True)

    assert env["CKV_GITLAB_CONF_DIR_NAME"] == str(operator_dir)
    assert fetched.read_text(encoding="utf-8") == '{"approvals_before_merge": 0}'
    said = [m for m in _warnings(caplog) if _RUNS_OFFLINE in m]
    assert len(said) == 1
    assert said[0].startswith(f"checkov's gitlab_configuration {_RUNS_OFFLINE}")
    assert "the directory CKV_GITLAB_CONF_DIR_NAME names" in said[0]
    assert "older than this scan" in said[0]
    assert "reports nothing" not in said[0]


def test_a_framework_the_config_file_names_beside_all_is_warned_of(tmp_path, caplog):
    config_file = tmp_path / "operator" / ".checkov.yaml"
    config_file.parent.mkdir()
    config_file.write_text(
        "framework:\n  - all\n  - bitbucket_configuration\n", encoding="utf-8"
    )
    scanner = _scanner(tmp_path, config_file=str(config_file), offline=True)

    with caplog.at_level(logging.WARNING, logger="ash"):
        _execute(scanner, offline=True)

    said = [m for m in _warnings(caplog) if _RUNS_OFFLINE in m]
    assert len(said) == 1
    assert said[0].startswith(f"checkov's bitbucket_configuration {_RUNS_OFFLINE}")


@pytest.mark.parametrize(
    "opts",
    [
        pytest.param({}, id="default-all"),
        pytest.param({"frameworks": ["terraform"]}, id="no-vcs-framework"),
    ],
)
def test_an_offline_scan_running_no_vcs_framework_warns_of_none(tmp_path, caplog, opts):
    scanner = _scanner(tmp_path, offline=True, **opts)

    with caplog.at_level(logging.WARNING, logger="ash"):
        _execute(scanner, offline=True)

    assert not [m for m in _warnings(caplog) if _RUNS_OFFLINE in m]


def test_a_linked_vcs_config_is_removed_as_the_link(tmp_path):
    scanner = _scanner(tmp_path, frameworks=["gitlab_configuration"])
    elsewhere = tmp_path / "elsewhere"
    kept = _plant_earlier_fetch(elsewhere / "gitlab_conf")
    conf_root = _ash_conf_dir(scanner, "gitlab_configuration").parent
    _symlink_or_skip(conf_root, elsewhere)

    _execute(scanner, offline=False)

    assert not conf_root.is_symlink()
    assert not conf_root.exists()
    assert kept.read_text(encoding="utf-8") == '{"approvals_before_merge": 0}'


def test_a_linked_conf_directory_is_removed_as_the_link(tmp_path):
    scanner = _scanner(tmp_path, frameworks=["gitlab_configuration"])
    elsewhere = tmp_path / "elsewhere"
    kept = _plant_earlier_fetch(elsewhere)
    conf_dir = _ash_conf_dir(scanner, "gitlab_configuration")
    _symlink_or_skip(conf_dir, elsewhere)

    _execute(scanner, offline=False)

    assert not conf_dir.is_symlink()
    assert not conf_dir.exists()
    assert kept.read_text(encoding="utf-8") == '{"approvals_before_merge": 0}'


def test_a_conf_directory_that_cannot_be_removed_is_warned_of(
    tmp_path, monkeypatch, caplog
):
    scanner = _scanner(tmp_path, frameworks=["gitlab_configuration"])
    fetched = _plant_earlier_fetch(_ash_conf_dir(scanner, "gitlab_configuration"))

    def refuse(path, *args, **kwargs):
        raise PermissionError(13, "Permission denied", str(path))

    # The module's own reference only: nothing else in the process loses rmtree.
    # raising=False so the test reads a scanner that never removes anything as a
    # missing warning, not as a missing attribute.
    monkeypatch.setattr(
        checkov_scanner, "shutil", SimpleNamespace(rmtree=refuse), raising=False
    )
    with caplog.at_level(logging.WARNING, logger="ash"):
        _execute(scanner, offline=False)

    assert fetched.exists()
    said = [m for m in _warnings(caplog) if "Could not remove" in m]
    assert len(said) == 1
    assert "earlier checkov run" in said[0]
    assert "Permission denied" in said[0]

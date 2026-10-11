# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Which part of its config ferret-scan loads comes from the operator.

``scanners.ferret-scan.options.profile`` selects a profile from the config ASH
passes ferret-scan, and ``use_default_config: false`` swaps the bundled config for
an empty one. Both change what is reported: run on the same files with ferret-scan
2.5.3, the bundled profiles reported from 111 findings down to none, and the empty
config left out findings the bundled config's validators report. A config file
inside the scanned tree therefore does not set either one; the defaults, a config
file outside the tree, or ``--config-overrides`` do (config/tool_config_trust.py).
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import patch

import pytest
import yaml

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.plugin_modules.ash_ferret_plugins.ferret_scanner import (
    DEFAULT_FERRET_CONFIG,
    FerretScanScanner,
)
from automated_security_helper.utils.uv_tool_runner import UVToolRunner


@pytest.fixture(autouse=True)
def _no_operator_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.delenv("ASH_MCP_WORKSPACE_ROOT", raising=False)


@pytest.fixture(autouse=True)
def _no_uv_probe():
    with patch.object(UVToolRunner, "is_uv_available", return_value=False):
        yield


def _repo(tmp_path: Path, options: Dict[str, Any]) -> Path:
    """A checkout whose own .ash/.ash.yaml sets ferret-scan's ``options``."""
    repo = tmp_path / "repo"
    (repo / ".ash").mkdir(parents=True)
    (repo / ".git").mkdir()
    (repo / ".ash" / ".ash.yaml").write_text(
        yaml.safe_dump({"scanners": {"ferret-scan": {"options": options}}}),
        encoding="utf-8",
    )
    (repo / "notes.txt").write_text("nothing here\n", encoding="utf-8")
    return repo


def _argv(repo: Path, tmp_path: Path, **resolve: Any) -> List[str]:
    config = resolve_config(source_dir=repo, **resolve)
    output = tmp_path / "out"
    (output / ASH_WORK_DIR_NAME).mkdir(parents=True, exist_ok=True)
    scanner = FerretScanScanner(
        config=config.get_plugin_config("scanner", "ferret-scan"),
        context=PluginContext(
            source_dir=repo,
            output_dir=output,
            work_dir=output / ASH_WORK_DIR_NAME,
            config=config,
        ),
    )
    return scanner._resolve_arguments(repo, tmp_path / "results.sarif")


def _value_after(argv: List[str], flag: str) -> Any:
    return argv[argv.index(flag) + 1] if flag in argv else None


def test_a_repositorys_config_does_not_choose_the_profile(tmp_path: Path) -> None:
    repo = _repo(tmp_path, {"profile": "quick"})
    assert "--profile" not in _argv(repo, tmp_path)


def test_a_repositorys_config_does_not_drop_the_bundled_config(tmp_path: Path) -> None:
    repo = _repo(tmp_path, {"use_default_config": False})
    argv = _argv(repo, tmp_path)
    assert Path(_value_after(argv, "--config")) == DEFAULT_FERRET_CONFIG


def test_the_warning_names_what_was_ignored(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    repo = _repo(tmp_path, {"profile": "quick", "use_default_config": False})
    with caplog.at_level(logging.WARNING):
        resolve_config(source_dir=repo)
    warnings = " ".join(r.getMessage() for r in caplog.records)
    assert "scanners.ferret-scan.options.profile" in warnings
    assert "scanners.ferret-scan.options.use_default_config" in warnings


def test_a_repository_value_equal_to_the_default_is_not_reported(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    repo = _repo(tmp_path, {"use_default_config": True, "profile": None})
    with caplog.at_level(logging.WARNING):
        argv = _argv(repo, tmp_path)
    assert Path(_value_after(argv, "--config")) == DEFAULT_FERRET_CONFIG
    assert not any(
        "scanners.ferret-scan.options" in r.getMessage() for r in caplog.records
    )


def test_an_override_chooses_the_profile(tmp_path: Path) -> None:
    repo = _repo(tmp_path, {"profile": "quick"})
    argv = _argv(
        repo,
        tmp_path,
        config_overrides=["scanners.ferret-scan.options.profile=security-audit"],
    )
    assert _value_after(argv, "--profile") == "security-audit"


def test_an_override_drops_the_bundled_config(tmp_path: Path) -> None:
    repo = _repo(tmp_path, {})
    argv = _argv(
        repo,
        tmp_path,
        config_overrides=["scanners.ferret-scan.options.use_default_config=false"],
    )
    passed = Path(_value_after(argv, "--config"))
    assert passed != DEFAULT_FERRET_CONFIG
    assert yaml.safe_load(passed.read_text(encoding="utf-8")) == {}


def test_an_operator_config_outside_the_tree_chooses_the_profile(
    tmp_path: Path,
) -> None:
    repo = _repo(tmp_path, {"profile": "quick"})
    operator = tmp_path / "operator" / "ash.yaml"
    operator.parent.mkdir()
    operator.write_text(
        yaml.safe_dump(
            {"scanners": {"ferret-scan": {"options": {"profile": "thorough"}}}}
        ),
        encoding="utf-8",
    )
    argv = _argv(repo, tmp_path, config_path=operator)
    assert _value_after(argv, "--profile") == "thorough"


def test_the_repositorys_other_ferret_options_still_apply(tmp_path: Path) -> None:
    """Only the options that choose ferret-scan's config are the operator's."""
    repo = _repo(tmp_path, {"profile": "quick", "checks": "SECRETS"})
    argv = _argv(repo, tmp_path)
    assert _value_after(argv, "--checks") == "SECRETS"

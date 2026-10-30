# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A ``UV_PYTHON`` inside the scanned tree is ignored with one warning per plugin.

``_run_subprocess`` drops a ``UV_PYTHON`` that names an interpreter inside the
scanned tree before the child starts. That was said at debug level, where an
operator whose variable was not honored never saw it. It is now a warning, said
once for a plugin and not once for each tool run, and it does not show the value.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.log import ASH_LOGGER

pytestmark = pytest.mark.unit

PluginContext.model_rebuild()
AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()

SAID = "Ignoring a UV_PYTHON"


class _Config(ScannerPluginConfigBase):
    name: str = "uv-warning"


class _Scanner(ScannerPluginBase):
    def validate_plugin_dependencies(self) -> bool:
        return True

    def _execute_scan(self, target, target_type, global_ignore_paths):
        raise NotImplementedError("the runner is all this test calls")


def _scanner(tmp_path: Path, name: str) -> Tuple[_Scanner, Path]:
    source = tmp_path / name / "source"
    source.mkdir(parents=True)
    output = tmp_path / name / "output"
    output.mkdir()
    context = PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=tmp_path / name / "work",
        config=AshConfig(project_name="uv-warning"),
    )
    return _Scanner(config=_Config(), context=context), source


def _run(scanner: _Scanner, results: Path, env: Optional[Dict[str, str]]) -> None:
    def run(*args: Any, **kwargs: Any) -> Dict[str, Any]:
        return {"returncode": 0, "stdout": "", "stderr": ""}

    with patch.object(subprocess_utils, "run_command_with_output_handling", run):
        scanner._run_subprocess(
            command=["uv", "pip", "list"], results_dir=results, env=env
        )


@pytest.fixture
def logged():
    records: List[Tuple[int, str]] = []

    class _Collect(logging.Handler):
        def emit(self, record):
            records.append(
                (record.levelno, logging.Formatter("%(message)s").format(record))
            )

    handler = _Collect(level=logging.DEBUG)
    level = ASH_LOGGER.level
    ASH_LOGGER.setLevel(logging.DEBUG)
    ASH_LOGGER.addHandler(handler)
    try:
        yield records
    finally:
        ASH_LOGGER.removeHandler(handler)
        ASH_LOGGER.setLevel(level)


def _said(records: List[Tuple[int, str]]) -> List[Tuple[int, str]]:
    return [(level, text) for level, text in records if SAID in text]


def test_the_ignored_variable_is_a_warning_said_once_for_two_runs(tmp_path, logged):
    scanner, source = _scanner(tmp_path, "one")
    inside = {"PATH": "/usr/bin", "UV_PYTHON": str(source / ".venv" / "bin" / "python")}

    _run(scanner, tmp_path / "results-a", dict(inside))
    _run(scanner, tmp_path / "results-b", dict(inside))

    said = _said(logged)
    assert len(said) == 1, logged
    assert said[0][0] == logging.WARNING, said


def test_the_warning_does_not_show_the_value(tmp_path, logged):
    scanner, source = _scanner(tmp_path, "one")
    value = str(source / ".venv" / "bin" / "python")

    _run(scanner, tmp_path / "results", {"PATH": "/usr/bin", "UV_PYTHON": value})

    said = _said(logged)
    assert len(said) == 1, logged
    assert value not in said[0][1], said
    assert ".venv" not in said[0][1], said


def test_another_plugin_says_it_again(tmp_path, logged):
    first, first_source = _scanner(tmp_path, "one")
    second, second_source = _scanner(tmp_path, "two")

    _run(
        first,
        tmp_path / "results-a",
        {"UV_PYTHON": str(first_source / ".venv" / "bin" / "python")},
    )
    _run(
        second,
        tmp_path / "results-b",
        {"UV_PYTHON": str(second_source / ".venv" / "bin" / "python")},
    )

    assert len(_said(logged)) == 2, logged


def test_a_variable_outside_the_tree_is_kept_and_nothing_is_said(tmp_path, logged):
    scanner, _ = _scanner(tmp_path, "one")
    elsewhere = str(tmp_path / "elsewhere" / "bin" / "python")

    _run(scanner, tmp_path / "results", {"PATH": "/usr/bin", "UV_PYTHON": elsewhere})

    assert _said(logged) == [], logged

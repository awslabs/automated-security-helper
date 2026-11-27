# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A ``UV_PYTHON`` inside the scanned tree is ignored with one warning in a process.

``_run_subprocess`` drops a ``UV_PYTHON`` that names an interpreter inside the
scanned tree before the child starts. It says so at warning level, without the
value, in the warning the uv runner names each variable it does not pass to uv in
(``uv_tool_runner._warn_of_a_variable_left_out``). That warning is said once in a
process for each variable and reason, so two runs, two plugins, and a run followed
by a judgment of the same value on another route say it once between them. What
was said is forgotten by ``_reset_uv_tool_runner_caches``, which each test here
calls before and after it runs.
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
from automated_security_helper.utils import subprocess_utils, uv_tool_runner
from automated_security_helper.utils.log import ASH_LOGGER

pytestmark = pytest.mark.unit

PluginContext.model_rebuild()
AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()

# How the uv runner's warning for a variable it does not pass to uv starts, for
# this variable; the reason follows it.
SAID = "UV_PYTHON is not passed to uv"


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


@pytest.fixture(autouse=True)
def forget_what_was_said():
    """The uv variables already warned of are remembered for the process, so each
    test starts and ends with none remembered."""
    uv_tool_runner._reset_uv_tool_runner_caches()
    yield
    uv_tool_runner._reset_uv_tool_runner_caches()


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


def test_two_plugins_give_one_warning_between_them(tmp_path, logged):
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

    # Each value is a path inside its plugin's tree: one reason, said once.
    assert len(_said(logged)) == 1, logged


def test_a_run_and_a_later_judgment_of_the_same_value_name_it_in_one_line(
    tmp_path, logged
):
    scanner, source = _scanner(tmp_path, "one")
    value = str(source / ".venv" / "bin" / "python")

    _run(scanner, tmp_path / "results", {"PATH": "/usr/bin", "UV_PYTHON": value})
    left = uv_tool_runner.without_tree_uv_files({"UV_PYTHON": value}, (source,))

    # The uv runner's filter leaves the same value out too, for the same reason (a
    # path inside the tree), and says nothing more: one line names it in all.
    names = set(left)
    assert "UV_PYTHON" not in names, names
    naming = [text for _, text in logged if "UV_PYTHON" in text]
    assert len(naming) == 1, naming
    # Control: the filter passes on a value outside the tree.
    kept = {"UV_PYTHON": str(tmp_path / "elsewhere" / "bin" / "python")}
    assert uv_tool_runner.without_tree_uv_files(dict(kept), (source,)) == kept


def test_a_variable_outside_the_tree_is_kept_and_nothing_is_said(tmp_path, logged):
    scanner, _ = _scanner(tmp_path, "one")
    elsewhere = str(tmp_path / "elsewhere" / "bin" / "python")

    _run(scanner, tmp_path / "results", {"PATH": "/usr/bin", "UV_PYTHON": elsewhere})

    assert _said(logged) == [], logged

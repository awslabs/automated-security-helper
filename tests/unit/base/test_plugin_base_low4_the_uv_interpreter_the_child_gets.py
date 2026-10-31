# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The interpreter a uv command gets from ``_run_subprocess``.

A uv command started in the scanned tree runs the tree's own ``.venv`` python
unless it is given one, so ``_run_subprocess`` sets ``UV_PYTHON`` to ASH's
interpreter, unless the environment the child gets already names one. Two edges:

- The decision is read from the child's environment, not from ASH's own: a
  caller's ``env`` without ``UV_PYTHON`` gets ASH's interpreter even when the
  operator set one for ASH, so the child is never left with none.
- A ``UV_PYTHON`` in the child's environment that names an interpreter inside the
  scanned tree is not taken as a choice: an ``env`` a scanner assembled is not
  known to be the operator's alone, and the tree's python is what the override
  exists to keep uv from finding.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_base import _uv_interpreter_inside
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.utils import subprocess_utils

pytestmark = pytest.mark.unit

PluginContext.model_rebuild()
AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()

UV_COMMAND = ["uv", "pip", "list"]


class _Config(ScannerPluginConfigBase):
    name: str = "uv-interpreter"


class _Scanner(ScannerPluginBase):
    def validate_plugin_dependencies(self) -> bool:
        return True

    def _execute_scan(self, target, target_type, global_ignore_paths):
        raise NotImplementedError("the runner is all this test calls")


@pytest.fixture
def source(tmp_path) -> Path:
    tree = tmp_path / "source"
    tree.mkdir()
    return tree


@pytest.fixture
def scanner(tmp_path, source) -> _Scanner:
    output = tmp_path / "output"
    output.mkdir()
    context = PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=tmp_path / "work",
        config=AshConfig(project_name="uv-interpreter"),
    )
    return _Scanner(config=_Config(), context=context)


def _child_env(
    scanner: _Scanner,
    results: Path,
    env: Optional[Dict[str, str]],
    cwd: Optional[Path] = None,
) -> Dict[str, Any]:
    """The environment the runner hands the child of a ``uv pip list`` run."""
    seen: List[Dict[str, Any]] = []

    def run(*args: Any, **kwargs: Any) -> Dict[str, Any]:
        seen.append(kwargs.get("env"))
        return {"returncode": 0, "stdout": "", "stderr": ""}

    with patch.object(subprocess_utils, "run_command_with_output_handling", run):
        scanner._run_subprocess(
            command=list(UV_COMMAND), results_dir=results, env=env, cwd=cwd
        )
    assert seen, "the runner never started the child"
    return dict(seen[0] or {})


def test_a_caller_env_without_an_interpreter_gets_ashs_even_when_the_operator_set_one(
    scanner, tmp_path, monkeypatch
):
    monkeypatch.setenv("UV_PYTHON", str(tmp_path / "operator" / "python"))

    child = _child_env(scanner, tmp_path / "results", {"PATH": "/usr/bin"})

    assert child["UV_PYTHON"] == sys.executable
    assert child["UV_NO_PROJECT"] == "1"


def test_a_caller_env_naming_an_interpreter_outside_the_tree_keeps_it(
    scanner, tmp_path
):
    theirs = str(tmp_path / "elsewhere" / "bin" / "python")

    child = _child_env(
        scanner, tmp_path / "results", {"PATH": "/usr/bin", "UV_PYTHON": theirs}
    )

    assert child["UV_PYTHON"] == theirs


def test_a_version_request_is_a_choice_and_kept(scanner, tmp_path):
    child = _child_env(
        scanner, tmp_path / "results", {"PATH": "/usr/bin", "UV_PYTHON": "3.12"}
    )

    assert child["UV_PYTHON"] == "3.12"


def test_an_interpreter_inside_the_tree_given_relative_to_the_start_directory_is_dropped(
    scanner, tmp_path, source
):
    child = _child_env(
        scanner,
        tmp_path / "results",
        {"PATH": "/usr/bin", "UV_PYTHON": "./.venv/bin/python"},
        cwd=source,
    )

    assert child["UV_PYTHON"] == sys.executable


def test_an_interpreter_inside_the_tree_given_in_full_is_dropped(
    scanner, tmp_path, source
):
    inside = str(source / ".venv" / "bin" / "python")

    child = _child_env(
        scanner, tmp_path / "results", {"PATH": "/usr/bin", "UV_PYTHON": inside}
    )

    assert child["UV_PYTHON"] == sys.executable


def test_an_interpreter_inside_the_tree_reached_through_a_link_is_dropped(
    scanner, tmp_path, source
):
    link = tmp_path / "linked-source"
    try:
        link.symlink_to(source, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("this platform cannot make a symlink here")
    (source / ".venv" / "bin").mkdir(parents=True)

    child = _child_env(
        scanner,
        tmp_path / "results",
        {"PATH": "/usr/bin", "UV_PYTHON": str(link / ".venv" / "bin" / "python")},
    )

    assert child["UV_PYTHON"] == sys.executable


def test_the_operators_own_interpreter_inside_the_tree_is_not_taken_either(
    scanner, tmp_path, source, monkeypatch
):
    monkeypatch.setenv("UV_PYTHON", str(source / ".venv" / "bin" / "python"))

    child = _child_env(scanner, tmp_path / "results", None)

    assert child["UV_PYTHON"] == sys.executable


class TestTheInsideTest:
    def test_a_name_looked_up_on_path_is_not_inside(self, source):
        assert not _uv_interpreter_inside({"UV_PYTHON": "python3.12"}, source, source)

    def test_no_choice_is_not_inside(self, source):
        assert not _uv_interpreter_inside({"PATH": "/usr/bin"}, source, source)
        assert not _uv_interpreter_inside({"UV_PYTHON": ""}, source, source)

    def test_the_tree_itself_is_not_an_interpreter_inside_it(self, source):
        assert not _uv_interpreter_inside({"UV_PYTHON": str(source)}, source, source)

    def test_a_sibling_whose_name_starts_like_the_tree_is_not_inside(
        self, tmp_path, source
    ):
        sibling = tmp_path / "source-other" / "python"

        assert not _uv_interpreter_inside({"UV_PYTHON": str(sibling)}, source, source)

    def test_a_relative_path_is_read_from_the_start_directory(self, tmp_path, source):
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()

        assert _uv_interpreter_inside({"UV_PYTHON": ".venv/bin/python"}, source, source)
        assert not _uv_interpreter_inside(
            {"UV_PYTHON": ".venv/bin/python"}, elsewhere, source
        )
        assert _uv_interpreter_inside(
            {"UV_PYTHON": os.path.join("..", "source", "bin", "python")},
            elsewhere,
            source,
        )

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A plugin scanner's own ``uv`` command uses no ``.venv`` or project in the tree.

A scanner's commands go through ``PluginBase._run_subprocess``, which starts them in
the scanned tree. Run from there, ``uv pip list`` and ``uv run`` ran the tree's
``.venv`` python, and ``uv run`` built the tree's project, running its build backend
(measured with uv 0.12.22; see
tests/unit/cli/test_dependencies_uv_commands_discover_nothing_from_the_tree.py).
``_run_subprocess`` now gives a uv command the environment from
``utils.python_child.uv_child_overrides``. A scanner's working directory is part of
how it reads its target, so it is not changed.

The stub scanner here runs the command through the real ``_run_subprocess``. The
control runs it the same way with the overrides replaced by none, and finds the
plant used.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import ClassVar, List, Literal

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.core.enums import OfflineStrategy, ScannerToolType
from automated_security_helper.utils import python_child
from tests.utils.planted_uv import (
    PIP_LIST,
    RUN,
    clear_uv_environment,
    plant_project,
    plant_venv,
    uv_binary,
)

pytestmark = [
    pytest.mark.skipif(
        sys.platform == "win32", reason="the planted .venv python is a shell script"
    ),
    # The unit tests' tool guard (tests/unit/conftest.py) would record the uv these
    # run by its path; whether the real uv reads the planted tree is the subject.
    pytest.mark.runs_real_tools(
        reason="the real uv's discovery of a planted .venv or project is what "
        "these tests measure"
    ),
]


class UvStubConfig(ScannerPluginConfigBase):
    name: Literal["uv-stub"] = "uv-stub"


class UvStubScanner(ScannerPluginBase):
    """A plugin scanner whose command is uv, run through the shared helper."""

    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED

    def model_post_init(self, context):
        self.command = "uv"
        self.tool_type = ScannerToolType.SAST
        super().model_post_init(context)

    def validate_plugin_dependencies(self) -> bool:
        return True

    def _execute_scan(self, target, target_type, global_ignore_paths):
        raise NotImplementedError


def _scanner(repo: Path, tmp_path: Path) -> UvStubScanner:
    output = tmp_path / "output"
    (output / ASH_WORK_DIR_NAME).mkdir(parents=True)
    context = PluginContext(
        source_dir=repo,
        output_dir=output,
        work_dir=output / ASH_WORK_DIR_NAME,
        config=AshConfig(project_name="test"),
    )
    return UvStubScanner(config=UvStubConfig(), context=context)


def _run(scanner: UvStubScanner, args: List[str]) -> None:
    scanner._run_subprocess(
        [uv_binary(), *args],
        stdout_preference="return",
        stderr_preference="return",
        timeout=120,
    )


CASES = [
    pytest.param(PIP_LIST, plant_venv, "venv", id="uv-pip-list-venv"),
    pytest.param(RUN, plant_venv, "venv", id="uv-run-venv"),
    pytest.param(RUN, plant_project, "project", id="uv-run-project"),
]


@pytest.fixture
def repo(tmp_path, monkeypatch):
    clear_uv_environment(monkeypatch)
    # The real uv records the interpreter it ran in its cache; outside the test's
    # HOME, which the guard's HOME check reads after the test.
    monkeypatch.setenv("UV_CACHE_DIR", str(tmp_path / "uv-cache"))
    path = tmp_path / "repo"
    path.mkdir()
    return path


@pytest.mark.parametrize(("args", "plant", "mark"), CASES)
@pytest.mark.integration
def test_control_without_the_overrides_the_scanners_uv_uses_the_plant(
    repo, tmp_path, monkeypatch, args, plant, mark
):
    marker = tmp_path / "MARKER"
    plant(repo, marker)
    # The stub takes the real function's arguments: _run_subprocess hands it the
    # command and the child's environment, and a one-argument stub raised a
    # TypeError that the helper recorded as a failed run, so no uv ever started
    # and the control measured nothing.
    monkeypatch.setattr(python_child, "uv_child_overrides", lambda argv, env=None: {})
    _run(_scanner(repo, tmp_path), args)
    assert mark in marker.read_text(encoding="utf-8")


@pytest.mark.parametrize(("args", "plant", "mark"), CASES)
@pytest.mark.integration
def test_a_scanners_uv_command_uses_no_venv_or_project_from_the_tree(
    repo, tmp_path, args, plant, mark
):
    marker = tmp_path / "MARKER"
    plant(repo, marker)
    _run(_scanner(repo, tmp_path), args)
    assert not marker.exists(), marker.read_text(encoding="utf-8")


@pytest.mark.unit
def test_the_overrides_reach_the_spawn_and_keep_the_scanners_own_env(
    repo, tmp_path, monkeypatch
):
    seen = {}

    def record(command, cwd=None, env=None, **_kwargs):
        seen.update(command=list(command), cwd=cwd, env=env)
        return {"returncode": 0, "stdout": "", "stderr": ""}

    from automated_security_helper.utils import subprocess_utils

    monkeypatch.setattr(subprocess_utils, "run_command_with_output_handling", record)
    scanner = _scanner(repo, tmp_path)
    scanner._run_subprocess(["uv", "pip", "list"], env={"SCANNER_SETTING": "kept"})
    assert seen["env"]["SCANNER_SETTING"] == "kept"
    assert seen["env"]["UV_NO_PROJECT"] == "1"
    assert seen["env"]["UV_PYTHON"] == sys.executable
    assert Path(seen["cwd"]) == repo

    seen.clear()
    scanner._run_subprocess(["uv", "tool", "run", "bandit"])
    assert seen["env"] is None

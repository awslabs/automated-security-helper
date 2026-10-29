# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""scripts/measure_workspace_parallelism.py: both arms name their scanners.

Left at the default set, a host missing any default-enabled scanner made every
timed scan exit 1 under the completeness gate, which time_once refuses as a
sample, so the measurement was abandoned instead of run.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytestmark = pytest.mark.unit


@pytest.fixture
def measure(script_loader):
    return script_loader("measure_workspace_parallelism")


def _selected_scanners(command: list[str]) -> list[str]:
    return [command[i + 1] for i, arg in enumerate(command) if arg == "--scanners"]


def test_the_single_project_arm_names_the_gate_scanners(measure, tmp_path: Path):
    command = measure.single_project_command(tmp_path / "p", tmp_path / "out")
    assert _selected_scanners(command) == list(measure.GATE_SCANNERS)
    assert "--source-dir" in command


def test_the_workspace_arm_names_the_same_scanners(measure, tmp_path: Path):
    command = measure.workspace_command(
        tmp_path / "ws.code-workspace", tmp_path / "out"
    )
    assert _selected_scanners(command) == list(measure.GATE_SCANNERS)
    assert "--workspace" in command


def test_the_set_is_the_two_scanners_the_fixture_exercises(measure):
    assert tuple(measure.GATE_SCANNERS) == ("bandit", "checkov")

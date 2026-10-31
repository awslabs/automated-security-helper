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


class TestArgumentBounds:
    """At the base every count was a plain int: 0 crashed late, after the timed runs."""

    @pytest.mark.parametrize(
        "option", ["--projects", "--bound", "--repetitions", "--files-per-project"]
    )
    @pytest.mark.parametrize("value", ["0", "-1", "two"])
    def test_a_count_below_one_is_refused_at_parse_time(self, measure, option, value):
        with pytest.raises(SystemExit) as refused:
            measure._parse_args([option, value])
        assert refused.value.code == 2

    @pytest.mark.parametrize("value", ["0", "-5", "nan", "inf", "soon"])
    def test_a_timeout_that_is_not_a_positive_finite_number_is_refused(
        self, measure, value
    ):
        with pytest.raises(SystemExit):
            measure._parse_args(["--timeout", value])

    def test_the_defaults_parse(self, measure):
        args = measure._parse_args([])
        assert args.projects == 5
        assert args.timeout == measure.DEFAULT_TIMEOUT_SECONDS


class TestTimedChild:
    """At the base time_once passed no timeout and no env to subprocess.run."""

    def _capture_run(self, measure, monkeypatch, outcome=None):
        calls: list[dict] = []

        class _Completed:
            returncode = 0
            stderr = ""

        def fake_run(command, **kwargs):
            calls.append(kwargs)
            if outcome is not None:
                raise outcome
            return _Completed()

        monkeypatch.setattr(measure.subprocess, "run", fake_run)
        return calls

    def test_the_child_runs_under_a_timeout(self, measure, monkeypatch, tmp_path):
        calls = self._capture_run(measure, monkeypatch)
        measure.time_once(["python", "-c", "pass"], tmp_path, tmp_path / "out", 12.5)
        assert calls[0]["timeout"] == 12.5

    def test_the_child_is_told_to_write_utf8(self, measure, monkeypatch, tmp_path):
        monkeypatch.setenv("PYTHONSAFEPATH", "1")
        calls = self._capture_run(measure, monkeypatch)
        measure.time_once(["python", "-c", "pass"], tmp_path, tmp_path / "out")
        env = calls[0]["env"]
        assert env["PYTHONIOENCODING"] == "utf-8"
        assert env["PYTHONUTF8"] == "1"
        assert "PYTHONSAFEPATH" not in env

    def test_a_timed_out_child_abandons_the_measurement(
        self, measure, monkeypatch, tmp_path
    ):
        self._capture_run(
            measure,
            monkeypatch,
            outcome=measure.subprocess.TimeoutExpired(cmd=["python"], timeout=1),
        )
        with pytest.raises(RuntimeError, match="ran past the 1s timeout"):
            measure.time_once(["python"], tmp_path, tmp_path / "out", 1.0)

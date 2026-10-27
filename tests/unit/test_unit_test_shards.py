# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The unit-test job's shards, and the pieces that must agree with them.

Why this file exists
--------------------
The whole suite is about 47,000 items, which a 4-worker runner cannot finish inside any
sensible job timeout, so ash-unified-ci.yml splits each OS and Python combination of the
``unit-test`` job into shards. Four things have to agree for that to run every test
exactly once and still gate coverage:

* the ``shard`` axis in the workflow, one literal list whose entries each carry the total
  they were cut for (``3of8``);
* ``.github/scripts/select-test-shard.py``, which deals the test files out by those names;
* the ``run-unit-tests`` action, which runs the whole suite for ``1of1`` and one shard
  otherwise, and uploads the shard's coverage data;
* the ``unit-coverage`` job, which downloads the shards of one combination and applies the
  80% gate to their combined data, failing when a shard is missing.

A shard dropped from the axis would silently stop running its slice of the suite, and
every remaining shard would still pass. The first test below is that guard.

What it does not cover
----------------------
It does not run the workflow. That a runner finishes a shard inside its timeout is a
measurement the CI run makes.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
UNIFIED_CI = REPO_ROOT / ".github" / "workflows" / "ash-unified-ci.yml"
RUN_UNIT_TESTS = REPO_ROOT / ".github" / "actions" / "run-unit-tests" / "action.yml"
SCRIPTS = REPO_ROOT / ".github" / "scripts"

#: The one combination whose shards the unit-coverage job combines, as the action names its
#: artifacts: ``test-results-<os>-<arch label>-py<version>-shard<i>of<n>``.
COVERAGE_PREFIX = "test-results-ubuntu-latest-x86_64-py3.12"


def _load_script(filename: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        filename.replace("-", "_").removesuffix(".py"), SCRIPTS / filename
    )
    assert spec is not None and spec.loader is not None, filename
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SELECT = _load_script("select-test-shard.py")
COMBINE = _load_script("combine-unit-coverage.py")


def _workflow_job(name: str) -> dict[str, Any]:
    return yaml.safe_load(UNIFIED_CI.read_text(encoding="utf-8"))["jobs"][name]


def _action_step(name: str) -> dict[str, Any]:
    action = yaml.safe_load(RUN_UNIT_TESTS.read_text(encoding="utf-8"))
    steps = [s for s in action["runs"]["steps"] if s.get("name") == name]
    assert len(steps) == 1, f"expected one {name!r} step, got {steps}"
    return steps[0]


def _shard_axis() -> list[str]:
    axis = _workflow_job("unit-test")["strategy"]["matrix"]["shard"]
    assert isinstance(axis, list), axis
    return [str(entry) for entry in axis]


class TestTheShardAxis:
    def test_it_lists_every_shard_of_one_total_once(self):
        """Dropping, repeating or renumbering an entry leaves part of the suite unrun."""
        axis = _shard_axis()
        parsed = [SELECT.parse_shard(entry) for entry in axis]
        counts = {count for _, count in parsed}
        assert len(counts) == 1, f"the shards disagree on their total: {axis}"
        (count,) = counts
        assert count >= 2, f"a one-shard axis is the unsharded run: {axis}"
        assert sorted(index for index, _ in parsed) == list(range(1, count + 1)), (
            f"the axis {axis} is not every shard from 1 to {count} exactly once, so "
            "the tests of the missing shard run nowhere"
        )

    def test_the_job_hands_its_shard_to_the_action(self):
        steps = _workflow_job("unit-test")["steps"]
        uses = [s for s in steps if s.get("uses") == "./.github/actions/run-unit-tests"]
        assert len(uses) == 1, steps
        assert uses[0]["with"]["shard"] == "${{ matrix.shard }}"

    def test_the_job_name_carries_the_shard(self):
        """Two legs with one name collide in the checks list and in artifacts."""
        assert "matrix.shard" in _workflow_job("unit-test")["name"]


class TestTheSelector:
    def test_the_shards_deal_every_file_exactly_once(self):
        count = SELECT.parse_shard(_shard_axis()[0])[1]
        files = [f"tests/unit/test_module_{i:04d}.py" for i in range(1000)]
        dealt = [
            name
            for index in range(1, count + 1)
            for name in SELECT.select(files, index, count)
        ]
        assert sorted(dealt) == files
        sizes = [len(SELECT.select(files, i, count)) for i in range(1, count + 1)]
        assert max(sizes) - min(sizes) <= 1, sizes

    @pytest.mark.parametrize(
        "text", ["", "0of8", "9of8", "1of0", "3", "3of", "of8", "1of8x", "-1of8"]
    )
    def test_a_malformed_shard_is_refused(self, text):
        with pytest.raises(ValueError):
            SELECT.parse_shard(text)

    def test_only_test_modules_are_selected(self):
        """The same names pytest.ini's python_files selects, and nothing else."""
        assert SELECT.TEST_FILE_PATTERN == "test_*.py"
        assert SELECT.TEST_ROOT == "tests"


class TestTheActionKeepsTheWholeSuiteForm:
    def test_the_default_shard_is_the_whole_suite(self):
        action = yaml.safe_load(RUN_UNIT_TESTS.read_text(encoding="utf-8"))
        assert action["inputs"]["shard"]["default"] == "1of1"

    def test_the_two_pytest_steps_are_exclusive(self):
        whole = _action_step("Run PyTest")
        part = _action_step("Run PyTest shard")
        assert whole["if"] == "inputs.shard == '1of1'"
        assert part["if"] == "inputs.shard != '1of1'"

    def test_a_shard_measures_coverage_without_gating_it(self):
        """A shard covers part of the package; the gate is the unit-coverage job's."""
        step = _action_step("Run PyTest shard")
        run = str(step["run"])
        assert "--cov-fail-under" not in run
        assert "--cov=automated_security_helper" in run
        assert "@test-results/shard-files.txt" in run
        coverage_file = Path(step["env"]["COVERAGE_FILE"])
        assert coverage_file.parent == Path("test-results")
        assert coverage_file.name == COMBINE.DATA_FILE
        assert not coverage_file.name.startswith("."), (
            "upload-artifact leaves out hidden files, so the data would never arrive"
        )

    def test_the_artifact_name_ends_with_the_shard(self):
        upload = _action_step("Upload test results")
        assert upload["with"]["name"].endswith("-shard${{ inputs.shard }}")
        assert upload["with"]["path"] == "test-results/"


class TestTheCoverageJobReadsWhatTheShardsUpload:
    def test_it_accepts_every_shard_of_the_axis(self):
        names = [f"{COVERAGE_PREFIX}-shard{entry}" for entry in _shard_axis()]
        assert COMBINE.check_shards(names, COVERAGE_PREFIX) == []

    def test_it_refuses_the_axis_with_any_one_shard_missing(self):
        """Positive control for the test above: the check can fail on this input."""
        names = [f"{COVERAGE_PREFIX}-shard{entry}" for entry in _shard_axis()]
        for missing in range(len(names)):
            kept = names[:missing] + names[missing + 1 :]
            assert COMBINE.check_shards(kept, COVERAGE_PREFIX), (
                f"dropped {names[missing]}"
            )

    def test_the_cell_it_combines_is_one_the_matrix_runs(self):
        matrix = _workflow_job("unit-test")["strategy"]["matrix"]
        assert "ubuntu-latest" in matrix["os"]
        assert "3.12" in matrix["python-version"]

    def test_it_downloads_and_combines_that_cell(self):
        job = _workflow_job("unit-coverage")
        assert job["needs"] == "unit-test"
        assert "cancelled()" in job["if"], (
            "without !cancelled() a failed shard skips the job, and a skipped required "
            "dependency reads as a pass"
        )
        steps = job["steps"]
        downloads = [
            s
            for s in steps
            if str(s.get("uses", "")).startswith("actions/download-artifact@")
        ]
        assert len(downloads) == 1, steps
        assert downloads[0]["with"]["pattern"] == f"{COVERAGE_PREFIX}-shard*"
        combine = [
            s for s in steps if "combine-unit-coverage.py" in str(s.get("run", ""))
        ]
        assert len(combine) == 1, steps
        assert f"--prefix {COVERAGE_PREFIX}" in str(combine[0]["run"])
        assert "--fail-under 80" in str(combine[0]["run"])

    def test_the_gate_still_lists_it(self):
        assert "unit-coverage" in _workflow_job("required-checks")["needs"]

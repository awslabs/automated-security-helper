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
* ``tests/utils/sharding.py``, a ``pytest_ignore_collect`` hook that ignores the test
  modules another shard owns, so pytest's own ``testpaths``, ``python_files`` and ignore
  rules still decide what is collected;
* the ``run-unit-tests`` action, which runs the whole suite for ``1of1`` and one shard
  otherwise, and uploads the shard's coverage data;
* the ``unit-coverage`` job, which downloads the shards of one OS family and applies the
  80% gate to their combined data, failing when a shard is missing or unreadable.

A shard dropped from the axis would silently stop running its slice of the suite, and
every remaining shard would still pass. The first test below is that guard. A split made
outside pytest (a list of files on the command line) would also skip pytest's ignore
rules for those files; the real-collection tests below run pytest on a planted tree to
hold the hook to the unsharded run's collection.

What it does not cover
----------------------
It does not run the workflow. That a runner finishes a shard inside its timeout is a
measurement the CI run makes.
"""

from __future__ import annotations

import configparser
import importlib.util
import os
import shlex
import subprocess
import sys
import textwrap
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import yaml

from tests.utils import sharding

REPO_ROOT = Path(__file__).resolve().parents[2]
UNIFIED_CI = REPO_ROOT / ".github" / "workflows" / "ash-unified-ci.yml"
RUN_UNIT_TESTS = REPO_ROOT / ".github" / "actions" / "run-unit-tests" / "action.yml"
PYTEST_INI = REPO_ROOT / "pytest.ini"
ROOT_CONFTEST = REPO_ROOT / "tests" / "conftest.py"
SCRIPTS = REPO_ROOT / ".github" / "scripts"

#: The OS families the unit-coverage job gates, each with the runner.arch GitHub reports for
#: it, and the Python version it gates. The action names its artifacts
#: ``test-results-<os>-<arch label>-py<version>-shard<i>of<n>``.
COVERAGE_RUNNERS = [
    ("ubuntu-latest", "X64"),
    ("ubuntu-24.04-arm", "ARM64"),
    ("macos-latest", "ARM64"),
    ("windows-latest", "X64"),
]
COVERAGE_PYTHON = "3.12"


def _load_script(filename: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        filename.replace("-", "_").removesuffix(".py"), SCRIPTS / filename
    )
    assert spec is not None and spec.loader is not None, filename
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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


def _pytest_ini_patterns(key: str) -> list[str]:
    parser = configparser.ConfigParser()
    parser.read(PYTEST_INI, encoding="utf-8")
    return shlex.split(parser.get("pytest", key, fallback=""))


def _clean_env(**extra: str) -> dict[str, str]:
    """The environment of a child that must not join this run's coverage or options."""
    env = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith(("PYTEST_", "COV_CORE_", "COVERAGE_"))
        and k != sharding.ENV_VAR
    }
    env.update(extra)
    return env


class TestTheShardAxis:
    def test_it_lists_every_shard_of_one_total_once(self):
        """Dropping, repeating or renumbering an entry leaves part of the suite unrun."""
        axis = _shard_axis()
        parsed = [sharding.parse_shard(entry) for entry in axis]
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


class TestTheShardFilter:
    def test_a_module_belongs_to_exactly_one_shard(self):
        count = sharding.parse_shard(_shard_axis()[0])[1]
        modules = [f"tests/unit/pkg{i % 7}/test_module_{i:04d}.py" for i in range(1000)]
        patterns = _pytest_ini_patterns("python_files")
        root = Path("/rootdir")
        for module in modules:
            keepers = [
                index
                for index in range(1, count + 1)
                if not sharding.ignored_by_shard(
                    root / module, root, patterns, (index, count)
                )
            ]
            assert len(keepers) == 1, (module, keepers)

    def test_the_shards_are_not_all_one_big_shard(self):
        count = sharding.parse_shard(_shard_axis()[0])[1]
        owners = [
            sharding.owner(f"tests/unit/test_module_{i:04d}.py", count)
            for i in range(1000)
        ]
        sizes = [owners.count(index) for index in range(1, count + 1)]
        assert min(sizes) > 0.5 * (1000 / count), sizes
        assert max(sizes) < 1.5 * (1000 / count), sizes

    def test_a_file_pytest_does_not_take_as_a_test_module_is_left_alone(self):
        """The filter reads python_files from pytest.ini, so it never ignores data files."""
        patterns = _pytest_ini_patterns("python_files")
        root = Path("/rootdir")
        for name in ("conftest.py", "helpers.py", "data.json", "README.md"):
            assert not sharding.matches_python_files(Path(name), patterns), name
            for shard in ((1, 3), (2, 3), (3, 3)):
                assert not sharding.ignored_by_shard(
                    root / "tests" / name, root, patterns, shard
                ), (name, shard)

    def test_every_python_files_pattern_in_pytest_ini_is_matched(self):
        patterns = _pytest_ini_patterns("python_files")
        assert patterns, "pytest.ini sets no python_files"
        for pattern in patterns:
            sample = Path(pattern.replace("*", "sample"))
            assert sharding.matches_python_files(sample, patterns), pattern

    def test_a_module_outside_the_rootdir_is_never_ignored(self):
        patterns = _pytest_ini_patterns("python_files")
        for shard in ((1, 2), (2, 2)):
            assert not sharding.ignored_by_shard(
                Path("/elsewhere/tests/test_x.py"),
                Path("/rootdir"),
                patterns,
                shard,
            )

    def test_the_environment_variable_is_read_strictly(self):
        assert sharding.shard_from_env({}) is None
        assert sharding.shard_from_env({sharding.ENV_VAR: ""}) is None
        assert sharding.shard_from_env({sharding.ENV_VAR: "3of8"}) == (3, 8)

    @pytest.mark.parametrize(
        "text", ["0of8", "9of8", "1of0", "3", "3of", "of8", "1of8x", "-1of8", "3 of 8"]
    )
    def test_a_malformed_shard_is_refused(self, text):
        with pytest.raises(ValueError):
            sharding.shard_from_env({sharding.ENV_VAR: text})

    def test_the_root_conftest_registers_the_hook(self):
        text = ROOT_CONFTEST.read_text(encoding="utf-8")
        assert "from tests.utils.sharding import pytest_ignore_collect" in text
        assert "sharding.check_environment()" in text


class TestTheFilterInARealCollection:
    """pytest itself, on a planted tree, collects the same tests sharded and unsharded."""

    #: One module per name, each with one test; the tree has a second python_files
    #: pattern, a norecursedirs directory, and a helper that looks like a test file but
    #: matches no pattern.
    MODULES = (
        [f"suite/test_{name}.py" for name in "abcdefgh"]
        + ["suite/sub/test_i.py", "suite/sub/check_j.py"]
        + ["suite/skipme/test_k.py", "suite/helper_l.py"]
    )

    def _plant(self, root: Path) -> None:
        (root / "pytest.ini").write_text(
            textwrap.dedent(
                """\
                [pytest]
                testpaths = suite
                python_files = test_*.py check_*.py
                norecursedirs = skipme
                """
            ),
            encoding="utf-8",
        )
        for relative in self.MODULES:
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            test_name = "test_" + path.stem.split("_")[-1]
            path.write_text(f"def {test_name}():\n    pass\n", encoding="utf-8")

    def _collect(self, root: Path, shard: str | None) -> tuple[int, set[str]]:
        extra = {sharding.ENV_VAR: shard} if shard else {}
        env = _clean_env(PYTHONPATH=str(REPO_ROOT), **extra)
        done = subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                "--collect-only",
                "-q",
                "-c",
                str(root / "pytest.ini"),
                "--rootdir",
                str(root),
                "--confcutdir",
                str(root),
                "-p",
                "tests.utils.sharding",
                "-p",
                "no:cacheprovider",
                "-p",
                "no:randomly",
            ],
            cwd=root,
            env=env,
            capture_output=True,
            text=True,
            timeout=300,
        )
        ids = {line for line in done.stdout.splitlines() if "::" in line}
        return done.returncode, ids

    def test_the_shards_together_collect_what_the_unsharded_run_does(self, tmp_path):
        self._plant(tmp_path)
        code, whole = self._collect(tmp_path, None)
        assert code == 0, whole
        # The planted tree's own rules: both patterns, and neither the norecursedirs
        # directory nor the file that matches no pattern.
        assert any("test_a.py" in i for i in whole)
        assert any("check_j.py" in i for i in whole)
        assert not any("skipme" in i for i in whole), whole
        assert not any("helper_l" in i for i in whole), whole

        count = 3
        per_shard = []
        for index in range(1, count + 1):
            code, ids = self._collect(tmp_path, f"{index}of{count}")
            assert code in (0, 5), (index, code)
            per_shard.append(ids)
        union = set().union(*per_shard)
        assert union == whole, (whole - union, union - whole)
        assert sum(len(ids) for ids in per_shard) == len(whole), "a test ran twice"
        assert sum(1 for ids in per_shard if ids) >= 2, (
            "the shards did not split the tests"
        )

    def test_a_malformed_shard_fails_the_run(self, tmp_path):
        self._plant(tmp_path)
        code, _ = self._collect(tmp_path, "9of8")
        assert code != 0


class TestTheActionRunsAShard:
    def test_the_default_shard_is_the_whole_suite(self):
        action = yaml.safe_load(RUN_UNIT_TESTS.read_text(encoding="utf-8"))
        assert action["inputs"]["shard"]["default"] == "1of1"

    def test_the_two_pytest_steps_are_exclusive(self):
        whole = _action_step("Run PyTest")
        part = _action_step("Run PyTest shard")
        assert whole["if"] == "inputs.shard == '1of1'"
        assert part["if"] == "inputs.shard != '1of1'"

    def test_a_shard_names_no_test_file_on_the_command_line(self):
        """A file named there skips pytest's ignore rules and its python_files match."""
        step = _action_step("Run PyTest shard")
        argv = shlex.split(str(step["run"]).replace("\\\n", " "))
        assert argv[:3] == ["uv", "run", "pytest"], argv
        for arg in argv[3:]:
            assert arg.startswith("-"), f"positional argument {arg!r} names a path"
        assert step["env"]["ASH_TEST_SHARD"] == "${{ inputs.shard }}"
        assert step["env"]["ASH_TEST_SHARD"] and sharding.ENV_VAR == "ASH_TEST_SHARD"

    def test_a_shard_measures_coverage_without_gating_it(self):
        """A shard covers part of the package; the gate is the unit-coverage job's."""
        step = _action_step("Run PyTest shard")
        run = str(step["run"])
        # pytest.ini's addopts carry --cov, and .coveragerc's fail_under=80 becomes
        # pytest-cov's threshold when none is given, so the shard sets it to zero itself.
        assert "--cov-fail-under=0" in run
        assert "--cov-fail-under=80" not in run
        assert "-o addopts=" in run, (
            "addopts would add the XML and HTML coverage reports and a junit path to "
            "every shard"
        )
        assert "--cov=automated_security_helper" in run
        assert "COVERAGE_FILE" not in step["env"], (
            "COVERAGE_FILE reaches every process a test starts, and a nested run could "
            "merge its data into the shard's"
        )

    def test_the_shards_data_is_kept_for_the_upload_even_after_a_red_run(self):
        step = _action_step("Keep this shard's coverage data")
        assert "failure()" in step["if"] and "success()" in step["if"]
        assert "inputs.shard != '1of1'" in step["if"]
        assert f"test-results/{COMBINE.DATA_FILE}" in str(step["run"])
        assert not COMBINE.DATA_FILE.startswith("."), (
            "upload-artifact leaves out hidden files, so the data would never arrive"
        )

    def test_the_report_step_publishes_a_shards_junit_file(self):
        """The shard writes its own junit path, and the report glob must reach it."""
        report = _action_step("Publish PyTest JUnit Test Report")
        pattern = str(report["with"]["report_paths"])
        for written in (
            "test-results/pytest.junit.xml",
            "test-results/pytest-shard.junit.xml",
        ):
            assert fnmatch.fnmatchcase(written, pattern), (pattern, written)
        assert "matrix.shard" not in pattern
        assert "inputs.shard" in str(report["with"]["check_name"])

    def test_the_cdk_nag_step_runs_in_the_first_shard_only(self):
        """Eleven tests once per OS and Python version, not once per shard."""
        step = _action_step("Run cdk-nag integration tests")
        assert "startsWith(inputs.shard, '1of')" in str(step["if"])

    def test_the_artifact_name_ends_with_the_shard(self):
        upload = _action_step("Upload test results")
        assert upload["with"]["name"].endswith("-shard${{ inputs.shard }}")
        assert upload["with"]["path"] == "test-results/"


class TestTheCoverageJobReadsWhatTheShardsUpload:
    @staticmethod
    def _shard_names(os_name: str, arch: str) -> list[str]:
        prefix = COMBINE.artifact_prefix(os_name, COVERAGE_PYTHON, arch)
        return [f"{prefix}-shard{entry}" for entry in _shard_axis()]

    @pytest.mark.parametrize(("os_name", "arch"), COVERAGE_RUNNERS)
    def test_it_accepts_every_shard_of_the_axis(self, os_name, arch):
        prefix = COMBINE.artifact_prefix(os_name, COVERAGE_PYTHON, arch)
        assert COMBINE.check_shards(self._shard_names(os_name, arch), prefix) == []

    @pytest.mark.parametrize(("os_name", "arch"), COVERAGE_RUNNERS)
    def test_it_refuses_the_axis_with_any_one_shard_missing(self, os_name, arch):
        """Positive control for the test above: the check can fail on this input."""
        prefix = COMBINE.artifact_prefix(os_name, COVERAGE_PYTHON, arch)
        names = self._shard_names(os_name, arch)
        for missing in range(len(names)):
            kept = names[:missing] + names[missing + 1 :]
            assert COMBINE.check_shards(kept, prefix), f"dropped {names[missing]}"

    def test_the_arch_labels_are_the_ones_the_action_puts_in_the_name(self):
        """The script rebuilds the artifact name; the action is where it is made."""
        step = _action_step("Resolve this runner's architecture from the runner itself")
        script = str(step["run"])
        for runner_arch, label in COMBINE.ARCH_LABELS.items():
            assert f"{runner_arch}) label={label} ;;" in script, (runner_arch, label)

    def test_it_gates_one_leg_per_os_family_the_matrix_runs(self):
        gated = _workflow_job("unit-coverage")["strategy"]["matrix"]["os"]
        assert sorted(gated) == sorted(os_name for os_name, _ in COVERAGE_RUNNERS)
        tested = _workflow_job("unit-test")["strategy"]["matrix"]
        assert set(gated) <= set(tested["os"])
        assert COVERAGE_PYTHON in tested["python-version"]

    def test_each_leg_runs_where_its_shards_ran(self):
        """Same runner image, same workspace path: the reason no remapping is needed."""
        job = _workflow_job("unit-coverage")
        assert job["runs-on"] == "${{ matrix.os }}"

    def test_it_downloads_and_combines_its_family(self):
        job = _workflow_job("unit-coverage")
        assert job["needs"] == "unit-test"
        # Exactly: ${{ cancelled() }} would read the other way round.
        assert job["if"] == "${{ !cancelled() }}", (
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
        assert (
            downloads[0]["with"]["pattern"]
            == f"test-results-${{{{ matrix.os }}}}-*-py{COVERAGE_PYTHON}-shard*"
        )
        combine = [
            s for s in steps if "combine-unit-coverage.py" in str(s.get("run", ""))
        ]
        assert len(combine) == 1, steps
        run = str(combine[0]["run"])
        assert combine[0]["env"]["MATRIX_OS"] == "${{ matrix.os }}"
        assert '--os "${MATRIX_OS}"' in run
        assert f"--python-version {COVERAGE_PYTHON}" in run
        assert "--fail-under 80" in run

    def test_the_gate_still_lists_it(self):
        assert "unit-coverage" in _workflow_job("required-checks")["needs"]


class TestTheCombineGate:
    """The gate the unit-coverage job runs, on real coverage data planted in a temp dir."""

    MODULE = textwrap.dedent(
        """\
        def a():
            return 1


        def b():
            return 2


        def c():
            return 3


        def d():
            return 4
        """
    )
    DRIVER = textwrap.dedent(
        """\
        import sys

        sys.path.insert(0, sys.argv[1])
        import plant_mod

        for name in sys.argv[2:]:
            getattr(plant_mod, name)()
        """
    )

    def _shard(self, tmp_path: Path, results: Path, index: int, calls: list[str]):
        """A shard artifact whose data came from running the named functions."""
        prefix = COMBINE.artifact_prefix("ubuntu-latest", COVERAGE_PYTHON, "X64")
        directory = results / f"{prefix}-shard{index}of2"
        directory.mkdir(parents=True, exist_ok=True)
        src = tmp_path / "src"
        src.mkdir(exist_ok=True)
        (src / "plant_mod.py").write_text(self.MODULE, encoding="utf-8")
        driver = tmp_path / "driver.py"
        driver.write_text(self.DRIVER, encoding="utf-8")
        done = subprocess.run(
            [
                sys.executable,
                "-m",
                "coverage",
                "run",
                f"--data-file={directory / COMBINE.DATA_FILE}",
                f"--source={src}",
                str(driver),
                str(src),
                *calls,
            ],
            cwd=tmp_path,
            env=_clean_env(),
            capture_output=True,
            text=True,
            timeout=300,
        )
        assert done.returncode == 0, done.stdout + done.stderr
        return directory

    def _gate(self, tmp_path: Path, monkeypatch, results: Path) -> int:
        for name in list(os.environ):
            if name.startswith(("COV_CORE_", "COVERAGE_")):
                monkeypatch.delenv(name)
        monkeypatch.setenv("RUNNER_ARCH", "X64")
        monkeypatch.chdir(tmp_path)
        return COMBINE.main(
            [
                "--results-dir",
                str(results),
                "--os",
                "ubuntu-latest",
                "--python-version",
                COVERAGE_PYTHON,
                "--fail-under",
                "80",
            ]
        )

    def test_shards_that_together_cover_enough_pass(self, tmp_path, monkeypatch):
        results = tmp_path / "results"
        self._shard(tmp_path, results, 1, ["a", "b"])
        self._shard(tmp_path, results, 2, ["c", "d"])
        assert self._gate(tmp_path, monkeypatch, results) == 0

    def test_shards_that_cover_too_little_fail_with_coverages_own_status(
        self, tmp_path, monkeypatch
    ):
        """The same planted module, with both shards running the same function."""
        results = tmp_path / "results"
        self._shard(tmp_path, results, 1, ["a"])
        self._shard(tmp_path, results, 2, ["a"])
        assert self._gate(tmp_path, monkeypatch, results) == 2

    def test_a_missing_shard_fails_even_when_the_others_cover_enough(
        self, tmp_path, monkeypatch
    ):
        """One shard alone covers 100 percent here, and still may not stand in for two."""
        results = tmp_path / "results"
        self._shard(tmp_path, results, 1, ["a", "b", "c", "d"])
        assert self._gate(tmp_path, monkeypatch, results) == 1

    def test_an_unreadable_data_file_fails_instead_of_being_skipped(
        self, tmp_path, monkeypatch
    ):
        results = tmp_path / "results"
        self._shard(tmp_path, results, 1, ["a", "b", "c", "d"])
        broken = self._shard(tmp_path, results, 2, ["a"])
        (broken / COMBINE.DATA_FILE).write_bytes(b"not a coverage data file")
        assert self._gate(tmp_path, monkeypatch, results) == 1

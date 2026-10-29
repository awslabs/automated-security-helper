# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The test-tier jobs, their shards, and the pieces that must agree with them.

Why this file exists
--------------------
The whole suite is about 47,000 items, which a 4-worker runner cannot finish inside any
sensible job timeout, so ash-unified-ci.yml selects tests by tier marker and splits the
expensive tier. Every test carries one of ``unit``, ``integration`` or ``e2e``, and
three families of jobs, one job per runner pool so that each pool carries its own
``max-parallel`` cap, run one tier each:

* ``unit-test-linux``, ``-macos`` and ``-windows`` run ``-m unit``, unsharded: the
  in-process tests take minutes on one runner, so the tier has no shard axis;
* ``integration-test-linux``, ``-macos`` and ``-windows`` run ``-m integration`` in
  four shards per OS and Python version, because the tests that start real tools carry
  about 6,300 serial seconds by the classification and the per-file medians of one run
  of the earlier layout, which the hash split puts at about 16 minutes (ubuntu) and 19
  (Windows) in the worst shard against the 30-minute timeout;
* ``e2e-test-linux``, ``-macos`` and ``-windows`` run ``-m e2e`` once per runner image
  on one Python version, unsharded.

Four things have to agree for the integration tier to run every test exactly once:

* the ``shard`` axis in each of the three integration jobs, one literal list whose
  entries each carry the total they were cut for (``3of4``);
* ``tests/utils/sharding.py``, a ``pytest_ignore_collect`` hook that ignores the test
  modules another shard owns, so pytest's own ``testpaths``, ``python_files`` and ignore
  rules still decide what is collected;
* the ``run-unit-tests`` action, which runs the whole tier for an empty shard and one
  shard otherwise, and names its artifact after the tier and the shard;
* the ``unit-coverage`` job, which downloads the unit tier's artifacts of one OS family
  and applies the 80% gate to their data, failing when a shard is missing or
  unreadable. (The unit tier is one artifact, ``shard1of1``, a complete set of one; the
  check still guards a set that was sharded.)

A shard dropped from the axis would silently stop running its slice of the suite, and
every remaining shard would still pass. The first test below is that guard. A split made
outside pytest (a list of files on the command line) would also skip pytest's ignore
rules for those files; the real-collection tests below run pytest on a planted tree to
hold the hook to the unsharded run's collection.

What it does not cover
----------------------
It does not run the workflow. That a runner finishes a shard inside its timeout is a
measurement the CI run makes. An empty shard is handled in code: a shard that owns
modules but holds no test of the tier is admitted (pytest would exit 5; the hook turns
that into 0 and says so), while a shard that collects nothing at all keeps exit 5. Both
cases are run in a real pytest below. Whether the whole tier is empty is not checked by
any one leg; the tier's other legs and the unit and e2e tiers would still exit 5 on
their own.
"""

from __future__ import annotations

import configparser
import fnmatch
import importlib.util
import os
import re
import shlex
import subprocess
import sys
import textwrap
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest
import yaml

from tests.utils import sharding
from tests.utils.ci_tiers import (
    E2E_TEST_JOB_IDS,
    INTEGRATION_TEST_JOB_IDS,
    POOLS,
    UNIT_TEST_JOB_IDS,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
UNIFIED_CI = REPO_ROOT / ".github" / "workflows" / "ash-unified-ci.yml"
RUN_UNIT_TESTS = REPO_ROOT / ".github" / "actions" / "run-unit-tests" / "action.yml"
PYTEST_INI = REPO_ROOT / "pytest.ini"
ROOT_CONFTEST = REPO_ROOT / "tests" / "conftest.py"
SCRIPTS = REPO_ROOT / ".github" / "scripts"

#: The OS families the unit-coverage job gates, each with the runner.arch GitHub reports for
#: it, and the Python version it gates. The action names its artifacts
#: ``test-results-<os>-<arch label>-py<version>-<tier>-shard<i>of<n>``.
COVERAGE_RUNNERS = [
    ("ubuntu-latest", "X64"),
    ("ubuntu-24.04-arm", "ARM64"),
    ("macos-latest", "ARM64"),
    ("windows-latest", "X64"),
]
COVERAGE_PYTHON = "3.12"

#: The shard axis of the integration tier. Four is a reading from the real classification
#: and the per-file medians of one run of the earlier layout (eight was the figure before
#: the tests were classified), so the first run of the tier jobs is what may move it; the
#: list is written out here so that moving it is a change to this file in the same diff.
INTEGRATION_SHARDS = ["1of4", "2of4", "3of4", "4of4"]


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


def _action_inputs() -> dict[str, Any]:
    return yaml.safe_load(RUN_UNIT_TESTS.read_text(encoding="utf-8"))["inputs"]


def _shard_axes() -> dict[str, list[str]]:
    """The ``shard`` axis of each integration-test job, by job id."""
    axes = {}
    for job_id in INTEGRATION_TEST_JOB_IDS:
        axis = _workflow_job(job_id)["strategy"]["matrix"]["shard"]
        assert isinstance(axis, list), (job_id, axis)
        axes[job_id] = [str(entry) for entry in axis]
    return axes


def _shard_axis() -> list[str]:
    """The one shard axis the three integration-test jobs share; they must not differ."""
    axes = _shard_axes()
    first = axes[INTEGRATION_TEST_JOB_IDS[0]]
    assert all(axis == first for axis in axes.values()), (
        f"the integration-test jobs disagree on the shard axis: {axes}"
    )
    return first


def _uses_the_action(job_id: str) -> dict[str, Any]:
    steps = _workflow_job(job_id)["steps"]
    uses = [s for s in steps if s.get("uses") == "./.github/actions/run-unit-tests"]
    assert len(uses) == 1, steps
    return uses[0]


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


def _rendered_artifact_name(
    os_name: str, label: str, python: str, marker: str, shard: str
) -> str:
    """The upload step's artifact name template with the runner's values put in.

    ``shard`` is the input as the caller gives it, so an unsharded run is "".
    """
    template = str(_action_step("Upload test results")["with"]["name"])
    values = {
        "inputs.os": os_name,
        "steps.runner-arch.outputs.label": label,
        "inputs.python-version": python,
        "inputs.marker": marker,
    }

    def expression(match: re.Match) -> str:
        text = match.group(1).strip()
        if text == "inputs.shard || '1of1'":
            return shard or "1of1"
        return values[text]

    return re.sub(r"\$\{\{(.*?)\}\}", expression, template)


@pytest.mark.unit
class TestTheShardAxis:
    @pytest.mark.parametrize("job_id", INTEGRATION_TEST_JOB_IDS)
    def test_it_lists_every_shard_of_one_total_once(self, job_id):
        """Dropping, repeating or renumbering an entry leaves part of the suite unrun."""
        axis = _shard_axes()[job_id]
        parsed = [sharding.parse_shard(entry) for entry in axis]
        counts = {count for _, count in parsed}
        assert len(counts) == 1, f"the shards disagree on their total: {axis}"
        (count,) = counts
        assert count >= 2, f"a one-shard axis is the unsharded run: {axis}"
        assert sorted(index for index, _ in parsed) == list(range(1, count + 1)), (
            f"the axis {axis} is not every shard from 1 to {count} exactly once, so "
            "the tests of the missing shard run nowhere"
        )

    def test_the_axis_is_the_four_shards_the_timeout_arithmetic_assumes(self):
        assert _shard_axis() == INTEGRATION_SHARDS

    @pytest.mark.parametrize("job_id", INTEGRATION_TEST_JOB_IDS)
    def test_the_job_hands_its_shard_and_its_tier_to_the_action(self, job_id):
        uses = _uses_the_action(job_id)
        assert uses["with"]["shard"] == "${{ matrix.shard }}"
        assert uses["with"]["marker"] == "integration"

    @pytest.mark.parametrize("job_id", INTEGRATION_TEST_JOB_IDS)
    def test_the_job_name_carries_the_shard(self, job_id):
        """Two legs with one name collide in the checks list and in artifacts."""
        assert "matrix.shard" in _workflow_job(job_id)["name"]

    @pytest.mark.parametrize("job_id", UNIT_TEST_JOB_IDS)
    def test_the_unit_jobs_are_not_sharded(self, job_id):
        """The unit tier fits one job per leg, so a shard axis would only repeat setup."""
        job = _workflow_job(job_id)
        assert "shard" not in job["strategy"]["matrix"]
        assert "shard" not in job["name"]
        uses = _uses_the_action(job_id)
        assert "shard" not in uses["with"], uses
        assert uses["with"]["marker"] == "unit"

    @pytest.mark.parametrize("job_id", E2E_TEST_JOB_IDS)
    def test_the_e2e_jobs_run_one_python_and_are_not_sharded(self, job_id):
        job = _workflow_job(job_id)
        assert sorted(job["strategy"]["matrix"]) == ["os"], job["strategy"]
        assert "shard" not in job["name"]
        uses = _uses_the_action(job_id)
        assert uses["with"]["python-version"] == "3.12"
        assert "shard" not in uses["with"], uses
        assert uses["with"]["marker"] == "e2e"
        setup = [
            s
            for s in job["steps"]
            if str(s.get("uses", "")).startswith("./.github/actions/setup-ash")
        ]
        assert [s["with"]["python-version"] for s in setup] == ["3.12"], setup


@pytest.mark.unit
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
        assert "from tests.utils.sharding import (" in text
        assert "    pytest_ignore_collect,\n" in text
        assert "    pytest_configure_node,\n" in text
        assert "sharding.configure(config)" in text


@pytest.mark.integration
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


@pytest.mark.integration
class TestAnEmptyShardOfATierRunInARealPytest:
    """The exit status of pytest itself, on a planted tree with one module per tier.

    The tree carries a conftest that wires the sharding module in the way
    tests/conftest.py does (``pytest_ignore_collect`` and ``pytest_configure_node``
    imported by name, ``sharding.configure`` called from its own ``pytest_configure``)
    and defines the hooks that conftest also defines, ``pytest_testnodedown`` and a
    ``pytest_sessionfinish`` wrapper, so a clash between those and the admission would
    show here. Nothing else loads the module: CI loads it only through that conftest.
    """

    COUNT = 8
    MODULES = {
        "suite/test_only_unit.py": "unit",
        "suite/test_only_integration.py": "integration",
    }
    CONFTEST = textwrap.dedent(
        """\
        import pytest

        from tests.utils import sharding
        from tests.utils.sharding import (  # noqa: F401
            pytest_configure_node,
            pytest_ignore_collect,
        )


        def pytest_configure(config):
            sharding.configure(config)


        @pytest.hookimpl(optionalhook=True)
        def pytest_testnodedown(node, error):
            pass


        @pytest.hookimpl(hookwrapper=True, trylast=True)
        def pytest_sessionfinish(session, exitstatus):
            yield
        """
    )

    def _plant(self, root: Path) -> None:
        (root / "conftest.py").write_text(self.CONFTEST, encoding="utf-8")
        (root / "pytest.ini").write_text(
            textwrap.dedent(
                """\
                [pytest]
                testpaths = suite
                python_files = test_*.py
                markers =
                    unit: the unit tier
                    integration: the integration tier
                """
            ),
            encoding="utf-8",
        )
        for relative, tier in self.MODULES.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                f"import pytest\n\npytestmark = pytest.mark.{tier}\n\n\n"
                "def test_it():\n    pass\n",
                encoding="utf-8",
            )

    def _owner(self, tier: str) -> int:
        (relative,) = [m for m, t in self.MODULES.items() if t == tier]
        return sharding.owner(relative, self.COUNT)

    def _empty_shard(self) -> int:
        """A shard that owns neither planted module, so it collects nothing at all."""
        taken = {self._owner("unit"), self._owner("integration")}
        return next(i for i in range(1, self.COUNT + 1) if i not in taken)

    def _run(self, root: Path, index: int, *extra: str):
        return subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                "-q",
                "-c",
                str(root / "pytest.ini"),
                "--rootdir",
                str(root),
                "--confcutdir",
                str(root),
                "-p",
                "no:cacheprovider",
                "-p",
                "no:randomly",
                *extra,
            ],
            cwd=root,
            env=_clean_env(
                PYTHONPATH=str(REPO_ROOT),
                **{sharding.ENV_VAR: f"{index}of{self.COUNT}"},
            ),
            capture_output=True,
            text=True,
            timeout=300,
        )

    def test_the_planted_shards_are_the_three_cases_the_tests_below_need(self):
        assert self._owner("unit") != self._owner("integration")
        assert self._empty_shard() not in {
            self._owner("unit"),
            self._owner("integration"),
        }

    def test_a_shard_that_owns_only_unit_modules_is_admitted_under_a_tier(
        self, tmp_path
    ):
        """The case the admission is for: every item deselected by ``-m integration``."""
        self._plant(tmp_path)
        index = self._owner("unit")
        done = self._run(tmp_path, index, "-m", "integration")
        assert done.returncode == 0, done.stdout + done.stderr
        assert f"shard {index}of{self.COUNT} holds no test selected by" in done.stdout
        assert "(1 deselected); admitted" in done.stdout, done.stdout

    def test_a_shard_that_owns_only_unit_modules_just_runs_them_without_a_marker(
        self, tmp_path
    ):
        """Without ``-m`` the same shard runs its unit test and passes: nothing to admit."""
        self._plant(tmp_path)
        done = self._run(tmp_path, self._owner("unit"))
        assert done.returncode == 0, done.stdout + done.stderr
        assert "1 passed" in done.stdout, done.stdout
        assert "admitted" not in done.stdout, done.stdout

    def test_a_shard_that_collects_nothing_at_all_exits_5_even_under_a_tier(
        self, tmp_path
    ):
        """A shard count larger than the suite must still fail the leg."""
        self._plant(tmp_path)
        done = self._run(tmp_path, self._empty_shard(), "-m", "integration")
        assert done.returncode == 5, done.stdout + done.stderr
        assert "admitted" not in done.stdout, done.stdout

    def test_a_shard_that_collects_nothing_at_all_exits_5_without_a_marker(
        self, tmp_path
    ):
        self._plant(tmp_path)
        done = self._run(tmp_path, self._empty_shard())
        assert done.returncode == 5, done.stdout + done.stderr
        assert "admitted" not in done.stdout, done.stdout

    def test_the_admission_holds_under_xdist_where_the_controller_collects_nothing(
        self, tmp_path
    ):
        """As CI runs it: ``-n 2``, the wiring conftest loaded, a shard of unit modules.

        The controller never collects; each worker collects and deselects, and the
        controller learns the count from the workers' ``workeroutput``.
        """
        import xdist  # noqa: F401 - the run below needs the plugin

        self._plant(tmp_path)
        index = self._owner("unit")
        done = self._run(tmp_path, index, "-m", "integration", "-n", "2")
        assert done.returncode == 0, done.stdout + done.stderr
        assert f"shard {index}of{self.COUNT} holds no test selected by" in done.stdout

    def test_a_shard_that_collects_nothing_at_all_exits_5_under_xdist_too(
        self, tmp_path
    ):
        import xdist  # noqa: F401 - the run below needs the plugin

        self._plant(tmp_path)
        done = self._run(tmp_path, self._empty_shard(), "-m", "integration", "-n", "2")
        assert done.returncode == 5, done.stdout + done.stderr
        assert "admitted" not in done.stdout, done.stdout

    def test_the_shard_that_owns_the_tier_runs_it_and_says_nothing(self, tmp_path):
        self._plant(tmp_path)
        done = self._run(tmp_path, self._owner("integration"), "-m", "integration")
        assert done.returncode == 0, done.stdout + done.stderr
        assert "1 passed" in done.stdout, done.stdout
        assert "admitted" not in done.stdout, done.stdout

    def test_a_failing_test_still_fails_the_shard(self, tmp_path):
        self._plant(tmp_path)
        path = tmp_path / "suite" / "test_only_integration.py"
        path.write_text(
            path.read_text(encoding="utf-8").replace("pass", "assert False"),
            encoding="utf-8",
        )
        done = self._run(tmp_path, self._owner("integration"), "-m", "integration")
        assert done.returncode == 1, done.stdout + done.stderr


@pytest.mark.integration
class TestATierRunThatRanNothingInARealPytest:
    """The exit status of pytest itself for a tier leg whose only test is skipped.

    The planted tree uses the wiring conftest of
    TestAnEmptyShardOfATierRunInARealPytest and one unit module holding a single
    ``@pytest.mark.skip`` test. The run is the unsharded unit leg of CI: ``-m unit`` with
    ``GITHUB_ACTIONS=true`` in the child's environment and no shard.
    """

    CONFTEST = TestAnEmptyShardOfATierRunInARealPytest.CONFTEST
    LINE = (
        "tier run executed no test: 1 collected, 1 skipped, 0 executed; "
        "a leg that runs nothing is not green"
    )

    def _plant(self, root: Path) -> None:
        (root / "conftest.py").write_text(self.CONFTEST, encoding="utf-8")
        (root / "pytest.ini").write_text(
            "[pytest]\ntestpaths = suite\npython_files = test_*.py\n"
            "markers =\n    unit: the unit tier\n",
            encoding="utf-8",
        )
        (root / "suite").mkdir()
        (root / "suite" / "test_only_skipped.py").write_text(
            "import pytest\n\npytestmark = pytest.mark.unit\n\n\n"
            '@pytest.mark.skip(reason="the tool is absent")\n'
            "def test_it():\n    pass\n",
            encoding="utf-8",
        )

    def _run(self, root: Path, *, under_ci: bool):
        env = _clean_env(PYTHONPATH=str(REPO_ROOT))
        env.pop(sharding.CI_ENV_VAR, None)
        if under_ci:
            env[sharding.CI_ENV_VAR] = "true"
        return subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                "-q",
                "-c",
                str(root / "pytest.ini"),
                "--rootdir",
                str(root),
                "--confcutdir",
                str(root),
                "-p",
                "no:cacheprovider",
                "-p",
                "no:randomly",
                "-m",
                "unit",
            ],
            cwd=root,
            env=env,
            capture_output=True,
            text=True,
            timeout=300,
        )

    def test_a_ci_unit_leg_whose_only_test_is_skipped_exits_1_and_says_so(
        self, tmp_path
    ):
        self._plant(tmp_path)
        done = self._run(tmp_path, under_ci=True)
        assert done.returncode == 1, done.stdout + done.stderr
        assert self.LINE in done.stdout, done.stdout

    def test_the_same_run_on_a_developer_machine_stays_green(self, tmp_path):
        """The control: without GITHUB_ACTIONS and a shard, a skipped test is a skip."""
        self._plant(tmp_path)
        done = self._run(tmp_path, under_ci=False)
        assert done.returncode == 0, done.stdout + done.stderr
        assert "1 skipped" in done.stdout, done.stdout
        assert "executed no test" not in done.stdout, done.stdout


@pytest.mark.unit
class TestAShardThatHoldsNoTestOfTheTierIsAdmitted:
    """A shard owns modules, not tiers, so with ``-m`` it can hold none of the tier.

    Exit 5 there would fail a leg that has nothing to run while the tier's other shards
    carry the rest. The admission needs a shard, a ``-m`` expression and at least one
    deselected item, and acts only on pytest's "no tests collected" status. The real
    pytest runs of these cases are in TestAnEmptyShardOfATierRunInARealPytest.
    """

    @staticmethod
    def _session(text: str, expression: str, written: list[str]) -> SimpleNamespace:
        stash = pytest.Stash()
        stash[sharding._TEXT_KEY] = text
        reporter = SimpleNamespace(write_line=written.append)
        config = SimpleNamespace(
            stash=stash,
            getoption=lambda name, default="": expression,
            pluginmanager=SimpleNamespace(get_plugin=lambda name: reporter),
        )
        return SimpleNamespace(config=config, exitstatus=5)

    def test_it_turns_exit_5_into_success_and_says_which_shard(self):
        written: list[str] = []
        session = self._session("3of8", "integration", written)
        assert sharding.admit_empty_shard(
            session, pytest.ExitCode.NO_TESTS_COLLECTED, 4
        )
        assert session.exitstatus == pytest.ExitCode.OK
        assert len(written) == 1, written
        assert "shard 3of8" in written[0] and "integration" in written[0], written
        assert "(4 deselected)" in written[0], written

    def test_a_shard_that_deselected_nothing_keeps_exit_5(self):
        """It collected nothing at all: a shard count larger than the suite."""
        written: list[str] = []
        session = self._session("3of8", "integration", written)
        assert not sharding.admit_empty_shard(
            session, pytest.ExitCode.NO_TESTS_COLLECTED, 0
        )
        assert session.exitstatus == 5 and not written

    def test_a_run_without_a_marker_expression_keeps_exit_5(self):
        written: list[str] = []
        session = self._session("3of8", "", written)
        assert not sharding.admit_empty_shard(
            session, pytest.ExitCode.NO_TESTS_COLLECTED, 4
        )
        assert session.exitstatus == 5 and not written

    def test_a_run_without_a_shard_keeps_exit_5(self):
        written: list[str] = []
        session = self._session("", "integration", written)
        assert not sharding.admit_empty_shard(
            session, pytest.ExitCode.NO_TESTS_COLLECTED, 4
        )
        assert session.exitstatus == 5 and not written

    @pytest.mark.parametrize(
        "status",
        [
            pytest.ExitCode.OK,
            pytest.ExitCode.TESTS_FAILED,
            pytest.ExitCode.INTERRUPTED,
            pytest.ExitCode.INTERNAL_ERROR,
            pytest.ExitCode.USAGE_ERROR,
        ],
    )
    def test_no_other_status_is_touched(self, status):
        written: list[str] = []
        session = self._session("3of8", "integration", written)
        session.exitstatus = status
        assert not sharding.admit_empty_shard(session, status, 4)
        assert session.exitstatus == status and not written

    def test_configure_registers_the_admission_once_for_a_run_with_a_shard(
        self, monkeypatch
    ):
        """On a real plugin manager: a second ``configure`` of one config adds nothing."""
        monkeypatch.setenv(sharding.ENV_VAR, "2of3")
        manager = pytest.PytestPluginManager()
        config = SimpleNamespace(stash=pytest.Stash(), pluginmanager=manager)
        sharding.configure(config)
        first = manager.get_plugin("ash-tier-run-outcome")
        assert first is not None
        sharding.configure(config)
        assert manager.get_plugin("ash-tier-run-outcome") is first

    def test_configure_registers_nothing_for_a_whole_run(self, monkeypatch):
        """No shard and not under GitHub Actions: a developer's plain ``pytest``."""
        monkeypatch.delenv(sharding.ENV_VAR, raising=False)
        monkeypatch.delenv(sharding.CI_ENV_VAR, raising=False)
        manager = pytest.PytestPluginManager()
        sharding.configure(SimpleNamespace(stash=pytest.Stash(), pluginmanager=manager))
        assert manager.get_plugin("ash-tier-run-outcome") is None

    def test_the_plugin_counts_what_the_run_and_its_workers_deselected(self):
        plugin = sharding._TierRunOutcome()
        plugin.pytest_deselected([object(), object()])
        plugin.pytest_deselected([object()])
        finished = SimpleNamespace(workeroutput={sharding.WORKEROUTPUT_KEY: 3})
        plugin.pytest_testnodedown(finished, None)
        crashed = SimpleNamespace(workeroutput=None)
        plugin.pytest_testnodedown(crashed, RuntimeError("worker crashed"))
        assert plugin.deselected == 6

    def test_a_worker_reports_its_count_and_leaves_the_exit_status_alone(self):
        written: list[str] = []
        session = self._session("3of8", "integration", written)
        session.config.workeroutput = {}
        plugin = sharding._TierRunOutcome()
        plugin.pytest_deselected([object(), object()])
        plugin.pytest_sessionfinish(session, pytest.ExitCode.NO_TESTS_COLLECTED)
        assert session.config.workeroutput == {sharding.WORKEROUTPUT_KEY: 2}
        assert session.exitstatus == 5 and not written

    def test_the_controller_admits_on_the_sum_of_its_workers_counts(self):
        written: list[str] = []
        session = self._session("3of8", "integration", written)
        plugin = sharding._TierRunOutcome()
        for count in (1, 1):
            node = SimpleNamespace(workeroutput={sharding.WORKEROUTPUT_KEY: count})
            plugin.pytest_testnodedown(node, None)
        plugin.pytest_sessionfinish(session, pytest.ExitCode.NO_TESTS_COLLECTED)
        assert session.exitstatus == pytest.ExitCode.OK
        assert "(2 deselected)" in written[0], written


@pytest.mark.unit
class TestATierRunThatExecutedNoTestFails:
    """A CI leg that selected tests and ran none of them is not green.

    Every selected test skipped (a tool is absent, a gate is off) exits 0 and reads green
    while it measured nothing. ``fail_a_tier_run_that_executed_no_test`` turns that
    into ``TESTS_FAILED`` for a CI tier run only, and leaves the admitted empty shard,
    a run that executed something and a plain local ``pytest`` alone. The real pytest
    run of the failing case is in TestATierRunThatRanNothingInARealPytest.
    """

    LINE = (
        "tier run executed no test: 3 collected, 3 skipped, 0 executed; "
        "a leg that runs nothing is not green"
    )

    @staticmethod
    def _session(
        written: list[str],
        *,
        expression: str = "unit",
        text: str = "",
        under_ci: bool = True,
        collected: int = 3,
        status: Any = pytest.ExitCode.OK,
        **options: Any,
    ) -> SimpleNamespace:
        stash = pytest.Stash()
        stash[sharding._TEXT_KEY] = text
        stash[sharding._CI_KEY] = under_ci
        values = {"markexpr": expression, **options}
        reporter = SimpleNamespace(write_line=written.append)
        config = SimpleNamespace(
            stash=stash,
            getoption=lambda name, default="": values.get(name, default),
            pluginmanager=SimpleNamespace(get_plugin=lambda name: reporter),
        )
        return SimpleNamespace(
            config=config, exitstatus=status, testscollected=collected
        )

    def test_every_selected_test_skipped_fails_the_run_and_says_so(self):
        written: list[str] = []
        session = self._session(written)
        assert sharding.fail_a_tier_run_that_executed_no_test(session, 0, 3)
        assert session.exitstatus == pytest.ExitCode.TESTS_FAILED
        assert written == [self.LINE]

    def test_a_run_that_executed_a_test_is_left_alone(self):
        written: list[str] = []
        session = self._session(written)
        assert not sharding.fail_a_tier_run_that_executed_no_test(session, 1, 2)
        assert session.exitstatus == pytest.ExitCode.OK and not written

    def test_an_admitted_empty_shard_stays_ok(self):
        """Nothing collected and 4 deselected: the admission, not the floor, decides."""
        written: list[str] = []
        session = self._session(
            written,
            expression="integration",
            text="3of8",
            under_ci=False,
            collected=0,
            status=pytest.ExitCode.NO_TESTS_COLLECTED,
        )
        plugin = sharding._TierRunOutcome()
        plugin.pytest_deselected([object()] * 4)
        plugin.pytest_sessionfinish(session, pytest.ExitCode.NO_TESTS_COLLECTED)
        assert session.exitstatus == pytest.ExitCode.OK
        assert len(written) == 1 and "admitted" in written[0], written

    def test_a_run_that_is_not_a_ci_tier_run_is_left_alone(self):
        """A developer's ``pytest -m unit``: no GITHUB_ACTIONS and no shard."""
        written: list[str] = []
        session = self._session(written, under_ci=False)
        assert not sharding.fail_a_tier_run_that_executed_no_test(session, 0, 3)
        assert session.exitstatus == pytest.ExitCode.OK and not written

    def test_a_shard_is_a_ci_tier_run_without_github_actions(self):
        written: list[str] = []
        session = self._session(written, text="2of4", under_ci=False)
        assert sharding.fail_a_tier_run_that_executed_no_test(session, 0, 3)
        assert session.exitstatus == pytest.ExitCode.TESTS_FAILED

    def test_an_xdist_worker_never_applies_the_floor(self):
        """A worker's share can be all skips while the run executed hundreds."""
        written: list[str] = []
        session = self._session(written)
        session.config.workerinput = {}
        assert not sharding.fail_a_tier_run_that_executed_no_test(session, 0, 3)
        assert session.exitstatus == pytest.ExitCode.OK and not written

    def test_a_run_without_a_marker_expression_is_left_alone(self):
        written: list[str] = []
        session = self._session(written, expression="")
        assert not sharding.fail_a_tier_run_that_executed_no_test(session, 0, 3)
        assert session.exitstatus == pytest.ExitCode.OK and not written

    @pytest.mark.parametrize("option", ["collectonly", "setupplan", "setuponly"])
    def test_a_run_that_runs_no_test_by_design_is_left_alone(self, option):
        written: list[str] = []
        session = self._session(written, **{option: True})
        assert not sharding.fail_a_tier_run_that_executed_no_test(session, 0, 3)
        assert session.exitstatus == pytest.ExitCode.OK and not written

    @pytest.mark.parametrize(
        "status",
        [
            pytest.ExitCode.TESTS_FAILED,
            pytest.ExitCode.INTERRUPTED,
            pytest.ExitCode.INTERNAL_ERROR,
            pytest.ExitCode.USAGE_ERROR,
            pytest.ExitCode.NO_TESTS_COLLECTED,
        ],
    )
    def test_no_other_status_is_touched(self, status):
        written: list[str] = []
        session = self._session(written, status=status)
        assert not sharding.fail_a_tier_run_that_executed_no_test(session, 0, 3)
        assert session.exitstatus == status and not written

    def test_a_run_that_collected_nothing_is_left_to_exit_5(self):
        written: list[str] = []
        session = self._session(written, collected=0)
        assert not sharding.fail_a_tier_run_that_executed_no_test(session, 0, 0)
        assert session.exitstatus == pytest.ExitCode.OK and not written

    @staticmethod
    def _report(when: str, outcome: str, **extra: Any) -> SimpleNamespace:
        return SimpleNamespace(
            when=when,
            failed=outcome == "failed",
            skipped=outcome == "skipped",
            **extra,
        )

    def test_the_plugin_counts_executed_and_skipped_tests_from_their_reports(self):
        plugin = sharding._TierRunOutcome()
        reports = [
            # passed: setup, call, teardown
            self._report("setup", "passed"),
            self._report("call", "passed"),
            self._report("teardown", "passed"),
            # a mark.skip: skipped in setup, no call
            self._report("setup", "skipped"),
            # pytest.skip() in the body
            self._report("setup", "passed"),
            self._report("call", "skipped"),
            # a fixture error: failed in setup, no call
            self._report("setup", "failed"),
            # an expected failure ran its body
            self._report("setup", "passed"),
            self._report("call", "skipped", wasxfail="reason"),
        ]
        for report in reports:
            plugin.pytest_runtest_logreport(report)
        assert (plugin.executed, plugin.skipped) == (3, 2)

    def test_a_controller_counts_the_reports_xdist_forwards_once(self):
        """The workers' own counts are not summed too: that would count each test twice."""
        written: list[str] = []
        session = self._session(written)
        plugin = sharding._TierRunOutcome()
        for _ in range(3):
            plugin.pytest_runtest_logreport(self._report("setup", "skipped"))
        node = SimpleNamespace(workeroutput={sharding.WORKEROUTPUT_KEY: 0})
        plugin.pytest_testnodedown(node, None)
        plugin.pytest_sessionfinish(session, pytest.ExitCode.OK)
        assert session.exitstatus == pytest.ExitCode.TESTS_FAILED
        assert written == [self.LINE]

    def test_a_worker_leaves_the_exit_status_to_the_controller(self):
        written: list[str] = []
        session = self._session(written)
        session.config.workeroutput = {}
        plugin = sharding._TierRunOutcome()
        plugin.pytest_sessionfinish(session, pytest.ExitCode.OK)
        assert session.exitstatus == pytest.ExitCode.OK and not written

    def test_configure_registers_the_plugin_for_a_run_under_github_actions(
        self, monkeypatch
    ):
        monkeypatch.delenv(sharding.ENV_VAR, raising=False)
        monkeypatch.setenv(sharding.CI_ENV_VAR, "true")
        manager = pytest.PytestPluginManager()
        config = SimpleNamespace(stash=pytest.Stash(), pluginmanager=manager)
        sharding.configure(config)
        assert manager.get_plugin("ash-tier-run-outcome") is not None
        assert config.stash[sharding._CI_KEY] is True

    @pytest.mark.parametrize("value", ["false", "1", ""])
    def test_only_the_value_true_marks_a_run_as_ci(self, monkeypatch, value):
        monkeypatch.delenv(sharding.ENV_VAR, raising=False)
        monkeypatch.setenv(sharding.CI_ENV_VAR, value)
        manager = pytest.PytestPluginManager()
        config = SimpleNamespace(stash=pytest.Stash(), pluginmanager=manager)
        sharding.configure(config)
        assert manager.get_plugin("ash-tier-run-outcome") is None
        assert config.stash[sharding._CI_KEY] is False


class TestTheSettingStaysInTheRunThatWasGivenIt:
    """ASH_TEST_SHARD is read once and removed, so no child pytest inherits it.

    A child that loaded tests/conftest.py and collected a directory would otherwise drop
    the modules other shards own, and pass or fail by which shard its parent ran in.
    """

    COUNT = 3
    SPAWNER = textwrap.dedent(
        """\
        import os
        import pathlib
        import subprocess
        import sys


        def test_a_child_pytest_sees_no_shard_and_every_module():
            assert "ASH_TEST_SHARD" not in os.environ
            done = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "pytest",
                    "--collect-only",
                    "-q",
                    "-p",
                    "tests.utils.sharding",
                    "-p",
                    "no:cacheprovider",
                    "-p",
                    "no:randomly",
                    str(pathlib.Path(__file__).parent / "pkg"),
                ],
                capture_output=True,
                text=True,
                timeout=300,
            )
            ids = [line for line in done.stdout.splitlines() if "::" in line]
            assert len(ids) == 6, done.stdout + done.stderr
        """
    )
    SPAWNER_PATH = "suite/test_spawn.py"
    MODULES = [f"suite/test_{name}.py" for name in "abcdef"] + [
        f"suite/pkg/test_p{i}.py" for i in range(1, 7)
    ]

    @staticmethod
    def _config(**attributes: Any) -> SimpleNamespace:
        return SimpleNamespace(stash=pytest.Stash(), **attributes)

    @pytest.mark.unit
    def test_configure_takes_the_setting_and_removes_it_from_the_environment(
        self, monkeypatch
    ):
        monkeypatch.setenv(sharding.ENV_VAR, "2of3")
        config = self._config()
        sharding.configure(config)
        assert sharding.ENV_VAR not in os.environ
        assert config.stash[sharding._SHARD_KEY] == (2, 3)

    @pytest.mark.unit
    def test_configure_twice_keeps_the_setting(self, monkeypatch):
        monkeypatch.setenv(sharding.ENV_VAR, "2of3")
        config = self._config()
        sharding.configure(config)
        sharding.configure(config)
        assert config.stash[sharding._SHARD_KEY] == (2, 3)

    @pytest.mark.unit
    def test_the_hook_reads_the_config_not_the_environment(self, monkeypatch):
        """Set after configure, in a child's environment, the variable changes nothing."""
        monkeypatch.delenv(sharding.ENV_VAR, raising=False)
        config = self._config(
            rootpath=Path("/rootdir"), getini=lambda name: ["test_*.py"]
        )
        sharding.configure(config)
        monkeypatch.setenv(sharding.ENV_VAR, "1of2")
        for name in ("test_a.py", "test_b.py", "test_c.py", "test_d.py"):
            path = Path("/rootdir") / "suite" / name
            assert sharding.pytest_ignore_collect(path, config) is None, name

    @pytest.mark.unit
    def test_a_worker_takes_the_setting_from_its_workerinput(self, monkeypatch):
        monkeypatch.delenv(sharding.ENV_VAR, raising=False)
        controller = self._config()
        controller.stash[sharding._SHARD_KEY] = (2, 3)
        controller.stash[sharding._TEXT_KEY] = "2of3"
        node = SimpleNamespace(config=controller, workerinput={})
        sharding.pytest_configure_node(node)
        assert node.workerinput[sharding.WORKERINPUT_KEY] == "2of3"

        worker = self._config(workerinput=dict(node.workerinput))
        sharding.configure(worker)
        assert worker.stash[sharding._SHARD_KEY] == (2, 3)
        assert sharding.ENV_VAR not in os.environ

    @pytest.mark.unit
    def test_a_malformed_setting_is_a_usage_error(self, monkeypatch):
        monkeypatch.setenv(sharding.ENV_VAR, "9of8")
        with pytest.raises(pytest.UsageError):
            sharding.configure(self._config())

    def _plant(self, root: Path) -> None:
        (root / "pytest.ini").write_text(
            "[pytest]\ntestpaths = suite\npython_files = test_*.py\n", encoding="utf-8"
        )
        for relative in [self.SPAWNER_PATH, *self.MODULES]:
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            if relative == self.SPAWNER_PATH:
                path.write_text(self.SPAWNER, encoding="utf-8")
            else:
                test_name = "test_" + path.stem.split("_")[-1]
                path.write_text(f"def {test_name}():\n    pass\n", encoding="utf-8")

    def _run(self, root: Path, shard: str, *extra: str) -> tuple[int, int]:
        done = subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
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
                *extra,
            ],
            cwd=root,
            env=_clean_env(PYTHONPATH=str(REPO_ROOT), **{sharding.ENV_VAR: shard}),
            capture_output=True,
            text=True,
            timeout=600,
        )
        found = re.search(r"(\d+) passed", done.stdout)
        assert done.returncode == 0, done.stdout + done.stderr
        assert found, done.stdout
        return done.returncode, int(found.group(1))

    def _owned(self, index: int) -> int:
        return sum(
            1
            for module in [self.SPAWNER_PATH, *self.MODULES]
            if sharding.owner(module, self.COUNT) == index
        )

    @pytest.mark.integration
    def test_a_child_pytest_of_a_shard_sees_no_shard_and_collects_every_module(
        self, tmp_path
    ):
        self._plant(tmp_path)
        index = sharding.owner(self.SPAWNER_PATH, self.COUNT)
        _, passed = self._run(tmp_path, f"{index}of{self.COUNT}")
        assert passed == self._owned(index)

    @pytest.mark.integration
    def test_the_same_holds_under_xdist_where_workers_get_the_setting_from_workerinput(
        self, tmp_path
    ):
        import xdist  # noqa: F401 - the run below needs the plugin

        self._plant(tmp_path)
        index = sharding.owner(self.SPAWNER_PATH, self.COUNT)
        _, passed = self._run(tmp_path, f"{index}of{self.COUNT}", "-n", "2")
        assert passed == self._owned(index), (
            "a worker that did not get the setting would run every module"
        )


@pytest.mark.unit
class TestTheActionRunsATier:
    def test_the_marker_is_required_and_has_no_default(self):
        marker = _action_inputs()["marker"]
        assert marker["required"] is True
        assert "default" not in marker

    def test_the_default_shard_is_the_whole_tier(self):
        shard = _action_inputs()["shard"]
        assert shard["default"] == ""
        assert shard["required"] is False
        # The empty value is read as "no shard" by the code the action hands it to.
        assert sharding.shard_from_env({sharding.ENV_VAR: shard["default"]}) is None

    def test_one_pytest_step_always_runs(self):
        action = yaml.safe_load(RUN_UNIT_TESTS.read_text(encoding="utf-8"))
        names = [step.get("name") for step in action["runs"]["steps"]]
        assert "Run PyTest shard" not in names, names
        assert names.count("Run PyTest") == 1, names
        assert "if" not in _action_step("Run PyTest"), (
            "a condition on the one pytest step would let a leg pass by running nothing"
        )

    def test_the_step_hands_the_shard_and_the_tier_to_pytest_through_env(self):
        step = _action_step("Run PyTest")
        assert step["env"]["ASH_TEST_SHARD"] == "${{ inputs.shard }}"
        assert sharding.ENV_VAR == "ASH_TEST_SHARD"
        assert step["env"]["MARKER"] == "${{ inputs.marker }}"
        assert '-m "$MARKER"' in str(step["run"])

    def test_the_step_names_no_test_file_on_the_command_line(self):
        """A file named there skips pytest's ignore rules and its python_files match."""
        run = str(_action_step("Run PyTest")["run"])
        assert "tests/" not in run, run
        assert ".py" not in run, run

    def test_the_step_measures_coverage_without_gating_it(self):
        """A run covers part of the package; the gate is the unit-coverage job's."""
        step = _action_step("Run PyTest")
        run = str(step["run"])
        assert "--cov-fail-under" not in run
        assert "--cov=automated_security_helper" in run
        assert "COVERAGE_FILE" not in step["env"], (
            "COVERAGE_FILE reaches every process a test starts, and a nested run could "
            "merge its data into the run's"
        )

    def test_the_coverage_data_is_not_a_hidden_file(self):
        assert not COMBINE.DATA_FILE.startswith("."), (
            "upload-artifact leaves out hidden files, so the data would never arrive"
        )

    def test_the_artifact_name_ends_with_the_shard_and_carries_the_tier_before_it(self):
        upload = _action_step("Upload test results")
        name = str(upload["with"]["name"])
        assert name.endswith("-shard${{ inputs.shard || '1of1' }}")
        assert "-${{ inputs.marker }}-shard" in name
        assert upload["with"]["path"] == "test-results/"

    def test_an_unsharded_run_uploads_as_a_complete_set_of_one(self):
        name = _rendered_artifact_name("ubuntu-latest", "x86_64", "3.12", "unit", "")
        assert name == "test-results-ubuntu-latest-x86_64-py3.12-unit-shard1of1"
        prefix = COMBINE.artifact_prefix("ubuntu-latest", "3.12", "X64", "unit")
        assert COMBINE.check_shards([name], prefix) == []

    def test_a_sharded_run_names_its_shard(self):
        name = _rendered_artifact_name(
            "macos-14", "arm64", "3.10", "integration", "2of4"
        )
        assert name == "test-results-macos-14-arm64-py3.10-integration-shard2of4"

    def test_the_check_name_is_distinct_per_leg(self):
        report = _action_step("Publish PyTest JUnit Test Report")
        name = str(report["with"]["check_name"])
        assert "${{ inputs.marker }}" in name
        assert "${{ inputs.shard || 'all' }}" in name


@pytest.mark.unit
class TestTheCoverageJobReadsWhatTheUnitRunsUpload:
    #: A set that was sharded, for the controls: the unit tier itself uploads one artifact.
    SHARDED = ["1of3", "2of3", "3of3"]

    @staticmethod
    def _names(os_name: str, arch: str, axis: list[str]) -> list[str]:
        prefix = COMBINE.artifact_prefix(os_name, COVERAGE_PYTHON, arch, "unit")
        return [f"{prefix}-shard{entry}" for entry in axis]

    @pytest.mark.parametrize(("os_name", "arch"), COVERAGE_RUNNERS)
    def test_it_accepts_the_unit_tiers_one_artifact(self, os_name, arch):
        prefix = COMBINE.artifact_prefix(os_name, COVERAGE_PYTHON, arch, "unit")
        assert COMBINE.check_shards(self._names(os_name, arch, ["1of1"]), prefix) == []

    @pytest.mark.parametrize(("os_name", "arch"), COVERAGE_RUNNERS)
    def test_it_accepts_every_shard_of_a_sharded_set(self, os_name, arch):
        prefix = COMBINE.artifact_prefix(os_name, COVERAGE_PYTHON, arch, "unit")
        names = self._names(os_name, arch, self.SHARDED)
        assert COMBINE.check_shards(names, prefix) == []

    @pytest.mark.parametrize(("os_name", "arch"), COVERAGE_RUNNERS)
    def test_it_refuses_a_sharded_set_with_any_one_shard_missing(self, os_name, arch):
        """Positive control for the test above: the check can fail on this input."""
        prefix = COMBINE.artifact_prefix(os_name, COVERAGE_PYTHON, arch, "unit")
        names = self._names(os_name, arch, self.SHARDED)
        for missing in range(len(names)):
            kept = names[:missing] + names[missing + 1 :]
            assert COMBINE.check_shards(kept, prefix), f"dropped {names[missing]}"

    @pytest.mark.parametrize(("os_name", "arch"), COVERAGE_RUNNERS)
    def test_it_does_not_take_another_tiers_artifact_for_its_own(self, os_name, arch):
        prefix = COMBINE.artifact_prefix(os_name, COVERAGE_PYTHON, arch, "unit")
        other = COMBINE.artifact_prefix(os_name, COVERAGE_PYTHON, arch, "integration")
        names = self._names(os_name, arch, ["1of1"]) + [f"{other}-shard1of4"]
        assert COMBINE.check_shards(names, prefix)

    def test_the_arch_labels_are_the_ones_the_action_puts_in_the_name(self):
        """The script rebuilds the artifact name; the action is where it is made."""
        step = _action_step("Resolve this runner's architecture from the runner itself")
        script = str(step["run"])
        for runner_arch, label in COMBINE.ARCH_LABELS.items():
            assert f"{runner_arch}) label={label} ;;" in script, (runner_arch, label)

    @pytest.mark.parametrize(("os_name", "arch"), COVERAGE_RUNNERS)
    def test_the_download_pattern_matches_what_the_unit_jobs_upload(
        self, os_name, arch
    ):
        job = _workflow_job("unit-coverage")
        download = [
            s
            for s in job["steps"]
            if str(s.get("uses", "")).startswith("actions/download-artifact@")
        ]
        assert len(download) == 1, job["steps"]
        pattern = str(download[0]["with"]["pattern"]).replace(
            "${{ matrix.os }}", os_name
        )
        label = COMBINE.ARCH_LABELS[arch]
        uploaded = _rendered_artifact_name(os_name, label, COVERAGE_PYTHON, "unit", "")
        assert fnmatch.fnmatchcase(uploaded, pattern), (uploaded, pattern)
        # The same leg's integration shards must not be pulled into the unit gate.
        integration = _rendered_artifact_name(
            os_name, label, COVERAGE_PYTHON, "integration", "1of4"
        )
        assert not fnmatch.fnmatchcase(integration, pattern), (integration, pattern)

    def test_it_gates_one_leg_per_os_family_the_matrix_runs(self):
        gated = _workflow_job("unit-coverage")["strategy"]["matrix"]["os"]
        assert sorted(gated) == sorted(os_name for os_name, _ in COVERAGE_RUNNERS)
        matrices = {
            job_id: _workflow_job(job_id)["strategy"]["matrix"]
            for job_id in UNIT_TEST_JOB_IDS
        }
        tested_os = {os_name for m in matrices.values() for os_name in m["os"]}
        assert set(gated) <= tested_os
        for job_id, tested in matrices.items():
            assert COVERAGE_PYTHON in tested["python-version"], job_id

    def test_each_leg_runs_where_its_runs_ran(self):
        """Same runner image, same workspace path: the reason no remapping is needed."""
        job = _workflow_job("unit-coverage")
        assert job["runs-on"] == "${{ matrix.os }}"

    def test_it_downloads_and_combines_its_family(self):
        job = _workflow_job("unit-coverage")
        assert isinstance(job["needs"], list), job["needs"]
        # ensure-cache is here because the job calls setup-ash, as every job that
        # restores the uv cache lists the job that writes it. The three unit-test jobs
        # need it too, so it adds no wait.
        assert sorted(job["needs"]) == sorted([*UNIT_TEST_JOB_IDS, "ensure-cache"]), (
            "the coverage gate must wait for all three unit-test jobs, or it combines "
            "the runs of an OS family that is still running"
        )
        # Exactly: ${{ cancelled() }} would read the other way round.
        assert job["if"] == "${{ !cancelled() }}", (
            "without !cancelled() a failed unit run skips the job, and a skipped "
            "required dependency reads as a pass"
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
            == f"test-results-${{{{ matrix.os }}}}-*-py{COVERAGE_PYTHON}-unit-shard*"
        )
        combine = [
            s for s in steps if "combine-unit-coverage.py" in str(s.get("run", ""))
        ]
        assert len(combine) == 1, steps
        run = str(combine[0]["run"])
        assert combine[0]["env"]["MATRIX_OS"] == "${{ matrix.os }}"
        assert '--os "${MATRIX_OS}"' in run
        assert f"--python-version {COVERAGE_PYTHON}" in run
        assert "--marker unit" in run
        assert "--fail-under 80" in run

    def test_the_gate_still_lists_it(self):
        assert "unit-coverage" in _workflow_job("required-checks")["needs"]


@pytest.mark.unit
class TestTheUnitTestMatrixIsSplitByOs:
    """The three unit-test jobs are one test matrix cut by runner pool, and stay one.

    Each job has its own ``max-parallel`` and its own runner images, which is the only
    reason there are three. Everything else has to match, or one OS family would run a
    different suite from the others: other Python versions, a shard added to one job
    only, or a step edited in one of three copies.
    """

    @staticmethod
    def _jobs() -> dict[str, dict[str, Any]]:
        return {job_id: _workflow_job(job_id) for job_id in UNIT_TEST_JOB_IDS}

    @staticmethod
    def _differing(base: dict[str, Any], other: dict[str, Any]) -> list[str]:
        return sorted(
            k for k in base.keys() | other.keys() if base.get(k) != other.get(k)
        )

    @staticmethod
    def _comparable(job: dict[str, Any]) -> dict[str, Any]:
        """The job without what the split is for: its cap and its matrix."""
        strategy = {
            k: v
            for k, v in job["strategy"].items()
            if k not in ("matrix", "max-parallel")
        }
        return {
            **{k: v for k, v in job.items() if k != "strategy"},
            "strategy": strategy,
        }

    def test_the_comparison_can_fail(self):
        """Positive control: the diff helper reports a key that differs."""
        assert self._differing({"a": 1, "b": 2}, {"a": 1, "b": 3}) == ["b"]
        assert self._differing({"a": 1}, {"a": 1}) == []

    def test_the_workflow_has_these_three_unit_test_jobs_and_no_other(self):
        jobs = yaml.safe_load(UNIFIED_CI.read_text(encoding="utf-8"))["jobs"]
        found = sorted(name for name in jobs if name.startswith("unit-test"))
        assert found == sorted(UNIT_TEST_JOB_IDS), found

    def test_no_runner_image_is_in_two_of_the_jobs(self):
        os_lists = {
            job_id: job["strategy"]["matrix"]["os"]
            for job_id, job in self._jobs().items()
        }
        for job_id, os_list in os_lists.items():
            assert isinstance(os_list, list) and os_list, (job_id, os_list)
        runners = [name for os_list in os_lists.values() for name in os_list]
        assert len(runners) == len(set(runners)), (
            "a runner image is in more than one unit-test job, so its legs would run "
            f"twice under two caps and share a check name: {os_lists}"
        )

    def test_the_jobs_agree_on_python_versions(self):
        matrices = {
            job_id: job["strategy"]["matrix"] for job_id, job in self._jobs().items()
        }
        values = {
            job_id: matrix["python-version"] for job_id, matrix in matrices.items()
        }
        first = values[UNIT_TEST_JOB_IDS[0]]
        assert all(value == first for value in values.values()), values

    def test_the_matrices_have_the_same_axes_and_no_include_or_exclude(self):
        keys = {
            job_id: sorted(job["strategy"]["matrix"])
            for job_id, job in self._jobs().items()
        }
        first = keys[UNIT_TEST_JOB_IDS[0]]
        assert all(value == first for value in keys.values()), keys
        assert first == ["os", "python-version"], (
            "the unit tier is unsharded, so its matrix is the OS and Python axes only"
        )
        assert not {"include", "exclude"} & set(first), (
            "an include or an exclude changes the leg count, and the job counts in the "
            f"workflow comments are checked against it: {keys}"
        )

    def test_the_steps_are_the_same_in_all_three(self):
        steps = {job_id: job["steps"] for job_id, job in self._jobs().items()}
        first = steps[UNIT_TEST_JOB_IDS[0]]
        assert first, steps
        for job_id, value in steps.items():
            assert value == first, f"{job_id} runs different steps from the others"

    def test_the_rendered_job_names_are_the_same_shape(self):
        names = {job_id: job["name"] for job_id, job in self._jobs().items()}
        first = names[UNIT_TEST_JOB_IDS[0]]
        assert first.startswith("unit-test ("), first
        assert all(value == first for value in names.values()), names

    def test_the_jobs_differ_in_nothing_but_their_cap_and_their_runner_images(self):
        jobs = self._jobs()
        first_id, *others = UNIT_TEST_JOB_IDS
        base = self._comparable(jobs[first_id])
        for job_id in others:
            differing = self._differing(base, self._comparable(jobs[job_id]))
            assert not differing, f"{job_id} differs from {first_id} in {differing}"


@pytest.mark.unit
class TestTheIntegrationAndE2eFamiliesMirrorTheUnitFamily:
    """Each tier family is the unit family's pool split, running beside it.

    The tiers run in parallel: none waits for a unit job. Their `needs:` and `if:` are
    pinned in one place, tests/unit/test_required_checks_census.py.
    """

    @staticmethod
    def _all() -> dict[str, dict[str, Any]]:
        return yaml.safe_load(UNIFIED_CI.read_text(encoding="utf-8"))["jobs"]

    def test_each_family_has_one_job_per_pool_and_no_other(self):
        jobs = self._all()
        assert sorted(n for n in jobs if n.startswith("integration-test-")) == sorted(
            INTEGRATION_TEST_JOB_IDS
        )
        assert sorted(n for n in jobs if n.startswith("e2e-test")) == sorted(
            E2E_TEST_JOB_IDS
        )

    @pytest.mark.parametrize("job_id", [*INTEGRATION_TEST_JOB_IDS, *E2E_TEST_JOB_IDS])
    def test_no_tier_job_waits_for_a_unit_job(self, job_id):
        """A wait on the unit job would only add its slowest leg to the critical path.

        Nothing is saved by it either: a failed unit leg must not skip the other tiers'
        results, so the tiers would run after it whatever it reported.
        """
        needs = _workflow_job(job_id)["needs"]
        assert not set(needs) & set(UNIT_TEST_JOB_IDS), (job_id, needs)

    @pytest.mark.parametrize("job_id", UNIT_TEST_JOB_IDS)
    def test_the_unit_jobs_carry_no_condition(self, job_id):
        """A unit job is skipped only behind a failed ensure-cache, which the gate reads."""
        assert "if" not in _workflow_job(job_id)

    @pytest.mark.parametrize("pool", POOLS)
    def test_each_job_runs_on_the_runner_images_of_its_unit_job(self, pool):
        unit = _workflow_job(f"unit-test-{pool}")
        for family in ("integration-test", "e2e-test"):
            job = _workflow_job(f"{family}-{pool}")
            assert job["strategy"]["matrix"]["os"] == unit["strategy"]["matrix"]["os"]
            assert job["runs-on"] == "${{ matrix.os }}"

    @pytest.mark.parametrize("pool", POOLS)
    def test_each_integration_job_covers_the_pythons_and_caps_of_its_unit_job(
        self, pool
    ):
        unit = _workflow_job(f"unit-test-{pool}")
        job = _workflow_job(f"integration-test-{pool}")
        assert (
            job["strategy"]["matrix"]["python-version"]
            == unit["strategy"]["matrix"]["python-version"]
        )
        assert job["strategy"]["max-parallel"] == unit["strategy"]["max-parallel"]
        assert job["strategy"]["fail-fast"] is False

    def test_the_integration_jobs_differ_in_nothing_but_pool_specific_keys(self):
        jobs = {job_id: _workflow_job(job_id) for job_id in INTEGRATION_TEST_JOB_IDS}
        first_id, *others = INTEGRATION_TEST_JOB_IDS
        base = TestTheUnitTestMatrixIsSplitByOs._comparable(jobs[first_id])
        for job_id in others:
            other = TestTheUnitTestMatrixIsSplitByOs._comparable(jobs[job_id])
            differing = [
                k for k in base.keys() | other.keys() if base.get(k) != other.get(k)
            ]
            assert not differing, f"{job_id} differs from {first_id} in {differing}"

    @pytest.mark.parametrize(
        "job_id", [*UNIT_TEST_JOB_IDS, *INTEGRATION_TEST_JOB_IDS, *E2E_TEST_JOB_IDS]
    )
    def test_every_tier_job_keeps_the_timeout_the_shard_arithmetic_assumes(
        self, job_id
    ):
        job = _workflow_job(job_id)
        assert job["timeout-minutes"] == 30
        assert job["permissions"] == {
            "contents": "read",
            "pull-requests": "write",
            "checks": "write",
            "statuses": "write",
        }

    def test_every_tier_job_is_in_the_gate(self):
        needs = _workflow_job("required-checks")["needs"]
        missing = [
            job_id
            for job_id in [
                *UNIT_TEST_JOB_IDS,
                *INTEGRATION_TEST_JOB_IDS,
                *E2E_TEST_JOB_IDS,
            ]
            if job_id not in needs
        ]
        assert not missing, missing


@pytest.mark.integration
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

    def _shard(
        self,
        tmp_path: Path,
        results: Path,
        index: int,
        calls: list[str],
        *,
        marker: str | None = None,
        count: int = 2,
    ):
        """An artifact whose data came from running the named functions."""
        prefix = COMBINE.artifact_prefix(
            "ubuntu-latest", COVERAGE_PYTHON, "X64", marker
        )
        directory = results / f"{prefix}-shard{index}of{count}"
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

    def _gate(
        self,
        tmp_path: Path,
        monkeypatch,
        results: Path,
        *,
        marker: str | None = None,
    ) -> int:
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
                *(["--marker", marker] if marker else []),
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

    def test_the_unit_tiers_one_artifact_is_a_complete_set(self, tmp_path, monkeypatch):
        """An unsharded unit run uploads shard1of1, and the gate takes it as it is."""
        results = tmp_path / "results"
        self._shard(tmp_path, results, 1, ["a", "b", "c", "d"], marker="unit", count=1)
        assert self._gate(tmp_path, monkeypatch, results, marker="unit") == 0

    def test_the_unit_tiers_one_artifact_below_the_threshold_fails(
        self, tmp_path, monkeypatch
    ):
        results = tmp_path / "results"
        self._shard(tmp_path, results, 1, ["a"], marker="unit", count=1)
        assert self._gate(tmp_path, monkeypatch, results, marker="unit") == 2

    def test_another_tiers_artifact_is_not_the_unit_tiers_set(
        self, tmp_path, monkeypatch
    ):
        """With --marker unit the gate looks only at the unit artifacts: none here."""
        results = tmp_path / "results"
        self._shard(
            tmp_path, results, 1, ["a", "b", "c", "d"], marker="integration", count=1
        )
        assert self._gate(tmp_path, monkeypatch, results, marker="unit") == 1

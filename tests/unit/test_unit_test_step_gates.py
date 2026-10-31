# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What CI's pytest step enforces that a contributor's default run does not.

A fresh clone runs ``uv sync`` then ``uv run pytest``, and that has to be green: no
optional extras are installed, so the tests that need the ``cdk`` extra skip. CI's
pytest step (``.github/actions/run-unit-tests/action.yml``, "Run PyTest") has to keep
failing where it fails today, so the leniency the default run gets must not reach it.
This file holds both sides:

* The step installs both extras and sets ``ASH_REQUIRE_CDK_EXTRA`` and
  ``ASH_REQUIRE_SYMBOLS_EXTRA``, which turn a skip for a missing extra into a failure.
* The cdk guard skips without the variable and fails with it.
* The step runs one tier of the suite: ``-m <marker>``, with ``--run-integration
  --run-slow --no-cov`` for the integration and e2e tiers and coverage measured, with
  no threshold, for the unit tier. A sharded leg also gets ``--snapshot-warn-unused``,
  since a shard leaves the other shards' snapshot files unused; a whole-tier run does
  not, so a stale entry inside the tier still fails it. The step's own
  script is run here under bash with
  ``uv`` replaced by a function that prints its arguments, so the argument list pinned
  is the one the shell builds and not a substring of the YAML.
* The 80% threshold is not the step's. It is passed by the ``unit-coverage`` job in
  ``ash-unified-ci.yml`` to ``combine-unit-coverage.py``, and in no config file, since
  in ``addopts`` it failed every run of one directory or one test on total coverage.
  The unit run's own pytest arguments are run here against a planted test and the gate
  is run on the data it leaves, so the threshold is shown to fail a run below it rather
  than read off the YAML.
* The cdk-nag integration file runs in the integration tier on every OS and Python
  version, which is what the separate step this action used to have guaranteed.
"""

from __future__ import annotations

import configparser
import importlib.machinery
import importlib.util
import os
import re
import shlex
import shutil
import subprocess
import sys
import types
from pathlib import Path
from typing import Any

import pytest
import yaml

from tests.utils import optional_extras
from tests.utils.helpers import checkout_env
from tests.utils.optional_extras import (
    CDK_EXTRA_MODULES,
    REQUIRE_CDK_EXTRA_ENV,
    require_cdk_extra,
)
from tests.utils.ci_tiers import INTEGRATION_TEST_JOB_IDS, UNIT_TEST_JOB_IDS

REPO_ROOT = Path(__file__).resolve().parents[2]
RUN_UNIT_TESTS = REPO_ROOT / ".github" / "actions" / "run-unit-tests" / "action.yml"
UNIFIED_CI = REPO_ROOT / ".github" / "workflows" / "ash-unified-ci.yml"
COMBINE_SCRIPT = REPO_ROOT / ".github" / "scripts" / "combine-unit-coverage.py"
PYTEST_INI = REPO_ROOT / "pytest.ini"
COVERAGERC = REPO_ROOT / ".coveragerc"
CDK_NAG_REAL_PACK = (
    REPO_ROOT / "tests" / "integration" / "scanners" / "test_cdk_nag_real_pack.py"
)

#: The threshold CI enforces today. Lowering it is a change to this file, in the same diff.
CI_COVERAGE_THRESHOLD = 80

#: The three tiers, in the order the action validates them.
TIERS = ("unit", "integration", "e2e")

_REQUIRES_BASH = pytest.mark.skipif(
    os.name == "nt" or shutil.which("bash") is None,
    reason="the step is a bash step, as on ubuntu-latest; its logic is the same on every OS",
)


def _step(name: str) -> dict[str, Any]:
    action = yaml.safe_load(RUN_UNIT_TESTS.read_text(encoding="utf-8"))
    steps = [s for s in action["runs"]["steps"] if s.get("name") == name]
    assert len(steps) == 1, (
        f"expected one {name!r} step in {RUN_UNIT_TESTS}, got {steps}"
    )
    return steps[0]


def _bash(script: str, **env: str) -> subprocess.CompletedProcess:
    """Run a step's script as the runner does: bash, errexit and pipefail on."""
    return subprocess.run(
        ["bash", "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", script],
        env={"PATH": os.environ.get("PATH", ""), **env},
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


def _pytest_argv(marker: str, **env: str) -> list[str]:
    """The arguments "Run PyTest" gives pytest for ``marker``, as the shell builds them.

    ``uv`` is a function that prints each of its arguments on a line of its own, so the
    script's array is expanded by bash itself; ``run pytest`` come first and are dropped.
    ``env`` is the rest of the step's environment; with none given the leg is unsharded,
    as the step's ``ASH_TEST_SHARD`` is empty for a whole-tier run.
    """
    script = str(_step("Run PyTest")["run"])
    done = _bash('uv() { printf "%s\\n" "$@"; }\n' + script, MARKER=marker, **env)
    assert done.returncode == 0, done.stdout + done.stderr
    argv = done.stdout.splitlines()
    assert argv[:2] == ["run", "pytest"], argv
    return argv[2:]


class TestTheUnitTestStepCannotPassBySkipping:
    @pytest.mark.unit
    def test_it_installs_both_extras(self):
        argv = shlex.split(_step("Install dependencies")["run"])
        assert argv[:2] == ["uv", "sync"], argv
        for extra in ("cdk", "symbols"):
            assert f"--extra={extra}" in argv or any(
                a == "--extra" and b == extra for a, b in zip(argv, argv[1:])
            ), f"the unit-test step no longer installs the {extra} extra: {argv}"

    @pytest.mark.unit
    @pytest.mark.parametrize(
        "variable", [REQUIRE_CDK_EXTRA_ENV, "ASH_REQUIRE_SYMBOLS_EXTRA"]
    )
    def test_it_turns_a_missing_extra_into_a_failure(self, variable):
        """Without the variable, a leg that lost an extra would pass by skipping its tests."""
        env = _step("Run PyTest").get("env") or {}
        if variable in env:
            given = env[variable]
            setting = (
                f"sets {variable} to {given!r}, which does not turn a missing "
                "extra into a failure:"
            )
        else:
            given = ""
            setting = f"does not set {variable}, so"
        value = str(given).strip().upper()
        assert value in ("1", "YES", "TRUE"), (
            f"'Run PyTest' {setting} the tests that need that extra skip in CI "
            "instead of failing when it is missing. The step sets: "
            f"{sorted(env, key=str)}"
        )

    @pytest.mark.unit
    @pytest.mark.parametrize(
        ("step_env", "said"),
        [
            pytest.param(
                {REQUIRE_CDK_EXTRA_ENV: "0"},
                f"sets {REQUIRE_CDK_EXTRA_ENV} to '0',",
                id="zero",
            ),
            pytest.param(
                {REQUIRE_CDK_EXTRA_ENV: "false"},
                f"sets {REQUIRE_CDK_EXTRA_ENV} to 'false',",
                id="false",
            ),
            pytest.param(
                {REQUIRE_CDK_EXTRA_ENV: "no"},
                f"sets {REQUIRE_CDK_EXTRA_ENV} to 'no',",
                id="no",
            ),
            pytest.param(
                {REQUIRE_CDK_EXTRA_ENV: " 0 "},
                f"sets {REQUIRE_CDK_EXTRA_ENV} to ' 0 ',",
                id="padded-zero",
            ),
            pytest.param(
                {REQUIRE_CDK_EXTRA_ENV: None},
                f"sets {REQUIRE_CDK_EXTRA_ENV} to None,",
                id="yaml-null",
            ),
            pytest.param(
                {"OTHER": "1"},
                f"does not set {REQUIRE_CDK_EXTRA_ENV},",
                id="absent",
            ),
        ],
    )
    def test_the_failure_says_what_the_step_sets(
        self,
        monkeypatch: pytest.MonkeyPatch,
        step_env: dict[object, object],
        said: str,
    ) -> None:
        """The failure's own first line says what the step does with the
        variable: the value as written (a YAML null as None), or that it does
        not set it. Only that line is read: pytest's explanation under it
        repeats the normalized value, so it would match whatever the message
        said."""
        monkeypatch.setitem(globals(), "_step", lambda name: {"env": step_env})
        with pytest.raises(AssertionError) as raised:
            self.test_it_turns_a_missing_extra_into_a_failure(REQUIRE_CDK_EXTRA_ENV)
        first_line = str(raised.value).split("\n", 1)[0]
        assert said in first_line

    @pytest.mark.unit
    def test_a_missing_variable_is_reported_when_a_name_is_not_text(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """YAML 1.1 reads an unquoted ``ON:`` key as True: the failure still
        lists the step's names, rather than raising TypeError sorting them."""
        monkeypatch.setitem(
            globals(), "_step", lambda name: {"env": {True: "x", "OTHER": "1"}}
        )
        with pytest.raises(AssertionError) as raised:
            self.test_it_turns_a_missing_extra_into_a_failure(REQUIRE_CDK_EXTRA_ENV)
        assert "The step sets: ['OTHER', True]" in str(raised.value)


@pytest.mark.unit
class TestTheCdkGuard:
    @pytest.fixture
    def cdk_absent(self, monkeypatch):
        # find_spec returns None for a name whose sys.modules entry is None, which is how
        # a module that cannot be imported looks to it.
        monkeypatch.setitem(sys.modules, "cdk_nag", None)

    @pytest.fixture
    def cdk_present(self, monkeypatch):
        for name in CDK_EXTRA_MODULES:
            module = types.ModuleType(name)
            module.__spec__ = importlib.machinery.ModuleSpec(name, None)
            monkeypatch.setitem(sys.modules, name, module)

    @staticmethod
    def _outcome(monkeypatch, flag: str | None) -> tuple[str, str]:
        """Run the guard and report what it did, without letting a skip or a failure escape.

        Each test asserts one outcome. If either exception were allowed to propagate, a
        guard that skipped where it should fail would turn its test into a skip, and a
        skipped test reads as harmless.
        """
        if flag is None:
            monkeypatch.delenv(REQUIRE_CDK_EXTRA_ENV, raising=False)
        else:
            monkeypatch.setenv(REQUIRE_CDK_EXTRA_ENV, flag)
        try:
            require_cdk_extra()
        except pytest.skip.Exception as exc:
            return "skipped", str(exc)
        except pytest.fail.Exception as exc:
            return "failed", str(exc)
        return "returned", ""

    def test_it_skips_without_the_ci_flag(self, cdk_absent, monkeypatch):
        outcome, message = self._outcome(monkeypatch, None)
        assert outcome == "skipped", (outcome, message)
        assert "cdk_nag" in message
        assert "uv sync --extra cdk" in message

    @pytest.mark.parametrize("value", ["1", "true", "YES"])
    def test_it_fails_under_the_ci_flag(self, cdk_absent, monkeypatch, value):
        outcome, message = self._outcome(monkeypatch, value)
        assert outcome == "failed", (
            f"with {REQUIRE_CDK_EXTRA_ENV}={value!r} and cdk_nag missing the guard "
            f"{outcome}, so a CI leg without the extra would pass: {message}"
        )
        assert REQUIRE_CDK_EXTRA_ENV in message
        assert "cdk_nag" in message

    @pytest.mark.parametrize("value", ["", "0", "no"])
    def test_a_value_that_is_not_yes_skips(self, cdk_absent, monkeypatch, value):
        outcome, message = self._outcome(monkeypatch, value)
        assert outcome == "skipped", (outcome, message)

    def test_it_returns_when_the_extra_is_installed(self, cdk_present, monkeypatch):
        """Positive control: the tests above see a skip or a failure because cdk_nag is absent."""
        assert self._outcome(monkeypatch, "1") == ("returned", "")

    def test_an_imported_module_without_a_spec_counts_as_installed(
        self, cdk_present, monkeypatch
    ):
        """find_spec raises ValueError for one; the guard must not turn that into an error."""
        stand_in = types.ModuleType("cdk_nag")
        stand_in.__spec__ = None
        monkeypatch.setitem(sys.modules, "cdk_nag", stand_in)
        assert self._outcome(monkeypatch, "1") == ("returned", "")

    def test_it_probes_one_module_per_distribution_the_scanner_needs(self):
        """A distribution added to the extra must be probed too, or a run lacking it passes.

        The scanner's own list is the reference: it is derived from the ``cdk`` extra in
        pyproject.toml. Mapping a module to its distribution needs them installed, so this
        runs where the extra is (every CI leg) and skips where it is not.
        """
        import importlib.metadata

        from automated_security_helper.plugin_modules.ash_builtin.scanners import (
            cdk_nag_scanner,
        )

        require_cdk_extra()
        by_module = importlib.metadata.packages_distributions()
        required = {d.lower() for d in cdk_nag_scanner._CDK_REQUIRED_DISTRIBUTIONS}
        assert required, (
            "the scanner lists no cdk distributions, so this compares nothing"
        )
        # aws_cdk is shared: aws-cdk-lib and its asset packages all install into it. So each
        # probed module has to belong to a required distribution, and each required
        # distribution has to own a probed module.
        owners = {
            module: {d.lower() for d in by_module.get(module, [])}
            for module in optional_extras.CDK_EXTRA_MODULES
        }
        unowned = [m for m, dists in owners.items() if not dists & required]
        assert not unowned, (
            f"{unowned} belong to none of {sorted(required)}; owners: {owners}"
        )
        unprobed = required - set().union(*owners.values())
        assert not unprobed, (
            f"the scanner needs {sorted(unprobed)}, which no module in "
            f"CDK_EXTRA_MODULES {optional_extras.CDK_EXTRA_MODULES} comes from"
        )


@pytest.mark.unit
class TestTheThresholdBelongsToTheUnitCoverageJob:
    def test_the_default_run_measures_no_coverage(self):
        """A run of one directory or one test must not fail on the whole suite's coverage."""
        parser = configparser.ConfigParser()
        parser.read(PYTEST_INI, encoding="utf-8")
        addopts = shlex.split(parser.get("pytest", "addopts"))
        assert "-n" in addopts, f"read the wrong addopts: {addopts}"
        coverage = [opt for opt in addopts if opt.startswith("--cov")]
        assert not coverage, (
            f"pytest.ini's addopts carry {coverage}, so every subset run measures coverage "
            "and fails on a threshold meant for the whole unit tier. Pass coverage options "
            "in .github/actions/run-unit-tests/action.yml instead."
        )

    def test_no_config_file_sets_a_coverage_threshold(self):
        """The 80 lives on the unit-coverage job's command only.

        A fail_under in .coveragerc (or in pyproject.toml's [tool.coverage.report])
        would gate every `pytest --cov` of a subset again, and would be a second place
        the number could drift from the one CI passes.
        """
        parser = configparser.ConfigParser()
        assert parser.read(COVERAGERC, encoding="utf-8"), f"could not read {COVERAGERC}"
        assert parser.has_section("report"), "read the wrong .coveragerc"
        assert not parser.has_option("report", "fail_under"), (
            ".coveragerc sets fail_under again; pass --fail-under from the "
            "unit-coverage job's combine command"
        )
        pyproject = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        assert "[tool.coverage" not in pyproject, (
            "pyproject.toml configures coverage, which .coveragerc is supposed to own"
        )

    def test_the_pytest_step_passes_no_threshold(self):
        """The composite no longer gates: a leg of any tier runs one slice of the code."""
        run = str(_step("Run PyTest")["run"])
        assert "--cov-fail-under" not in run, run
        assert "fail_under" not in run, run

    def test_the_unit_coverage_job_applies_the_threshold_to_the_unit_tier(self):
        job = yaml.safe_load(UNIFIED_CI.read_text(encoding="utf-8"))["jobs"][
            "unit-coverage"
        ]
        combine = [
            s
            for s in job["steps"]
            if "combine-unit-coverage.py" in str(s.get("run", ""))
        ]
        assert len(combine) == 1, job["steps"]
        words = shlex.split(str(combine[0]["run"]).replace("\\\n", " "))
        assert "--self-test" in words, "the gate is not self-tested before it is used"
        gate = words[words.index("--results-dir") - 1 :]
        for option, value in (
            ("--fail-under", str(CI_COVERAGE_THRESHOLD)),
            ("--marker", "unit"),
        ):
            assert option in gate, f"the combine command does not pass {option}: {gate}"
            assert gate[gate.index(option) + 1] == value, (option, gate)

    def test_the_unit_run_keeps_its_coverage_data_for_the_upload(self):
        step = _step("Keep the unit run's coverage data")
        condition = str(step["if"])
        assert "success()" in condition and "failure()" in condition
        assert "inputs.marker == 'unit'" in condition
        assert "cp .coverage test-results/coverage.data" in str(step["run"])
        assert "coverage.data" in COMBINE_SCRIPT.read_text(encoding="utf-8")


@pytest.mark.integration
@_REQUIRES_BASH
class TestTheStepBuildsTheRightArgumentsForEachTier:
    """The step's script, run with ``uv`` stubbed, for each value of ``MARKER``."""

    @pytest.mark.parametrize("marker", TIERS)
    def test_it_selects_the_tier_and_writes_its_report(self, marker):
        argv = _pytest_argv(marker)
        assert argv[:2] == ["-m", marker], argv
        assert "--junit-xml=test-results/pytest.junit.xml" in argv, argv

    @pytest.mark.parametrize("marker", TIERS)
    def test_a_sharded_leg_warns_instead_of_failing_on_the_other_shards_snapshots(
        self, marker
    ):
        """A shard collects part of the tier, so the other shards' snapshot files are unused.

        When every collected test of a shard carries the tier marker, syrupy reports
        those whole files as unused and fails the session with every test passed. The
        flag is passed by the step for a sharded leg and not through pytest.ini's
        addopts, so a run on a contributor's machine keeps the unused-snapshot check.
        """
        assert "--snapshot-warn-unused" in _pytest_argv(marker, ASH_TEST_SHARD="2of4")
        ini = PYTEST_INI.read_text(encoding="utf-8")
        assert "snapshot-warn-unused" not in ini

    @pytest.mark.parametrize("marker", TIERS)
    @pytest.mark.parametrize("shard", [None, ""])
    def test_a_whole_tier_run_keeps_syrupys_unused_snapshot_check(self, marker, shard):
        """A whole-tier run deselects the other tiers with ``-m``, and under a deselection
        syrupy reports only an entry whose own test ran and no longer asserts it. Those
        are real stale entries, so the step leaves syrupy's failing default in place
        there: a warn-unused flag would hide every orphaned entry inside a tier from CI.
        """
        env = {} if shard is None else {"ASH_TEST_SHARD": shard}
        assert "--snapshot-warn-unused" not in _pytest_argv(marker, **env)

    @pytest.mark.parametrize("marker", TIERS)
    def test_it_names_no_test_path(self, marker):
        """A path named there would skip pytest's ignore rules and its python_files match."""
        argv = _pytest_argv(marker)
        positional = [
            arg
            for index, arg in enumerate(argv)
            if not arg.startswith("-") and argv[index - 1] != "-m"
        ]
        assert not positional, argv

    def test_the_unit_tier_measures_the_package_and_gates_nothing(self):
        argv = _pytest_argv("unit")
        assert "--cov=automated_security_helper" in argv, argv
        assert "--cov-config=.coveragerc" in argv, argv
        assert "--cov-report=" in argv, "a report here would print what the gate reads"
        assert not [a for a in argv if a.startswith("--cov-fail-under")], argv
        assert "--no-cov" not in argv, argv
        assert "--run-integration" not in argv and "--run-slow" not in argv, argv

    @pytest.mark.parametrize("marker", ["integration", "e2e"])
    def test_the_other_tiers_run_the_gated_tests_and_measure_no_coverage(self, marker):
        argv = _pytest_argv(marker)
        for flag in ("--run-integration", "--run-slow", "--no-cov"):
            assert flag in argv, f"{marker}: {flag} is missing from {argv}"
        assert not [a for a in argv if a.startswith("--cov") and a != "--no-cov"], argv


@pytest.mark.integration
@_REQUIRES_BASH
class TestTheMarkerIsValidatedBeforeAnythingRuns:
    def _validate(self, marker: str) -> subprocess.CompletedProcess:
        step = _step("Validate the tier marker")
        return _bash(str(step["run"]), MARKER=marker)

    @pytest.mark.parametrize("marker", TIERS)
    def test_each_tier_is_accepted(self, marker):
        done = self._validate(marker)
        assert done.returncode == 0, done.stdout + done.stderr

    @pytest.mark.parametrize(
        "marker",
        ["", "Unit", "integration ", "unit or integration", "slow", "all", "e2e\n"],
    )
    def test_anything_else_fails_closed(self, marker):
        done = self._validate(marker)
        assert done.returncode != 0, (marker, done.stdout)
        assert "::error::" in done.stdout, done.stdout

    def test_the_error_does_not_print_the_value(self):
        """A workflow command may only print a value that is neutralized or listed in
        test_workflow_commands_print_no_unchecked_value.py, and this is the one value
        the case did not recognize."""
        done = self._validate("x\r::warning::from the value")
        assert done.returncode != 0
        assert "from the value" not in done.stdout, done.stdout

    def test_it_runs_before_the_install_and_the_tests(self):
        action = yaml.safe_load(RUN_UNIT_TESTS.read_text(encoding="utf-8"))
        names = [step.get("name") for step in action["runs"]["steps"]]
        validate = names.index("Validate the tier marker")
        assert validate < names.index("Install dependencies"), names
        assert validate < names.index("Run PyTest"), names


@pytest.mark.integration
@_REQUIRES_BASH
class TestTheGateFailsAUnitRunBelowTheThreshold:
    """The unit run's own pytest arguments over one planted test, then the real gate."""

    PLANTED = (
        "import pytest\n"
        "\n"
        "pytestmark = pytest.mark.unit\n"
        "\n"
        "\n"
        "def test_imports_the_package():\n"
        "    import automated_security_helper  # noqa: F401\n"
    )

    @staticmethod
    def _combine() -> types.ModuleType:
        spec = importlib.util.spec_from_file_location(
            "_combine_unit_coverage", COMBINE_SCRIPT
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def _clean_env(self) -> dict[str, str]:
        return {
            k: v
            for k, v in os.environ.items()
            if not k.startswith(("PYTEST_", "COV_CORE_", "COVERAGE_"))
        }

    def _run_unit_tier(self, tmp_path: Path) -> Path:
        """Run the step's unit arguments over a planted test; return the results dir.

        The run gets its own ini, rootdir and conftest cut-off, so none of this
        repository's conftests or addopts load, and its own COVERAGE_FILE, so its data
        files never mix with those of the run that is executing this test. The data is
        then copied where the "Keep the unit run's coverage data" step puts it, under
        the name the upload step gives the artifact of an unsharded unit run.
        """
        shutil.copy(COVERAGERC, tmp_path / ".coveragerc")
        (tmp_path / "pytest.ini").write_text(
            "[pytest]\nmarkers =\n    unit: the unit tier\n", encoding="utf-8"
        )
        planted = tmp_path / "test_planted.py"
        planted.write_text(self.PLANTED, encoding="utf-8")
        env = self._clean_env()
        env["COVERAGE_FILE"] = str(tmp_path / ".coverage")
        done = subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                *_pytest_argv("unit"),
                str(planted),
                "-c",
                str(tmp_path / "pytest.ini"),
                "--rootdir",
                str(tmp_path),
                "--confcutdir",
                str(tmp_path),
                "-p",
                "no:cacheprovider",
                "-p",
                "no:randomly",
                "-q",
            ],
            cwd=tmp_path,
            env=checkout_env(env),
            capture_output=True,
            text=True,
            timeout=600,
        )
        assert done.returncode == 0, done.stdout + done.stderr
        assert "1 passed" in done.stdout, done.stdout
        prefix = self._combine().artifact_prefix("ubuntu-latest", "3.12", "X64", "unit")
        artifact = tmp_path / "results" / f"{prefix}-shard1of1"
        artifact.mkdir(parents=True)
        shutil.copy(tmp_path / ".coverage", artifact / "coverage.data")
        return tmp_path / "results"

    def _gate(self, tmp_path: Path, results: Path, threshold: int):
        env = self._clean_env()
        env["RUNNER_ARCH"] = "X64"
        return subprocess.run(
            [
                sys.executable,
                str(COMBINE_SCRIPT),
                "--results-dir",
                str(results),
                "--os",
                "ubuntu-latest",
                "--python-version",
                "3.12",
                "--marker",
                "unit",
                "--fail-under",
                str(threshold),
            ],
            cwd=tmp_path,
            env=checkout_env(env),
            capture_output=True,
            text=True,
            timeout=600,
        )

    def test_the_gate_fails_a_run_below_the_threshold(self, tmp_path):
        """The measured half: one import of the package covers far less than 80%."""
        results = self._run_unit_tier(tmp_path)
        done = self._gate(tmp_path, results, CI_COVERAGE_THRESHOLD)
        assert done.returncode == 2, done.stdout + done.stderr

    def test_the_same_gate_passes_with_no_threshold(self, tmp_path):
        """Positive control: the failure above is the threshold, not the harness."""
        results = self._run_unit_tier(tmp_path)
        done = self._gate(tmp_path, results, 0)
        assert done.returncode == 0, done.stdout + done.stderr


def _glob_matches(pattern: str, path: str) -> bool:
    """@actions/glob semantics for the patterns used here: ``**/`` spans directories."""
    regex = re.escape(pattern).replace(r"\*\*/", "(?:.*/)?").replace(r"\*", "[^/]*")
    return re.fullmatch(regex, path) is not None


@pytest.mark.unit
class TestThePytestStepKeepsItsReport:
    """The action runs pytest once, and the report step publishes the file it writes.

    A second pytest step would have to take a ``--junit-xml`` path of its own, because
    pytest.ini's addopts carry ``--junit-xml=test-results/pytest.junit.xml`` and a later
    run on the shared path would overwrite the earlier report. The cdk-nag step that
    needed one is gone, so the action runs pytest in exactly one step.
    """

    def test_exactly_one_step_runs_pytest(self):
        action = yaml.safe_load(RUN_UNIT_TESTS.read_text(encoding="utf-8"))
        running = [
            step.get("name")
            for step in action["runs"]["steps"]
            if "uv run pytest" in str(step.get("run", ""))
        ]
        assert running == ["Run PyTest"], running

    def test_the_step_writes_the_file_the_report_step_publishes(self):
        run = str(_step("Run PyTest")["run"])
        written = re.findall(r"--junit-xml=([^\s)]+)", run)
        assert written == ["test-results/pytest.junit.xml"], written
        patterns = str(
            _step("Publish PyTest JUnit Test Report")["with"]["report_paths"]
        ).splitlines()
        assert any(
            _glob_matches(p.strip(), written[0]) for p in patterns if p.strip()
        ), f"report_paths {patterns} does not match {written[0]}"

    def test_the_glob_helper_matches_like_actions_glob(self):
        assert _glob_matches("**/pytest.junit.xml", "test-results/pytest.junit.xml")
        assert _glob_matches("**/pytest.junit.xml", "pytest.junit.xml")
        assert _glob_matches("test-results/*.junit.xml", "test-results/a.junit.xml")
        assert not _glob_matches(
            "test-results/*.junit.xml", "test-results/x/a.junit.xml"
        )
        assert not _glob_matches("**/pytest.junit.xml", "test-results/cdk.junit.xml")


@pytest.mark.unit
class TestTheCdkNagPathRunsInTheIntegrationTier:
    """The property the separate "Run cdk-nag integration tests" step guarded.

    That step ran tests/integration/scanners/test_cdk_nag_real_pack.py once per OS and
    Python version, because the default run skipped the integration directory and the
    one integration job runs on one platform and one Python. The integration-test jobs
    now run ``-m integration`` on every OS and Python version of the unit matrix, with
    ASH_REQUIRE_CDK_EXTRA set by the action, and that file carries the integration
    marker, so the tier job runs it everywhere without a second step.
    """

    @staticmethod
    def _jobs() -> dict[str, Any]:
        return yaml.safe_load(UNIFIED_CI.read_text(encoding="utf-8"))["jobs"]

    def test_the_action_has_no_step_of_its_own_for_it(self):
        action = yaml.safe_load(RUN_UNIT_TESTS.read_text(encoding="utf-8"))
        for step in action["runs"]["steps"]:
            assert "test_cdk_nag_real_pack" not in str(step.get("run", "")), step
            assert "cdk-nag integration" not in str(step.get("name", "")), step

    def test_the_file_carries_the_integration_marker(self):
        text = CDK_NAG_REAL_PACK.read_text(encoding="utf-8")
        assert re.search(r"pytest\.mark\.integration\b", text), (
            f"{CDK_NAG_REAL_PACK.name} has no integration marker, so `-m integration` "
            "would not select it and the cdk-nag path would run nowhere"
        )
        assert not re.search(r"pytest\.mark\.(unit|e2e)\b", text), (
            f"{CDK_NAG_REAL_PACK.name} carries a second tier marker"
        )

    @pytest.mark.parametrize(
        ("integration_id", "unit_id"),
        zip(INTEGRATION_TEST_JOB_IDS, UNIT_TEST_JOB_IDS),
    )
    def test_the_integration_job_covers_every_os_and_python_of_its_unit_job(
        self, integration_id, unit_id
    ):
        jobs = self._jobs()
        integration = jobs[integration_id]["strategy"]["matrix"]
        unit = jobs[unit_id]["strategy"]["matrix"]
        assert integration["os"] == unit["os"]
        assert integration["python-version"] == unit["python-version"]
        uses = [
            step
            for step in jobs[integration_id]["steps"]
            if step.get("uses") == "./.github/actions/run-unit-tests"
        ]
        assert len(uses) == 1, jobs[integration_id]["steps"]
        assert uses[0]["with"]["marker"] == "integration"
        # No step-level condition. The job-level condition is pinned in
        # tests/unit/test_required_checks_census.py.
        assert "if" not in uses[0]

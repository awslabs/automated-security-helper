# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What CI's unit-test step enforces that a contributor's default run does not.

A fresh clone runs ``uv sync`` then ``uv run pytest``, and that has to be green: no
optional extras are installed, so the tests that need the ``cdk`` extra skip. CI's
unit-test step (``.github/actions/run-unit-tests/action.yml``, "Run PyTest") has to keep
failing where it fails today, so the leniency the default run gets must not reach it.
This file holds both sides:

* The step installs both extras and sets ``ASH_REQUIRE_CDK_EXTRA`` and
  ``ASH_REQUIRE_SYMBOLS_EXTRA``, which turn a skip for a missing extra into a failure.
* The cdk guard skips without the variable and fails with it.
* Coverage and its 80% threshold are passed by the step, not by ``pytest.ini``. In
  ``addopts`` they failed every run of one directory or one test on total coverage. The
  step's own command is run here against a planted test, so the threshold is shown to
  fail a run below it rather than read off the YAML.
"""

from __future__ import annotations

import configparser
import importlib.machinery
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

REPO_ROOT = Path(__file__).resolve().parents[2]
RUN_UNIT_TESTS = REPO_ROOT / ".github" / "actions" / "run-unit-tests" / "action.yml"
PYTEST_INI = REPO_ROOT / "pytest.ini"
COVERAGERC = REPO_ROOT / ".coveragerc"

#: The threshold CI enforces today. Lowering it is a change to this file, in the same diff.
CI_COVERAGE_THRESHOLD = 80


def _step(name: str) -> dict[str, Any]:
    action = yaml.safe_load(RUN_UNIT_TESTS.read_text(encoding="utf-8"))
    steps = [s for s in action["runs"]["steps"] if s.get("name") == name]
    assert len(steps) == 1, (
        f"expected one {name!r} step in {RUN_UNIT_TESTS}, got {steps}"
    )
    return steps[0]


def _ci_pytest_argv() -> list[str]:
    """The "Run PyTest" command as argv, with the shell's line continuations joined."""
    command = _step("Run PyTest")["run"].replace("\\\n", " ")
    argv = shlex.split(command)
    assert argv[:3] == ["uv", "run", "pytest"], argv
    return argv


class TestTheUnitTestStepCannotPassBySkipping:
    def test_it_installs_both_extras(self):
        argv = shlex.split(_step("Install dependencies")["run"])
        assert argv[:2] == ["uv", "sync"], argv
        for extra in ("cdk", "symbols"):
            assert f"--extra={extra}" in argv or any(
                a == "--extra" and b == extra for a, b in zip(argv, argv[1:])
            ), f"the unit-test step no longer installs the {extra} extra: {argv}"

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


class TestCoverageIsGatedByTheCiStepOnly:
    def test_the_default_run_measures_no_coverage(self):
        """A run of one directory or one test must not fail on the whole suite's coverage."""
        parser = configparser.ConfigParser()
        parser.read(PYTEST_INI, encoding="utf-8")
        addopts = shlex.split(parser.get("pytest", "addopts"))
        assert "-n" in addopts, f"read the wrong addopts: {addopts}"
        coverage = [opt for opt in addopts if opt.startswith("--cov")]
        assert not coverage, (
            f"pytest.ini's addopts carry {coverage}, so every subset run measures coverage "
            "and fails on a threshold meant for the full suite. Pass coverage options in "
            ".github/actions/run-unit-tests/action.yml instead."
        )

    def test_no_config_file_sets_a_coverage_threshold(self):
        """The 80 lives on the CI command only.

        A fail_under in .coveragerc (or in pyproject.toml's [tool.coverage.report])
        would gate every `pytest --cov` of a subset again, and would be a second place
        the number could drift from the one CI passes.
        """
        parser = configparser.ConfigParser()
        assert parser.read(COVERAGERC, encoding="utf-8"), f"could not read {COVERAGERC}"
        assert parser.has_section("report"), "read the wrong .coveragerc"
        assert not parser.has_option("report", "fail_under"), (
            ".coveragerc sets fail_under again; pass --cov-fail-under from the CI step"
        )
        pyproject = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        assert "[tool.coverage" not in pyproject, (
            "pyproject.toml configures coverage, which .coveragerc is supposed to own"
        )

    def test_the_ci_step_measures_the_package_with_the_threshold(self):
        argv = _ci_pytest_argv()
        assert "--cov=automated_security_helper" in argv, argv
        assert f"--cov-fail-under={CI_COVERAGE_THRESHOLD}" in argv, (
            f"'Run PyTest' does not pass --cov-fail-under={CI_COVERAGE_THRESHOLD}: {argv}"
        )

    def _run_ci_command(
        self, tmp_path: Path, threshold: int
    ) -> subprocess.CompletedProcess:
        """Run the step's own pytest arguments over one planted test, outside the suite.

        The run gets its own ini, rootdir and conftest cut-off, so none of this
        repository's conftests or addopts load, and its own COVERAGE_FILE, so its data
        files never mix with those of the run that is executing this test.
        """
        shutil.copy(COVERAGERC, tmp_path / ".coveragerc")
        (tmp_path / "pytest.ini").write_text("[pytest]\n", encoding="utf-8")
        planted = tmp_path / "test_planted.py"
        planted.write_text(
            "def test_imports_the_package():\n"
            "    import automated_security_helper  # noqa: F401\n",
            encoding="utf-8",
        )
        args = [
            f"--cov-fail-under={threshold}" if a.startswith("--cov-fail-under=") else a
            for a in _ci_pytest_argv()[3:]
        ]
        env = {
            k: v
            for k, v in os.environ.items()
            if not k.startswith(("PYTEST_", "COV_CORE_", "COVERAGE_"))
        }
        env["COVERAGE_FILE"] = str(tmp_path / ".coverage")
        return subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                *args,
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

    def test_the_ci_command_fails_a_run_below_the_threshold(self, tmp_path):
        """The measured half: one import of the package covers far less than 80%."""
        result = self._run_ci_command(tmp_path, CI_COVERAGE_THRESHOLD)
        output = result.stdout + result.stderr
        assert result.returncode != 0, output
        assert re.search(
            rf"Required test coverage of {CI_COVERAGE_THRESHOLD}(\.0+)?% not reached",
            output,
        ), output
        assert (tmp_path / "test-results" / "pytest.coverage.xml").is_file(), (
            "the step's XML report went somewhere other than the path it names"
        )

    def test_the_same_command_passes_with_no_threshold(self, tmp_path):
        """Positive control: the failure above is the threshold, not the harness."""
        result = self._run_ci_command(tmp_path, 0)
        assert result.returncode == 0, result.stdout + result.stderr
        assert "1 passed" in result.stdout, result.stdout


def _pytest_steps() -> dict[str, list[str]]:
    """Every step of the action that runs pytest, as argv."""
    action = yaml.safe_load(RUN_UNIT_TESTS.read_text(encoding="utf-8"))
    steps = {}
    for step in action["runs"]["steps"]:
        argv = shlex.split(str(step.get("run", "")).replace("\\\n", " "))
        if argv[:3] == ["uv", "run", "pytest"]:
            steps[step["name"]] = argv
    return steps


def _junit_path(argv: list[str]) -> str:
    """Where a pytest run writes its JUnit report: its own flag, else pytest.ini's addopts."""
    for i, arg in enumerate(argv):
        if arg.startswith("--junit-xml="):
            return arg.split("=", 1)[1]
        if arg == "--junit-xml":
            return argv[i + 1]
    parser = configparser.ConfigParser()
    parser.read(PYTEST_INI, encoding="utf-8")
    return _junit_path(shlex.split(parser.get("pytest", "addopts")) + ["--junit-xml="])


def _glob_matches(pattern: str, path: str) -> bool:
    """@actions/glob semantics for the patterns used here: ``**/`` spans directories."""
    regex = re.escape(pattern).replace(r"\*\*/", "(?:.*/)?").replace(r"\*", "[^/]*")
    return re.fullmatch(regex, path) is not None


class TestEveryPytestStepKeepsItsOwnReport:
    """Each pytest step writes a junit report of its own.

    pytest.ini's addopts carry ``--junit-xml=test-results/pytest.junit.xml``, and the
    cdk-nag integration step runs after "Run PyTest", so it takes a path of its own:
    on the shared one it would overwrite the full suite's report, and the published
    check would show the 11 cdk-nag tests and nothing else.
    """

    def test_each_pytest_step_writes_a_different_junit_file(self):
        paths = {name: _junit_path(argv) for name, argv in _pytest_steps().items()}
        assert {"Run PyTest", "Run cdk-nag integration tests"} <= paths.keys(), paths
        assert all(paths.values()), paths
        assert len(set(paths.values())) == len(paths), (
            f"two pytest steps write the same JUnit file, so the later one replaces the "
            f"earlier one's report: {paths}"
        )

    def test_the_report_step_publishes_every_junit_file(self):
        reports = {name: _junit_path(argv) for name, argv in _pytest_steps().items()}
        patterns = str(
            _step("Publish PyTest JUnit Test Report")["with"]["report_paths"]
        ).splitlines()
        unpublished = {
            name: path
            for name, path in reports.items()
            if not any(_glob_matches(p.strip(), path) for p in patterns if p.strip())
        }
        assert not unpublished, (
            f"report_paths {patterns} does not match the reports of {unpublished}"
        )

    def test_the_glob_helper_matches_like_actions_glob(self):
        assert _glob_matches("**/pytest.junit.xml", "test-results/pytest.junit.xml")
        assert _glob_matches("**/pytest.junit.xml", "pytest.junit.xml")
        assert _glob_matches("test-results/*.junit.xml", "test-results/a.junit.xml")
        assert not _glob_matches(
            "test-results/*.junit.xml", "test-results/x/a.junit.xml"
        )
        assert not _glob_matches("**/pytest.junit.xml", "test-results/cdk.junit.xml")

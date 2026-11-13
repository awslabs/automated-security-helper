# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The required-checks gate must depend on every job in its own workflow.

Why this file exists
--------------------
``required-checks`` in ``.github/workflows/ash-unified-ci.yml`` is the one context a
ruleset can require, because it is the one check name that does not move with a matrix.
It reports the verdict its ``needs`` already computed, so the share of the workflow it
speaks for is exactly its ``needs`` list.

That used to be guarded by ``EXPECTED_UPSTREAM_JOBS: "8"`` compared against
``len(needs)`` -- both sides inside the gate job, so the comparison could not see the
drift it existed to prevent. Adding a tenth job without adding it to ``needs`` leaves
both sides at 8 and the gate passes over shrunk coverage. The direction it did catch,
updating ``needs`` and forgetting the literal, is the harmless one.

``.github/scripts/assert-required-checks-census.py`` replaces it with a census taken
from the workflow's own ``jobs:`` mapping. This file is what makes that script
trustworthy, and it carries two instruments rather than one:

1. The script's job scanner is dependency-free, because the gate runs on a bare runner
   and reaching the network for PyYAML would put a registry round trip inside the one
   job whose purpose is to be reliable. So the scanner is not taken on trust: every test
   below that reads a workflow cross-checks it against ``yaml.safe_load``, which is
   available here because PyYAML is a test dependency.
2. The census itself is exercised against a synthesized tenth job, so the test proves
   the new instrument catches what the old one could not rather than merely that it
   passes today.

What it does not cover
----------------------
Nothing here runs the gate on a runner, so it cannot prove ``${{ github.job }}``
expands to ``required-checks`` -- that is GitHub's contract, asserted by reading the
step's text rather than by executing it.

Since the gate stopped taking a runner when every dependency succeeded, the census in
``TestTheGateCoversItsWorkflow`` is also the one that runs on a green pull request: this
file runs in every unit-test leg, and the three unit-test jobs are in the gate's
``needs``.
"""

from __future__ import annotations

import importlib.util
import json
import re
import shlex
from pathlib import Path
from typing import Any

import pytest
import yaml

# The unit-test matrix is three jobs, one per runner pool, so each pool has its own
# max-parallel cap. The gate waits for every one of them.
from tests.utils.ci_tiers import TIER_JOB_IDS, UNIT_TEST_JOB_IDS

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = REPO_ROOT / ".github" / "workflows"
UNIFIED_CI = WORKFLOWS / "ash-unified-ci.yml"
CENSUS_SCRIPT = REPO_ROOT / ".github" / "scripts" / "assert-required-checks-census.py"

GATE_JOB = "required-checks"

# The floor exists so a workflow that lost its jobs -- or a scanner that stopped finding
# them -- cannot satisfy the agreement tests by finding nothing on both sides.
_MINIMUM_JOBS_IN_UNIFIED_CI = 8


def _census_module():
    """Loads the gate's script by path; its filename is not a valid module name."""
    spec = importlib.util.spec_from_file_location(
        "_required_checks_census", CENSUS_SCRIPT
    )
    assert spec and spec.loader, f"cannot load {CENSUS_SCRIPT}"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


census = _census_module()


def _workflow_paths() -> list[Path]:
    return sorted(p for p in WORKFLOWS.iterdir() if p.suffix in (".yml", ".yaml"))


def _yaml_job_names(path: Path) -> list[str]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return list((data or {}).get("jobs") or {})


def _needs_of(path: Path, job: str) -> list[str]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    needs = data["jobs"][job].get("needs") or []
    return [needs] if isinstance(needs, str) else list(needs)


def _all_success(names: list[str]) -> dict[str, dict[str, Any]]:
    return {name: {"result": "success"} for name in names}


class TestTheScannerAgreesWithARealYamlParser:
    """The dependency-free scanner is only usable if it matches a real parse.

    Run over every workflow in the repository, not just the gated one, because the
    scanner's hard cases are block scalars and heredocs and those are spread across the
    whole directory. A scanner that happened to be right about one file is not evidence.
    """

    def test_every_workflow_job_list_matches_yaml_safe_load(self):
        paths = _workflow_paths()
        assert len(paths) >= 10, (
            f"only {len(paths)} workflow file(s) found under {WORKFLOWS}. This test is a "
            "comparison over a population; with an empty or tiny population it agrees "
            "with itself and proves nothing."
        )

        mismatches = []
        total_jobs = 0
        for path in paths:
            expected = _yaml_job_names(path)
            actual = census.workflow_job_names(path.read_text(encoding="utf-8"))
            total_jobs += len(expected)
            if expected != actual:
                mismatches.append(
                    f"  {path.name}: yaml.safe_load says {expected}, the scanner says {actual}"
                )

        assert not mismatches, (
            "the gate's dependency-free job scanner disagrees with yaml.safe_load:\n"
            + "\n".join(mismatches)
            + "\n\nThe scanner is what the gate uses on a runner, so a disagreement here "
            "is a gate that is measuring the wrong set of jobs."
        )

        # Positive control on this comparison: two readers returning empty lists agree.
        assert total_jobs >= 20, (
            f"the workflows collectively declare {total_jobs} job(s), which is too few "
            "for this comparison to have compared anything. Either the parse broke or "
            "the workflows are gone."
        )


class TestTheGateCoversItsWorkflow:
    def test_the_census_passes_on_the_tree_as_committed(self):
        needs = _needs_of(UNIFIED_CI, GATE_JOB)
        problems = census.check(
            UNIFIED_CI.read_text(encoding="utf-8"), GATE_JOB, _all_success(needs)
        )
        assert not problems, (
            "the required-checks gate does not cover every job in ash-unified-ci.yml:\n"
            + "\n".join(f"  - {p}" for p in problems)
        )

    def test_the_job_count_is_above_the_floor(self):
        """Positive control. An empty workflow would satisfy the test above vacuously."""
        names = census.workflow_job_names(UNIFIED_CI.read_text(encoding="utf-8"))
        assert len(names) - 1 >= _MINIMUM_JOBS_IN_UNIFIED_CI, (
            f"ash-unified-ci.yml has {len(names)} job(s) including the gate, below the "
            f"floor of {_MINIMUM_JOBS_IN_UNIFIED_CI} gated ones. With no jobs to census "
            "the check above passes without comparing anything."
        )
        assert GATE_JOB in names

    def test_a_tenth_job_outside_needs_is_caught(self):
        """The regression the old literal could not see.

        A job added to the workflow and not to `needs` left `len(needs)` at 8 and
        `EXPECTED_UPSTREAM_JOBS` at 8, so the comparison passed. Asserted here against
        the real file with one synthesized job, so the fixture cannot drift from the
        structure the scanner has to handle.
        """
        text = UNIFIED_CI.read_text(encoding="utf-8")
        needs = _needs_of(UNIFIED_CI, GATE_JOB)

        marker = f"  {GATE_JOB}:\n"
        assert marker in text, "the gate job's key was not found; this fixture is stale"
        drifted = text.replace(
            marker,
            "  advisory-thing:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: echo 'a job nobody added to the gate'\n" + marker,
            1,
        )
        assert drifted != text

        # The old instrument, reproduced: a count against a count.
        assert len(needs) == len(_needs_of(UNIFIED_CI, GATE_JOB)), "sanity"
        assert (
            len(census.workflow_job_names(drifted))
            == len(census.workflow_job_names(text)) + 1
        ), "the synthesized job did not land inside `jobs:`"

        problems = census.check(drifted, GATE_JOB, _all_success(needs))
        assert any("advisory-thing" in p for p in problems), (
            "the census did not report a job that exists in the workflow but is absent "
            f"from the gate's `needs`. Problems reported: {problems}"
        )

    def test_a_job_dropped_from_needs_is_caught(self):
        """The other direction of the same drift: `needs` shrinks, the workflow does not."""
        needs = _needs_of(UNIFIED_CI, GATE_JOB)
        problems = census.check(
            UNIFIED_CI.read_text(encoding="utf-8"), GATE_JOB, _all_success(needs[:-1])
        )
        assert any(needs[-1] in p for p in problems), (
            f"dropping {needs[-1]!r} from `needs` was not reported. Problems: {problems}"
        )

    def test_a_failed_upstream_job_is_still_caught(self):
        """The census must not have displaced the verdict check it shares a step with."""
        needs = _needs_of(UNIFIED_CI, GATE_JOB)
        results = _all_success(needs)
        results[needs[0]] = {"result": "failure"}
        problems = census.check(
            UNIFIED_CI.read_text(encoding="utf-8"), GATE_JOB, results
        )
        assert any(p == f"{needs[0]}: failure" for p in problems), problems

    def test_a_skipped_upstream_job_is_not_tolerated(self):
        """GitHub counts a skipped required check as a pass; this must not."""
        needs = _needs_of(UNIFIED_CI, GATE_JOB)
        results = _all_success(needs)
        results[needs[0]] = {"result": "skipped"}
        problems = census.check(
            UNIFIED_CI.read_text(encoding="utf-8"), GATE_JOB, results
        )
        assert any(p == f"{needs[0]}: skipped" for p in problems), problems


#: The two job-level conditions that keep a gated job running after a dependency failed.
_STATUS_CONDITIONS = ("${{!cancelled()}}", "${{always()}}")


def _jobs_skippable_unseen(jobs: dict[str, Any], gated: list[str]) -> list[str]:
    """Gated jobs that can be skipped without the run being cancelled or a gated job failing.

    A job with `needs:` and no status function is skipped when a dependency fails or is
    skipped. That is harmless when the gate sees the dependency's own result, which
    holds for a gated job that is created on every run: it has no `if:` and no `needs:`
    of its own, so it can only succeed, fail or be cancelled, and the gate runs on the
    last two. ensure-cache is that kind of dependency. Any other dependency is not
    enough: an ungated one reports to nobody, one with an `if:` can be skipped quietly,
    and one with `needs:` of its own can be skipped by a failure the gate never reads.
    Those jobs have to run under `!cancelled()` or `always()` themselves. No other
    job-level `if:` is admitted: a `!cancelled() && needs.<dep>.result == 'success'`
    spells the default out at greater length and adds no case the default lacks, so a
    job that waits only for a dependency of the kind the gate sees carries none.
    """

    def always_runs(name: str) -> bool:
        job = jobs.get(name) or {}
        return name in gated and not job.get("if") and not job.get("needs")

    bad = []
    for name in gated:
        job = jobs[name]
        condition = re.sub(r"\s+", "", str(job.get("if", "")))
        needs = job.get("needs") or []
        needs = [needs] if isinstance(needs, str) else list(needs)
        if condition in _STATUS_CONDITIONS:
            continue
        if not condition and all(always_runs(dep) for dep in needs):
            continue
        bad.append(f"  {name}: needs={job.get('needs')} if={condition!r}")
    return bad


#: Jobs that carry the docs gates, and the commands that are the gate in each: lint
#: runs scripts/verify_docs_freshness.py, integration-test runs the docs examples, and
#: build-docs runs the strict site build and the versioned-site check. Each must run on
#: every pull request, be in required-checks' needs, and report its own exit status.
#: The census above lets a gated job carry `${{ !cancelled() }}` or `${{ always() }}`;
#: these may carry no job-level `if:` at all, so no edit can turn them off for pull
#: requests.
_UNCONDITIONAL_JOBS: dict[str, tuple[str, ...]] = {
    "lint": ("scripts/verify_docs_freshness.py",),
    "integration-test": ("tests/integration/docs",),
    "build-docs": ("mkdocs build", "scripts/docs_versions.py check"),
}
#: (job, command) for every docs gate, for the parametrized tests below.
_GATE_COMMANDS = [
    (job, command)
    for job, commands in _UNCONDITIONAL_JOBS.items()
    for command in commands
]
#: The one step-level condition a docs step may carry: it still runs after an earlier
#: step failed, and only a cancelled run skips it.
_STEP_CONDITION_ALLOWED = "${{!cancelled()}}"
#: Shell control operators. One on the line that runs a gate command hands the step's
#: exit status to another command: `cmd || true` and `cmd; true` always pass.
_CONTROL_OPERATORS = frozenset({"|", "||", "&", "&&", ";", ";;", "|&"})


def _word(command: str) -> str:
    """``command`` as a whole word, so ``--ignore=tests/integration/docs`` is not it."""
    return rf"(?:^|\s){re.escape(command)}(?:\s|$)"


def _runs(step: dict, command: str) -> bool:
    """Whether ``command`` is an argument of the step's `run:`."""
    return re.search(_word(command), str(step.get("run", ""))) is not None


def _step_problems(job: str, step: dict, command: str) -> list[str]:
    """Why a step that runs ``command`` could pass, or be skipped, when it fails."""
    where = f"{job}: the step running {command}"
    problems = []
    condition = re.sub(r"\s+", "", str(step.get("if", "")))
    if condition not in ("", _STEP_CONDITION_ALLOWED):
        problems.append(f"{where} has if: {step['if']!r}")
    if step.get("continue-on-error") not in (None, False):
        problems.append(f"{where} has continue-on-error: {step['continue-on-error']!r}")
    shell = step.get("shell")
    if isinstance(shell, str) and "{0}" in shell and "-e" not in shell.split():
        problems.append(f"{where} runs under shell {shell!r}, which has no -e")
    lines = re.sub(r"\\\n", " ", str(step.get("run", ""))).splitlines()
    for index, line in enumerate(lines):
        if not re.search(_word(command), line):
            continue
        if any(
            re.match(r"\s*set\s+(\+e\b|\+o\s+errexit\b)", earlier)
            for earlier in lines[:index]
        ):
            problems.append(f"{where} turns errexit off before it")
        lexer = shlex.shlex(line, posix=True, punctuation_chars=True)
        lexer.whitespace_split = True
        operators = sorted(set(lexer) & _CONTROL_OPERATORS)
        if operators:
            problems.append(
                f"{where} hands its exit status to another command with "
                f"{' '.join(operators)}"
            )
    return problems


def _ways_to_skip(text: str) -> list[str]:
    """Each way a docs gate could be skipped, or pass while its command fails."""
    jobs = yaml.safe_load(text)["jobs"]
    gate_needs = jobs.get(GATE_JOB, {}).get("needs") or []
    gate_needs = [gate_needs] if isinstance(gate_needs, str) else gate_needs
    problems = []
    for name, commands in _UNCONDITIONAL_JOBS.items():
        if name not in jobs:
            problems.append(f"{name}: the job is gone")
            continue
        job = jobs[name]
        if name not in gate_needs:
            problems.append(f"{name}: not in {GATE_JOB}'s needs")
        if "if" in job:
            problems.append(f"{name}: job-level if: {job['if']!r}")
        if job.get("continue-on-error") not in (None, False):
            problems.append(
                f"{name}: job-level continue-on-error: {job['continue-on-error']!r}"
            )
        for command in commands:
            steps = [s for s in job.get("steps", []) if _runs(s, command)]
            if not steps:
                problems.append(f"{name}: no step runs {command}")
            for step in steps:
                problems += _step_problems(name, step, command)
    return problems


def _with_gate_step(job: str, command: str, change) -> list[str]:
    """The census of the real workflow with ``change`` applied to one docs step."""
    data = yaml.safe_load(UNIFIED_CI.read_text(encoding="utf-8"))
    steps = [s for s in data["jobs"][job]["steps"] if _runs(s, command)]
    assert steps, f"no step in {job} runs {command}; this fixture is stale"
    for step in steps:
        change(step)
    return _ways_to_skip(yaml.safe_dump(data))


class TestTheDocsGatesRunOnEveryPullRequest:
    def test_the_docs_gates_cannot_be_skipped(self):
        problems = _ways_to_skip(UNIFIED_CI.read_text(encoding="utf-8"))
        assert not problems, (
            "a docs gate in ash-unified-ci.yml can be skipped, or pass while it fails. "
            "GitHub reports a skipped job as a success, so the required-checks gate "
            "would pass without it:\n" + "\n".join(f"  - {p}" for p in problems)
        )

    @pytest.mark.parametrize("job", sorted(_UNCONDITIONAL_JOBS))
    def test_a_job_level_if_is_caught(self, job):
        text = UNIFIED_CI.read_text(encoding="utf-8")
        key = f"\n  {job}:\n"
        assert text.count(key) == 1, (
            f"the {job} job's key was not found; fixture is stale"
        )
        drifted = text.replace(
            key, key + "    if: github.event_name != 'pull_request'\n", 1
        )
        assert _ways_to_skip(drifted) == [
            f"{job}: job-level if: \"github.event_name != 'pull_request'\""
        ]

    @pytest.mark.parametrize("job", sorted(_UNCONDITIONAL_JOBS))
    def test_continue_on_error_on_a_docs_job_is_caught(self, job):
        text = UNIFIED_CI.read_text(encoding="utf-8")
        key = f"\n  {job}:\n"
        drifted = text.replace(key, key + "    continue-on-error: true\n", 1)
        assert drifted != text, f"the {job} job's key was not found; fixture is stale"
        assert _ways_to_skip(drifted) == [f"{job}: job-level continue-on-error: True"]

    @pytest.mark.parametrize("job", sorted(_UNCONDITIONAL_JOBS))
    def test_a_docs_job_dropped_from_the_gate_is_caught(self, job):
        data = yaml.safe_load(UNIFIED_CI.read_text(encoding="utf-8"))
        data["jobs"][GATE_JOB]["needs"].remove(job)
        assert _ways_to_skip(yaml.safe_dump(data)) == [
            f"{job}: not in {GATE_JOB}'s needs"
        ]

    @pytest.mark.parametrize("job,command", _GATE_COMMANDS)
    def test_a_skippable_docs_step_is_caught(self, job, command):
        problems = _with_gate_step(
            job, command, lambda s: s.update({"if": "github.event_name == 'push'"})
        )
        assert problems == [
            f"{job}: the step running {command} has if: \"github.event_name == 'push'\""
        ]

    @pytest.mark.parametrize("job,command", _GATE_COMMANDS)
    def test_continue_on_error_on_a_docs_step_is_caught(self, job, command):
        problems = _with_gate_step(
            job, command, lambda s: s.update({"continue-on-error": True})
        )
        assert problems == [
            f"{job}: the step running {command} has continue-on-error: True"
        ]

    @pytest.mark.parametrize("suffix", ["|| true", "; true", "| tee docs.log", "&"])
    @pytest.mark.parametrize("job,command", _GATE_COMMANDS)
    def test_an_exit_status_handed_to_another_command_is_caught(
        self, job, command, suffix
    ):
        def append(step):
            step["run"] = step["run"].rstrip("\n") + f" {suffix}\n"

        problems = _with_gate_step(job, command, append)
        assert len(problems) == 1, problems
        assert problems[0].startswith(
            f"{job}: the step running {command} hands its exit status to another "
            f"command with {suffix.split()[0]}"
        ), problems

    @pytest.mark.parametrize("job,command", _GATE_COMMANDS)
    def test_errexit_turned_off_is_caught(self, job, command):
        def prepend(step):
            step["run"] = "set +e\n" + step["run"]

        assert _with_gate_step(job, command, prepend) == [
            f"{job}: the step running {command} turns errexit off before it"
        ]

    @pytest.mark.parametrize("job,command", _GATE_COMMANDS)
    def test_an_operator_on_another_line_is_not_reported(self, job, command):
        """The control: `echo start || true` on its own line leaves the gate's status."""

        def prepend(step):
            step["run"] = "echo start || true\n" + step["run"]

        assert _with_gate_step(job, command, prepend) == []

    @pytest.mark.parametrize("job,command", _GATE_COMMANDS)
    def test_a_removed_docs_step_is_caught(self, job, command):
        data = yaml.safe_load(UNIFIED_CI.read_text(encoding="utf-8"))
        data["jobs"][job]["steps"] = [
            s for s in data["jobs"][job]["steps"] if not _runs(s, command)
        ]
        problems = _ways_to_skip(yaml.safe_dump(data))
        assert f"{job}: no step runs {command}" in problems, problems


class TestTheScriptRefusesToPassVacuously:
    """Each way this check could find nothing and report success is closed on purpose."""

    def test_an_empty_workflow_raises(self):
        with pytest.raises(ValueError, match="no jobs were found"):
            census.check("name: nothing\non: push\n", GATE_JOB, {})

    def test_a_missing_gate_job_raises(self):
        text = "jobs:\n  lint:\n    runs-on: ubuntu-latest\n"
        with pytest.raises(ValueError, match="is not among the workflow's jobs"):
            census.check(text, GATE_JOB, {})

    def test_a_workflow_holding_only_the_gate_raises(self):
        text = f"jobs:\n  {GATE_JOB}:\n    runs-on: ubuntu-latest\n"
        with pytest.raises(ValueError, match="only job in the workflow"):
            census.check(text, GATE_JOB, {})

    @pytest.mark.parametrize("raw", [None, "", "   "])
    def test_an_absent_needs_context_raises(self, raw):
        with pytest.raises(ValueError, match="NEEDS_JSON is unset or empty"):
            census._load_needs(raw)

    def test_malformed_needs_json_raises(self):
        with pytest.raises(ValueError, match="not valid JSON"):
            census._load_needs("{nope")

    def test_a_needs_context_that_is_not_an_object_raises(self):
        with pytest.raises(ValueError, match="expected an object"):
            census._load_needs(json.dumps(["lint"]))

    # Synthetic fixtures for the shapes the scanner has to survive, each compared against
    # yaml.safe_load rather than against a hand-written expected list.
    #
    # That choice is deliberate and it was earned. The first draft of this test asserted a
    # literal expectation for the heredoc case and failed -- and the scanner was right,
    # the expectation was wrong: a heredoc line de-indented to column 2 really does
    # terminate the block scalar and really is a new job key as far as YAML is concerned.
    # Comparing against the parser removes the possibility of encoding a wrong belief
    # about YAML in the fixture, which is the only kind of mistake a fixture like this
    # can make silently.
    _FIXTURES = {
        "heredoc inside a step": (
            "jobs:\n"
            "  real-job:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: |\n"
            "          python3 - <<'PY'\n"
            "          jobs:\n"
            "            not-a-job: true\n"
            "          PY\n"
            f"  {GATE_JOB}:\n"
            "    runs-on: ubuntu-latest\n"
        ),
        # An earlier draft of the block-scalar regex also matched a bare number, so
        # `timeout-minutes: 5` opened a phantom block scalar and every job after it went
        # missing. That is the shape that would have made the census silently short.
        "numeric job-level values": (
            "jobs:\n"
            "  first:\n"
            "    timeout-minutes: 5\n"
            "  second:\n"
            "    timeout-minutes: 15\n"
            f"  {GATE_JOB}:\n"
            "    runs-on: ubuntu-latest\n"
        ),
        # The scanner reads a key preceded by a sequence dash at the column the dash
        # occupies, not at the column of the dash. Without that, `- run: |` measured its
        # own body against the wrong indentation.
        "folded and chomped block indicators": (
            "jobs:\n"
            "  first:\n"
            "    steps:\n"
            "      - run: >-\n"
            "          one long line\n"
            "      - run: |2\n"
            "          indented\n"
            f"  {GATE_JOB}:\n"
            "    runs-on: ubuntu-latest\n"
        ),
        "needs given as a sequence and as a string": (
            "jobs:\n"
            "  a:\n"
            "    runs-on: ubuntu-latest\n"
            "  b:\n"
            "    needs: a\n"
            f"  {GATE_JOB}:\n"
            "    needs:\n"
            "      - a\n"
            "      - b\n"
        ),
        "comments at the job indentation": (
            "jobs:\n"
            "  # a comment that looks like nothing\n"
            "  first:\n"
            "    runs-on: ubuntu-latest\n"
            "\n"
            "  # another:\n"
            f"  {GATE_JOB}:\n"
            "    runs-on: ubuntu-latest\n"
        ),
    }

    @pytest.mark.parametrize("label", sorted(_FIXTURES))
    def test_the_scanner_matches_yaml_on_each_awkward_shape(self, label):
        text = self._FIXTURES[label]
        expected = list((yaml.safe_load(text) or {}).get("jobs") or {})
        assert expected, f"fixture {label!r} declares no jobs, so it compares nothing"
        assert census.workflow_job_names(text) == expected, (
            f"fixture {label!r}: yaml.safe_load says {expected}, the scanner disagrees"
        )


class TestTheGateActuallyRunsTheScript:
    """The script is only a gate if the gate calls it, and only if nothing else does."""

    def _gate_steps(self) -> list[dict[str, Any]]:
        data = yaml.safe_load(UNIFIED_CI.read_text(encoding="utf-8"))
        return data["jobs"][GATE_JOB]["steps"]

    def test_the_gate_invokes_the_census_script(self):
        script_rel = "assert-required-checks-census.py"
        runs = [step.get("run", "") for step in self._gate_steps()]
        assert any(script_rel in run for run in runs), (
            f"no step in {GATE_JOB} runs {script_rel}, so the script is not wired in and "
            "nothing takes the census on a runner."
        )

    def test_the_gate_passes_its_own_job_key_rather_than_a_literal(self):
        steps = self._gate_steps()
        runs = " ".join(str(step.get("run", "")) for step in steps)
        assert "--gate-job" in runs, "the gate does not tell the script which job it is"

        # The value may be interpolated into the `run:` body or handed over through the
        # environment; the repository's convention is the latter, and both satisfy the
        # property that matters -- the name is read from the run, not written down again.
        env_values = " ".join(
            str(v) for step in steps for v in (step.get("env") or {}).values()
        )
        assert "github.job" in runs + " " + env_values, (
            "--gate-job is passed as a literal. The gate's own name would then be a "
            "third hand-kept copy, which is the shape this whole change removes."
        )

    def test_the_gate_checks_out_the_repository(self):
        """The census reads a file, so a gate without a checkout fails for the wrong reason."""
        uses = [str(step.get("uses", "")) for step in self._gate_steps()]
        assert any(u.startswith("actions/checkout@") for u in uses), (
            f"{GATE_JOB} does not check out the repository, but the census script reads "
            "the workflow off disk."
        )

    def test_the_gate_runs_on_every_non_success_result(self):
        """The gate is skipped only when every dependency succeeded.

        GitHub reports a skipped job as Success, so the gate's `if:` decides the verdict
        on its own whenever it skips the job. It must keep `always()` -- without it the
        implicit `success()` skips the gate on exactly the failures it exists to report
        -- and it must run on a failed or cancelled dependency and on a cancelled run.
        A skipped dependency is reachable only through a cancelled run (see the next
        test), so `cancelled()` is what covers it.

        It does NOT name `skipped`: with a skipped job upstream of a dependency,
        `contains(needs.*.result, 'skipped')` is true even when every direct dependency
        succeeded (probe runs 37631261974 and 37631443473), which put the gate back on a
        runner on every green pull request.
        """
        data = yaml.safe_load(UNIFIED_CI.read_text(encoding="utf-8"))
        condition = re.sub(r"\s+", "", str(data["jobs"][GATE_JOB].get("if", "")))
        assert condition.startswith("${{always()&&("), (
            f"{GATE_JOB}'s `if:` no longer starts from always(): {condition!r}. "
            "Without it a failed dependency skips the gate, and a skipped required "
            "check is a pass."
        )
        for term in (
            "cancelled()",
            "contains(needs.*.result,'failure')",
            "contains(needs.*.result,'cancelled')",
        ):
            assert term in condition, (
                f"{GATE_JOB} does not carry {term!r}, so that outcome reaches the "
                f"ruleset as a skipped gate, which GitHub counts as a pass. "
                f"Condition: {condition!r}"
            )
        assert "'skipped'" not in condition, (
            "the `skipped` term is true whenever any job upstream of a dependency was "
            "skipped, so the gate would take a runner on every green run"
        )
        # Every term must widen when the gate runs, never narrow it.
        assert "success()" not in condition and "!" not in condition, condition
        assert condition.count("&&") == 1, condition

    def test_no_gated_job_can_be_skipped_except_by_a_cancelled_run(self):
        """What lets `cancelled()` stand in for a `skipped` term.

        A job with `needs:` and no status function is skipped whenever a dependency
        fails or is skipped -- and if that dependency is ungated, the gate would see
        neither. So every gated job with `needs` must run under `!cancelled()` or
        `always()`, and no gated job may carry any other job-level `if:`. The one
        exception is a job that waits only for gated jobs that run on every run and
        have no `needs` of their own (ensure-cache): its failure is in the gate's
        `needs`, so the skip that follows it is not unseen.
        """
        data = yaml.safe_load(UNIFIED_CI.read_text(encoding="utf-8"))
        bad = _jobs_skippable_unseen(data["jobs"], _needs_of(UNIFIED_CI, GATE_JOB))
        assert not bad, (
            "these gated jobs can be skipped without the run being cancelled, which "
            "the gate's condition cannot see:\n" + "\n".join(bad)
        )

    @pytest.mark.parametrize("name", TIER_JOB_IDS)
    def test_a_tier_job_waits_only_for_ensure_cache_and_is_skipped_only_with_it(
        self, name
    ):
        """The one place the tier jobs' `needs:` are pinned, with no `if:` beside them.

        The integration-test and e2e-test jobs run beside the unit-test jobs, not after
        them: a wait on the unit jobs would add their slowest leg to the critical path
        and save nothing, since a failed unit leg must not skip the other tiers' signal.
        What does save runners is skipping the tiers when ensure-cache failed, and
        `needs` alone does that: a job with `needs` and no status function in its `if:`
        is skipped when a dependency fails. The gate sees that skip through ensure-cache,
        which is in its own `needs`. An `if:` spelling the same rule out
        (`!cancelled() && needs.ensure-cache.result == 'success'`) is what the unit jobs
        never carried and these six jobs carried for a while; it is refused here as it
        is for the unit jobs, so the census does not learn a second spelling of the
        default.
        """
        jobs = yaml.safe_load(UNIFIED_CI.read_text(encoding="utf-8"))["jobs"]
        assert name in _needs_of(UNIFIED_CI, GATE_JOB), (
            f"{GATE_JOB} does not wait for {name}"
        )
        assert jobs[name]["needs"] == ["ensure-cache"], jobs[name]["needs"]
        assert "if" not in jobs[name], (
            f"{name} has if: {jobs[name]['if']!r}; `needs: [ensure-cache]` alone skips it "
            "when the cache warm-up failed, so a job-level condition is a second spelling "
            "of the default"
        )

    def test_a_job_that_waits_on_an_always_running_gated_job_may_skip_with_it(self):
        jobs = {"base": {}, "leaf": {"needs": ["base"]}}
        assert _jobs_skippable_unseen(jobs, ["base", "leaf"]) == []

    def test_a_job_that_waits_on_an_ungated_job_is_caught(self):
        jobs = {
            "warm": {"if": "github.event_name == 'push'"},
            "leaf": {"needs": ["warm"]},
        }
        assert _jobs_skippable_unseen(jobs, ["leaf"]) == [
            "  leaf: needs=['warm'] if=''"
        ]

    def test_a_job_that_waits_on_a_conditional_gated_job_is_caught(self):
        jobs = {
            "base": {"if": "${{ github.event_name == 'push' }}"},
            "leaf": {"needs": ["base"]},
        }
        problems = _jobs_skippable_unseen(jobs, ["base", "leaf"])
        assert any(p.startswith("  leaf:") for p in problems), problems

    def test_a_job_that_waits_on_a_job_with_needs_of_its_own_is_caught(self):
        jobs = {"a": {}, "b": {"needs": ["a"]}, "c": {"needs": ["b"]}}
        problems = _jobs_skippable_unseen(jobs, ["a", "b", "c"])
        assert [p.strip().split(":")[0] for p in problems] == ["c"], problems

    def test_a_status_function_keeps_a_job_with_any_dependency_running(self):
        jobs = {
            "warm": {"if": "github.event_name == 'push'"},
            "leaf": {"needs": ["warm"], "if": "${{ !cancelled() }}"},
        }
        assert _jobs_skippable_unseen(jobs, ["leaf"]) == []

    @pytest.mark.parametrize(
        "condition",
        [
            "${{ !cancelled() && needs.base.result == 'success' }}",
            "${{ !cancelled() && needs.base.result == 'failure' }}",
            "${{ !cancelled() || needs.base.result == 'success' }}",
            "${{ !cancelled() && needs.base.result == 'success' && github.ref == 'x' }}",
            "${{ needs.base.result == 'success' }}",
            "${{ !cancelled() && needs.other.result == 'success' }}",
        ],
    )
    def test_any_other_condition_on_a_job_with_needs_is_caught(self, condition):
        """No gated job may carry a job-level `if:` other than the two status conditions.

        The first case is the one the census admitted for a while, a `!cancelled()`
        narrowed by a `needs.<dep>.result == 'success'` term. It is the default's own
        rule written out (a job with `needs` and no status function is skipped when the
        dependency fails), so admitting it taught the census a second spelling of the
        default and nothing else; the six tier jobs that carried it carry no `if:` now,
        like the unit jobs.
        """
        jobs = {"base": {}, "other": {}, "leaf": {"needs": ["base"], "if": condition}}
        problems = _jobs_skippable_unseen(jobs, ["base", "other", "leaf"])
        assert [p.strip().split(":")[0] for p in problems] == ["leaf"], problems

    def test_unit_test_carries_the_census_to_the_gate(self):
        """The drift half of the census reaches the gate through unit-test.

        When every dependency succeeds the gate does not run, so the script's census
        is not taken on a runner. TestTheGateCoversItsWorkflow takes it instead, and it
        only gates a merge because this file is collected by the unit-test legs and
        the three unit-test jobs are in the gate's `needs`.
        """
        needs = _needs_of(UNIFIED_CI, GATE_JOB)
        missing = [job_id for job_id in UNIT_TEST_JOB_IDS if job_id not in needs]
        assert not missing, f"{GATE_JOB} does not wait for {missing}"
        assert Path(__file__).resolve().is_relative_to(REPO_ROOT / "tests" / "unit")

    def test_the_old_count_literal_is_gone(self):
        """A regression guard on the fix itself.

        Leaving EXPECTED_UPSTREAM_JOBS behind would be a second, weaker gate that fails
        for a reason the census already covers -- and that a future edit could 'fix' by
        bumping instead of by adding to `needs`.
        """
        # Matched as an assignment rather than as a substring: the comment on the gate
        # names the old variable on purpose, to record what was replaced and why. A
        # substring test would make writing that history impossible.
        assignments = [
            line
            for line in UNIFIED_CI.read_text(encoding="utf-8").splitlines()
            if re.match(r"^\s*EXPECTED_UPSTREAM_JOBS\s*:", line)
        ]
        assert not assignments, (
            "EXPECTED_UPSTREAM_JOBS is set again in ash-unified-ci.yml: "
            f"{assignments}. The census replaced it because a literal compared against "
            "len(needs) is blind to a job that was never added to `needs`."
        )

    def test_that_regression_guard_can_actually_fire(self):
        """Positive control for the guard above, which asserts an absence.

        A test that looks for a pattern nothing produces passes whether or not its
        matcher works. This one proves the matcher matches the shape it is looking for.
        """
        assert re.match(
            r"^\s*EXPECTED_UPSTREAM_JOBS\s*:", '          EXPECTED_UPSTREAM_JOBS: "8"'
        )
        assert not re.match(
            r"^\s*EXPECTED_UPSTREAM_JOBS\s*:",
            '  # This job used to carry `EXPECTED_UPSTREAM_JOBS: "8"` and compare it',
        )

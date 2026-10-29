# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The ``runs-on`` of the tier jobs in ash-unified-ci.yml.

The Linux unit and integration jobs can route their legs to self-hosted runners behind
one repository configuration variable; every other tier job runs on the hosted image it
names. These tests pin the shape of that switch rather than evaluate it, since no GitHub
expression evaluator runs here:

- ``unit-test-linux`` has one expression whose LAST alternative is ``matrix.os``, so an
  unset variable renders the hosted image the job has always used.
- ``integration-test-linux`` carries the same expression, byte for byte: the integration
  jobs run on the runner images of their unit job, and one switch keeps that so.
- The switch is ``vars.ASH_CI_SELF_HOSTED_LINUX`` compared to the string ``true``.
- The repository is public, so the switch admits only ``push``, ``workflow_dispatch``
  and a ``pull_request`` whose head repository is this repository. ``merge_group`` and
  forks are not admitted, whatever the variable says.
- The two runner labels encode the architecture, and ``matrix.os`` selects between them.
- The macOS and Windows jobs of both tiers, every e2e job and ``unit-coverage`` keep the
  literal ``${{ matrix.os }}``. The coverage combine reads the unit tier's data by absolute
  path, which a self-hosted runner has to reproduce; the e2e tier drives the container
  image and the installed scanners, which a bare runner host does not carry.

Each structural check has a negative counterpart on a planted string, so a reverted or
rewritten workflow cannot pass by matching nothing.

Every test here reads YAML in process and starts nothing, so the module is unit tier.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

from tests.utils.ci_tiers import (
    E2E_TEST_JOB_IDS,
    INTEGRATION_TEST_JOB_IDS,
    UNIT_TEST_JOB_IDS,
)

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
UNIFIED_CI = REPO_ROOT / ".github" / "workflows" / "ash-unified-ci.yml"

HOSTED_LITERAL = "${{ matrix.os }}"
VARIABLE = "vars.ASH_CI_SELF_HOSTED_LINUX"
LABELS = ("ash-ci-linux-x64", "ash-ci-linux-arm64")
#: The two jobs that carry the switch. Everything else keeps the hosted literal.
SWITCHED_JOB_IDS = ("unit-test-linux", "integration-test-linux")
HOSTED_JOB_IDS = tuple(
    job_id
    for job_id in (*UNIT_TEST_JOB_IDS, *INTEGRATION_TEST_JOB_IDS, *E2E_TEST_JOB_IDS)
    if job_id not in SWITCHED_JOB_IDS
) + ("unit-coverage",)
#: The events the switch admits. A pull request is admitted only from this repository.
ADMITTED_EVENTS = ("push", "workflow_dispatch", "pull_request")
#: The only comparison that tells a same-repository pull request from a fork's.
HEAD_REPOSITORY_CHECK = (
    "github.event.pull_request.head.repo.full_name == github.repository"
)

#: A runs-on that looks switched but has none of the properties: the planted negative.
PLANTED = "${{ github.event_name == 'push' && 'some-label' || 'ubuntu-latest' }}"


def _jobs() -> dict[str, Any]:
    return yaml.safe_load(UNIFIED_CI.read_text(encoding="utf-8"))["jobs"]


def _runs_on(job_id: str) -> str:
    value = _jobs()[job_id]["runs-on"]
    assert isinstance(value, str), (job_id, value)
    return value


def _one_line(expression: str) -> str:
    return " ".join(expression.split())


class TestTheHostedJobsKeepTheLiteral:
    def test_the_hosted_set_is_the_seven_other_tier_jobs_and_the_coverage_gate(self):
        """Positive control on the list itself: eight jobs, none of them switched.

        Nine tier jobs less the two switched Linux jobs is seven (the macOS and Windows
        jobs of the unit and integration tiers, and all three e2e jobs, the Linux one
        included), plus the coverage gate.
        """
        assert len(HOSTED_JOB_IDS) == 8, HOSTED_JOB_IDS
        assert not set(HOSTED_JOB_IDS) & set(SWITCHED_JOB_IDS)

    @pytest.mark.parametrize("job_id", HOSTED_JOB_IDS)
    def test_runs_on_is_the_matrix_os_literal(self, job_id):
        assert _runs_on(job_id) == HOSTED_LITERAL


class TestTheLinuxJobsAreSwitchedBehindAVariable:
    @pytest.fixture()
    def expression(self) -> str:
        return _one_line(_runs_on("unit-test-linux"))

    def test_the_integration_job_carries_the_same_expression(self, expression):
        assert _one_line(_runs_on("integration-test-linux")) == expression

    def test_it_is_one_expression(self, expression):
        assert expression.startswith("${{ ") and expression.endswith(" }}"), expression
        assert expression.count("${{") == 1, expression

    def test_the_last_alternative_is_the_hosted_image(self, expression):
        """Unset variable, any event: the job renders what it ran on before the switch."""
        assert expression.endswith("|| matrix.os }}"), expression
        assert not _one_line(PLANTED).endswith("|| matrix.os }}")

    def test_the_switch_is_the_repository_variable_compared_to_true(self, expression):
        assert f"{VARIABLE} == 'true'" in expression, expression
        assert expression.index(VARIABLE) < expression.index("github.event_name"), (
            "the variable is the first operand, so an unset variable short-circuits "
            "before any event is read"
        )
        assert VARIABLE not in PLANTED

    def test_it_admits_exactly_these_events(self, expression):
        named = set(re.findall(r"github\.event_name == '([a-z_]+)'", expression))
        assert named == set(ADMITTED_EVENTS), named
        assert "merge_group" not in expression, (
            "a merge-queue entry carries a fork's commits; it stays hosted"
        )
        planted = set(re.findall(r"github\.event_name == '([a-z_]+)'", PLANTED))
        assert planted != set(ADMITTED_EVENTS)

    def test_a_pull_request_is_admitted_only_from_this_repository(self, expression):
        assert HEAD_REPOSITORY_CHECK in expression, expression
        # The comparison guards the pull_request arm specifically: both sit inside the
        # same parenthesized operand, joined by &&.
        arm = re.search(
            r"\(github\.event_name == 'pull_request' && "
            + re.escape(HEAD_REPOSITORY_CHECK)
            + r"\)",
            expression,
        )
        assert arm, expression
        assert HEAD_REPOSITORY_CHECK not in PLANTED

    def test_the_labels_encode_the_architecture(self, expression):
        for label in LABELS:
            assert f"'{label}'" in expression, (label, expression)
        selector = re.search(
            r"contains\(matrix\.os, '-arm'\) && 'ash-ci-linux-arm64' \|\| 'ash-ci-linux-x64'",
            expression,
        )
        assert selector, expression
        assert not any(label in PLANTED for label in LABELS)

    @pytest.mark.parametrize("job_id", SWITCHED_JOB_IDS)
    def test_the_two_linux_images_map_to_two_different_labels(self, job_id):
        """The selector's input is the os axis; both images must take different arms."""
        images = _jobs()[job_id]["strategy"]["matrix"]["os"]
        arms = {image: ("-arm" in image) for image in images}
        assert set(arms.values()) == {True, False}, arms

    @pytest.mark.parametrize("job_id", SWITCHED_JOB_IDS)
    def test_the_name_and_action_inputs_still_read_matrix_os(self, job_id):
        """The artifact and check names come from inputs.os; the switch leaves them alone."""
        job = _jobs()[job_id]
        assert "${{ matrix.os }}" in job["name"], job["name"]
        action_steps = [
            step
            for step in job["steps"]
            if str(step.get("uses", "")) == "./.github/actions/run-unit-tests"
        ]
        assert len(action_steps) == 1, job["steps"]
        assert action_steps[0]["with"]["os"] == "${{ matrix.os }}", action_steps[0]

    def test_no_other_job_is_switched(self):
        """Two jobs move. A third switched job is a decision, not a side effect."""
        switched = sorted(
            job_id
            for job_id, job in _jobs().items()
            if VARIABLE in _one_line(str(job.get("runs-on", "")))
        )
        assert switched == sorted(SWITCHED_JOB_IDS), switched

    def test_the_workflow_has_no_pull_request_target_trigger(self):
        """A privileged trigger plus a self-hosted runner is the shape GitHub warns about."""
        workflow = yaml.safe_load(UNIFIED_CI.read_text(encoding="utf-8"))
        triggers = workflow.get("on") or workflow.get(True) or {}
        assert "pull_request_target" not in triggers, sorted(triggers)
        assert "pull_request" in triggers, sorted(triggers)

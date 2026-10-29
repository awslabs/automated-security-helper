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
  and a ``pull_request`` whose head repository is this repository and whose author is
  not a bot account. ``merge_group``, forks and bot pull requests (Dependabot's branches
  live in this repository, but they change what the runner would install) are not
  admitted, whatever the variable says.
- The two runner labels encode the architecture, and ``matrix.os`` selects between them.
- The macOS and Windows jobs of both tiers, every e2e job and ``unit-coverage`` keep the
  literal ``${{ matrix.os }}``. The coverage combine reads the unit tier's data by absolute
  path, which a self-hosted runner has to reproduce; the e2e tier drives the container
  image and the installed scanners, which a bare runner host does not carry.

The structural checks read the expression's text. Text alone cannot catch a precedence
mistake (drop the parentheses around the event group and every substring is still there
while a same-repository pull request routes to a self-hosted label with the variable
unset), so the module also EVALUATES the expression: a small interpreter for the subset
GitHub Actions expressions use here (string literals, dotted context names, ``==``,
``!=``, ``&&``, ``||``, parentheses, ``contains()``), with GitHub's semantics for the
operators (``&&`` and ``||`` return an operand, string comparison ignores case, an
unset context is the empty string), and a truth table over the variable, the event, the
pull request's origin and author, and the two Linux images. A mutant of the real
expression with the event parentheses removed must fail that table, which is the
control on the evaluator itself.

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
#: Keeps a bot's pull request (Dependabot's, an app's) on the hosted image: its branch
#: lives in this repository, but what it changes is the packages the runner would install.
NOT_A_BOT_CHECK = "github.event.pull_request.user.type != 'Bot'"

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


# --------------------------------------------------------------------------- evaluator
#
# The subset of the GitHub Actions expression language the runs-on uses, evaluated with
# GitHub's documented semantics: `&&` returns its left operand when that is falsy and its
# right operand otherwise; `||` returns its left operand when that is truthy and its right
# operand otherwise; `==` and `!=` compare strings ignoring case; `contains(a, b)` is a
# case-insensitive substring test on strings; a context path that is not set is the empty
# string; the empty string and false are falsy, everything else is truthy. Nothing else is
# implemented, on purpose: a token this grammar does not know is an error, so a rewrite of
# the expression that leans on a construct these tests never saw fails loudly.

_TOKEN = re.compile(
    r"\s*(?:(?P<str>'(?:[^']|'')*')|(?P<op>==|!=|&&|\|\||[(),])|(?P<name>[A-Za-z_][\w.\-]*))"
)


def _tokenize(source: str) -> list[tuple[str, str]]:
    tokens: list[tuple[str, str]] = []
    pos = 0
    source = source.strip()
    while pos < len(source):
        match = _TOKEN.match(source, pos)
        if not match or match.end() == pos:
            raise ValueError(f"cannot tokenize {source[pos:pos + 20]!r}")
        pos = match.end()
        if match.group("str") is not None:
            tokens.append(("str", match.group("str")[1:-1].replace("''", "'")))
        elif match.group("op") is not None:
            tokens.append(("op", match.group("op")))
        else:
            tokens.append(("name", match.group("name")))
    return tokens


class _Expression:
    """A recursive-descent evaluator over the token list, bound to one context."""

    def __init__(self, source: str, context: dict[str, str]) -> None:
        self.tokens = _tokenize(source)
        self.pos = 0
        self.context = context

    def evaluate(self) -> Any:
        value = self._or()
        if self.pos != len(self.tokens):
            raise ValueError(f"trailing tokens: {self.tokens[self.pos:]}")
        return value

    def _peek(self) -> tuple[str, str] | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _take(self, kind: str, text: str | None = None) -> str:
        token = self._peek()
        if token is None or token[0] != kind or (text is not None and token[1] != text):
            raise ValueError(f"expected {kind} {text!r} at {self.pos}, got {token!r}")
        self.pos += 1
        return token[1]

    @staticmethod
    def _truthy(value: Any) -> bool:
        return value is not False and value != ""

    def _or(self) -> Any:
        value = self._and()
        while self._peek() == ("op", "||"):
            self._take("op", "||")
            right = self._and()
            value = value if self._truthy(value) else right
        return value

    def _and(self) -> Any:
        value = self._comparison()
        while self._peek() == ("op", "&&"):
            self._take("op", "&&")
            right = self._comparison()
            value = right if self._truthy(value) else value
        return value

    def _comparison(self) -> Any:
        left = self._primary()
        token = self._peek()
        if token in (("op", "=="), ("op", "!=")):
            self._take("op")
            right = self._primary()
            equal = str(left).lower() == str(right).lower()
            return equal if token[1] == "==" else not equal
        return left

    def _primary(self) -> Any:
        token = self._peek()
        if token is None:
            raise ValueError("unexpected end of expression")
        if token == ("op", "("):
            self._take("op", "(")
            value = self._or()
            self._take("op", ")")
            return value
        if token[0] == "str":
            return self._take("str")
        name = self._take("name")
        if self._peek() == ("op", "("):
            if name != "contains":
                raise ValueError(f"unknown function {name!r}")
            self._take("op", "(")
            haystack = self._or()
            self._take("op", ",")
            needle = self._or()
            self._take("op", ")")
            return str(needle).lower() in str(haystack).lower()
        return self.context.get(name, "")


def _evaluate(expression: str, context: dict[str, str]) -> Any:
    """The value GitHub would give `runs-on` for this expression under this context."""
    inner = _one_line(expression)
    assert inner.startswith("${{") and inner.endswith("}}"), inner
    return _Expression(inner[3:-2], context).evaluate()


#: A GitHub context for one run: the variable, the event, the pull request's origin and
#: author, and the matrix image. Missing keys read as the empty string, as on GitHub.
def _context(
    *,
    variable: str | None,
    event: str,
    os_name: str,
    head_repo: str | None = None,
    author_type: str | None = None,
) -> dict[str, str]:
    context = {
        "github.event_name": event,
        "github.repository": "awslabs/automated-security-helper",
        "matrix.os": os_name,
    }
    if variable is not None:
        context["vars.ASH_CI_SELF_HOSTED_LINUX"] = variable
    if head_repo is not None:
        context["github.event.pull_request.head.repo.full_name"] = head_repo
    if author_type is not None:
        context["github.event.pull_request.user.type"] = author_type
    return context


#: Every pull-request shape the table covers: (head repository, author type).
PR_SHAPES = {
    "same-repo human PR": ("awslabs/automated-security-helper", "User"),
    "same-repo bot PR": ("awslabs/automated-security-helper", "Bot"),
    "fork PR": ("someone/automated-security-helper", "User"),
    "fork bot PR": ("someone/automated-security-helper", "Bot"),
}
#: Variable values the table covers; None is "not set".
VARIABLE_VALUES = (None, "", "true", "TRUE", "True", "false", "1", "yes")
LINUX_IMAGES = ("ubuntu-latest", "ubuntu-24.04-arm")


def _expected(variable: str | None, event: str, shape: str | None, os_name: str) -> str:
    """The label the design promises, written independently of the expression's text."""
    switched_on = variable is not None and variable.lower() == "true"
    if event in ("push", "workflow_dispatch"):
        admitted = True
    elif event == "pull_request":
        admitted = shape == "same-repo human PR"
    else:
        admitted = False
    if switched_on and admitted:
        return "ash-ci-linux-arm64" if "-arm" in os_name else "ash-ci-linux-x64"
    return os_name


def _truth_table(expression: str) -> list[tuple[tuple[Any, ...], Any, str]]:
    """Every (case, actual, expected) row of the table for one expression text."""
    rows = []
    for variable in VARIABLE_VALUES:
        for os_name in LINUX_IMAGES:
            for event in ("push", "workflow_dispatch", "merge_group", "schedule"):
                actual = _evaluate(
                    expression, _context(variable=variable, event=event, os_name=os_name)
                )
                rows.append(
                    ((variable, event, None, os_name), actual, _expected(variable, event, None, os_name))
                )
            for shape, (head_repo, author_type) in PR_SHAPES.items():
                actual = _evaluate(
                    expression,
                    _context(
                        variable=variable,
                        event="pull_request",
                        os_name=os_name,
                        head_repo=head_repo,
                        author_type=author_type,
                    ),
                )
                rows.append(
                    (
                        (variable, "pull_request", shape, os_name),
                        actual,
                        _expected(variable, "pull_request", shape, os_name),
                    )
                )
    return rows


def _without_the_event_parentheses(expression: str) -> str:
    """The mutant the text checks cannot see: the event group's parentheses removed."""
    flat = _one_line(expression)
    open_at = flat.index("(github.event_name == 'push'")
    close_marker = "!= 'Bot'))"
    close_at = flat.index(close_marker) + len(close_marker) - 1
    mutant = flat[:open_at] + flat[open_at + 1 : close_at] + flat[close_at + 1 :]
    assert mutant != flat and mutant.count("(") == flat.count("(") - 1, mutant
    return mutant


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
        assert NOT_A_BOT_CHECK in expression, expression
        # Both comparisons guard the pull_request arm specifically: the three sit inside
        # the same parenthesized operand, joined by &&.
        arm = re.search(
            r"\(github\.event_name == 'pull_request' && "
            + re.escape(HEAD_REPOSITORY_CHECK)
            + r" && "
            + re.escape(NOT_A_BOT_CHECK)
            + r"\)",
            expression,
        )
        assert arm, expression
        assert HEAD_REPOSITORY_CHECK not in PLANTED
        assert NOT_A_BOT_CHECK not in PLANTED

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


class TestTheExpressionEvaluates:
    """What the runs-on DOES under every context the design names, not how it reads."""

    def test_the_evaluator_has_github_semantics(self):
        """Positive controls on the interpreter before it judges the real expression."""
        ctx = {"a": "x", "b": "", "c": "Yes"}
        assert _Expression("'A' == 'a'", ctx).evaluate() is True
        assert _Expression("'A' != 'a'", ctx).evaluate() is False
        assert _Expression("a && 'left-wins-when-truthy'", ctx).evaluate() == (
            "left-wins-when-truthy"
        )
        assert _Expression("b && 'never'", ctx).evaluate() == ""
        assert _Expression("b || 'fallback'", ctx).evaluate() == "fallback"
        assert _Expression("a || 'fallback'", ctx).evaluate() == "x"
        assert _Expression("missing == ''", ctx).evaluate() is True
        assert _Expression("contains('ubuntu-24.04-ARM', '-arm')", ctx).evaluate() is True
        assert _Expression("contains(c, 'no')", ctx).evaluate() is False
        assert _Expression("(b || a) && c", ctx).evaluate() == "Yes"
        with pytest.raises(ValueError):
            _Expression("startsWith(a, 'x')", ctx).evaluate()
        with pytest.raises(ValueError):
            _Expression("a ==", ctx).evaluate()

    def test_the_table_has_the_shape_it_claims(self):
        rows = _truth_table(_runs_on("unit-test-linux"))
        # 8 variable values x 2 images x (4 non-PR events + 4 PR shapes)
        assert len(rows) == 8 * 2 * 8, len(rows)
        expected_labels = {row[2] for row in rows}
        assert expected_labels == {
            "ubuntu-latest",
            "ubuntu-24.04-arm",
            "ash-ci-linux-x64",
            "ash-ci-linux-arm64",
        }, expected_labels

    @pytest.mark.parametrize("job_id", SWITCHED_JOB_IDS)
    def test_every_context_renders_the_label_the_design_promises(self, job_id):
        rows = _truth_table(_runs_on(job_id))
        wrong = [(case, actual, expected) for case, actual, expected in rows if actual != expected]
        assert not wrong, wrong

    @pytest.mark.parametrize("job_id", SWITCHED_JOB_IDS)
    def test_with_the_variable_unset_every_context_is_the_hosted_image(self, job_id):
        """The default the pull request's own run measures: no label, ever."""
        rows = _truth_table(_runs_on(job_id))
        for case, actual, _ in rows:
            if case[0] is None or case[0].lower() != "true":
                assert actual == case[3], (case, actual)

    @pytest.mark.parametrize("job_id", SWITCHED_JOB_IDS)
    def test_a_fork_or_a_bot_never_reaches_a_self_hosted_label(self, job_id):
        rows = _truth_table(_runs_on(job_id))
        for case, actual, _ in rows:
            if case[1] == "pull_request" and case[2] != "same-repo human PR":
                assert actual == case[3], (case, actual)
            if case[1] in ("merge_group", "schedule"):
                assert actual == case[3], (case, actual)

    def test_the_mutant_without_the_event_parentheses_fails_the_table(self):
        """The control on the evaluator: a precedence mistake the text checks cannot see.

        With the parentheses gone, `&&` binds before `||`, so with the variable unset a
        same-repository pull request renders a self-hosted label and workflow_dispatch
        renders a boolean. The table must catch it, or it catches nothing.
        """
        mutant = _without_the_event_parentheses(_runs_on("unit-test-linux"))
        rows = _truth_table(mutant)
        wrong = [(case, actual, expected) for case, actual, expected in rows if actual != expected]
        assert wrong, "the table admitted the mutant"
        unset_same_repo = [
            actual
            for case, actual, _ in rows
            if case[0] is None and case[1] == "pull_request" and case[2] == "same-repo human PR"
        ]
        assert unset_same_repo and all(
            actual in ("ash-ci-linux-x64", "ash-ci-linux-arm64") for actual in unset_same_repo
        ), unset_same_repo
        # And the text checks still pass on the mutant, which is why they are not enough.
        assert f"{VARIABLE} == 'true'" in mutant
        assert mutant.endswith("|| matrix.os }}")
        assert set(re.findall(r"github\.event_name == '([a-z_]+)'", mutant)) == set(
            ADMITTED_EVENTS
        )

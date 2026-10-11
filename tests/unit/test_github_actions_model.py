# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The Actions model in tests/utils/github_actions.py follows GitHub's documented rules.

Why this file exists
--------------------
Three workflow tests decide pass or fail by evaluating expressions, trigger filters and
step shells through that model instead of matching text:
``test_required_scan_installs_ash_from_the_base_branch.py``,
``test_scan_workflow_keeps_the_checkout_out_of_its_installs.py`` and
``test_docs_deploy_write_scope.py``. A model that evaluated ``||`` as a boolean, compared
strings case-sensitively, or let ``*`` match ``/`` would make those tests agree with a
wrong reading of the workflow. Each case below is a rule from GitHub's documentation
("Evaluate expressions in workflows and actions" and "Workflow syntax: filter pattern
cheat sheet"), checked against the model.

What it does not cover
----------------------
Only the subset the workflows here use. Anything else raises ``ExpressionError``, which
one test below pins, so an unmodeled construct fails loudly instead of evaluating to a
plausible value.
"""

from __future__ import annotations

import math

import pytest

from tests.utils import github_actions as ga

CONTEXT = ga.base_context(
    event_name="pull_request",
    head_ref="feature",
    ref="refs/pull/1/merge",
    event={"repository": {"default_branch": "main"}},
)


class TestExpressions:
    @pytest.mark.parametrize(
        "expression,expected",
        [
            # || and && return an operand, not a boolean.
            ("github.head_ref || 'fallback'", "feature"),
            ("github.base_ref || 'fallback'", "fallback"),
            ("'' && 'x'", ""),
            ("'a' && 'b'", "b"),
            # The caller's ash-version idiom, on a pull request.
            (
                (
                    "github.head_ref || (github.event_name == 'merge_group' && "
                    "github.event.repository.default_branch) || github.ref_name"
                ),
                "feature",
            ),
            # Strings compare case-insensitively.
            ("'Pull_Request' == github.event_name", True),
            # Mismatched types are coerced to numbers.
            ("'' == 0", True),
            ("null == 0", True),
            ("true == 1", True),
            ("'true' == true", False),
            ("'abc' == 0", False),
            ("1 == '1'", True),
            # Functions.
            ("startsWith(github.ref, 'REFS/PULL/')", True),
            ("endsWith(github.ref, '/merge')", True),
            ("contains('refs/tags/v3', 'TAGS')", True),
            ("format('refs/heads/{0}', 'main')", "refs/heads/main"),
            ("format('{{0}} is {0}', 'x')", "{0} is x"),
            ("!startsWith(github.ref, 'refs/tags/')", True),
            # A missing property is null.
            ("github.event.pull_request.head.sha", None),
        ],
    )
    def test_documented_semantics(self, expression, expected):
        assert ga.evaluate(expression, CONTEXT) == expected

    def test_nan_is_falsy_and_unequal_to_itself(self):
        assert not ga.truthy(math.nan)
        assert ga.evaluate("'abc' == 'abc'", CONTEXT) is True
        assert ga._equals(math.nan, math.nan) is False

    def test_render_keeps_the_type_of_a_whole_expression(self):
        assert ga.render("${{ true }}", CONTEXT) is True
        assert ga.render("x-${{ true }}", CONTEXT) == "x-true"
        assert ga.render("${{ github.base_ref }}/a", CONTEXT) == "/a"

    def test_an_if_reads_the_same_with_or_without_the_expression_markers(self):
        assert ga.condition_holds("github.event_name == 'pull_request'", CONTEXT)
        assert ga.condition_holds("${{ github.event_name == 'pull_request' }}", CONTEXT)
        assert not ga.condition_holds("github.event_name == 'push'", CONTEXT)
        assert ga.condition_holds(None, CONTEXT)

    def test_an_unmodeled_function_fails_loudly(self):
        with pytest.raises(ga.ExpressionError):
            ga.evaluate("hashFiles('uv.lock')", CONTEXT)


class TestFilterPatterns:
    @pytest.mark.parametrize(
        "patterns,name,expected",
        [
            (["*"], "main", True),
            (["*"], "releases/10", False),  # `*` does not match `/`
            (["**"], "releases/10", True),
            (["v[12].[0-9]+.[0-9]+"], "v1.10.1", True),
            (["v[12].[0-9]+.[0-9]+"], "v2.0.0", True),
            (["v[12].[0-9]+.[0-9]+"], "v3.0.0", False),
            (["v[0-9]+.[0-9]+.[0-9]+"], "v3-docs-preview", False),
            (["v*"], "vanity", True),
            # Order matters: a later negative excludes, a later positive re-includes.
            (["releases/**", "!releases/**-alpha"], "releases/10", True),
            (["releases/**", "!releases/**-alpha"], "releases/beta/3-alpha", False),
            (["!releases/**-alpha", "releases/**"], "releases/beta/3-alpha", True),
        ],
    )
    def test_documented_filter_patterns(self, patterns, name, expected):
        assert ga.filter_matches(patterns, name) is expected

    def _workflow(self, push):
        return ga.Workflow(ga.REPO_ROOT / "synthetic.yml", {True: {"push": push}})

    def _push(self, ref):
        return ga.base_context(event_name="push", ref=ref)

    def test_a_tags_only_filter_does_not_run_for_branches(self):
        workflow = self._workflow({"tags": ["v*"]})
        assert ga.triggers(workflow, self._push("refs/tags/v1"))
        assert not ga.triggers(workflow, self._push("refs/heads/main"))

    def test_a_branches_only_filter_does_not_run_for_tags(self):
        workflow = self._workflow({"branches": ["main"]})
        assert ga.triggers(workflow, self._push("refs/heads/main"))
        assert not ga.triggers(workflow, self._push("refs/tags/v1"))

    def test_no_ref_filter_runs_for_both(self):
        workflow = self._workflow(None)
        assert ga.triggers(workflow, self._push("refs/heads/main"))
        assert ga.triggers(workflow, self._push("refs/tags/v1"))

    def test_path_filters_are_not_applied_to_tag_pushes(self):
        workflow = self._workflow({"branches": ["*"], "tags": ["*"], "paths": ["x/**"]})
        assert ga.triggers(workflow, self._push("refs/tags/v1"))


class TestTheModelReadsTheRealWorkflows:
    """Controls that the model reaches the files the other tests evaluate."""

    def test_every_workflow_has_triggers(self):
        workflows = ga.all_workflows()
        assert len(workflows) >= 10
        missing = [w.name for w in workflows if not w.on]
        assert not missing, f"no `on:` read from {missing} (PyYAML reads `on` as True)"

    def test_every_job_level_if_in_the_repository_evaluates(self):
        """Unmodeled syntax in a job `if:` would make job_runs() guess; none may."""
        unreadable = []
        for workflow in ga.all_workflows():
            for job_id, job in workflow.jobs.items():
                try:
                    ga.condition_holds(job.get("if"), CONTEXT)
                except ga.ExpressionError as error:
                    unreadable.append(f"  {workflow.name}: {job_id}: {error}")
        assert not unreadable, "\n".join(unreadable)


class TestGithubEnvLayering:
    """GITHUB_ENV overrides workflow and job env and yields to the step's own env."""

    def test_both_file_command_forms_are_read(self, tmp_path):
        sandbox = ga.StepSandbox(tmp_path)
        files = sandbox.runner_temp / "_runner_file_commands"
        files.mkdir(exist_ok=True)
        (files / "env").write_text(
            "A=one\nB<<EOF\nline 1\nline 2\nEOF\nA=two\nC=x=y\n", encoding="utf-8"
        )
        assert ga.read_github_env(sandbox) == {
            "A": "two",
            "B": "line 1\nline 2",
            "C": "x=y",
        }

    def test_the_precedence_is_workflow_job_file_step(self, tmp_path):
        sandbox = ga.StepSandbox(tmp_path)
        workflow = ga.Workflow(
            tmp_path / "w.yml",
            {"env": {"W": "workflow", "J": "workflow", "F": "workflow"}},
        )
        job = {"env": {"J": "job", "F": "job"}}
        step = {
            "run": 'printf "%s %s %s %s\\n" "$W" "$J" "$F" "$S"\n',
            "env": {"S": "step", "F2": "${{ env.F }}"},
        }
        run = ga.run_step(
            sandbox,
            workflow,
            job,
            step,
            ga.base_context(),
            github_env={"F": "file", "S": "file"},
        )
        assert run.proc.stdout.strip() == "workflow job file step", run.describe()
        rendered = ga.render_env(
            step["env"], {**ga.base_context(), "env": {"F": "file"}}
        )
        assert rendered["F2"] == "file"

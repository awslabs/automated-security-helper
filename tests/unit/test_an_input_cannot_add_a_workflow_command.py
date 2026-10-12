# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""No step prints an input, or a value read from the checkout, before checking it.

Why this file exists
--------------------
The runner reads every line of a step's stdout and stderr, and a line is a workflow
command when it starts with ``::`` after leading whitespace, or when it holds the
legacy ``##[`` marker anywhere. It ends a line at a carriage return as well as at a
line feed. So a value that holds a line break followed by ``::warning::...``, or that
holds ``##[``, adds a command of its author's choosing to whatever line prints it.

The reusable scan workflow's first two refusals printed the value they refused:
``ash-repo: "a/b\\n::warning::EXTRA"`` produced a second line, ``::warning::EXTRA``.
The same shape was in other steps, and other inputs reached git's, ASH's and actions'
own messages before anything checked them.

What this asserts
-----------------
1. The reusable scan workflow's first step refuses every string input that holds a
   line feed, a carriage return or ``##[``, with one ``::error::`` line that names the
   input and does not print it, and lets ordinary values through, spaces included.
   One trailing line feed, which a one-line YAML block scalar always ends in, is
   dropped first; a second line, two trailing line feeds, a carriage return anywhere
   and a value that is only a line feed are still refused.
2. The checked value is the value used: the check writes each value as its output,
   ``github_actions.checked_inputs`` matches what it writes, and no later step (nor
   the report job) reads a string input as given. The only references left are
   workflow and job env, which cannot read a step's output; each is listed with why.
   A one-line block scalar reaches Run ASH and the config-ref step without its line
   feed.
3. The config-ref step refuses a config-ref that git would read as an option, before
   git runs, and fetches the same commit for ``main`` given as a one-line block scalar
   as for ``main``.
4. The composite actions that print their inputs (prepull-base-image, run-scan-test)
   check them in their first step; the refusals in tool-download-cache and
   validate-container do not print the value they refuse. Their steps use the inputs
   as given, so their check drops no line feed.
5. prepull-base-image refuses an ``ARG BASE_IMAGE`` or ``ARG BASE_IMAGE_DIGEST``
   value that could start a command before it prints either one.
6. The pull request title check refuses such a title before printing it or handing
   it to commitizen.

Each case counts the lines the runner would act on with
``github_actions.workflow_command_lines``, and also requires that the value's text
appears nowhere in the step's output.

What it does not cover
----------------------
The runner itself, the actions a step calls, and ASH's own output. act verification
of these workflows runs separately.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

from tests.utils import github_actions as ga

pytestmark = pytest.mark.skipif(
    os.name == "nt" or shutil.which("bash") is None or shutil.which("git") is None,
    reason="the steps under test are bash steps that run on Linux runners",
)

ACTIONS_DIR = ga.REPO_ROOT / ".github" / "actions"
SCAN_WORKFLOW = ga.WORKFLOWS_DIR / "run-ash-security-scan.yml"
TITLE_WORKFLOW = ga.WORKFLOWS_DIR / "ash-pr-title-check.yml"

MARKER = "EXTRA"

#: Each way a value can add a command: a line feed or a carriage return before a
#: `::` command, and the legacy marker the runner finds anywhere in a line. Each is a
#: real command, so a step that printed it would issue it.
COMMAND_TEXT = [
    pytest.param(f"x\n::warning::{MARKER}", id="line feed"),
    pytest.param(f"x\r::warning::{MARKER}", id="carriage return"),
    pytest.param(f"x ##[warning]{MARKER}", id="legacy marker"),
]

#: Shapes the scan workflow's check refuses even though it drops one trailing line
#: feed first.
REFUSED_AFTER_ONE_LINE_FEED = [
    pytest.param(f"--verbose\n::warning::{MARKER}\n", id="two lines in a block scalar"),
    pytest.param(f"::warning::{MARKER}\n\n", id="two trailing line feeds"),
    pytest.param(f"--verbose\r::warning::{MARKER}\n", id="a carriage return"),
    pytest.param(f"--verbose ##[warning]{MARKER}\n", id="the legacy marker"),
    pytest.param("\n", id="only a line feed"),
]

#: Every git the steps under test run reads a local path or nothing: https is
#: rewritten to a path that does not exist, and only the file protocol is allowed.
NO_NETWORK_GIT = {
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_COUNT": "1",
    "GIT_CONFIG_KEY_0": "url.file:///nonexistent/no-network.insteadOf",
    "GIT_CONFIG_VALUE_0": "https://github.com/",
    "GIT_ALLOW_PROTOCOL": "file",
}


def assert_refused_without_printing(run: ga.StepRun, name: str) -> None:
    """The step failed with one `::error::` line naming `name`, and printed no value."""
    output = run.proc.stdout + run.proc.stderr
    commands = ga.workflow_command_lines(run.proc.stdout, run.proc.stderr)
    assert run.proc.returncode != 0, run.describe()
    assert len(commands) == 1 and commands[0].lstrip().startswith("::error::"), (
        f"expected one ::error:: line and no other workflow command, got {commands}\n"
        f"{run.describe()}"
    )
    assert name in commands[0], (name, commands[0])
    assert MARKER not in output, f"the refused value was printed:\n{run.describe()}"


def assert_clean(run: ga.StepRun) -> None:
    commands = ga.workflow_command_lines(run.proc.stdout, run.proc.stderr)
    assert run.proc.returncode == 0, run.describe()
    assert commands == [], commands


def _git(*args: str, cwd: Path) -> None:
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(cwd),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@example.invalid",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@example.invalid",
    }
    proc = subprocess.run(  # nosec B603 B607 - fixed git argv in a temp directory
        ["git", "-c", "commit.gpgsign=false", "-c", "init.defaultBranch=main", *args],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, f"git {' '.join(args)}: {proc.stderr}"


# --------------------------------------------------------------------- reusable workflow


def _scan_workflow() -> tuple[ga.Workflow, dict[str, Any]]:
    workflow = ga.load_workflow(SCAN_WORKFLOW)
    return workflow, workflow.jobs["ash"]


def _string_inputs() -> list[str]:
    workflow, _ = _scan_workflow()
    declared = (workflow.on.get("workflow_call") or {}).get("inputs") or {}
    return [
        name for name, spec in declared.items() if (spec or {}).get("type") == "string"
    ]


def _scan_context(**with_values: Any) -> dict[str, Any]:
    workflow, _ = _scan_workflow()
    context = ga.base_context(
        event_name="pull_request",
        repository="example/scanned",
        repository_owner="example",
        ref="refs/pull/1/merge",
        event={},
    )
    caller = {"with": dict(with_values)}
    return ga.with_inputs(context, ga.call_inputs(caller, workflow, context))


def _run_first_scan_step(tmp_path: Path, **with_values: Any) -> ga.StepRun:
    workflow, job = _scan_workflow()
    sandbox = ga.StepSandbox(tmp_path / "runner")
    first = (job.get("steps") or [])[0]
    return ga.run_step(
        sandbox,
        workflow,
        job,
        first,
        _scan_context(**with_values),
        extra_env=NO_NETWORK_GIT,
    )


class TestTheScanWorkflowChecksEveryStringInputFirst:
    def test_the_workflow_has_string_inputs_to_check(self):
        # Guards the parametrization below against reading no inputs at all.
        assert {"ash-version", "ash-repo", "config", "output-dir"} <= set(
            _string_inputs()
        )

    @pytest.mark.parametrize("value", COMMAND_TEXT)
    @pytest.mark.parametrize("name", _string_inputs())
    def test_the_first_step_refuses_the_input_without_printing_it(
        self, tmp_path, name, value
    ):
        run = _run_first_scan_step(tmp_path, **{name: value})
        assert_refused_without_printing(run, name)

    def test_the_defaults_pass_the_first_step_and_print_no_command(self, tmp_path):
        workflow, job = _scan_workflow()
        first = (job.get("steps") or [])[0]
        assert "GITHUB_ENV" not in str(first.get("run")), (
            "the first step should only check the inputs; it writes GITHUB_ENV"
        )
        assert_clean(_run_first_scan_step(tmp_path))

    @pytest.mark.parametrize(
        "name,value",
        [
            ("config", "my configs/.ash.yaml"),
            ("output-dir", "out dir/ash output"),
            ("python-version", ">=3.11 <3.14"),
            ("ash-args", "--exclude-scanners cdk-nag --verbose"),
        ],
    )
    def test_ordinary_values_with_spaces_pass(self, tmp_path, name, value):
        assert_clean(_run_first_scan_step(tmp_path, **{name: value}))


def _input_check_step() -> dict[str, Any]:
    _, job = _scan_workflow()
    found = [s for s in job.get("steps") or [] if s.get("id") == ga.INPUT_CHECK_STEP_ID]
    assert len(found) == 1, (
        f"no step with id {ga.INPUT_CHECK_STEP_ID!r} in the scan job"
    )
    return found[0]


def _check_inputs(tmp_path: Path, **with_values: Any) -> tuple[ga.StepRun, dict]:
    """Run the real input check; return its run and the outputs it wrote."""
    workflow, job = _scan_workflow()
    sandbox = ga.StepSandbox(tmp_path / "check")
    run = ga.run_step(
        sandbox,
        workflow,
        job,
        _input_check_step(),
        _scan_context(**with_values),
        extra_env=NO_NETWORK_GIT,
    )
    return run, ga.read_github_output(sandbox)


def _context_from_check(outputs: dict[str, str], **with_values: Any) -> dict[str, Any]:
    """A scan context whose steps.inputs.outputs are what the real check wrote."""
    context = _scan_context(**with_values)
    context["steps"] = {
        **context["steps"],
        ga.INPUT_CHECK_STEP_ID: {"outputs": dict(outputs)},
    }
    return context


class TestOneTrailingLineFeedIsDropped:
    """A YAML block scalar (`ash-args: |`) always ends in a line feed, and nothing can
    follow it, so one is dropped before the check. Anything more is refused."""

    @pytest.mark.parametrize(
        "name,value,checked",
        [
            ("ash-args", "--verbose\n", "--verbose"),
            ("config", "my configs/.ash.yaml\n", "my configs/.ash.yaml"),
            ("config-ref", "main\n", "main"),
        ],
    )
    def test_a_one_line_block_scalar_passes_without_its_line_feed(
        self, tmp_path, name, value, checked
    ):
        run, outputs = _check_inputs(tmp_path, **{name: value})
        assert_clean(run)
        assert outputs[name.replace("-", "_")] == checked, outputs

    @pytest.mark.parametrize(
        "caller_yaml,checked",
        [
            pytest.param("ash-args: |\n  --verbose\n", "--verbose", id="literal |"),
            pytest.param("ash-args: >\n  --verbose\n", "--verbose", id="folded >"),
            pytest.param(
                "ash-args: >\n  --verbose\n  --debug\n",
                "--verbose --debug",
                id="folded >, two source lines folded into one",
            ),
            pytest.param("ash-args: >-\n  --verbose\n", "--verbose", id="folded >-"),
            pytest.param("ash-args: |-\n  --verbose\n", "--verbose", id="literal |-"),
            pytest.param("ash-args: --verbose\n", "--verbose", id="plain scalar"),
            pytest.param(
                "ash-args: |\n  --verbose\n  --debug\n", None, id="literal |, two lines"
            ),
            pytest.param(
                "ash-args: |+\n  --verbose\n\n", None, id="literal |+, kept blank line"
            ),
        ],
    )
    def test_each_way_a_caller_writes_ash_args(self, tmp_path, caller_yaml, checked):
        """The values a caller's YAML gives, read the way the runner reads `with:`.

        A folded scalar (`>`) ends in one line feed like a literal one (`|`), and
        folds its source lines into one, so it passes. None means refused."""
        value = yaml.safe_load(caller_yaml)["ash-args"]
        run, outputs = _check_inputs(tmp_path, **{"ash-args": value})
        if checked is None:
            assert_refused_without_printing(run, "ash-args")
            assert "ash_args" not in outputs, outputs
        else:
            assert_clean(run)
            assert outputs["ash_args"] == checked, outputs

    @pytest.mark.parametrize("value", REFUSED_AFTER_ONE_LINE_FEED)
    @pytest.mark.parametrize("name", ["ash-args", "config-ref"])
    def test_anything_more_is_refused(self, tmp_path, name, value):
        run, outputs = _check_inputs(tmp_path, **{name: value})
        assert_refused_without_printing(run, name)
        assert name.replace("-", "_") not in outputs, outputs

    @pytest.mark.parametrize(
        "with_values",
        [
            pytest.param({}, id="defaults"),
            pytest.param(
                {
                    "ash-args": "--verbose\n",
                    "config": "a b/.ash.yaml",
                    "base-ref": "x\n",
                },
                id="block scalars and spaces",
            ),
        ],
    )
    def test_the_model_writes_what_the_check_writes(self, tmp_path, with_values):
        run, outputs = _check_inputs(tmp_path, **with_values)
        assert_clean(run)
        expected = _scan_context(**with_values)["steps"][ga.INPUT_CHECK_STEP_ID]
        assert outputs == expected["outputs"], (outputs, expected)


#: The references to a string input that the scan workflow keeps as given, with why:
#: workflow and job env cannot read a step's output. (where, input).
RAW_REFERENCES_KEPT = {
    # The pin step replaces both from the checked values before any step uses them.
    ("env/ASH_UVX_SOURCE", "ash-repo"),
    ("env/ASH_UVX_SOURCE", "ash-version"),
    ("env/ASH_ASSETS_URL", "ash-repo"),
    ("env/ASH_ASSETS_URL", "ash-version"),
    # Reads only whether config-ref is empty; the check refuses a lone line feed, so
    # that answer is the same for the checked value.
    ("jobs/ash/env/ASH_DEPENDENCIES_UNKNOWN_TOOLS", "config-ref"),
}


def _raw_input_references() -> set[tuple[str, str]]:
    workflow, _ = _scan_workflow()
    names = _string_inputs()
    pattern = re.compile(
        r"\binputs\.(" + "|".join(map(re.escape, names)) + r")(?![\w-])"
    )
    found: set[tuple[str, str]] = set()

    def walk(node: Any, path: list[str]) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                walk(value, [*path, str(key)])
        elif isinstance(node, list):
            for index, value in enumerate(node):
                walk(value, [*path, str(index)])
        elif isinstance(node, str):
            for match in pattern.finditer(node):
                found.add(("/".join(path), match.group(1)))

    for key in ("env", "jobs"):
        walk(workflow.data.get(key), [key])
    return found


class TestTheCheckedValueIsTheValueUsed:
    def test_only_the_check_and_the_listed_env_read_a_string_input(self):
        check_index = (_scan_workflow()[1].get("steps") or []).index(
            _input_check_step()
        )
        check_prefix = f"jobs/ash/steps/{check_index}/"
        outside = {
            ref
            for ref in _raw_input_references()
            if not ref[0].startswith(check_prefix)
        }
        assert outside == RAW_REFERENCES_KEPT, (
            "a step reads a string input as given instead of the input check's output: "
            f"{sorted(outside - RAW_REFERENCES_KEPT)}; listed but gone: "
            f"{sorted(RAW_REFERENCES_KEPT - outside)}"
        )

    def test_no_later_step_reads_the_check_inputs_environment(self):
        _, job = _scan_workflow()
        steps = job.get("steps") or []
        later = steps[steps.index(_input_check_step()) + 1 :]
        reading = [
            s.get("name")
            for s in later
            if re.search(
                r"\bINPUT_[A-Z_]+\b", str(s.get("run") or "") + str(s.get("env"))
            )
        ]
        assert reading == [], reading

    @pytest.mark.parametrize(
        "step_name,variable,output",
        [
            ("Run ASH", "ASH_ARGS", "ash_args"),
            ("Read the ASH config from config-ref", "CONFIG_REF", "config_ref"),
            (
                "Read the tool config files the config names from config-ref",
                "CONFIG_REF",
                "config_ref",
            ),
        ],
    )
    def test_ash_args_and_config_ref_come_from_the_check(
        self, step_name, variable, output
    ):
        _, job = _scan_workflow()
        (step,) = [s for s in job["steps"] if s.get("name") == step_name]
        expected = f"${{{{ steps.{ga.INPUT_CHECK_STEP_ID}.outputs.{output} }}}}"
        assert (step.get("env") or {}).get(variable) == expected, step.get("env")

    def test_the_report_job_reads_the_scan_jobs_checked_outputs(self):
        workflow, job = _scan_workflow()
        outputs = job.get("outputs") or {}
        assert outputs.get("output-dir") == "${{ steps.inputs.outputs.output_dir }}"
        assert (
            outputs.get("repository-owner")
            == "${{ steps.inputs.outputs.repository_owner }}"
        )
        report = str(workflow.jobs["report"])
        assert "needs.ash.outputs.output-dir" in report
        assert "needs.ash.outputs.repository-owner" in report

    @pytest.mark.parametrize(
        "step_name,variable,name,value,used",
        [
            ("Run ASH", "ASH_ARGS", "ash-args", "--verbose\n", "--verbose"),
            (
                "Read the ASH config from config-ref",
                "CONFIG_REF",
                "config-ref",
                "main\n",
                "main",
            ),
        ],
    )
    def test_a_one_line_block_scalar_reaches_the_step_without_its_line_feed(
        self, tmp_path, step_name, variable, name, value, used
    ):
        run, outputs = _check_inputs(tmp_path, **{name: value})
        assert_clean(run)
        _, job = _scan_workflow()
        (step,) = [s for s in job["steps"] if s.get("name") == step_name]
        context = _context_from_check(outputs, **{name: value})
        assert ga.render_env(step.get("env"), context)[variable] == used


class TestNothingReadsAnUncheckedValueAfterARefusal:
    """Steps that run after a failure must not reach a value nobody checked: before the
    pin step succeeds, ASH_UVX_SOURCE and ASH_ASSETS_URL hold ash-repo and ash-version
    as given, and uvx prints its source in its errors."""

    def _running_after(self, steps_context: dict[str, Any]) -> list[dict[str, Any]]:
        _, job = _scan_workflow()
        steps = job.get("steps") or []
        context = {**_scan_context(), "__status__": "failure"}
        context["steps"] = {**context["steps"], **steps_context}
        start = steps.index(_input_check_step()) + 1
        return [s for s in steps[start:] if ga.condition_holds(s.get("if"), context)]

    def test_no_step_runs_after_the_input_check_refused(self):
        running = self._running_after(
            {ga.INPUT_CHECK_STEP_ID: {"outcome": "failure", "outputs": {}}}
        )
        assert [s.get("name") for s in running] == []

    def test_no_step_reads_the_unpinned_ash_source_after_the_pin_failed(self):
        running = self._running_after(
            {
                ga.INPUT_CHECK_STEP_ID: {"outcome": "success", "outputs": {}},
                "ash-pin": {"outcome": "failure", "outputs": {}},
            }
        )
        reading = [
            s.get("name")
            for s in running
            if re.search(r"ASH_UVX_SOURCE|ASH_ASSETS_URL", str(s.get("run") or ""))
        ]
        assert reading == [], reading
        assert running, "no step runs after a failed pin; the locator is broken"


class TestConfigRefIsNotReadAsAnOption:
    """git fetch reads `--upload-pack=<command>` after the remote name as an option,
    and runs that command for a local or ssh remote."""

    def _config_ref_step(self) -> dict[str, Any]:
        _, job = _scan_workflow()
        (step,) = [s for s in job["steps"] if s.get("id") == "config-ref"]
        return step

    @pytest.mark.parametrize(
        "config_ref",
        [
            pytest.param("--upload-pack=touch {marker}", id="an option"),
            pytest.param("main --upload-pack=touch {marker}", id="a space"),
        ],
    )
    def test_the_step_refuses_before_git_runs(self, tmp_path, config_ref):
        workflow, job = _scan_workflow()
        sandbox = ga.StepSandbox(tmp_path / "runner")
        origin = tmp_path / "origin.git"
        _git("init", "-q", "--bare", str(origin), cwd=tmp_path)
        _git("init", "-q", ".", cwd=sandbox.workspace)
        _git("remote", "add", "origin", str(origin), cwd=sandbox.workspace)
        marker = tmp_path / "upload-pack-ran"
        value = config_ref.format(marker=marker)
        context = _scan_context(**{"config-ref": value, "config": ".ash/.ash.yaml"})
        run = ga.run_step(
            sandbox,
            workflow,
            job,
            self._config_ref_step(),
            context,
            extra_env={"GIT_ALLOW_PROTOCOL": "file", "GIT_CONFIG_NOSYSTEM": "1"},
        )
        assert not marker.exists(), (
            f"git ran the upload-pack command named by config-ref:\n{run.describe()}"
        )
        assert run.proc.returncode != 0, run.describe()
        commands = ga.workflow_command_lines(run.proc.stdout, run.proc.stderr)
        assert len(commands) == 1 and commands[0].startswith("::error::config-ref"), (
            commands,
            run.describe(),
        )
        assert "upload-pack" not in run.proc.stdout + run.proc.stderr, run.describe()

    def test_a_one_line_block_scalar_fetches_what_the_plain_value_fetches(
        self, tmp_path
    ):
        origin = tmp_path / "origin.git"
        seed = tmp_path / "seed"
        seed.mkdir()
        _git("init", "-q", "--bare", str(origin), cwd=tmp_path)
        _git("init", "-q", ".", cwd=seed)
        (seed / ".ash").mkdir()
        (seed / ".ash" / ".ash.yaml").write_text("reporters: {}\n", encoding="utf-8")
        _git("add", "-A", cwd=seed)
        _git("commit", "-q", "-m", "config", cwd=seed)
        _git("push", "-q", str(origin), "HEAD:refs/heads/main", cwd=seed)

        workflow, job = _scan_workflow()
        fetched = {}
        for label, value in (("plain", "main"), ("block scalar", "main\n")):
            with_values = {"config-ref": value, "config": ".ash/.ash.yaml"}
            check, outputs = _check_inputs(tmp_path / label, **with_values)
            assert_clean(check)
            sandbox = ga.StepSandbox(tmp_path / label / "runner")
            _git("init", "-q", ".", cwd=sandbox.workspace)
            _git("remote", "add", "origin", str(origin), cwd=sandbox.workspace)
            run = ga.run_step(
                sandbox,
                workflow,
                job,
                self._config_ref_step(),
                _context_from_check(outputs, **with_values),
                extra_env={"GIT_ALLOW_PROTOCOL": "file", "GIT_CONFIG_NOSYSTEM": "1"},
            )
            assert run.proc.returncode == 0, run.describe()
            fetched[label] = ga.read_github_output(sandbox).get("commit")
        assert fetched["plain"] and fetched["plain"] == fetched["block scalar"], fetched


# --------------------------------------------------------------------- composite actions


def _action(name: str) -> dict[str, Any]:
    return yaml.safe_load(
        (ACTIONS_DIR / name / "action.yml").read_text(encoding="utf-8")
    )


def _action_context(
    doc: dict[str, Any], action_dir: Path, **values: Any
) -> dict[str, Any]:
    inputs = {
        name: (spec or {}).get("default", "")
        for name, spec in (doc.get("inputs") or {}).items()
    }
    inputs.update(values)
    context = ga.base_context(action_path=str(action_dir), event_name="push")
    return ga.with_inputs(context, inputs)


def _run_action_step(
    tmp_path: Path,
    name: str,
    step: dict[str, Any],
    sandbox: ga.StepSandbox | None = None,
    **values: Any,
) -> ga.StepRun:
    doc = _action(name)
    action_dir = ACTIONS_DIR / name
    sandbox = sandbox or ga.StepSandbox(tmp_path / "runner")
    return ga.run_step(
        sandbox,
        ga.Workflow(action_dir / "action.yml", {}),
        {},
        step,
        _action_context(doc, action_dir, **values),
        extra_env={**NO_NETWORK_GIT, "RUNNER_ARCH": "X64"},
    )


def _first_step(name: str) -> dict[str, Any]:
    return _action(name)["runs"]["steps"][0]


#: The inputs each action prints somewhere, and so checks first. run-scan-test's
#: snyk-token is a secret it never prints.
CHECKED_ACTION_INPUTS = [
    ("prepull-base-image", "oci-runner"),
    ("prepull-base-image", "runner-wrapper"),
    ("prepull-base-image", "attempts"),
    ("prepull-base-image", "dockerfile"),
    ("prepull-base-image", "block-registries-on-hit"),
    ("run-scan-test", "method"),
    ("run-scan-test", "os"),
    ("run-scan-test", "config-file"),
    ("run-scan-test", "oci-runner"),
    ("run-scan-test", "offline"),
]


class TestCompositeActionsCheckTheirInputsFirst:
    def test_every_input_but_the_secret_is_listed(self):
        for action in ("prepull-base-image", "run-scan-test"):
            declared = set(_action(action).get("inputs") or {})
            listed = {i for a, i in CHECKED_ACTION_INPUTS if a == action}
            assert declared - listed <= {"snyk-token"}, (action, declared - listed)

    @pytest.mark.parametrize("value", COMMAND_TEXT)
    @pytest.mark.parametrize("action,name", CHECKED_ACTION_INPUTS)
    def test_the_first_step_refuses_the_input_without_printing_it(
        self, tmp_path, action, name, value
    ):
        run = _run_action_step(tmp_path, action, _first_step(action), **{name: value})
        assert_refused_without_printing(run, name)

    @pytest.mark.parametrize(
        "action,values",
        [
            ("prepull-base-image", {}),
            (
                "prepull-base-image",
                {"runner-wrapper": "sudo -E", "oci-runner": "finch"},
            ),
            (
                "run-scan-test",
                {
                    "method": "python-local",
                    "os": "ubuntu-latest",
                    "oci-runner": "docker",
                },
            ),
        ],
    )
    def test_ordinary_values_pass(self, tmp_path, action, values):
        assert_clean(_run_action_step(tmp_path, action, _first_step(action), **values))


class TestARefusalDoesNotPrintTheValueItRefuses:
    @pytest.mark.parametrize("value", COMMAND_TEXT)
    def test_tool_download_cache_mode(self, tmp_path, value):
        (step,) = [
            s
            for s in _action("tool-download-cache")["runs"]["steps"]
            if s.get("name") == "Fail on an unknown mode"
        ]
        run = _run_action_step(tmp_path, "tool-download-cache", step, mode=value)
        assert_refused_without_printing(run, "mode")

    @pytest.mark.parametrize("value", COMMAND_TEXT)
    def test_validate_container_runtime(self, tmp_path, value):
        (step,) = [
            s
            for s in _action("validate-container")["runs"]["steps"]
            if s.get("name") == "Assert this runtime has a scan leg"
        ]
        run = _run_action_step(tmp_path, "validate-container", step, runtime=value)
        assert_refused_without_printing(run, "runtime")


# --------------------------------------------------------------- values from the checkout

DIGEST = "sha256:" + "0" * 64
BASE = "public.ecr.aws/docker/library/python:3.12-slim-bookworm"


class TestBaseImageArgsAreCheckedBeforeTheyArePrinted:
    @pytest.mark.parametrize(
        "base,pin",
        [
            pytest.param(
                f"{BASE}\r::warning::{MARKER}", DIGEST, id="BASE_IMAGE, carriage return"
            ),
            pytest.param(
                f"{BASE}##[warning]{MARKER}", DIGEST, id="BASE_IMAGE, legacy marker"
            ),
            pytest.param(
                BASE,
                f"{DIGEST}\r::warning::{MARKER}",
                id="BASE_IMAGE_DIGEST, carriage return",
            ),
            pytest.param(
                BASE, f"x##[warning]{MARKER}", id="BASE_IMAGE_DIGEST, legacy marker"
            ),
        ],
    )
    def test_the_pull_step_refuses_the_value_without_printing_it(
        self, tmp_path, base, pin
    ):
        sandbox = ga.StepSandbox(tmp_path / "runner")
        # A runtime that answers nothing, so no step reaches a real one.
        sandbox.install_stub("docker", sandbox.stub_dir)
        (sandbox.workspace / "Dockerfile").write_bytes(
            f"ARG BASE_IMAGE={base}\nARG BASE_IMAGE_DIGEST={pin}\nFROM ${{BASE_IMAGE}}\n".encode()
        )
        (step,) = [
            s
            for s in _action("prepull-base-image")["runs"]["steps"]
            if s.get("id") == "pull"
        ]
        run = _run_action_step(tmp_path, "prepull-base-image", step, sandbox=sandbox)
        assert_refused_without_printing(run, "BASE_IMAGE")


# --------------------------------------------------------------------- pull request title


class TestThePullRequestTitleIsCheckedBeforeItIsPrinted:
    def _title_step(self) -> tuple[ga.Workflow, dict[str, Any], dict[str, Any]]:
        workflow = ga.load_workflow(TITLE_WORKFLOW)
        job = workflow.jobs["pr-title"]
        (step,) = [
            s
            for s in job["steps"]
            if s.get("name") == "Validate PR title with commitizen"
        ]
        return workflow, job, step

    def _run(self, tmp_path: Path, title: str) -> ga.StepRun:
        workflow, job, step = self._title_step()
        sandbox = ga.StepSandbox(tmp_path / "runner")
        sandbox.install_stub("cz", sandbox.stub_dir)
        context = ga.base_context(
            event_name="pull_request", event={"pull_request": {"title": title}}
        )
        return ga.run_step(sandbox, workflow, job, step, context)

    @pytest.mark.parametrize("value", COMMAND_TEXT)
    def test_the_title_is_refused_before_commitizen_sees_it(self, tmp_path, value):
        run = self._run(tmp_path, f"fix: {value}")
        assert_refused_without_printing(run, "title")
        assert run.calls_to("cz") == [], run.describe()

    def test_an_ordinary_title_reaches_commitizen(self, tmp_path):
        run = self._run(tmp_path, "fix(ci): keep inputs out of workflow commands")
        assert_clean(run)
        assert [c["argv"] for c in run.calls_to("cz")] == [
            ["check", "--message", "fix(ci): keep inputs out of workflow commands"]
        ]

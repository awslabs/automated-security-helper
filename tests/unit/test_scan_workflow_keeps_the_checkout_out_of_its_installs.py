# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The reusable scan workflow does not let the scanned checkout steer its own tooling.

Why this file exists
--------------------
``run-ash-security-scan.yml`` checks out the repository it scans and then, in the same
job, installs scanners and runs ASH helper code. Three mechanisms let the checkout
decide what those steps do, before the scan starts:

* ``ash dependencies install`` takes its source directory from the working directory,
  resolves its config from ``ASH_CONFIG`` or by discovery in that directory, imports
  every ``ash_plugin_modules`` entry the config names, and builds each plugin from that
  config's section (``automated_security_helper/cli/dependencies.py``, ``install``).
  The Install Grype and Install Syft steps ran it from the checkout with ``ASH_CONFIG``
  set from the ``config`` input. The Install OpenGrep step already runs it from
  ``RUNNER_TEMP`` with ``ASH_CONFIG`` unset, and so does any step that installs a tool
  the same way; this file holds every install step to that shape.
* ``python -m`` and ``python -c`` put the working directory first on ``sys.path``. Run
  from a checkout that contains ``automated_security_helper/`` (ASH scanning itself, so
  the pull request's tree), ``uv run ... -- python -m automated_security_helper...``
  imports the checkout's module rather than the ``ASH_UVX_SOURCE`` it installed, and
  ``python3 -c 'import json ...'`` imports a ``json.py`` at the checkout's root before
  the standard library's. The OpenGrep pin lookup passes ``-I`` for this reason (see its
  comment); the cache-key and database-age steps did not.
* ``uv run`` reads uv settings (``[tool.uv]`` in ``pyproject.toml``, ``uv.toml``) from the
  directory it runs in, even with ``--no-project``. Measured with uv 0.12.0: the debug log
  says ``Found workspace configuration at <cwd>/pyproject.toml`` and resolution then goes
  to the index that file names; ``--no-config`` stops it; ``uvx`` reads neither. So the
  checkout chose the package index the helpers' dependencies came from, the OpenGrep pin
  lookup included.

What this asserts
-----------------
Each step's own shell is run, extracted from the YAML, with ``uv``, ``uvx``, ``grype``
and friends replaced by stubs that record argv, working directory and environment
(``tests/utils/github_actions.py``), under a runner-shaped layout where ``RUNNER_TEMP``
is a sibling of the checkout.

1. Every ``ash dependencies install`` is started outside the checkout with ``ASH_CONFIG``
   unset or empty, both with the ``config`` input empty (this repository's caller) and set.
   Control: Install OpenGrep, which passes before the fix.
2. Every python the job starts, directly or through ``uv run``, either isolates
   ``sys.path`` (``-I``/``-P``/``PYTHONSAFEPATH``) or runs outside the checkout. Control:
   the OpenGrep pin lookup.
3. Every ``uv run`` either skips config discovery (``--no-config``/``UV_NO_CONFIG``) or runs
   outside the checkout. Controls: a frozen fixed command passes and the frozen pre-fix
   command fails the same predicate, so the predicate can tell them apart.

Steps are located by content, not by name, so a renamed or merged step is still checked,
and so is a step added later. ``test_the_install_steps_found_install_grype_and_syft`` fails
if the locator stops finding the Install Grype and Install Syft steps.

What it does not cover
----------------------
The ``Run ASH`` and ``Show ASH Summary Report`` steps run ASH on the checkout on purpose
(it is what they scan); ``uvx`` there reads no settings from the checkout (measured above).
The uv measurement is uv 0.12.0 locally; the runner's uv version is whatever ``setup-uv``
installs. That version is named in the workflow rather than taken from the checkout's
``required-version`` (``TestUvItselfIsNotChosenByTheCheckout``, added with the fix);
that check reads the step's inputs and relies on setup-uv's documented default.
"""

from __future__ import annotations

import os
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
import yaml

from tests.utils import github_actions as ga

SCAN_WORKFLOW = ga.WORKFLOWS_DIR / "run-ash-security-scan.yml"
JOB_ID = "ash"
REPO = "awslabs/automated-security-helper"

_REQUIRES_BASH = pytest.mark.skipif(
    os.name == "nt" or shutil.which("bash") is None,
    reason="the steps under test are bash steps that run on ubuntu-latest",
)

pytestmark = _REQUIRES_BASH


def _workflow_and_job() -> tuple[ga.Workflow, dict[str, Any]]:
    workflow = ga.load_workflow(SCAN_WORKFLOW)
    return workflow, workflow.jobs[JOB_ID]


def _steps_whose_run_contains(fragment: str) -> list[str]:
    _, job = _workflow_and_job()
    return [
        str(step.get("name"))
        for step in job.get("steps") or []
        if fragment in str(step.get("run") or "")
    ]


def _step(name: str) -> dict[str, Any]:
    _, job = _workflow_and_job()
    for step in job.get("steps") or []:
        if str(step.get("name")) == name:
            return step
    raise AssertionError(f"no step named {name!r} in {SCAN_WORKFLOW.name}")


INSTALL_STEPS = _steps_whose_run_contains("ash dependencies install")
PYTHON_STEPS = sorted(
    set(_steps_whose_run_contains("uv run")) | set(_steps_whose_run_contains("python"))
)
UV_RUN_STEPS = _steps_whose_run_contains("uv run")

CONFIG_INPUTS = [
    pytest.param("", id="config input empty"),
    pytest.param(".ash/.ash.yaml", id="config input set"),
]


def _context(config: str) -> dict[str, Any]:
    context = ga.base_context(
        event_name="pull_request",
        repository=REPO,
        repository_owner=REPO.split("/")[0],
        ref="refs/pull/812/merge",
        ref_name="812/merge",
        head_ref="feature-branch",
        base_ref="main",
        event={
            "repository": {"default_branch": "main", "full_name": REPO},
            "pull_request": {
                "head": {"ref": "feature-branch", "repo": {"full_name": REPO}},
                "base": {"ref": "main", "repo": {"full_name": REPO}},
            },
        },
    )
    workflow, _ = _workflow_and_job()
    caller = {
        "with": {
            "install-grype": True,
            "install-syft": True,
            "install-opengrep": True,
            "install-cfn-nag": True,
            "config": config,
        }
    }
    return ga.with_inputs(context, ga.call_inputs(caller, workflow, context))


def _sandbox(tmp_path: Path) -> ga.StepSandbox:
    """A checkout shaped like ASH scanning itself, with a repository config in it."""
    sandbox = ga.StepSandbox(tmp_path)
    (sandbox.workspace / ".ash").mkdir()
    (sandbox.workspace / ".ash" / ".ash.yaml").write_text(
        yaml.safe_dump({"ash_plugin_modules": ["module_named_by_the_checkout"]}),
        encoding="utf-8",
    )
    (sandbox.workspace / "automated_security_helper").mkdir()
    # The database guards call "${ASH_TOOL_BIN}/grype" directly.
    sandbox.install_stub("grype", sandbox.runner_temp / "ash-tools")
    return sandbox


def _run(sandbox: ga.StepSandbox, step: dict[str, Any], config: str = "") -> ga.StepRun:
    workflow, job = _workflow_and_job()
    built = (datetime.now(timezone.utc) - timedelta(hours=3)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    return ga.run_step(
        sandbox, workflow, job, step, _context(config), extra_env={"STUB_BUILT": built}
    )


def _install_calls(run: ga.StepRun) -> list[dict[str, Any]]:
    return [
        call
        for call in run.calls_to("uvx")
        if "dependencies" in call["argv"] and "install" in call["argv"]
    ]


def _python_launches(run: ga.StepRun) -> list[dict[str, Any]]:
    return [call for call in run.calls if ga.python_options(call) is not None]


def _sys_path_problem(sandbox: ga.StepSandbox, call: dict[str, Any]) -> str | None:
    options = ga.python_options(call) or []
    if ga.isolates_sys_path(options, call["env"]):
        return None
    where = ga.effective_directory(call) if call["tool"] == "uv" else call["cwd"]
    if not sandbox.is_inside_workspace(where):
        return None
    return (
        f"{call['tool']} {' '.join(call['argv'])}\n    runs in {where} (the checkout) "
        f"with interpreter options {options}, so the checkout is first on sys.path"
    )


def _uv_config_problem(sandbox: ga.StepSandbox, call: dict[str, Any]) -> str | None:
    if "--no-config" in ga.uv_global_args(call["argv"]):
        return None
    if str(call["env"].get("UV_NO_CONFIG") or "").lower() in ("1", "true", "yes"):
        return None
    where = ga.effective_directory(call)
    if not sandbox.is_inside_workspace(where):
        return None
    return (
        f"uv {' '.join(call['argv'])}\n    runs in {where} (the checkout) without "
        "--no-config, so uv reads the checkout's [tool.uv] / uv.toml"
    )


class TestToolInstallsRunOutsideTheCheckout:
    @pytest.mark.parametrize("config", CONFIG_INPUTS)
    @pytest.mark.parametrize("step_name", INSTALL_STEPS)
    def test_ash_dependencies_install_runs_outside_the_checkout_without_its_config(
        self, tmp_path, step_name, config
    ):
        sandbox = _sandbox(tmp_path)
        run = _run(sandbox, _step(step_name), config)
        calls = _install_calls(run)
        assert calls, (
            f"step {step_name!r} ran no `ash dependencies install`:\n" + run.describe()
        )
        for call in calls:
            assert not sandbox.is_inside_workspace(call["cwd"]), (
                f"step {step_name!r} runs `uvx {' '.join(call['argv'])}` in "
                f"{call['cwd']}, the checkout. `ash dependencies install` resolves its config from the "
                "working directory and imports the plugin modules that config names, so "
                "the scanned repository picks what is installed. Run it from "
                "RUNNER_TEMP, as Install OpenGrep does.\n" + run.describe()
            )
            assert call["env"]["ASH_CONFIG"] in (None, ""), (
                f"step {step_name!r} runs `ash dependencies install` with ASH_CONFIG="
                f"{call['env']['ASH_CONFIG']!r}, the caller's scan config. Unset it "
                "(`env -u ASH_CONFIG`), as Install OpenGrep does.\n" + run.describe()
            )

    def test_the_install_steps_found_install_grype_and_syft(self, tmp_path):
        """Control on the locator: the steps this file is about are among those found."""
        tools: set[str] = set()
        for index, name in enumerate(INSTALL_STEPS):
            run = _run(_sandbox(tmp_path / str(index)), _step(name))
            for call in _install_calls(run):
                argv = call["argv"]
                tools |= {argv[i + 1] for i, a in enumerate(argv[:-1]) if a == "--tool"}
        assert {"grype", "syft", "opengrep"} <= tools, (
            f"the install steps found ({INSTALL_STEPS}) install {sorted(tools)}"
        )


class TestHelperCodeComesFromTheInstalledAsh:
    @pytest.mark.parametrize("step_name", PYTHON_STEPS)
    def test_python_started_by_the_scan_job_does_not_import_from_the_checkout(
        self, tmp_path, step_name
    ):
        sandbox = _sandbox(tmp_path)
        run = _run(sandbox, _step(step_name))
        launches = _python_launches(run)
        assert launches, f"step {step_name!r} started no python:\n" + run.describe()
        problems = [p for p in (_sys_path_problem(sandbox, c) for c in launches) if p]
        assert not problems, (
            f"step {step_name!r} starts python with the checkout first on sys.path:\n  "
            + "\n  ".join(problems)
            + "\nPass -I (as the OpenGrep pin lookup does) or run it outside the "
            "checkout.\n" + run.describe()
        )

    @pytest.mark.parametrize("step_name", UV_RUN_STEPS)
    def test_uv_started_by_the_scan_job_does_not_read_the_checkouts_uv_settings(
        self, tmp_path, step_name
    ):
        sandbox = _sandbox(tmp_path)
        run = _run(sandbox, _step(step_name))
        calls = [c for c in run.calls_to("uv") if c["argv"][:1] == ["run"]]
        assert calls, f"step {step_name!r} ran no `uv run`:\n" + run.describe()
        problems = [p for p in (_uv_config_problem(sandbox, c) for c in calls) if p]
        assert not problems, (
            f"step {step_name!r} lets the checkout configure uv:\n  "
            + "\n  ".join(problems)
            + "\nPass --no-config or run it outside the checkout.\n"
            + run.describe()
        )


# Frozen on purpose: the pre-fix cache-key command as it stood at 267b77807, and the
# same command in the shape the fix is expected to take. They are run through the same
# harness and predicates as the workflow's own steps.
_FROZEN_PRE_FIX = (
    'uv run --no-project --with "${ASH_UVX_SOURCE}" -- \\\n'
    "  python -m automated_security_helper.utils.content_databases cache-key grype-db\n"
)
_FROZEN_FIXED = (
    '(cd "${RUNNER_TEMP}" && uv run --no-project --with "${ASH_UVX_SOURCE}" -- \\\n'
    "  python -I -m automated_security_helper.utils.content_databases cache-key grype-db)\n"
)
_FROZEN_NO_CONFIG = (
    'uv run --no-config --no-project --with "${ASH_UVX_SOURCE}" -- \\\n'
    "  python -I -m automated_security_helper.utils.content_databases cache-key grype-db\n"
)


class TestTheHarnessCanFail:
    """The predicates above must reject the pre-fix shape and accept the fixed shapes."""

    def _launch(self, tmp_path: Path, script: str) -> tuple[ga.StepSandbox, dict]:
        sandbox = _sandbox(tmp_path)
        run = _run(sandbox, {"name": "frozen", "run": script})
        (call,) = [c for c in run.calls_to("uv") if c["argv"][:1] == ["run"]]
        return sandbox, call

    def test_the_pre_fix_command_is_rejected_by_both_predicates(self, tmp_path):
        sandbox, call = self._launch(tmp_path, _FROZEN_PRE_FIX)
        assert _sys_path_problem(sandbox, call)
        assert _uv_config_problem(sandbox, call)

    def test_the_command_run_from_runner_temp_passes_both_predicates(self, tmp_path):
        sandbox, call = self._launch(tmp_path, _FROZEN_FIXED)
        assert _sys_path_problem(sandbox, call) is None
        assert _uv_config_problem(sandbox, call) is None

    def test_the_command_with_no_config_and_isolation_passes_both_predicates(
        self, tmp_path
    ):
        sandbox, call = self._launch(tmp_path, _FROZEN_NO_CONFIG)
        assert _sys_path_problem(sandbox, call) is None
        assert _uv_config_problem(sandbox, call) is None


class TestUvItselfIsNotChosenByTheCheckout:
    """setup-uv's own default reads the checkout.

    With no ``version`` input, setup-uv v10 installs the uv that ``required-version`` in
    the checkout's ``uv.toml`` or ``pyproject.toml`` names, else the latest (its
    action.yml: "Defaults to the version in pyproject.toml or `latest`"). That uv then
    installs the ASH that scans the checkout, so the version must be named here.
    """

    def test_every_setup_uv_step_in_the_scan_job_names_its_version(self):
        _, job = _workflow_and_job()
        steps = [
            step
            for step in job.get("steps") or []
            if str(step.get("uses") or "").startswith("astral-sh/setup-uv@")
        ]
        assert steps, "the scan job has no setup-uv step; this compared nothing"
        for step in steps:
            inputs = step.get("with") or {}
            assert str(inputs.get("version") or "").strip(), (
                f"step {step.get('name')!r} sets no `version`, so setup-uv installs "
                "the uv the scanned checkout's required-version asks for"
            )
            assert "version-file" not in inputs, (
                f"step {step.get('name')!r} reads its uv version from a file"
            )

    def test_every_setup_uv_step_in_the_scan_job_names_its_cache_directory(self):
        """Without `cache-local-path`, setup-uv takes `cache-dir` from the checkout.

        setup-uv v10 (src/utils/inputs.ts, getCacheLocalPath) reads `cache-dir` from the
        checkout's uv.toml or `[tool.uv]` in pyproject.toml before its own default, and
        restores and saves the cache at that path. An explicit input comes first.
        """
        _, job = _workflow_and_job()
        steps = [
            step
            for step in job.get("steps") or []
            if str(step.get("uses") or "").startswith("astral-sh/setup-uv@")
        ]
        assert steps, "the scan job has no setup-uv step; this compared nothing"
        sandbox_runner_temp = "/home/runner/work/_temp"
        for step in steps:
            value = (step.get("with") or {}).get("cache-local-path")
            assert value, (
                f"step {step.get('name')!r} sets no cache-local-path, so a cache-dir in "
                "the scanned checkout's uv.toml or pyproject.toml decides where the uv "
                "cache is restored and saved"
            )
            rendered = ga.to_string(ga.render(value, ga.base_context()))
            assert rendered.startswith(sandbox_runner_temp + "/"), (
                f"step {step.get('name')!r} puts the uv cache at {rendered!r}, not "
                "under RUNNER_TEMP"
            )


class TestRubyIsNotChosenByTheCheckout:
    """setup-ruby's defaults read version files in the checkout.

    ruby/setup-ruby v1 (action.yml) reads `.ruby-version`, `.tool-versions` or
    `mise.toml` when `ruby-version` is unset, and with its default `bundler:
    Gemfile.lock` installs the Bundler that the BUNDLED WITH section of a
    Gemfile.lock in `working-directory` names. `working-directory` defaults to the
    checkout, so a pull request that adds a Gemfile.lock at its root chose the
    Bundler release the scan job installed and ran.
    """

    def test_every_setup_ruby_step_names_its_versions(self):
        _, job = _workflow_and_job()
        steps = [
            step
            for step in job.get("steps") or []
            if str(step.get("uses") or "").startswith("ruby/setup-ruby@")
        ]
        assert steps, "the scan job has no setup-ruby step; this compared nothing"
        for step in steps:
            inputs = step.get("with") or {}
            assert str(inputs.get("ruby-version") or "").strip() not in (
                "",
                "default",
            ), (
                f"step {step.get('name')!r} lets setup-ruby read the Ruby version "
                "from the checkout"
            )
            bundler = str(inputs.get("bundler") or "Gemfile.lock").strip()
            assert bundler != "Gemfile.lock", (
                f"step {step.get('name')!r} installs the Bundler that a Gemfile.lock "
                "in the checkout names; set `bundler:` explicitly"
            )
            working_directory = str(inputs.get("working-directory") or "")
            assert "runner.temp" in working_directory, (
                f"step {step.get('name')!r} resolves its version files in "
                f"{working_directory or 'the checkout'!r}, not under RUNNER_TEMP"
            )


class TestOnlyTheAshStepsSeeTheConfig:
    """ASH_CONFIG is set on the scan and report steps and nowhere else.

    It used to be workflow-level, so every helper step saw the caller's config path,
    which with config-ref is the checkout's copy, not the one the scan uses. None of
    them reads it today; a later helper that did would read the wrong file.
    """

    @pytest.mark.parametrize(
        "step_name", sorted(set(PYTHON_STEPS) | set(INSTALL_STEPS))
    )
    def test_a_helper_step_runs_without_ash_config(self, tmp_path, step_name):
        sandbox = _sandbox(tmp_path)
        run = _run(sandbox, _step(step_name), ".ash/.ash.yaml")
        calls = [
            c for c in run.calls if c["tool"] in ("uv", "uvx", "python", "python3")
        ]
        assert calls, f"step {step_name!r} started nothing:\n" + run.describe()
        with_config = [c for c in calls if c["env"].get("ASH_CONFIG") not in (None, "")]
        assert not with_config, (
            f"step {step_name!r} runs with ASH_CONFIG set:\n" + run.describe()
        )

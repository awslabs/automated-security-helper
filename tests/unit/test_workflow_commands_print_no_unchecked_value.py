# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A value a step prints in a workflow command cannot add a command of its own.

Why this file exists
--------------------
The runner reads every line of a step's stdout and stderr, and treats a line as a
workflow command when it starts with `::` after leading spaces or holds `##[`
anywhere. It ends a line at a carriage return as well as a line feed. So a step that
prints `::warning::... ${value} ...` with a value holding `\\r::error::...` writes two
commands, and the second one is the value's. The input check
(test_an_input_cannot_add_a_workflow_command.py) covers values that come from
workflow inputs. Values that come from elsewhere (a downloaded database's metadata,
what `command -v` or `uname -m` reports, the config read from config-ref) pass
through one_line, which turns every control character into a space, `::` into
`: :` and `##[` into `# #[`. A definer step writes it to RUNNER_TEMP, once per job,
and the Python steps carry a copy (tests/utils/workflow_commands.py).

What this asserts
-----------------
1. Every value that a workflow-command line under .github/ prints goes through
   one_line or is in ALLOWED, with the reason it cannot hold a line break or a
   command; and every ALLOWED entry is still printed, so the table stays exact.
   OWN_TREE and SERVICE are judgments rather than facts about the value, and are
   refused in a workflow that other repositories call. CHECKED needs an input
   check earlier in the same job.
2. Every definer writes the same helper, and every step that loads it has a
   definer earlier in its own job. Fixtures show both checks can fail.
3. Every Python copy of one_line is the canonical text, and it gives the same
   answer as the bash helper for every control character, separator and marker,
   under every locale a runner may set.
4. Each step whose prints were changed, run with a value holding a carriage
   return, a line feed, `::warning::` and `##[warning]`, prints exactly the
   workflow-command lines it means to and none of the value's command text.
   The config-ref step's cases are in test_required_scan_reads_the_base_branchs_config.py,
   beside the git fixture they need.

What it does not cover
----------------------
Only lines that start a workflow command are read for values. A plain `echo` of a
value can add a command too, if the value holds a line break; the steps changed
here pass those through one_line as well, and the behavior tests hold them to it,
but the census does not look for them elsewhere. Output of the tools a step runs
(ASH itself, uv, bundler) is not read, except where a behavior test runs it. The
scripts under .github/scripts are not read. Steps are run under the model in
tests/utils/github_actions.py, not on a runner.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import unicodedata
from pathlib import Path
from typing import Any

import pytest
import yaml

from tests.utils import github_actions as ga
from tests.utils import workflow_commands as wc

_REQUIRES_BASH = pytest.mark.skipif(
    os.name == "nt" or shutil.which("bash") is None,
    reason="the steps and the helper are bash, as on ubuntu-latest",
)

SCAN_WORKFLOW = ga.WORKFLOWS_DIR / "run-ash-security-scan.yml"
REPO_SCAN = ga.WORKFLOWS_DIR / "ash-repo-scan.yml"
REPO = "awslabs/automated-security-helper"
INPUT_CHECK_NAME = "Refuse an input that could start a workflow command"

# --------------------------------------------------------------------------- 1

#: Why a value is printed as it is. Each holds for the value at that line only.
NUMBER = "a count, an exit status or arithmetic the step computes"
LITERAL = "text the step or its file sets: a fixed path, a command, an input's name"
RUNNER = "set by the runner: its OS and architecture, or a path on its own disk"
WORKFLOW = "a matrix or `with:` value written in a workflow file of this repository"
CHECKED = (
    "an input the job's input check refuses control characters and `##[` in, "
    "or a value made only from such inputs"
)
CHECKED_HERE = (
    "checked for control characters and `##[` in this step, before it is printed"
)
FIXED_FORM = (
    "a value whose form the tool that reports it fixes: a container image id "
    "(sha256:<hex>), a git mode or object type"
)
#: The two judgments. Neither is allowed in a workflow other repositories call.
OWN_TREE = (
    "read from, or produced by a tool run over, the tree the workflow itself comes "
    "from, in a workflow only this repository's events start: a change that could "
    "put a line break in the value could change the workflow too"
)
SERVICE = "returned by GitHub for a pull request the step itself opened"
JUDGMENTS = (OWN_TREE, SERVICE)

_PREPULL = ".github/actions/prepull-base-image/action.yml"
_SCAN_TEST = ".github/actions/run-scan-test/action.yml"
_COMPOSITE = "(composite action)"

ALLOWED: dict[tuple[str, str, str], dict[str, str]] = {
    (_PREPULL, _COMPOSITE, "Compute the base-image cache key"): {"DOCKERFILE": CHECKED},
    (_PREPULL, _COMPOSITE, "Pre-pull the build base image"): {
        "ATTEMPTS": CHECKED,
        "DOCKERFILE": CHECKED,
        "runtime": CHECKED,
        'wrapper[*]+"${wrapper[*]': CHECKED,
        "base": CHECKED_HERE,
        "pin": CHECKED_HERE,
        "primary_repo": CHECKED_HERE,
        "tag": CHECKED_HERE,
        "repo": CHECKED_HERE,
        "ref": CHECKED_HERE,
        "override": CHECKED_HERE,
        "tried": CHECKED_HERE,
        "unanswered": CHECKED_HERE,
        "exhausted": LITERAL,
        "kind": LITERAL,
        "n": NUMBER,
        "sleep_for": NUMBER,
        "pin_id": FIXED_FORM,
        "placed_id": FIXED_FORM,
        "tag_id": FIXED_FORM,
    },
    (_PREPULL, _COMPOSITE, INPUT_CHECK_NAME): {"1": LITERAL},
    (_SCAN_TEST, _COMPOSITE, "Install Community Plugin Tools"): {
        "*": OWN_TREE,
        "attempts": NUMBER,
        "n": NUMBER,
        "n * 10": NUMBER,
    },
    (
        _SCAN_TEST,
        _COMPOSITE,
        "Put ASH's entry point ahead of the MSYS2 toolchain (Windows)",
    ): {"$candidates -join ' ; '": RUNNER},
    (_SCAN_TEST, _COMPOSITE, INPUT_CHECK_NAME): {"1": LITERAL},
    (_SCAN_TEST, _COMPOSITE, "Resolve this runner's platform from the runner itself"): {
        "RUNNER_ARCH": RUNNER,
        "RUNNER_OS": RUNNER,
    },
    (_SCAN_TEST, _COMPOSITE, "Validate ASH using Python Local (Windows)"): {
        "AshPath": RUNNER
    },
    (_SCAN_TEST, _COMPOSITE, "Validate GitLab SAST Report Schema Compliance"): {
        "Bash": LITERAL
    },
    (_SCAN_TEST, _COMPOSITE, "Validate No Plugin Errors (Python Local Windows)"): {
        "ReportExit": NUMBER
    },
    (
        ".github/actions/run-unit-tests/action.yml",
        _COMPOSITE,
        "Resolve this runner's architecture from the runner itself",
    ): {"RUNNER_ARCH": RUNNER},
    (
        ".github/actions/validate-container/action.yml",
        _COMPOSITE,
        "Scan with the built image",
    ): {
        "RUNTIME": WORKFLOW,
        "rc": NUMBER,
    },
    (
        ".github/actions/validate-container/action.yml",
        _COMPOSITE,
        "nerdctl: build image",
    ): {
        "ATTEMPTS": LITERAL,
        "n": NUMBER,
        "rc": NUMBER,
    },
    (
        ".github/actions/validate-mcp/action.yml",
        _COMPOSITE,
        "mcp: install MCP Inspector",
    ): {
        "PKG": LITERAL,
        "attempt": NUMBER,
    },
    (".github/actions/validate-nix/action.yml", _COMPOSITE, "nix: scan"): {
        "rc": NUMBER
    },
    (
        ".github/workflows/ash-create-release.yml",
        "create-release-pr",
        "Create release PR",
    ): {"PR_URL": SERVICE},
    (
        ".github/workflows/ash-create-release.yml",
        "create-release-pr",
        "Determine bump and create release artifacts",
    ): {"LINE_MAJOR": LITERAL, "NEW_VERSION": OWN_TREE},
    (
        ".github/workflows/ash-create-release.yml",
        "create-release-pr",
        "Fold Unreleased notes into the release notes",
    ): {"LINES": NUMBER, "NEXT_TAG": OWN_TREE, "NOTES": OWN_TREE},
    (
        ".github/workflows/ash-create-release.yml",
        "create-release-pr",
        "Resolve release line",
    ): {
        "COUNT": NUMBER,
        "DETECTED:-no": OWN_TREE,
        "LAST_TAG": OWN_TREE,
        "LINE_MAJOR": LITERAL,
        "OLD_VERSION": OWN_TREE,
        "RELEASE_LINE": LITERAL,
    },
    (
        ".github/workflows/ash-iac-drift.yml",
        "cdk-nag",
        "Account for a non-zero synth exit code neither check explained",
    ): {"synth_rc": NUMBER},
    (
        ".github/workflows/ash-iac-drift.yml",
        "cdk-nag",
        "Assert cdk-nag scanned every stack and reported no unsuppressed finding",
    ): {
        "' and '.join(parts)": LITERAL,
        "', '.join(uncovered)": OWN_TREE,
        "MANIFEST": LITERAL,
        "OUT": LITERAL,
        "REGISTER": LITERAL,
        "len(covered)": NUMBER,
        "len(reports)": NUMBER,
        "len(stacks)": NUMBER,
        "name": OWN_TREE,
        "row['compliance']": OWN_TREE,
        "row['resourceId']": OWN_TREE,
        "row['ruleId']": OWN_TREE,
        "row['ruleInfo']": OWN_TREE,
        "row['ruleLevel']": OWN_TREE,
        "stack": OWN_TREE,
    },
    (
        ".github/workflows/ash-iac-drift.yml",
        "cdk-nag",
        "Assert the CloudFormation spec validator reported no error-severity violation",
    ): {
        "description": OWN_TREE,
        "len(fatal)": NUMBER,
        "plugin_name": OWN_TREE,
        "rule": OWN_TREE,
        "severity": OWN_TREE,
        "severity or 'no severity reported'": OWN_TREE,
        "where": OWN_TREE,
    },
    (
        ".github/workflows/ash-iac-drift.yml",
        "cdk-template-drift",
        "Regenerate the committed templates and let git report the drift",
    ): {"REGEN_CMD": LITERAL, "SYNTH_DIR": LITERAL},
    (
        ".github/workflows/ash-iac-drift.yml",
        "discover",
        "Assert no generated path is hidden from git by an ignore rule",
    ): {"path": LITERAL},
    (
        ".github/workflows/ash-iac-drift.yml",
        "generated-buildspec-drift",
        "Ask the construct whether its committed output is current",
    ): {"check_rc": NUMBER},
    (
        ".github/workflows/ash-iac-drift.yml",
        "generated-buildspec-drift",
        "Check the committed buildspecs match the construct",
    ): {"regen_cmd": OWN_TREE},
    (
        ".github/workflows/ash-iac-drift.yml",
        "generated-buildspec-drift",
        "Regenerate the buildspec and let git report the drift",
    ): {"script": OWN_TREE},
    (
        ".github/workflows/ash-iac-drift.yml",
        "terraform-hygiene",
        "Initialize and validate every module and example",
    ): {"dir": OWN_TREE},
    (
        ".github/workflows/ash-iac-drift.yml",
        "terraform-hygiene",
        "Run the modules' terraform tests",
    ): {"dir": OWN_TREE},
    (
        ".github/workflows/ash-install-methods.yml",
        "validate",
        "Assert this install method is routed to a validator",
    ): {"METHOD": WORKFLOW},
    (
        ".github/workflows/ash-package.yml",
        "build",
        "Assert the build produced exactly one wheel and one sdist",
    ): {"#sdists[@]": NUMBER, "#wheels[@]": NUMBER},
    (
        ".github/workflows/ash-tag-on-merge.yml",
        "tag-and-release",
        "Create tag and GitHub Release",
    ): {"CURATED": OWN_TREE, "TAG": OWN_TREE},
    (
        ".github/workflows/ash-tag-on-merge.yml",
        "tag-and-release",
        "Update floating major tag",
    ): {"VERSION": OWN_TREE},
    (
        ".github/workflows/ash-typescript-ci.yml",
        "typescript-tests",
        "Confirm the package is present",
    ): {"matrix.package": WORKFLOW},
    (".github/workflows/ash-unified-ci.yml", "actionlint", "Lint every workflow"): {
        "f": OWN_TREE
    },
    (
        ".github/workflows/ash-unified-ci.yml",
        "actionlint",
        "Self-test -- an unquoted expansion must be reported",
    ): {"rc": NUMBER},
    (
        ".github/workflows/ash-unified-ci.yml",
        "install-validation",
        "Assert this install method is routed to a validator",
    ): {"METHOD": WORKFLOW},
    (".github/workflows/ash-unified-ci.yml", "install-validation", "bundle: verdict"): {
        "failed": LITERAL
    },
    (
        ".github/workflows/ash-unified-ci.yml",
        "sandbox-scanner-parity",
        "Show what sandbox-exec denied the scanners",
    ): {"log": OWN_TREE},
    (
        ".github/workflows/run-ash-security-scan.yml",
        "ash",
        "Pin the ASH ref to a commit",
    ): {
        "ASH_REPO": CHECKED,
        "ASH_VERSION": CHECKED,
    },
    (
        ".github/workflows/run-ash-security-scan.yml",
        "ash",
        "Read the ASH config from config-ref",
    ): {
        "CONFIG_PATH": CHECKED,
        "CONFIG_REF": CHECKED,
        "CONFIG_REF_MISSING": CHECKED,
        "RELATIVE": CHECKED,
        "MODE": FIXED_FORM,
        "TYPE": FIXED_FORM,
    },
    (".github/workflows/run-ash-security-scan.yml", "ash", INPUT_CHECK_NAME): {
        "name//_/-": LITERAL
    },
}


def _printed() -> list[wc.Printed]:
    return wc.printed_values()


def _files_other_repositories_call() -> set[str]:
    found = set()
    for path in wc.workflow_files():
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        on = data.get(True, data.get("on"))
        if isinstance(on, dict) and "workflow_call" in on:
            found.add(path.relative_to(wc.REPO_ROOT).as_posix())
    return found


class TestEveryPrintedValueIsNeutralizedOrAllowed:
    def test_the_census_finds_the_prints(self):
        found = _printed()
        assert len(found) > 150, f"only {len(found)} printed values found"
        assert sum(p.neutralized for p in found) >= 10, "no one_line call was found"

    def test_every_printed_value_goes_through_one_line_or_is_allowed(self):
        unexplained = [
            f"{p.file} | {p.job} | {p.step}: {p.value!r}\n    {p.line}"
            for p in _printed()
            if not p.neutralized
            and p.value not in ALLOWED.get((p.file, p.job, p.step), {})
        ]
        assert not unexplained, (
            "these values are printed in a workflow command without one_line and "
            "without a reason in ALLOWED:\n" + "\n".join(unexplained)
        )

    def test_every_allowed_entry_is_still_printed(self):
        printed = {(p.file, p.job, p.step, p.value) for p in _printed()}
        stale = [
            f"{where} {value!r}"
            for where, values in ALLOWED.items()
            for value in values
            if (*where, value) not in printed
        ]
        assert not stale, "ALLOWED names values no longer printed:\n" + "\n".join(stale)

    def test_no_judgment_is_allowed_in_a_workflow_other_repositories_call(self):
        called = _files_other_repositories_call()
        assert ".github/workflows/run-ash-security-scan.yml" in called, called
        judged = [
            f"{where} {value!r}"
            for where, values in ALLOWED.items()
            for value, reason in values.items()
            if where[0] in called and reason in JUDGMENTS
        ]
        assert not judged, "\n".join(judged)

    def test_a_checked_value_follows_an_input_check_in_its_job(self):
        steps_by_job = {}
        for path in wc.workflow_files():
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            for job, steps in wc.jobs_and_steps(data):
                where = path.relative_to(wc.REPO_ROOT).as_posix()
                steps_by_job[(where, job)] = [str(s.get("name")) for s in steps]
        missing = []
        for (file, job, step), values in ALLOWED.items():
            if CHECKED not in values.values():
                continue
            names = steps_by_job[(file, job)]
            if INPUT_CHECK_NAME not in names[: names.index(step)]:
                missing.append(f"{file} | {job} | {step}")
        assert not missing, "CHECKED with no input check before it:\n" + "\n".join(
            missing
        )

    def test_a_value_checked_here_is_checked_in_its_step(self):
        for (file, job, step), values in ALLOWED.items():
            if CHECKED_HERE not in values.values():
                continue
            data = yaml.safe_load((wc.REPO_ROOT / file).read_text(encoding="utf-8"))
            run = next(
                str(s.get("run"))
                for j, steps in wc.jobs_and_steps(data)
                if j == job
                for s in steps
                if s.get("name") == step
            )
            assert "[[:cntrl:]]" in run and "'##['" in run, f"{file} | {step}"


class TestTheCensusReadsWhatTheRunnerWouldRead:
    """Controls: a fixture workflow whose prints are known."""

    FIXTURE = {
        "on": {"pull_request": {}},
        "jobs": {
            "j": {
                "runs-on": "ubuntu-latest",
                "steps": [
                    {
                        "name": "shell",
                        "run": (
                            'echo "::error::raw ${RAW} and $BARE"\n'
                            'echo "::error::wrapped $(one_line "${WRAPPED}")"\n'
                            'echo "plain ${PLAIN}"\n'
                            'echo "::error::escaped \\$ESCAPED"\n'
                            '# echo "::error::${COMMENTED}"\n'
                            'echo "::warning::continued \\\n  ${CONTINUED}"\n'
                        ),
                    },
                    {
                        "name": "python",
                        "run": (
                            "python3 - <<'PY'\n"
                            'print(f"::error::{raw_py}")\n'
                            'print(f"::error::{one_line(wrapped_py)}")\n'
                            'print(f"plain {plain_py}")\n'
                            "PY\n"
                        ),
                    },
                ],
            }
        },
    }

    def test_the_census_finds_each_kind_of_print(self, tmp_path):
        workflows = tmp_path / ".github" / "workflows"
        workflows.mkdir(parents=True)
        (workflows / "fixture.yml").write_text(yaml.safe_dump(self.FIXTURE))
        found = {(p.step, p.value, p.neutralized) for p in wc.printed_values(tmp_path)}
        assert found == {
            ("shell", "RAW", False),
            ("shell", "BARE", False),
            ("shell", 'one_line "${WRAPPED}"', True),
            ("shell", "CONTINUED", False),
            ("python", "raw_py", False),
            ("python", "one_line(wrapped_py)", True),
        }, found


# --------------------------------------------------------------------------- 2


def _job_with(*steps: dict[str, Any]) -> dict[str, Any]:
    return {"jobs": {"j": {"steps": list(steps)}}}


_DEFINER = {"name": wc.DEFINER_NAME, "shell": "bash", "run": wc.DEFINER_RUN}
_LOADER = {"name": "loads it", "run": wc.HELPER_SOURCE + '\necho "$(one_line x)"\n'}


class TestEveryLoaderHasADefinerBeforeIt:
    def test_every_definer_writes_the_same_helper(self):
        definers = wc.definer_steps()
        where = {(file, job) for file, job, _, _ in definers}
        assert {
            (".github/workflows/run-ash-security-scan.yml", "ash"),
            (".github/workflows/ash-repo-scan.yml", "grype-db-cache"),
        } <= where, where
        for file, job, _, step in definers:
            assert step.get("name") == wc.DEFINER_NAME, (file, job, step.get("name"))
            assert step.get("shell") == "bash", (file, job)
            assert step.get("run") == wc.DEFINER_RUN, (file, job, step.get("run"))

    def test_every_step_that_loads_the_helper_has_a_definer_before_it(self):
        missing = []
        loaders = 0
        for path in wc.workflow_files():
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            for _, steps in wc.jobs_and_steps(data):
                loaders += sum(
                    wc.HELPER_SOURCE in str(s.get("run") or "") for s in steps
                )
            missing += [(path.name, *m) for m in wc.helper_without_definer(data)]
        assert loaders >= 5, f"only {loaders} steps load the helper"
        assert not missing, missing

    def test_a_loader_before_its_definer_is_found(self):
        assert wc.helper_without_definer(_job_with(_LOADER, _DEFINER)) == [
            ("j", "loads it")
        ]

    def test_a_definer_in_another_job_does_not_count(self):
        data = {"jobs": {"a": {"steps": [_DEFINER]}, "b": {"steps": [_LOADER]}}}
        assert wc.helper_without_definer(data) == [("b", "loads it")]

    def test_a_definer_that_writes_another_helper_does_not_count(self):
        altered = {**_DEFINER, "run": wc.DEFINER_RUN.replace("# #[", "##[")}
        assert wc.helper_without_definer(_job_with(altered, _LOADER)) == [
            ("j", "loads it")
        ]

    def test_a_loader_after_its_definer_passes(self):
        assert wc.helper_without_definer(_job_with(_DEFINER, _LOADER)) == []


# --------------------------------------------------------------------------- 3

#: Every code point one_line replaces: C0 (but NUL, which no argument can hold), DEL,
#: C1, U+2028 and U+2029.
REPLACED = [
    chr(c)
    for c in range(1, 0x2030)
    if unicodedata.category(chr(c)) in ("Cc", "Zl", "Zp")
]
#: Text one_line must change only where it holds `::` or `##[`.
KEPT = [chr(0xE9), chr(0xA0), chr(0x3000), chr(0xFEFF), chr(0x1F600), "x", ":", "#["]
SAMPLES = [
    *(f"a{c}b" for c in REPLACED),
    *(f"a{c}b" for c in KEPT),
    *wc.COMMAND_TEXT_VALUES.values(),
    "a::b",
    ":::",
    "::::",
    "##[",
    "###[[",
    "a##[##[b",
    "#" + chr(0x2028) + "#[",
    ":" + chr(0x85) + ":",
    "",
]


def _python_one_line(values: list[str]) -> list[str]:
    """PY_ONE_LINE run the way the Python steps run it, in its own interpreter."""
    program = (
        "import json, sys, unicodedata\n"
        + wc.PY_ONE_LINE
        + "print(json.dumps([one_line(v) for v in json.load(sys.stdin)]))\n"
    )
    proc = subprocess.run(
        [sys.executable, "-I", "-c", program],
        input=json.dumps(values),
        capture_output=True,
        text=True,
        check=True,
        timeout=60,
    )
    return json.loads(proc.stdout)


def _bash_one_line(values: list[str], locale_name: str) -> list[str]:
    script = wc.HELPER_TEXT + 'for v in "$@"; do one_line "$v"; printf "\\0"; done\n'
    proc = subprocess.run(
        ["bash", "--noprofile", "--norc", "-c", script, "bash", *values],
        env={**os.environ, "LC_ALL": locale_name},
        capture_output=True,
        check=True,
        timeout=60,
    )
    return [part.decode("utf-8") for part in proc.stdout.split(b"\0")[:-1]]


class TestEveryCopyOfOneLineAgrees:
    def test_every_python_copy_is_the_canonical_text(self):
        copies = wc.python_one_line_copies()
        assert copies, "no Python step carries one_line"
        for file, step, text in copies:
            assert text == wc.PY_ONE_LINE, (file, step, text)

    @_REQUIRES_BASH
    @pytest.mark.parametrize("locale_name", wc.runner_locales())
    def test_bash_and_python_give_the_same_answer(self, locale_name):
        bash = _bash_one_line(SAMPLES, locale_name)
        python = _python_one_line(SAMPLES)
        assert len(bash) == len(SAMPLES), (len(bash), len(SAMPLES))
        differ = [
            (value, got, want)
            for value, got, want in zip(SAMPLES, bash, python)
            if got != want
        ]
        assert not differ, differ[:10]

    @_REQUIRES_BASH
    @pytest.mark.parametrize("locale_name", wc.runner_locales())
    def test_the_answer_is_one_line_holding_no_command(self, locale_name):
        for value, got in zip(SAMPLES, _bash_one_line(SAMPLES, locale_name)):
            assert not any(c in got for c in REPLACED), (value, got)
            assert "::" not in got and "##[" not in got, (value, got)

    def test_text_without_controls_or_markers_is_kept(self):
        assert _python_one_line(KEPT) == KEPT


# --------------------------------------------------------------------------- 4


def _job(workflow_path: Path, job_id: str) -> tuple[ga.Workflow, dict[str, Any]]:
    workflow = ga.load_workflow(workflow_path)
    return workflow, workflow.jobs[job_id]


def _named(job: dict[str, Any], name: str) -> dict[str, Any]:
    for step in job.get("steps") or []:
        if step.get("name") == name:
            return step
    raise AssertionError(f"no step named {name!r}")


def _context(workflow: ga.Workflow) -> dict[str, Any]:
    context = ga.base_context(
        event_name="push",
        repository=REPO,
        repository_owner=REPO.split("/")[0],
        ref="refs/heads/main",
        ref_name="main",
        event={"repository": {"default_branch": "main", "full_name": REPO}},
    )
    if "workflow_call" not in workflow.on:
        return context
    caller = {
        "with": {
            "install-grype": True,
            "install-opengrep": True,
            "install-cfn-nag": True,
        }
    }
    return ga.with_inputs(context, ga.call_inputs(caller, workflow, context))


def _script(directory: Path, name: str, body: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)
    return path


def _path_with(sandbox: ga.StepSandbox, *first: Path) -> str:
    return os.pathsep.join(
        [*(str(p) for p in first), str(sandbox.stub_dir), os.environ.get("PATH", "")]
    )


def _assert_stays_on_its_line(run: ga.StepRun, value: str, commands: int) -> None:
    printed = run.proc.stdout + run.proc.stderr
    lines = ga.workflow_command_lines(run.proc.stdout, run.proc.stderr)
    assert len(lines) == commands, (
        f"expected {commands} workflow-command line(s), got {lines}\n{run.describe()}"
    )
    assert wc.command_text(value) not in printed, run.describe()
    assert "from the value" in printed, (
        "the value was not printed at all, so this run shows nothing:\n"
        + run.describe()
    )


WITH_COMMAND_TEXT = [pytest.param(v, id=k) for k, v in wc.COMMAND_TEXT_VALUES.items()]

_RESTORE_GUARD = "Refuse a restored grype database older than its declared bound"
_SAVE_GUARD = "Check the grype database may be saved (default branch only)"
_FAILING = "#!/bin/sh\nexit 1\n"


@_REQUIRES_BASH
class TestTheGrypeGuardsPrintTheBuildTimeOnOneLine:
    def _run(self, tmp_path, workflow_path, job_id, name, value, *, uv_fails, **env):
        workflow, job = _job(workflow_path, job_id)
        sandbox = ga.StepSandbox(tmp_path)
        sandbox.install_stub("grype", sandbox.runner_temp / "ash-tools")
        first = (
            [_script(tmp_path / "failing", "uv", _FAILING).parent] if uv_fails else []
        )
        return ga.run_step(
            sandbox,
            workflow,
            job,
            _named(job, name),
            _context(workflow),
            extra_env={"STUB_BUILT": value, "PATH": _path_with(sandbox, *first), **env},
        )

    @pytest.mark.parametrize("value", WITH_COMMAND_TEXT)
    def test_the_restore_guard_refusing_it(self, tmp_path, value):
        run = self._run(
            tmp_path, SCAN_WORKFLOW, "ash", _RESTORE_GUARD, value, uv_fails=True
        )
        assert run.proc.returncode == 0, run.describe()
        _assert_stays_on_its_line(run, value, commands=1)

    @pytest.mark.parametrize("value", WITH_COMMAND_TEXT)
    def test_the_restore_guard_keeping_it(self, tmp_path, value):
        run = self._run(
            tmp_path, SCAN_WORKFLOW, "ash", _RESTORE_GUARD, value, uv_fails=False
        )
        assert "inside its bound" in run.proc.stdout, run.describe()
        _assert_stays_on_its_line(run, value, commands=0)

    @pytest.mark.parametrize("value", WITH_COMMAND_TEXT)
    def test_the_save_guard_refusing_it(self, tmp_path, value):
        run = self._run(
            tmp_path, SCAN_WORKFLOW, "ash", _SAVE_GUARD, value, uv_fails=True
        )
        _assert_stays_on_its_line(run, value, commands=1)

    @pytest.mark.parametrize("value", WITH_COMMAND_TEXT)
    def test_the_repository_cache_job_refusing_it(self, tmp_path, value):
        """This one runs the real check-age, which refuses the value without printing it."""
        run = self._run(
            tmp_path,
            REPO_SCAN,
            "grype-db-cache",
            "Check the grype database may be saved",
            value,
            uv_fails=False,
            PYTHONPATH=str(ga.REPO_ROOT),
        )
        assert "not saving the grype database" in run.proc.stdout, run.describe()
        _assert_stays_on_its_line(run, value, commands=1)


@_REQUIRES_BASH
class TestTheOpenGrepInstallPrintsWhatItWasToldOnOneLine:
    def _run(self, tmp_path, tools: Path | None, **env):
        workflow, job = _job(SCAN_WORKFLOW, "ash")
        sandbox = ga.StepSandbox(tmp_path)
        first = [tools] if tools else []
        return sandbox, ga.run_step(
            sandbox,
            workflow,
            job,
            _named(job, "Install OpenGrep"),
            _context(workflow),
            extra_env={"PATH": _path_with(sandbox, *first), **env},
        )

    @pytest.mark.parametrize("value", WITH_COMMAND_TEXT)
    def test_a_machine_name_with_no_pin(self, tmp_path, value):
        tools = _script(
            tmp_path / "tools", "uname", "#!/bin/sh\nprintf '%s\\n' \"$MACHINE\"\n"
        )
        _, run = self._run(tmp_path, tools.parent, MACHINE=value)
        assert run.proc.returncode != 0, run.describe()
        _assert_stays_on_its_line(run, value, commands=1)

    @pytest.mark.parametrize("value", WITH_COMMAND_TEXT)
    def test_an_ash_source_that_pins_nothing(self, tmp_path, value):
        tools = _script(tmp_path / "tools", "uv", _FAILING)
        _, run = self._run(tmp_path, tools.parent, ASH_UVX_SOURCE=value)
        assert run.proc.returncode != 0, run.describe()
        _assert_stays_on_its_line(run, value, commands=1)

    @pytest.mark.parametrize("value", WITH_COMMAND_TEXT)
    def test_a_pin_the_installed_binary_does_not_match(self, tmp_path, value):
        tools = _script(tmp_path / "tools", "uv", "#!/bin/sh\nprintf '%s' \"$PIN\"\n")
        # A restored cache, so the step also prints the line that discards it.
        (tmp_path / "home" / ".opengrep" / "cli" / "latest").mkdir(parents=True)
        _, run = self._run(tmp_path, tools.parent, PIN=value)
        assert run.proc.returncode != 0, run.describe()
        assert "Discarding the restored OpenGrep cache" in run.proc.stdout, (
            run.describe()
        )
        _assert_stays_on_its_line(run, value, commands=1)


_BUNDLE_WITHOUT_BINSTUB = "#!/bin/sh\nexit 0\n"
_BUNDLE_WITH_FAILING_BINSTUB = """#!/bin/sh
if [ "$1" = binstubs ]; then
  while [ "$#" -gt 0 ]; do
    if [ "$1" = --path ]; then
      mkdir -p "$2"
      printf '#!/bin/sh\\nexit 3\\n' > "$2/cfn_nag_scan"
      chmod +x "$2/cfn_nag_scan"
    fi
    shift
  done
fi
exit 0
"""
#: A binstub bash cannot run: it prints "Permission denied" with the path as it is.
_BUNDLE_WITH_UNRUNNABLE_BINSTUB = _BUNDLE_WITH_FAILING_BINSTUB.replace(
    '      chmod +x "$2/cfn_nag_scan"\n', ""
)
_CURL_WRITING_NOTHING = """#!/bin/sh
while [ "$#" -gt 0 ]; do
  if [ "$1" = -o ]; then : > "$2"; fi
  shift
done
"""


#: For a value that reaches the step through PATH, which splits at `:`, so a
#: directory on it cannot hold `::`. A line break then `##[` still adds a command.
NO_COLON = [
    pytest.param("x\r##[warning]from the value", id="carriage return"),
    pytest.param("x\n##[warning]from the value", id="line feed"),
    pytest.param("x ##[warning]from the value", id="legacy marker"),
]


@_REQUIRES_BASH
class TestTheCfnNagInstallPrintsItsPathsOnOneLine:
    """The paths come from RUNNER_TEMP and from what `command -v` finds on PATH.

    The sandbox's root, and so RUNNER_TEMP, holds the value, which puts it in every
    path the step builds from RUNNER_TEMP; or a directory on PATH does. The stubs
    sit in a directory of their own, so that a root holding `:` cannot hide them.
    """

    @staticmethod
    def _coreutils(tmp_path: Path, *tools: str) -> Path:
        """Only the programs the step runs, so nothing else on this host's PATH counts."""
        directory = tmp_path / "coreutils"
        directory.mkdir()
        for tool in ("bash", *tools):
            found = shutil.which(tool)
            assert found, f"{tool} is not on PATH"
            (directory / tool).symlink_to(found)
        return directory

    def _run(self, tmp_path, value, *, tools: Path | None = None):
        workflow, job = _job(SCAN_WORKFLOW, "ash")
        sandbox = ga.StepSandbox(tmp_path / ("runner " + value.replace("/", "_")))
        stubs = tmp_path / "stubs"
        for tool in (*ga.STUB_TOOLS, *ga.PASS_THROUGH_TOOLS):
            sandbox.install_stub(tool, stubs)
        first = [str(tools)] if tools else []
        coreutils = self._coreutils(tmp_path, "mkdir", "dirname", "ls", "chmod")
        path = os.pathsep.join([*first, str(stubs), str(coreutils)])
        return ga.run_step(
            sandbox,
            workflow,
            job,
            _named(job, "Install cfn-nag"),
            _context(workflow),
            extra_env={"PATH": path},
        )

    @pytest.mark.parametrize("value", NO_COLON)
    def test_an_install_that_works(self, tmp_path, value):
        run = self._run(tmp_path, value)
        assert run.proc.returncode == 0, run.describe()
        assert "cfn_nag_scan resolves to" in run.proc.stdout, run.describe()
        _assert_stays_on_its_line(run, value, commands=0)

    @pytest.mark.parametrize("value", WITH_COMMAND_TEXT)
    def test_a_missing_lockfile(self, tmp_path, value):
        tools = _script(tmp_path / "tools", "curl", _CURL_WRITING_NOTHING)
        run = self._run(tmp_path, value, tools=tools.parent)
        assert run.proc.returncode != 0 and "No Gemfile.lock" in run.proc.stderr, (
            run.describe()
        )
        _assert_stays_on_its_line(run, value, commands=1)

    @pytest.mark.parametrize("value", NO_COLON)
    def test_ruby_missing_from_path(self, tmp_path, value):
        # bundle and ruby in a directory whose name holds the value; no gem anywhere,
        # and only the two tools the step runs before the check.
        sandbox = ga.StepSandbox(tmp_path / "runner")
        found = tmp_path / ("bin " + value)
        for tool in ("bundle", "ruby", "curl"):
            sandbox.install_stub(tool, found)
        coreutils = self._coreutils(tmp_path, "mkdir", "dirname")
        workflow, job = _job(SCAN_WORKFLOW, "ash")
        run = ga.run_step(
            sandbox,
            workflow,
            job,
            _named(job, "Install cfn-nag"),
            _context(workflow),
            extra_env={"PATH": f"{found}{os.pathsep}{coreutils}"},
        )
        assert run.proc.returncode != 0 and "Ruby is not on PATH" in run.proc.stderr, (
            run.describe()
        )
        _assert_stays_on_its_line(run, value, commands=1)

    @pytest.mark.parametrize("value", WITH_COMMAND_TEXT)
    def test_a_binstub_that_was_not_written(self, tmp_path, value):
        tools = _script(tmp_path / "tools", "bundle", _BUNDLE_WITHOUT_BINSTUB)
        run = self._run(tmp_path, value, tools=tools.parent)
        assert run.proc.returncode != 0 and "is not on PATH" in run.proc.stderr, (
            run.describe()
        )
        _assert_stays_on_its_line(run, value, commands=1)

    @pytest.mark.parametrize("value", NO_COLON)
    def test_a_binstub_that_does_not_run(self, tmp_path, value):
        tools = _script(tmp_path / "tools", "bundle", _BUNDLE_WITH_FAILING_BINSTUB)
        run = self._run(tmp_path, value, tools=tools.parent)
        assert run.proc.returncode != 0 and "will not run" in run.proc.stderr, (
            run.describe()
        )
        _assert_stays_on_its_line(run, value, commands=1)

    @pytest.mark.parametrize("value", NO_COLON)
    def test_a_binstub_bash_cannot_run(self, tmp_path, value):
        """The step runs the binstub again to show why; bash's error names its path."""
        tools = _script(tmp_path / "tools", "bundle", _BUNDLE_WITH_UNRUNNABLE_BINSTUB)
        run = self._run(tmp_path, value, tools=tools.parent)
        assert run.proc.returncode != 0 and "Permission denied" in run.proc.stderr, (
            run.describe()
        )
        _assert_stays_on_its_line(run, value, commands=1)

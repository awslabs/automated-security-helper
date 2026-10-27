# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The CI examples must work as written, against the ASH and workflow they name.

Why this file exists
--------------------
Nothing read the two CI examples, and both had gone stale.

examples/AWSCodeBuild/buildspec.yml installed ASH `v3.0.0-beta`, a pre-release from
before 3.0.0, and its README said Python 3.8 or later while ASH requires 3.10. It
collected `**/ash_output/**` and `**/reports/*.junit.xml` without naming the output
directory the scan writes to, so whether the build kept anything depended on the
default output directory and on whether CodeBuild's `**` enters a directory named
`.ash`.

examples/GitHubActions/ash-repo-scan.yml:

* filtered push with `branches: ["!main"]`. GitHub's workflow syntax reference:
  "If you define a branch with the `!` character, you must also define at least one
  branch without the `!` character. If you only want to exclude branches, use
  `branches-ignore` instead."
* granted `security-events: write` to the job that calls run-ash-security-scan.yml,
  commented as required for SARIF collection. A called workflow can only narrow its
  caller's token and that workflow does not request the permission, so the grant
  never reached its upload step (tests/unit/test_sarif_upload_permissions.py).
* set `collect-sarif-report: true` on push and workflow_dispatch, where that upload
  cannot succeed: the release `v3` names runs it there and fails the job. Code
  scanning takes the upload on any pull_request event, from a fork too.
* set an env variable, PYTHON_VERSION, that nothing read.

What is asserted
----------------
For CodeBuild: the install pin names the packaged release and `cz bump` rewrites it
and the README's copy; every `ash` command line passes only options this tree's CLI
declares; and the artifact and the report group are read from the output directory
the scan command names.

For GitHub Actions: every input it passes is one the workflow declares; its branch
filters are ones GitHub accepts; the scan job is granted only permissions the called
workflow requests; it asks for the in-workflow SARIF upload only where every release
can do it, a pull_request event; and it installs the ASH of the ref it calls the
workflow at.
"""

from __future__ import annotations

import shlex
import sys
from pathlib import Path

import pytest
import yaml

from tests.unit.deploy.test_deploy_ash_cli_contract import (
    Invocation,
    _cli,
    shell_invocations,
    unknown_to_cli,
)
from tests.utils.github_expressions import evaluate

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised only on 3.10
    import tomli as tomllib

REPO_ROOT = Path(__file__).resolve().parents[2]
CODEBUILD = REPO_ROOT / "examples" / "AWSCodeBuild" / "buildspec.yml"
CODEBUILD_README = REPO_ROOT / "examples" / "AWSCodeBuild" / "README.md"
GITHUB_EXAMPLE = REPO_ROOT / "examples" / "GitHubActions" / "ash-repo-scan.yml"
SCAN_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "run-ash-security-scan.yml"


def _commitizen() -> dict:
    with (REPO_ROOT / "pyproject.toml").open("rb") as handle:
        return tomllib.load(handle)["tool"]["commitizen"]


def _load(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _triggers(document: dict) -> dict:
    # PyYAML reads the bare key `on` as the boolean True (YAML 1.1).
    return document.get("on", document.get(True)) or {}


# ---------------------------------------------------------------------------
# AWS CodeBuild
# ---------------------------------------------------------------------------


def _codebuild_commands() -> list[str]:
    phases = _load(CODEBUILD)["phases"]
    return [command for phase in phases.values() for command in phase["commands"]]


def _codebuild_invocations() -> list[Invocation]:
    return shell_invocations("\n".join(_codebuild_commands()), "codebuild example")


def test_the_codebuild_example_installs_the_packaged_release():
    expected = f"v{_commitizen()['version']}"
    variables = _load(CODEBUILD)["env"]["variables"]

    assert variables["ASH_VERSION"] == expected
    install = [c for c in _codebuild_commands() if "pip install" in c]
    assert install == ['pip install "git+${ASH_REPO_CLONE_URL}@${ASH_VERSION}"'], (
        install
    )
    readme_rows = [
        line
        for line in CODEBUILD_README.read_text(encoding="utf-8").splitlines()
        if line.startswith("| `ASH_VERSION`")
    ]
    assert len(readme_rows) == 1 and f"`{expected}`" in readme_rows[0], readme_rows


def test_cz_bump_rewrites_the_codebuild_examples_pin(monkeypatch):
    """The same check tests/unit/deploy/test_deploy_ash_cli_contract.py makes for deploy/."""
    from commitizen.bump import _resolve_files_and_regexes

    monkeypatch.chdir(REPO_ROOT)
    settings = _commitizen()
    current = settings["version"]
    rewritten = set()
    for path, regex in _resolve_files_and_regexes(settings["version_files"], current):
        resolved = Path(path).resolve()
        for number, line in enumerate(
            resolved.read_text(encoding="utf-8").splitlines(), 1
        ):
            if regex.search(line) and current in line:
                rewritten.add((resolved, number))

    pins = [
        (path, number)
        for path, marker in (
            (CODEBUILD, "ASH_VERSION:"),
            (CODEBUILD_README, "| `ASH_VERSION`"),
        )
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
        if marker in line
    ]
    assert len(pins) == 2, pins
    missed = [
        f"{path.name}:{number}"
        for path, number in pins
        if (path, number) not in rewritten
    ]
    assert not missed, f"`cz bump` would leave these on the old release: {missed}"


def test_the_codebuild_example_passes_only_options_the_cli_declares():
    root = _cli()
    invocations = _codebuild_invocations()

    assert {invocation.command_path(root) for invocation in invocations} == {
        "",
        "report",
    }, "the reader no longer sees the scan and report command lines"
    problems = [
        p for invocation in invocations for p in unknown_to_cli(invocation, root)
    ]
    assert not problems, problems


def _output_dir(invocation: Invocation) -> str:
    words = list(invocation.words)
    assert "--output-dir" in words, (
        f"{' '.join(words)} does not name its output directory, so what the "
        "buildspec collects depends on ASH's default"
    )
    return words[words.index("--output-dir") + 1]


def test_the_codebuild_example_collects_what_the_scan_writes():
    document = _load(CODEBUILD)
    output_dirs = {_output_dir(invocation) for invocation in _codebuild_invocations()}

    assert len(output_dirs) == 1, output_dirs
    (output_dir,) = output_dirs
    assert document["artifacts"]["base-directory"] == output_dir
    assert document["artifacts"]["files"] == ["**/*"]
    (group,) = document["reports"].values()
    assert group["file-format"] == "JUNITXML"
    assert group["base-directory"] == f"{output_dir}/reports"
    assert group["files"] == ["ash.junit.xml"]


def test_the_codebuild_readme_states_ashs_python_floor():
    with (REPO_ROOT / "pyproject.toml").open("rb") as handle:
        requires = tomllib.load(handle)["project"]["requires-python"]
    floor = requires.split(",")[0].removeprefix(">=")
    readme = CODEBUILD_README.read_text(encoding="utf-8")

    assert f"Python {floor} or later" in readme, requires


# ---------------------------------------------------------------------------
# GitHub Actions
# ---------------------------------------------------------------------------


def _scan_job() -> dict:
    jobs = _load(GITHUB_EXAMPLE)["jobs"]
    callers = [
        job
        for job in jobs.values()
        if "/.github/workflows/run-ash-security-scan.yml@" in str(job.get("uses", ""))
    ]
    assert len(callers) == 1, callers
    return callers[0]


def test_the_github_example_passes_only_inputs_the_workflow_declares():
    declared = _triggers(_load(SCAN_WORKFLOW))["workflow_call"]["inputs"]
    passed = _scan_job()["with"]

    assert not set(passed) - set(declared), sorted(set(passed) - set(declared))


def test_the_github_examples_branch_filters_are_ones_github_accepts():
    for event, spec in _triggers(_load(GITHUB_EXAMPLE)).items():
        patterns = (spec or {}).get("branches")
        if patterns is None:
            continue
        assert any(not str(p).startswith("!") for p in patterns), (
            f"{event}: branches {patterns} has only `!` patterns; GitHub requires a "
            "positive one with them, and branches-ignore for exclusions alone"
        )


def test_the_github_example_grants_only_what_the_workflow_requests():
    requested = set(_load(SCAN_WORKFLOW)["permissions"])
    granted = set(_scan_job()["permissions"])

    assert granted <= requested, (
        f"the example grants {sorted(granted - requested)}, which "
        "run-ash-security-scan.yml does not request, so the grant never reaches it"
    )


EVENTS = {
    "same-repo pull request": {
        "github.event_name": "pull_request",
        "github.event.pull_request.head.repo.full_name": "org/repo",
    },
    "fork pull request": {
        "github.event_name": "pull_request",
        "github.event.pull_request.head.repo.full_name": "fork/repo",
    },
    "push": {"github.event_name": "push"},
    "workflow_dispatch": {"github.event_name": "workflow_dispatch"},
}


@pytest.mark.parametrize("event", sorted(EVENTS))
def test_the_github_example_asks_for_the_sarif_upload_only_where_it_works(event):
    value = _scan_job()["with"].get("collect-sarif-report")
    assert (
        isinstance(value, str) and value.startswith("${{") and value.endswith("}}")
    ), (
        f"collect-sarif-report is {value!r}; the upload works on pull_request events "
        "only, and the release the example pins fails the job elsewhere"
    )
    context = {"github.repository": "org/repo", **EVENTS[event]}

    asked = evaluate(value[3:-2].strip(), context, "success")

    assert asked == event.endswith("pull request"), value


def test_the_github_example_installs_the_ash_of_the_ref_it_calls():
    job = _scan_job()
    ref = job["uses"].rsplit("@", 1)[1]

    assert job["with"]["ash-version"] == ref


def test_the_github_example_sets_no_unused_env():
    document = _load(GITHUB_EXAMPLE)
    text = GITHUB_EXAMPLE.read_text(encoding="utf-8")
    unused = [
        name
        for name in (document.get("env") or {})
        if text.count(name) == 1 and f"env.{name}" not in text
    ]
    assert not unused, unused


def test_the_shell_reader_sees_the_codebuild_scan_line():
    """Positive control for the reader on the exact shape the buildspec uses."""
    line = "ash --mode container --no-progress --output-dir .ash/ash_output"
    (invocation,) = shell_invocations(line, "control")
    assert invocation.words == tuple(shlex.split(line))[1:]

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
declares; the artifact and the report group are read from the output directory
the scan command names; and the build and post-build commands, run against a stand-in
`ash`, spell the scan and the report the way that ASH does, picking the older spelling
only from an answer and failing, with what the probe printed, when a probe crashes.

For GitHub Actions: every input it passes is one the workflow declares; its branch
filters are ones GitHub accepts; the scan job is granted only permissions the called
workflow requests; it asks for the in-workflow SARIF upload only where every release
can do it, a pull_request event; and it installs the ASH of the ref it calls the
workflow at.
"""

from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
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

pytestmark = pytest.mark.unit

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

    assert variables["RELEASE_TAG"] == expected
    install = [c for c in _codebuild_commands() if "pip install" in c]
    assert install == ['pip install "git+${ASH_REPO_CLONE_URL}@${RELEASE_TAG}"'], (
        install
    )
    readme_rows = [
        line
        for line in CODEBUILD_README.read_text(encoding="utf-8").splitlines()
        if line.startswith("| `RELEASE_TAG`")
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
            (CODEBUILD, "RELEASE_TAG:"),
            (CODEBUILD_README, "| `RELEASE_TAG`"),
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
    """Both spellings of each command are read: the example's RELEASE_TAG can name a
    release older than 3.9, so it asks the installed ASH for `scan fs` and
    `results report` and falls back to the subject-less scan and `ash report`."""
    root = _cli()
    invocations = _codebuild_invocations()

    assert {invocation.command_path(root) for invocation in invocations} == {
        "",
        "scan fs",
        "report",
        "results report",
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
    # A `--help` command line asks which spelling the installed ASH has and writes
    # nothing. The buildspec's probes are command substitutions the reader does not
    # open, so this keeps one written as a command of its own from being read as a scan.
    output_dirs = {
        _output_dir(invocation)
        for invocation in _codebuild_invocations()
        if "--help" not in invocation.words
    }

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
    """Positive control for the reader on the exact shape the buildspec uses.

    The probe captures ``ash scan fs --help`` into a variable inside a quoted command
    substitution, which the reader takes for one word of an assignment. So the only
    ASH command lines it reads are the two spellings of the scan, each with its options.
    """
    scan = "ash scan fs --mode container --no-progress --output-dir .ash/ash_output"
    legacy = "ash --mode container --no-progress --output-dir .ash/ash_output"
    block = f"""\
ASH_PROBE_STATUS=0
ASH_PROBE_HELP="$(ash scan fs --help 2>&1)" || ASH_PROBE_STATUS=$?
case "$ASH_PROBE_STATUS:$ASH_PROBE_HELP" in
  0:*"scan fs"*)
    ASH_SCAN_FS=yes
    echo "ash: scanning with 'ash scan fs'" >&2 ;;
  *)
    echo "ash: could not tell whether this ASH has 'ash scan fs'" >&2
    printf '%s\\n' "$ASH_PROBE_HELP" | tail -n 20 >&2
    exit 1 ;;
esac
if [ "$ASH_SCAN_FS" = yes ]; then
  {scan}
else
  {legacy}
fi
"""
    invocations = shell_invocations(block, "control")
    assert [invocation.words for invocation in invocations] == [
        tuple(shlex.split(scan))[1:],
        tuple(shlex.split(legacy))[1:],
    ]


# ---------------------------------------------------------------------------
# The example's commands, run against a stand-in ash
# ---------------------------------------------------------------------------

posix_only = pytest.mark.skipif(
    os.name == "nt", reason="runs a POSIX buildspec command destined for Linux"
)

#: A stand-in ``ash`` that answers the two help probes the example asks, as each kind of
#: release does, and records every other call as one JSON argv per line. Releases:
#: ``with-subject`` (ASH 3.9), ``without-subject`` (an older ASH, which shows the
#: subject-less scan's help for ``scan fs --help`` since click reads ``--help`` before it
#: refuses the extra argument, and has no ``results`` command), ``refusing`` (an older
#: ASH that refuses the word ``fs`` with the usage error instead) and ``crashing``.
_STAND_IN_ASH = """\
import json
import os
import sys

argv = sys.argv[1:]
release = os.environ["ASH_STUB_RELEASE"]
if argv in (["scan", "fs", "--help"], ["results", "report", "--help"]):
    scan = argv[0] == "scan"
    if release == "crashing":
        sys.stderr.write("Traceback (most recent call last):\\nMemoryError\\n")
        sys.exit(1)
    if release == "with-subject":
        sys.stdout.write(
            "Usage: ash scan fs [OPTIONS]\\n" if scan else "Usage: ash results report\\n"
        )
        sys.exit(0)
    if scan and release == "without-subject":
        sys.stdout.write("Usage: ash scan [OPTIONS]\\n")
        sys.exit(0)
    if scan:
        sys.stderr.write("Usage: ash scan [OPTIONS]\\n")
        sys.stderr.write("Error: Got unexpected extra argument (fs)\\n")
        sys.exit(5)
    sys.stderr.write("Error: No such command 'results'.\\n")
    sys.exit(5)
with open(os.environ["ASH_STUB_LOG"], "a", encoding="utf-8") as handle:
    handle.write(json.dumps(argv) + "\\n")
"""


def _phase_command(phase: str) -> str:
    (command,) = _load(CODEBUILD)["phases"][phase]["commands"]
    return command


def _run_codebuild_command(
    tmp_path: Path, command: str, release: str
) -> tuple[list[list[str]], subprocess.CompletedProcess]:
    """Run *command* in a POSIX shell with the stand-in first on PATH.

    Returns the calls the stand-in recorded and the finished shell.
    """
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    ash = bin_dir / "ash"
    ash.write_text(f"#!{sys.executable} -I\n{_STAND_IN_ASH}", encoding="utf-8")
    ash.chmod(0o755)
    log = tmp_path / "ash.jsonl"
    shell = shutil.which("sh")
    assert shell, "no sh on PATH"
    work = tmp_path / "work"
    work.mkdir()
    finished = subprocess.run(
        [shell, "-c", command],
        cwd=work,
        env={
            "PATH": f"{bin_dir}{os.pathsep}/usr/bin{os.pathsep}/bin",
            "ASH_STUB_RELEASE": release,
            "ASH_STUB_LOG": str(log),
        },
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    if not log.exists():
        return [], finished
    return [
        json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()
    ], finished


@posix_only
@pytest.mark.parametrize(
    "release, prefix",
    [
        ("with-subject", ["scan", "fs", "--mode", "container"]),
        ("without-subject", ["--mode", "container"]),
        ("refusing", ["--mode", "container"]),
    ],
)
def test_the_codebuild_example_scans_the_way_its_ash_does(tmp_path, release, prefix):
    calls, finished = _run_codebuild_command(tmp_path, _phase_command("build"), release)

    assert finished.returncode == 0, finished.stderr
    # One call: the probe is answered, not recorded.
    assert len(calls) == 1, calls
    assert calls[0][: len(prefix)] == prefix, calls[0]
    assert calls[0][calls[0].index("--output-dir") + 1] == ".ash/ash_output"


@posix_only
@pytest.mark.parametrize(
    "release, command",
    [
        ("with-subject", ["results", "report"]),
        ("without-subject", ["report"]),
        ("refusing", ["report"]),
    ],
)
def test_the_codebuild_example_reports_the_way_its_ash_does(tmp_path, release, command):
    calls, finished = _run_codebuild_command(
        tmp_path, _phase_command("post_build"), release
    )

    assert finished.returncode == 0, finished.stderr
    assert calls == [[*command, "--output-dir", ".ash/ash_output"]], calls


@posix_only
@pytest.mark.parametrize(
    "phase, asked",
    [("build", "ash scan fs"), ("post_build", "ash results report")],
)
def test_the_codebuild_example_does_not_read_a_crashed_probe_as_an_older_ash(
    tmp_path, phase, asked
):
    """A crash says nothing about the ASH's commands. Read as an older ASH, it would run
    the older spelling on an ASH that has the new one, with no word of why.

    The build ends with 70, a status ASH never gives: the scan's own 1 is "incomplete
    result", and a build that ended with it could be a scan or a probe that failed.
    """
    calls, finished = _run_codebuild_command(
        tmp_path, _phase_command(phase), "crashing"
    )

    assert calls == [], calls
    assert finished.returncode == 70, finished.stderr
    assert f"could not tell whether this ASH has '{asked}'" in finished.stderr
    assert f"'{asked} --help' exited 1" in finished.stderr
    assert "MemoryError" in finished.stderr


@posix_only
@pytest.mark.parametrize(
    "phase, release, said",
    [
        (
            "build",
            "with-subject",
            "scanning with 'ash scan fs': its help names 'scan fs'",
        ),
        (
            "build",
            "without-subject",
            (
                "scanning with the older spelling: the help of 'ash scan fs --help' "
                "does not name 'scan fs'"
            ),
        ),
        (
            "build",
            "refusing",
            "scanning with the older spelling: this ASH refused the word 'fs'",
        ),
        (
            "post_build",
            "with-subject",
            "reporting with 'ash results report': its help names 'results report'",
        ),
        (
            "post_build",
            "without-subject",
            "reporting with the older spelling: this ASH refused the word 'results'",
        ),
    ],
)
def test_the_codebuild_example_says_which_spelling_it_chose_and_why(
    tmp_path, phase, release, said
):
    _, finished = _run_codebuild_command(tmp_path, _phase_command(phase), release)

    assert f"ash: {said}" in finished.stderr, finished.stderr

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The Docs CI Runners workflow, .github/workflows/ash-docs-ci-runners.yml.

WHY THIS EXISTS
---------------
The workflow runs the CI pages' pipelines with their CI systems' own runners on
GitHub-hosted runners, two of which mount the Docker socket into containers. Its safety
rests on properties a later edit could drop without any run failing, so they are
checked here, on the file:

* it starts only on pull_request, filtered to a listed set of paths, each with its
  reason, and on workflow_dispatch with a per-leg selector; never on a schedule, from
  another workflow, or with the base repository's token on a fork's code;
* its token is ``contents: read`` and nothing widens it, it reads no secret and asks
  for no OIDC token, no checkout keeps credentials, every action is pinned to a commit,
  and setup-uv takes no input but ``enable-cache: false``;
* under act, no job and no step runs: act cannot evaluate env in a job-level ``if``, so
  jobs check ``github.event.act`` and every step checks ``env.ACT``;
* no ``${{ }}`` expression is pasted into a script, so an event value cannot become
  shell text;
* each leg builds the wheel under test itself, exactly one, and nothing passes it
  between jobs; each leg's logs upload under a name unique to the leg and the attempt;
* every image pull during a leg is recorded from before the tool installs and checked
  after the runs; the CodeBuild leg makes disk room before its pulls; install_tools.py
  and the Jenkins tool check's Python run in isolated mode, and the tool check runs
  exactly its pinned lines; act is never verbose, since the uploaded logs are readable
  by anyone for seven days;
* no variable reaches a step but the leg's own and the pinned actions': the workflow
  sets no env, the job sets the leg's, only the pytest steps add one (the wheel's
  path), and no script sets one for the steps after it;
* every script runs in bash from the workflow's defaults, and the workflow, the job
  and its steps use only the keys these tests read;
* the pytest steps clear pytest.ini's addopts, drop PYTEST_ADDOPTS from their
  environment, turn pytest.ini's live logging off and pass every flag they need
  themselves; pytest.ini is the file they read, and its addopts and its other settings
  are pinned here, so an option or a setting added there cannot reach or miss the CI
  runs without someone deciding which;
* the pytest steps give every long option its value as ``--name=value``, so pytest
  cannot read a value as a test path and load the conftest.py files around it, and
  the only conftest.py files on their test modules' path are tests/conftest.py and
  tests/integration/docs/conftest.py, both in the path filter;
* pytest's work trees, where every Jenkins home lives, are outside the uploaded
  output directory, and each pytest step has its own; the upload leaves out the
  secret-shaped names the harness leaves out of what it copies there, in any letter
  case, as the harness matches them;
* the matrix's legs are the census's legs, so a runner leg cannot be added or lost on
  one side only.
"""

from __future__ import annotations

import ast
import configparser
import importlib.util
import re
import shlex
import sys
from pathlib import Path, PurePosixPath

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ash-docs-ci-runners.yml"
WORKFLOW_REL = ".github/workflows/ash-docs-ci-runners.yml"
CI_RUNNERS = REPO_ROOT / "tests" / "integration" / "docs" / "ci_runners"
SHA_PIN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}$")
LOG_NAME = (
    "docs-ci-runners-${{ matrix.runner }}-${{ strategy.job-index }}"
    "-attempt-${{ github.run_attempt }}"
)


def _text() -> str:
    if not WORKFLOW.is_file():
        pytest.fail(f"missing {WORKFLOW_REL}")
    return WORKFLOW.read_text(encoding="utf-8")


def _workflow() -> dict:
    document = yaml.safe_load(_text())
    assert isinstance(document, dict), f"{WORKFLOW_REL} is not a mapping"
    if True in document:  # PyYAML reads the key `on` as True
        document["on"] = document.pop(True)
    return document


def _jobs() -> dict:
    jobs = _workflow().get("jobs")
    assert isinstance(jobs, dict) and jobs, "the workflow has no jobs"
    return jobs


def _steps(job: dict) -> list[dict]:
    steps = job.get("steps") or []
    assert all(isinstance(step, dict) for step in steps)
    return steps


def _all_steps() -> list[tuple[str, int, dict]]:
    return [
        (job_id, index, step)
        for job_id, job in _jobs().items()
        for index, step in enumerate(_steps(job))
    ]


def _leg_job() -> tuple[str, dict]:
    """The one job that runs the runner legs: the one with a matrix of legs."""
    legs = [
        (job_id, job)
        for job_id, job in _jobs().items()
        if isinstance(job.get("strategy"), dict)
        and isinstance(job["strategy"].get("matrix"), dict)
        and "include" in job["strategy"]["matrix"]
    ]
    assert len(legs) == 1, (
        f"expected one job with a matrix of legs, got {[j for j, _ in legs]}"
    )
    return legs[0]


def _first(steps: list[dict], needle: str) -> int:
    hits = [i for i, step in enumerate(steps) if needle in str(step.get("run", ""))]
    assert hits, f"no step of the leg job runs {needle!r}"
    return hits[0]


# ---------------------------------------------------------------------------
# Triggers and the path filter
# ---------------------------------------------------------------------------


def test_it_starts_only_on_pull_requests_by_path_and_on_dispatch_by_leg():
    on = _workflow().get("on")
    assert isinstance(on, dict), "on: must be a mapping of events"
    assert set(on) == {"pull_request", "workflow_dispatch"}, (
        f"triggers {sorted(on)}: no schedule, workflow_call, pull_request_target or "
        "workflow_run"
    )
    paths = (on["pull_request"] or {}).get("paths")
    assert isinstance(paths, list) and paths, (
        "pull_request needs an explicit paths list"
    )
    assert "paths-ignore" not in (on["pull_request"] or {})
    inputs = (on["workflow_dispatch"] or {}).get("inputs") or {}
    assert "legs" in inputs, "workflow_dispatch needs a legs input to pick the legs"


def _path_entries(text: str) -> list[tuple[str, str]]:
    """(pattern, reason) of each entry of the pull_request paths list, read from the
    text: the reason is the entry's trailing comment, or the comment lines directly
    above it."""
    lines = text.split("\n")
    in_pull_request = False
    start = None
    for index, line in enumerate(lines):
        if re.match(r"^\s+pull_request:\s*(#.*)?$", line):
            in_pull_request = True
            continue
        if in_pull_request and re.match(r"^\s+paths:\s*(#.*)?$", line):
            start = index
            break
    assert start is not None, "no paths: under pull_request:"
    indent = len(lines[start]) - len(lines[start].lstrip())
    entries: list[tuple[str, str]] = []
    pending: list[str] = []
    for line in lines[start + 1 :]:
        stripped = line.strip()
        if not stripped:
            pending = []
            continue
        if stripped.startswith("#"):
            pending.append(stripped.lstrip("#").strip())
            continue
        if len(line) - len(line.lstrip()) <= indent:
            break
        match = re.match(r"^-\s*(['\"]?)([^'\"#]+?)\1\s*(?:#\s*(.*))?$", stripped)
        assert match, f"cannot read the paths entry {stripped!r}"
        reason = (match.group(3) or " ".join(pending)).strip()
        entries.append((match.group(2), reason))
        pending = []
    return entries


def test_every_path_entry_carries_its_reason():
    text = _text()
    entries = _path_entries(text)
    assert [pattern for pattern, _ in entries] == _workflow()["on"]["pull_request"][
        "paths"
    ]
    unexplained = [
        p for p, reason in entries if len(re.findall(r"[A-Za-z]+", reason)) < 2
    ]
    assert not unexplained, f"paths entries without a reason: {unexplained}"


def _glob(pattern: str) -> re.Pattern:
    """A GitHub paths filter or upload-artifact pattern, matched case-sensitively, as
    both are on Linux: ** spans directories, * and ? do not, and [...] is one of the
    characters it lists."""
    regex, index = "", 0
    while index < len(pattern):
        if pattern.startswith("**/", index):
            regex, index = regex + "(?:.*/)?", index + 3
        elif pattern.startswith("**", index):
            regex, index = regex + ".*", index + 2
        elif pattern[index] == "*":
            regex, index = regex + "[^/]*", index + 1
        elif pattern[index] == "?":
            regex, index = regex + "[^/]", index + 1
        elif pattern[index] == "[":
            end = pattern.find("]", index + 1)
            listed = pattern[index + 1 : end]
            assert end > index and re.fullmatch(r"[A-Za-z0-9]+", listed), (
                f"this reader takes only plain character sets: {pattern!r}"
            )
            regex, index = regex + f"[{listed}]", end + 1
        else:
            regex, index = regex + re.escape(pattern[index]), index + 1
    return re.compile(regex)


def _filtered(path: str, patterns: list[str]) -> bool:
    """Whether a change to path starts the workflow: the last pattern matching it
    decides, and a ! pattern excludes."""
    selected = False
    for pattern in patterns:
        negated = pattern.startswith("!")
        if _glob(pattern.lstrip("!")).fullmatch(path):
            selected = not negated
    return selected


def _check_the_glob_reader() -> None:
    """Control for the matcher the path tests use: GitHub's rules, on known cases."""
    assert _filtered("docs/content/a/b.md", ["docs/**"])
    assert _filtered("docs/b.md", ["docs/**/b.md"])
    assert not _filtered("docs/content/a/b.md", ["docs/*"])
    assert not _filtered("docs/x.md", ["docs/**", "!docs/x.md"])
    assert _filtered("a/B.KEY", ["**/*.[kK][eE][yY]"])
    assert not _filtered("a/B.KEY", ["**/*.key"])
    assert not _filtered("a/b.kex", ["**/*.[kK][eE][yY]"])


def _census():
    checks = sys.modules.get("_ash_docs_checks")
    if checks is None:
        if str(REPO_ROOT) not in sys.path:
            sys.path.insert(0, str(REPO_ROOT))
        spec = importlib.util.spec_from_file_location(
            "_ash_docs_checks", REPO_ROOT / "scripts" / "docs_checks.py"
        )
        assert spec and spec.loader
        checks = importlib.util.module_from_spec(spec)
        sys.modules["_ash_docs_checks"] = checks
        spec.loader.exec_module(checks)
    gate = sys.modules.get("_ash_docs_gate_for_runner")
    if gate is None:
        spec = importlib.util.spec_from_file_location(
            "_ash_docs_gate_for_runner",
            REPO_ROOT / "scripts" / "verify_docs_freshness.py",
        )
        assert spec and spec.loader
        gate = importlib.util.module_from_spec(spec)
        sys.modules["_ash_docs_gate_for_runner"] = gate
        spec.loader.exec_module(gate)
    if not hasattr(checks, "ci_runner_census"):
        pytest.fail("scripts/docs_checks.py defines no ci_runner_census")
    return checks.ci_runner_census(
        checks.load_pages(gate.collect_md_files(), gate.REPO_ROOT)
    )


#: What the pipelines' runs depend on, besides the CI pages: the workflows they call,
#: the image build, the dependencies and the wheel build, the pytest settings and the
#: conftest.py files the runs read, the harness and the checks, the fixture, this
#: workflow, the code whose output the runs assert on (the CLI, the SARIF and JUnit
#: reporters, the changed-files code), and the tool installs every pipeline runs, whose
#: SHA256 checks the pages' cache text relies on.
DEPENDED_ON = (
    ".github/workflows/run-ash-security-scan.yml",
    ".github/workflows/upload-ash-sarif.yml",
    "Dockerfile",
    "pyproject.toml",
    "uv.lock",
    "hatch_build.py",
    "pytest.ini",
    "tests/conftest.py",
    "tests/integration/docs/conftest.py",
    "scripts/docs_checks.py",
    "tests/integration/docs/ci_runners/runners.toml",
    "tests/integration/docs/ci_runners/install_tools.py",
    "tests/integration/docs/test_docs_ci_runners.py",
    "tests/integration/docs/test_docs_ci_runners_can_fail.py",
    "tests/test_data/docs_fixtures/sample-project/app.py",
    WORKFLOW_REL,
    "automated_security_helper/cli/entrypoint.py",
    "automated_security_helper/cli/main.py",
    "automated_security_helper/cli/scan.py",
    "automated_security_helper/cli/merge.py",
    "automated_security_helper/plugin_modules/ash_builtin/reporters/sarif_reporter.py",
    "automated_security_helper/plugin_modules/ash_builtin/reporters/github_ghas_reporter.py",
    "automated_security_helper/plugin_modules/ash_builtin/reporters/junitxml_reporter.py",
    "automated_security_helper/utils/get_scan_set.py",
    "automated_security_helper/interactions/run_ash_scan.py",
    "automated_security_helper/cli/dependencies.py",
    "automated_security_helper/utils/tool_downloads.py",
    "automated_security_helper/utils/download_utils.py",
)
#: Exact entries, not globs: a pattern broad enough to cover them would start every
#: leg for a typo on any page, or for an edit to another directory's conftest.py.
EXACT = (
    WORKFLOW_REL,
    "Dockerfile",
    "pyproject.toml",
    "uv.lock",
    "pytest.ini",
    "tests/conftest.py",
    "tests/integration/docs/conftest.py",
)
#: Changes that must not start the workflow.
UNRELATED = (
    "README.md",
    "docs/content/reference/scanners.md",
    "docs/content/how-to/suppress-findings.md",
)


def test_the_path_filter_names_every_ci_page_and_template():
    census = _census()
    patterns = _workflow()["on"]["pull_request"]["paths"]
    pages = {entry.page for entries in census.legs.values() for entry in entries}
    pages |= {entry.page for entry in census.runner_none}
    pages |= {entry.page for entry in census.static_only}
    assert pages, "the census names no page"
    expected = set(pages) | {
        f"{page}.template"
        for page in pages
        if (REPO_ROOT / f"{page}.template").is_file()
    }
    missing = sorted(expected - set(patterns))
    assert not missing, (
        f"CI pages and templates the path filter does not name: {missing}"
    )


def test_the_path_filter_covers_what_the_runs_depend_on_and_nothing_unrelated():
    patterns = _workflow()["on"]["pull_request"]["paths"]
    _check_the_glob_reader()
    # The runner tests, the harness and this workflow are what the CI-runner change
    # adds; everything else on the lists is in the tree already.
    for path in DEPENDED_ON + UNRELATED:
        assert (
            (REPO_ROOT / path).exists()
            or path.startswith("tests/integration/docs/")
            or path == WORKFLOW_REL
        ), f"{path} does not exist; update this list with the tree"
    uncovered = [path for path in DEPENDED_ON if not _filtered(path, patterns)]
    assert not uncovered, f"changes to these do not start the workflow: {uncovered}"
    assert not [p for p in EXACT if p not in patterns], f"name these exactly: {EXACT}"
    local_actions = sorted(
        {
            str(step["uses"])[2:].rstrip("/") + "/action.yml"
            for _job, _index, step in _all_steps()
            if str(step.get("uses", "")).startswith("./")
        }
    )
    uncovered_actions = [a for a in local_actions if not _filtered(a, patterns)]
    assert not uncovered_actions, (
        f"local actions the filter misses: {uncovered_actions}"
    )
    started = [path for path in UNRELATED if _filtered(path, patterns)]
    assert not started, f"these unrelated changes start every leg: {started}"


# ---------------------------------------------------------------------------
# Token, secrets, credentials, pins
# ---------------------------------------------------------------------------


def test_the_token_is_read_only_and_nothing_widens_it():
    workflow = _workflow()
    assert workflow.get("permissions") == {"contents": "read"}
    for job_id, job in _jobs().items():
        assert job.get("permissions", {}) in ({}, {"contents": "read"}), (
            f"job {job_id} widens the token: {job.get('permissions')}"
        )
    text = _text()
    assert "secrets." not in text and "id-token" not in text


def test_no_checkout_keeps_credentials():
    checkouts = [
        (job_id, step)
        for job_id, _index, step in _all_steps()
        if str(step.get("uses", "")).startswith("actions/checkout@")
    ]
    assert checkouts, "no checkout step"
    for job_id, step in checkouts:
        assert (step.get("with") or {}).get("persist-credentials") is False, job_id


def test_every_action_is_pinned_to_a_commit_with_its_version():
    for number, line in enumerate(_text().split("\n"), 1):
        code = line.split("#", 1)[0] if not line.lstrip().startswith("#") else ""
        match = re.search(r"\buses:\s*(['\"]?)([^\s'\"]+)\1", code)
        if not match or match.group(2).startswith("./"):
            continue
        assert SHA_PIN.match(match.group(2)), (
            f"line {number}: {match.group(2)} is not pinned"
        )
        assert re.search(r"#\s*v?\d+(\.\d+)*", line), (
            f"line {number}: no version comment"
        )


def test_setup_uv_caches_nothing():
    """setup-uv takes no input but ``enable-cache: false``. Its other inputs change what
    the steps after it run with (python-version sets UV_PYTHON, tool-dir UV_TOOL_DIR,
    and activate-environment activates a virtual environment), which
    test_no_variable_reaches_a_step_but_the_leg_s_own cannot see."""
    steps = [
        step
        for _job, _index, step in _all_steps()
        if str(step.get("uses", "")).startswith("astral-sh/setup-uv@")
    ]
    assert steps, "no setup-uv step"
    for step in steps:
        assert (step.get("with") or {}).get("enable-cache") is False
        assert step.get("with") == {"enable-cache": False}, (
            f"setup-uv takes enable-cache: false and nothing else: {step.get('with')}"
        )


# ---------------------------------------------------------------------------
# Nothing runs under act; nothing is pasted into a script
# ---------------------------------------------------------------------------


def test_under_act_no_job_and_no_step_runs():
    for job_id, job in _jobs().items():
        assert "github.event.act != true" in str(job.get("if", "")), (
            f"job {job_id}'s if: must check github.event.act"
        )
        for index, step in enumerate(_steps(job)):
            assert "!env.ACT" in str(step.get("if", "")), (
                f"job {job_id} step {index}'s if: must check !env.ACT"
            )


def test_no_expression_is_pasted_into_a_script():
    pasted = [
        (job_id, index)
        for job_id, index, step in _all_steps()
        if "${{" in str(step.get("run", ""))
    ]
    assert not pasted, f"steps with ${{{{ in run:, pass the value through env: {pasted}"


#: The keys the workflow, its job and the job's steps may set: the ones these tests
#: read. A job-level container, services or defaults, or a step's shell or
#: working-directory, would run the scripts somewhere else or in another way than the
#: pins here read them.
WORKFLOW_KEYS = {"name", "on", "permissions", "concurrency", "defaults", "jobs"}
JOB_KEYS = {
    "name",
    "if",
    "runs-on",
    "timeout-minutes",
    "permissions",
    "strategy",
    "env",
    "steps",
}
STEP_KEYS = {"name", "id", "if", "uses", "with", "env", "run", "timeout-minutes"}
#: The step that writes the one_line and with_commands_stopped helper, as the other
#: workflows name it. Like theirs, it names the default shell outright.
HELPER_DEFINER = "Write the one_line helper"


def test_every_script_runs_in_bash_and_nothing_sets_a_key_these_tests_do_not_read():
    """GitHub runs a bash step as `bash --noprofile --norc -eo pipefail`, which the
    scripts' status handling is written for. Only the helper's definer sets `shell`,
    and only to bash, the workflow's own default."""
    workflow = _workflow()
    assert set(workflow) == WORKFLOW_KEYS, f"workflow keys: {sorted(workflow)}"
    assert workflow.get("defaults") == {"run": {"shell": "bash"}}
    for job_id, job in _jobs().items():
        assert set(job) == JOB_KEYS, f"job {job_id} keys: {sorted(job)}"
        assert job.get("if") == "${{ github.event.act != true }}", (
            f"job {job_id}'s if: is exactly the act check: {job.get('if')!r}"
        )
        for index, step in enumerate(_steps(job)):
            where = f"job {job_id} step {index} ({step.get('name')})"
            if step.get("name") == HELPER_DEFINER:
                assert step.get("shell") == "bash", (
                    f"{where} sets shell {step.get('shell')!r}, not the default bash"
                )
            else:
                assert "shell" not in step, f"{where} sets its own shell"
            unread = set(step) - {"shell"} - STEP_KEYS
            assert not unread, f"{where} sets {sorted(unread)}"


# ---------------------------------------------------------------------------
# The wheel, the logs
# ---------------------------------------------------------------------------


def test_each_leg_builds_exactly_one_wheel_and_none_passes_between_jobs():
    _job_id, job = _leg_job()
    steps = _steps(job)
    builds = [
        step
        for step in steps
        if "uv build" in str(step.get("run", ""))
        and "--wheel" in str(step.get("run", ""))
    ]
    assert len(builds) == 1, "the leg job builds the wheel under test itself"
    script = builds[0]["run"]
    assert "shopt -s nullglob" in script
    assert re.search(r"-ne 1\b|!= 1\b", script), (
        "the build step checks for exactly one wheel"
    )
    assert steps.index(builds[0]) < _first(steps, "test_docs_ci_runners.py")
    for job_id, _index, step in _all_steps():
        uses = str(step.get("uses", ""))
        assert not uses.startswith("actions/download-artifact@"), job_id
        if uses.startswith("actions/upload-artifact@"):
            assert ".whl" not in str((step.get("with") or {}).get("path", "")), job_id


def test_each_leg_uploads_its_logs_under_a_name_unique_to_the_leg_and_attempt():
    _job_id, job = _leg_job()
    uploads = [
        step
        for step in _steps(job)
        if str(step.get("uses", "")).startswith("actions/upload-artifact@")
    ]
    assert len(uploads) == 1, (
        "one upload of the leg's logs, saved pipelines and reports"
    )
    upload = uploads[0]
    assert (upload.get("with") or {}).get("name") == LOG_NAME
    assert (upload.get("with") or {}).get("retention-days") == 7
    assert upload.get("if") == "${{ !cancelled() && !env.ACT }}"


# ---------------------------------------------------------------------------
# Images, disk room, isolated installs, quiet act
# ---------------------------------------------------------------------------


def test_image_pulls_are_recorded_before_the_installs_and_checked_after_the_runs():
    _job_id, job = _leg_job()
    steps = _steps(job)
    record = _first(steps, "docker events")
    script = str(steps[record]["run"])
    assert "type=image" in script and "event=pull" in script and "json" in script
    install = _first(steps, "install_tools.py")
    run = _first(steps, "test_docs_ci_runners.py")
    check = _first(steps, "image_allowlist.py")
    assert record < install < run < check, (
        "record the pulls before the installs, run, then check every pull"
    )


def test_the_codebuild_leg_makes_room_before_its_pulls():
    _job_id, job = _leg_job()
    steps = _steps(job)
    install = _first(steps, "install_tools.py")
    room = [
        index
        for index, step in enumerate(steps[:install])
        if "codebuild-agent" in str(step.get("if", ""))
        and "df -h" in str(step.get("run", ""))
        and re.search(
            r"data-root|rm -rf|docker (system|image) prune", str(step.get("run", ""))
        )
    ]
    assert room, (
        "a step before the installs, on the CodeBuild leg, frees disk or moves Docker's data root"
    )


def test_install_tools_runs_in_isolated_mode():
    runs = [
        str(step.get("run", ""))
        for _job, _index, step in _all_steps()
        if "install_tools.py" in str(step.get("run", ""))
    ]
    assert runs
    for script in runs:
        for line in script.split("\n"):
            if "install_tools.py" in line:
                assert (
                    "python3 -I tests/integration/docs/ci_runners/install_tools.py"
                    in line
                ), line


def test_the_jenkins_tool_check_runs_python_in_isolated_mode():
    """The step runs in the checkout, so a `python3 -c` without -I would import a module
    of the checkout's root (a venv.py, say) before the standard library's, and would
    read the PYTHON* variables."""
    _job_id, job = _leg_job()
    steps = {step.get("name"): step for step in _steps(job)}
    code = _code(str(steps["Check the Jenkins agent's tools"].get("run", "")))
    calls = [
        code[match.end() :].split("\n", 1)[0]
        for match in re.finditer(r"(?<![\w./-])python3?(?=\s)", code)
    ]
    assert calls, "the Jenkins tool check runs Python"
    assert any(call.startswith(" -I -c ") for call in calls), calls
    assert all(call.startswith(" -I -c ") or call == " --version" for call in calls), (
        f"every python3 that runs code here runs with -I: {calls}"
    )


#: The Jenkins tool check, line by line: the image's system PATH, one Python run in
#: isolated mode, the tools the page's Jenkinsfile and its cfn-nag install need, and
#: their versions. Pinned whole, so a Python spelled another way (python3.12, a path
#: to it) cannot run code here without -I.
JENKINS_TOOL_CHECK_LINES = (
    "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "missing=()",
    (
        "python3 -I -c 'import sys, venv, ensurepip; "
        "sys.exit(0 if sys.version_info >= (3, 10) else 1)' ||"
    ),
    'missing+=("Python 3.10 or later with venv")',
    "for tool in git node npm ruby gem cc make; do",
    'command -v "${tool}" > /dev/null || missing+=("${tool}")',
    "done",
    (
        "ruby -rrbconfig -e 'exit(File.file?(File.join("
        'RbConfig::CONFIG["rubyhdrdir"], "ruby.h")))\' ||'
    ),
    'missing+=("Ruby\'s headers")',
    'if [ "${#missing[@]}" -ne 0 ]; then',
    'echo "::error::the Jenkins agent\'s system PATH lacks: ${missing[*]}"',
    "exit 1",
    "fi",
    "python3 --version",
    "git --version",
    "node --version",
    "npm --version",
    "ruby --version",
)


def test_the_jenkins_tool_check_runs_exactly_its_lines():
    _job_id, job = _leg_job()
    steps = {step.get("name"): step for step in _steps(job)}
    lines = _logical_lines(str(steps["Check the Jenkins agent's tools"].get("run", "")))
    assert lines == list(JENKINS_TOOL_CHECK_LINES), (
        f"the Jenkins tool check runs something else: {lines}"
    )


#: Where act's command line is built and started. run_act.py builds it and no other
#: program's, so all of run_act.py is read: its module constants, its helpers, act_argv
#: and run_act. The command line leaves run_act.py through act_argv and run_act, so
#: each function elsewhere that calls them is read too, found by the call rather than
#: listed. env.py's launch and launch_argv are read as well: every launch's command
#: line goes through them (``env -i K=V ... argv``), act's included, so a word they
#: add reaches act or env.
ACT_MODULE = "run_act.py"
ACT_ENTRY_POINTS = ("act_argv", "run_act")
SHARED_LAUNCH = {"env.py": ("launch", "launch_argv")}
#: The assignments not read for ``--verbose``: rewrite.py's tables of the options pip
#: and uv take before their command names, which the rewrite reads a page's commands
#: against. ``--verbose`` there is an option to recognize in page text, and nothing
#: passes these tables to a program.
VERBOSE_TEXT_TABLES = {
    "rewrite.py": (
        "_UV_GLOBAL_OPTIONS",
        "_PIP_GENERAL_OPTIONS",
        "_PIP_INSTALL_FLAGS",
        "_UV_TOOL_INSTALL_FLAGS",
    ),
}
#: act's verbose flag: ``--verbose``, or ``-v`` alone or in a cluster of short flags,
#: each with or without a value, as act's flag parser reads them (``-v=true``).
VERBOSE_FLAG = re.compile(r"--verbose(=.*)?|-[A-Za-z]*v[A-Za-z]*(=.*)?")


def _check_the_verbose_flag_reader() -> None:
    """Control for the pattern the act check uses: act's spellings of its verbose flag
    match, and other flags do not."""
    for flag in ("-v", "-qv", "--verbose", "--verbose=true"):
        assert VERBOSE_FLAG.fullmatch(flag), flag
    for flag in ("--var", "--env", "-W", "-P"):
        assert not VERBOSE_FLAG.fullmatch(flag), flag


def _words(text: str) -> list[str]:
    """``text``, and its shell words when it holds whitespace: a constant can hold part
    of a command line that is split later (``"--rm -v".split()``)."""
    if not any(character.isspace() for character in text):
        return [text]
    try:
        return [text, *shlex.split(text)]
    except ValueError:
        return [text, *text.split()]


def _built_flags(tree: ast.AST) -> list[ast.expr]:
    """The f-strings and ``+`` chains in ``tree`` that start with a dash and fill in
    part of the flag's name, as ``f"-{short}"`` does: which flag they build cannot be
    read here. A message such as ``f"--json {value} ..."`` names its flag whole and
    fills in only what follows it."""
    built = []
    for node in ast.walk(tree):
        if isinstance(node, ast.JoinedStr):
            parts = list(node.values)
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            parts, stack = [], [node]
            while stack:
                part = stack.pop()
                if isinstance(part, ast.BinOp) and isinstance(part.op, ast.Add):
                    stack += [part.right, part.left]
                else:
                    parts.append(part)
        else:
            continue
        shape = "".join(
            part.value
            if isinstance(part, ast.Constant) and isinstance(part.value, str)
            else "\0"
            for part in parts
        )
        name = re.split(r"[\s=]", shape, maxsplit=1)[0]
        if name.startswith("-") and "\0" in name:
            built.append(node)
    return built


def _strings(tree: ast.AST) -> list[ast.Constant]:
    """The string constants in ``tree`` but its bare string statements (docstrings),
    which nothing passes on."""
    bare = {
        id(node.value)
        for node in ast.walk(tree)
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant)
    }
    return [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and id(node) not in bare
    ]


def _text_tables(module: str, tree: ast.Module) -> set[int]:
    """The ids of every node in ``module``'s VERBOSE_TEXT_TABLES assignments."""
    names = VERBOSE_TEXT_TABLES.get(module, ())
    tables = {
        node.targets[0].id: node
        for node in tree.body
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id in names
    }
    missing = [name for name in names if name not in tables]
    assert not missing, f"{module} assigns no {missing}"
    return {id(inner) for table in tables.values() for inner in ast.walk(table)}


def _calls(function: ast.AST, names: set[str]) -> bool:
    """Whether ``function`` calls one of ``names``, by itself or as an attribute."""
    for node in ast.walk(function):
        if isinstance(node, ast.Call):
            called = node.func
            if isinstance(called, ast.Name) and called.id in names:
                return True
            if isinstance(called, ast.Attribute) and called.attr in names:
                return True
    return False


def _act_scopes(trees: dict[str, ast.Module]) -> list[tuple[str, ast.AST]]:
    """The code act's command line goes through: run_act.py, the SHARED_LAUNCH
    functions, and each function elsewhere that calls an ACT_ENTRY_POINTS function by
    its name or a name it is imported as. A module, a function or a caller of these
    that is not found fails the check, which would otherwise read less than it means
    to and pass."""
    missing = [module for module in (ACT_MODULE, *SHARED_LAUNCH) if module not in trees]
    assert not missing, f"the harness has no {missing}"
    defined = {
        node.name
        for node in trees[ACT_MODULE].body
        if isinstance(node, ast.FunctionDef)
    }
    undefined = [name for name in ACT_ENTRY_POINTS if name not in defined]
    assert not undefined, f"{ACT_MODULE} defines no {undefined}"
    scopes: list[tuple[str, ast.AST]] = [(ACT_MODULE, trees[ACT_MODULE])]
    for module, names in SHARED_LAUNCH.items():
        functions = {
            node.name: node
            for node in trees[module].body
            if isinstance(node, ast.FunctionDef)
        }
        missing = [name for name in names if name not in functions]
        assert not missing, f"{module} defines no {missing}"
        scopes += [(module, functions[name]) for name in names]
    stem = ACT_MODULE.removesuffix(".py")
    callers: list[tuple[str, ast.AST]] = []
    for module, tree in trees.items():
        if module == ACT_MODULE:
            continue
        names = set(ACT_ENTRY_POINTS) | {
            alias.asname
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
            and (node.module or "").rpartition(".")[2] == stem
            for alias in node.names
            if alias.name in ACT_ENTRY_POINTS and alias.asname
        }
        callers += [
            (module, node)
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and _calls(node, names)
        ]
    assert callers, f"no function of the harness calls {' or '.join(ACT_ENTRY_POINTS)}"
    return scopes + callers


def _act_launch_flags() -> set[str]:
    """The verbose flags the harness could give act, as ``module:line 'flag'``.

    ``--verbose`` is looked for in every string constant of every module but those in
    VERBOSE_TEXT_TABLES, and in its shell words, so a module or a helper added to the
    harness is read without being listed. A short ``-v`` is looked for only in the code
    act's command line goes through (_act_scopes): elsewhere in the harness ``-v`` is
    another program's (run_circleci.py's volume mounts) or text the harness matches (the
    printf ``-v`` rewrite.py looks for in page text). There, too, an f-string or a ``+``
    chain that fills in part of a flag's name fails the check (_built_flags). What it
    cannot read: a flag made with ``join``, ``format`` or ``%``, or one that comes from
    outside the harness.
    """
    assert CI_RUNNERS.is_dir(), f"the harness is not at {CI_RUNNERS}"
    trees = {
        path.name: ast.parse(path.read_text(encoding="utf-8"))
        for path in sorted(CI_RUNNERS.glob("*.py"))
    }
    flags: set[str] = set()
    for module, tree in trees.items():
        tables = _text_tables(module, tree)
        flags |= {
            f"{module}:{node.lineno} {node.value!r}"
            for node in _strings(tree)
            if id(node) not in tables
            and any(
                word.startswith("--") and VERBOSE_FLAG.fullmatch(word)
                for word in _words(node.value)
            )
        }
    for module, scope in _act_scopes(trees):
        flags |= {
            f"{module}:{node.lineno} {node.value!r}"
            for node in _strings(scope)
            if any(VERBOSE_FLAG.fullmatch(word) for word in _words(node.value))
        }
        flags |= {
            f"{module}:{node.lineno} {ast.unparse(node)}"
            for node in _built_flags(scope)
        }
    return flags


def test_act_is_never_verbose():
    text = _text()
    assert "--verbose" not in text
    for line in text.split("\n"):
        assert not re.search(r"(^|[\s;&|(])act\s[^#\n]*\s-v(\s|$)", line), line
    _check_the_verbose_flag_reader()
    flags = _act_launch_flags()
    assert not flags, f"the harness could give act a verbose flag: {sorted(flags)}"


def _harness_copy(tmp_path: Path, monkeypatch, edits=()) -> Path:
    """A copy of the harness's modules, with each ``(module, old, new)`` of ``edits``
    made once, which CI_RUNNERS names for the rest of the test."""
    copy = tmp_path / "ci_runners"
    copy.mkdir()
    for path in sorted(CI_RUNNERS.glob("*.py")):
        (copy / path.name).write_text(
            path.read_text(encoding="utf-8"), encoding="utf-8"
        )
    for module, old, new in edits:
        text = (copy / module).read_text(encoding="utf-8")
        assert text.count(old) == 1, f"{module} does not hold {old!r} once"
        (copy / module).write_text(text.replace(old, new), encoding="utf-8")
    monkeypatch.setitem(globals(), "CI_RUNNERS", copy)
    return copy


_ACT_ARGV_JSON = '        "--json",\n'
#: Edits to the harness that the check must fail: a verbose flag given to act in
#: act_argv or run_act, through a module constant, a helper or the code that calls
#: them, in each spelling act reads or built from parts; and a ``--verbose`` anywhere
#: else but rewrite.py's option tables, since nothing shows that it cannot reach a
#: command line.
VERBOSE_ACT_EDITS = {
    "act_argv passes --verbose": (
        ("run_act.py", _ACT_ARGV_JSON, _ACT_ARGV_JSON + '        "--verbose",\n'),
    ),
    "act_argv passes -v": (
        ("run_act.py", _ACT_ARGV_JSON, _ACT_ARGV_JSON + '        "-v",\n'),
    ),
    "run_act adds --verbose": (
        (
            "run_act.py",
            "        env,\n        argv,\n        cwd=cwd,\n",
            '        env,\n        [*argv, "--verbose"],\n        cwd=cwd,\n',
        ),
    ),
    "act_argv reads a module constant": (
        (
            "run_act.py",
            'STUB_RECORDS_VARIABLE = "DOCTEST_STUB_RECORDS"\n',
            'STUB_RECORDS_VARIABLE = "DOCTEST_STUB_RECORDS"\nACT_FLAGS = ("-v",)\n',
        ),
        ("run_act.py", _ACT_ARGV_JSON, _ACT_ARGV_JSON + "        *ACT_FLAGS,\n"),
    ),
    "act_argv calls a helper": (
        (
            "run_act.py",
            "def act_argv(\n",
            'def _act_flags() -> list[str]:\n    return ["-v"]\n\n\ndef act_argv(\n',
        ),
        ("run_act.py", _ACT_ARGV_JSON, _ACT_ARGV_JSON + "        *_act_flags(),\n"),
    ),
    "the caller of run_act adds -v": (
        (
            "pipelines.py",
            '    _record(out, "act", argv)\n',
            '    argv = [*argv, "-v"]\n    _record(out, "act", argv)\n',
        ),
    ),
    "--verbose outside rewrite.py's option tables": (
        (
            "rewrite.py",
            "@dataclass(frozen=True)\nclass _LeadingOptions:\n",
            '_DEBUG = "--verbose"\n\n\n@dataclass(frozen=True)\nclass _LeadingOptions:\n',
        ),
    ),
    "act_argv passes -v=true": (
        ("run_act.py", _ACT_ARGV_JSON, _ACT_ARGV_JSON + '        "-v=true",\n'),
    ),
    "act_argv splits a command fragment holding -v": (
        ("run_act.py", _ACT_ARGV_JSON, '        *"--json -v".split(),\n'),
    ),
    "act_argv builds -v in an f-string": (
        (
            "run_act.py",
            'STUB_RECORDS_VARIABLE = "DOCTEST_STUB_RECORDS"\n',
            'STUB_RECORDS_VARIABLE = "DOCTEST_STUB_RECORDS"\nSHORT = "v"\n',
        ),
        ("run_act.py", _ACT_ARGV_JSON, _ACT_ARGV_JSON + '        f"-{SHORT}",\n'),
    ),
    "act_argv builds -v with +": (
        (
            "run_act.py",
            'STUB_RECORDS_VARIABLE = "DOCTEST_STUB_RECORDS"\n',
            'STUB_RECORDS_VARIABLE = "DOCTEST_STUB_RECORDS"\nSHORT = "v"\n',
        ),
        ("run_act.py", _ACT_ARGV_JSON, _ACT_ARGV_JSON + '        "-" + SHORT,\n'),
    ),
}
#: Edits the check must pass: a message in the act launch code that names an option
#: before the part it fills in, and a ``-v`` on a command line that is not act's
#: (``docker rm -v`` in the container sweep).
HARMLESS_EDITS = {
    "a message naming an option": (
        (
            "run_act.py",
            'f"{ref} is not an action a stub stands in for"',
            'f"--local-repository {ref} is not an action a stub stands in for"',
        ),
    ),
    "docker rm -v in the container sweep": (
        (
            "env.py",
            'self._docker(["rm", "-f", *new], out)',
            'self._docker(["rm", "-f", "-v", *new], out)',
        ),
    ),
}


@pytest.mark.parametrize(
    "edits", list(VERBOSE_ACT_EDITS.values()), ids=list(VERBOSE_ACT_EDITS)
)
def test_a_verbose_act_fails_the_check(tmp_path, monkeypatch, edits):
    _harness_copy(tmp_path, monkeypatch, edits)
    assert _act_launch_flags(), "the check passes a verbose flag it must fail"


@pytest.mark.parametrize(
    "edits", list(HARMLESS_EDITS.values()), ids=list(HARMLESS_EDITS)
)
def test_text_that_does_not_make_act_verbose_passes_the_check(
    tmp_path, monkeypatch, edits
):
    _harness_copy(tmp_path, monkeypatch, edits)
    flags = _act_launch_flags()
    assert not flags, f"the check fails on {sorted(flags)}"


@pytest.mark.parametrize("module", [ACT_MODULE, *SHARED_LAUNCH])
def test_a_moved_act_launch_module_fails_the_check(tmp_path, monkeypatch, module):
    """A launch module renamed or moved would take its part of the check with it."""
    copy = _harness_copy(tmp_path, monkeypatch)
    (copy / module).rename(copy / f"moved_{module}")
    with pytest.raises(AssertionError, match=re.escape(module)):
        _act_launch_flags()


def test_a_missing_harness_fails_the_check(tmp_path, monkeypatch):
    monkeypatch.setitem(globals(), "CI_RUNNERS", tmp_path / "ci_runners")
    with pytest.raises(AssertionError, match="ci_runners"):
        _act_launch_flags()


#: Edits after which the check would find no function that calls act_argv or run_act,
#: and so read none: act_argv renamed with its call, or every call made by another
#: name.
UNCALLED_ACT_EDITS = {
    "act_argv renamed": (
        ("run_act.py", "def act_argv(\n", "def build_argv(\n"),
        ("pipelines.py", "run_act.act_argv(", "run_act.build_argv("),
    ),
    "act_argv and run_act called by other names": (
        ("pipelines.py", "run_act.act_argv(", "run_act.__dict__['act_argv']("),
        ("pipelines.py", "run_act.run_act(", "run_act.__dict__['run_act']("),
    ),
}


@pytest.mark.parametrize(
    "edits", list(UNCALLED_ACT_EDITS.values()), ids=list(UNCALLED_ACT_EDITS)
)
def test_act_launch_code_the_check_cannot_find_fails_it(tmp_path, monkeypatch, edits):
    _harness_copy(tmp_path, monkeypatch, edits)
    with pytest.raises(AssertionError, match="act_argv"):
        _act_launch_flags()


# ---------------------------------------------------------------------------
# The legs
# ---------------------------------------------------------------------------


def test_the_matrix_legs_are_the_census_legs():
    """Red until the CI pages carry their runner markers, like the census itself."""
    _job_id, job = _leg_job()
    include = job["strategy"]["matrix"]["include"]
    legs = {(entry.get("runner"), entry.get("page")) for entry in include}
    assert len(legs) == len(include), "a leg is listed twice"
    assert legs == set(_census().legs)


#: The header paragraph that says why the bundled Jenkins leg runs an old core.
JENKINS_HEADING = "WHY THE BUNDLED JENKINS LEG RUNS AN OLD CORE"


def _comment_paragraph(text: str, heading: str) -> str:
    """The comment lines under a `# HEADING` line, up to the next heading or the end of
    the comment block, joined, with whitespace collapsed."""
    lines = text.split("\n")
    starts = [i for i, line in enumerate(lines) if line.strip() == f"# {heading}"]
    assert len(starts) == 1, f"the workflow has no single `# {heading}` comment"
    body: list[str] = []
    for line in lines[starts[0] + 1 :]:
        stripped = line.strip()
        if not stripped.startswith("#"):
            break
        words = stripped.lstrip("#").strip()
        if words.startswith("WHY ") and words == words.upper():
            break
        body.append(words)
    return " ".join(" ".join(body).split())


def test_the_jenkins_legs_run_both_cores_and_the_old_core_is_explained():
    _job_id, job = _leg_job()
    runners = {entry.get("runner") for entry in job["strategy"]["matrix"]["include"]}
    assert {"jenkinsfile-runner-lts", "jenkinsfile-runner-bundled"} <= runners
    comments = _comment_paragraph(_text(), JENKINS_HEADING)
    for phrase in (
        "2.375.4",
        "the LTS core pinned in runners.toml",
        "past its upstream support period",
        "GitHub-hosted runner",
        "no listener",
        "no credentials",
        "committed plugin closure",
    ):
        assert phrase in comments, (
            f"the comment on the bundled Jenkins leg does not say {phrase!r}"
        )
    text = _text()
    assert not re.search(r"\b(CVE|GHSA)-", text), "no advisory ids in the workflow"
    assert not re.search(r"vulnerab|exploit", text, re.IGNORECASE), (
        "neutral words: the workflow describes what runs, not what is vulnerable"
    )


def test_no_plain_http_url_and_no_http_port():
    text = _text()
    assert "http://" not in text
    assert not re.search(r"--httpPort", text, re.IGNORECASE)


def test_the_codebuild_leg_shows_disk_use_after_its_pulls():
    _job_id, job = _leg_job()
    steps = _steps(job)
    install = _first(steps, "install_tools.py")
    after = [
        index
        for index, step in enumerate(steps)
        if index > install
        and "codebuild-agent" in str(step.get("if", ""))
        and "df -h" in str(step.get("run", ""))
    ]
    assert after, "a step after the installs, on the CodeBuild leg, prints df -h"


#: Commands whose output can quote a pipeline's output or a downloaded file's name.
QUOTING = ("pytest", "check_junit.py", "image_allowlist.py", "install_tools.py")
#: A command that prints a file, such as a runner log, to the job's log.
PRINTS_A_FILE = re.compile(r"(^|[\s;&|(])(cat|tail|head|less|more|tac)\s")
TOKEN = re.compile(
    r'^\s*token="\$\(od -An -N16 -tx1 /dev/urandom [^\n]*\)"\s*$', re.MULTILINE
)
STOP = "printf '::stop-commands::%s\\n' \"${token}\""
RESUME = "printf '\\n::%s::\\n' \"${token}\""
REFUSAL = "no random token could be read for stop-commands, so the command did not run"
#: How a step loads the helper its definer wrote, and how it runs a command through
#: it: with_commands_stopped prints the token pair itself, runs the command in a
#: process group of its own, and closes the section when the step's timeout fires.
HELPER_SOURCE = '. "${RUNNER_TEMP}/ash-one-line.sh"'
HELPER_CALL = "with_commands_stopped "


def _code(script: str) -> str:
    """The script without its comment lines, so prose naming a command is ignored."""
    return "\n".join(
        line for line in script.split("\n") if not line.strip().startswith("#")
    )


def _quoting_positions(code: str) -> list[int]:
    positions = [
        m.start() for needle in QUOTING for m in re.finditer(re.escape(needle), code)
    ]
    offset = 0
    for line in code.split("\n"):
        if PRINTS_A_FILE.search(line):
            positions.append(offset)
        offset += len(line) + 1
    return positions


def test_commands_that_can_quote_a_pipeline_run_with_workflow_commands_stopped():
    wrapped = 0
    for job_id, index, step in _all_steps():
        if step.get("name") == HELPER_DEFINER:
            # The helper's own text, which the other workflows' copies hold equal
            # (test_every_definer_writes_the_same_helper), is not a command that
            # can quote a pipeline.
            continue
        code = _code(str(step.get("run", "")))
        positions = _quoting_positions(code)
        if not positions:
            continue
        where = f"job {job_id} step {index} ({step.get('name')})"
        if HELPER_SOURCE in code:
            call = code.rindex(HELPER_CALL)
            assert code.count(HELPER_CALL) == 1 and code.index(HELPER_SOURCE) < call, (
                f"{where}: one with_commands_stopped call, after the helper is loaded"
            )
            assert _logical_lines(code)[-1].startswith(HELPER_CALL), (
                f"{where}: the call is the last command, so its status is the step's"
            )
            assert all(call < position for position in positions), (
                f"{where}: every command that can quote a pipeline runs through "
                "with_commands_stopped"
            )
            wrapped += 1
            continue
        assert TOKEN.search(code), f"{where}: the token is not read from /dev/urandom"
        assert code.count(STOP) == 1 and code.count(RESUME) == 1, (
            f"{where}: one stop-commands line and one resume line"
        )
        stop, resume = code.index(STOP), code.index(RESUME)
        refusal = code.find(REFUSAL)
        assert TOKEN.search(code).start() < refusal < stop, (
            f"{where}: a step that could not read a token refuses before it runs anything"
        )
        assert re.search(r"-ne 32 \]; then\n[^\n]*\n\s*exit 1\n", code[:stop]), (
            f"{where}: the refusal checks the token's length and exits 1"
        )
        assert all(stop < position < resume for position in positions), (
            f"{where}: every command that can quote a pipeline runs between the "
            "stop-commands line and the resume line"
        )
        assert re.search(r'exit "\$\{status\}"\s*$', code[resume:]), (
            f"{where}: the step exits with the command's status after resuming"
        )
        wrapped += 1
    assert wrapped >= 4, (
        "the installs, the runs, the controls and the checks are wrapped"
    )


def test_the_leg_job_installs_then_runs_then_controls_then_checks():
    _job_id, job = _leg_job()
    steps = _steps(job)
    install = _first(steps, "install_tools.py")
    runs = _first(steps, "test_docs_ci_runners.py")
    controls = _first(steps, "test_docs_ci_runners_can_fail.py")
    census = _first(steps, "check_junit.py")
    images = _first(steps, "image_allowlist.py")
    assert install < runs < controls < census, (
        "install the tools, run the pages' pipelines, run the negative controls, then "
        "check that every block of the leg ran"
    )
    assert runs < images


#: The one selection every step of a leg reads: a pull request runs every leg, a
#: dispatch runs the legs its `legs` input names.
SELECTED = (
    "(github.event_name == 'pull_request' || inputs.legs == 'all' "
    "|| inputs.legs == matrix.runner)"
)


def _conjuncts(condition: str) -> list[str]:
    """The top-level `&&` operands of an `if:` expression."""
    body = condition.strip()
    if body.startswith("${{") and body.endswith("}}"):
        body = body[3:-2]
    parts, depth, start, index = [], 0, 0, 0
    while index < len(body):
        char = body[index]
        if char == "'":
            index = body.index("'", index + 1)
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif depth == 0 and body.startswith("&&", index):
            parts.append(body[start:index].strip())
            start = index + 2
            index += 1
        index += 1
    parts.append(body[start:].strip())
    return parts


def _check_the_conjunct_reader() -> None:
    assert _conjuncts("${{ !env.ACT && (a || b && c) && d == 'x && y' }}") == [
        "!env.ACT",
        "(a || b && c)",
        "d == 'x && y'",
    ]


def test_the_legs_input_selects_legs_and_a_pull_request_runs_every_leg():
    _check_the_conjunct_reader()
    legs_input = _workflow()["on"]["workflow_dispatch"]["inputs"]["legs"]
    job_id, job = _leg_job()
    runners = [entry.get("runner") for entry in job["strategy"]["matrix"]["include"]]
    assert legs_input.get("type") == "choice"
    assert legs_input.get("default") == "all"
    options = legs_input.get("options") or []
    assert options[:1] == ["all"] and sorted(options[1:]) == sorted(set(runners)), (
        f"the legs input offers all and each leg: {options}"
    )
    assert "exclude" not in job["strategy"]["matrix"]
    assert not re.search(r"inputs\.|event_name", str(job.get("if", ""))), (
        "the job runs for every leg; its steps read the selection"
    )
    for index, step in enumerate(_steps(job)):
        if str(step.get("uses", "")).startswith("actions/upload-artifact@"):
            continue
        conjuncts = _conjuncts(str(step.get("if", "")))
        assert SELECTED in conjuncts, (
            f"job {job_id} step {index} ({step.get('name')}) runs whatever the legs "
            f"input says; its if: must have {SELECTED} as an operand of &&"
        )
        others = [c for c in conjuncts if c != SELECTED]
        assert not [c for c in others if re.search(r"inputs\.|event_name", c)], (
            f"job {job_id} step {index}: only the selection reads the event or the input"
        )


def test_a_leg_that_is_not_selected_says_so_in_its_name():
    _job_id, job = _leg_job()
    assert job.get("name") == (
        "${{ matrix.runner }} (${{ matrix.page }})"
        "${{ !" + SELECTED + " && ' - not selected' || '' }}"
    ), (
        "a row a dispatch did not select ends green with nothing run, so its name says so"
    )


# ---------------------------------------------------------------------------
# What makes a leg red
# ---------------------------------------------------------------------------


def _if(*terms: str) -> str:
    return "${{ " + " && ".join(terms) + " }}"


NOT_ACT, NOT_CANCELLED = "!env.ACT", "!cancelled()"
INSTALL_RAN = (
    "(steps.install.outcome == 'success' || steps.install.outcome == 'failure')"
)
#: Every step of the leg job, in order, with its exact `if:`. A skipped step is not a
#: failure, so a term that can never be true would turn a leg green with nothing checked;
#: each condition is therefore pinned whole. The census checks run whether or not their
#: pytest step ran, so a skipped run fails the leg on its missing junit file.
LEG_STEPS = (
    ("Check out the pull request", _if(NOT_ACT, SELECTED)),
    ("Install uv", _if(NOT_ACT, SELECTED)),
    ("Install the test environment", _if(NOT_ACT, SELECTED)),
    ("Build the wheel under test", _if(NOT_ACT, SELECTED)),
    (
        "Make disk room for the CodeBuild images",
        _if(NOT_ACT, SELECTED, "matrix.runner == 'codebuild-agent'"),
    ),
    (
        "Check the Jenkins agent's tools",
        _if(NOT_ACT, SELECTED, "startsWith(matrix.runner, 'jenkinsfile-runner-')"),
    ),
    ("Start recording image pulls", _if(NOT_ACT, SELECTED)),
    ("Write the one_line helper", _if(NOT_ACT, SELECTED)),
    ("Install the leg's runner, tools and images", _if(NOT_ACT, SELECTED)),
    (
        "Show disk use after the CodeBuild pulls",
        _if(
            NOT_CANCELLED,
            NOT_ACT,
            SELECTED,
            "matrix.runner == 'codebuild-agent'",
            INSTALL_RAN,
        ),
    ),
    ("Run the pages' pipelines", _if(NOT_ACT, SELECTED)),
    (
        "Check that the pipelines can fail",
        _if(NOT_CANCELLED, NOT_ACT, SELECTED, "steps.install.outcome == 'success'"),
    ),
    (
        "Stop recording image pulls",
        _if(NOT_CANCELLED, NOT_ACT, SELECTED, "steps.events.outcome == 'success'"),
    ),
    (
        "Check every image pull against the pins",
        _if(NOT_CANCELLED, NOT_ACT, SELECTED, "steps.events.outcome == 'success'"),
    ),
    ("Check every block of the leg ran", _if(NOT_CANCELLED, NOT_ACT, SELECTED)),
    ("Check every control ran", _if(NOT_CANCELLED, NOT_ACT, SELECTED)),
    ("Upload the leg's logs, pipelines and reports", _if(NOT_CANCELLED, NOT_ACT)),
)


def test_the_leg_job_runs_these_steps_in_this_order_under_these_conditions():
    _job_id, job = _leg_job()
    actual = [(step.get("name"), step.get("if")) for step in _steps(job)]
    assert actual == list(LEG_STEPS)


def test_no_step_turns_a_failure_into_a_pass():
    for job_id, index, step in _all_steps():
        assert "continue-on-error" not in step, (
            f"job {job_id} step {index} ({step.get('name')}) sets continue-on-error"
        )
    for job_id, job in _jobs().items():
        assert "continue-on-error" not in job, f"job {job_id} sets continue-on-error"


def _logical_lines(script: str) -> list[str]:
    """The script's lines, stripped, without blank and comment lines, with each
    backslash continuation joined to the next line by one space."""
    logical: list[str] = []
    pending = ""
    for line in script.split("\n"):
        stripped = line.strip()
        if not stripped or (not pending and stripped.startswith("#")):
            continue
        if stripped.endswith("\\"):
            pending += stripped[:-1].rstrip() + " "
            continue
        logical.append(pending + stripped)
        pending = ""
    assert not pending, "a continuation line ends the script"
    return logical


OUT_DIR = 'out="${RUNNER_TEMP:?}/ci-runner-out"'
#: The root of the pytest steps' work trees (each step's --basetemp is a directory of
#: its own under it), outside the output directory the upload takes.
WORK_DIR = 'work="${RUNNER_TEMP:?}/ci-runner-work"'
PYTEST_BEFORE = (OUT_DIR, WORK_DIR, 'mkdir -p "${work}"')
TOKEN_LINES = (
    "token=\"$(od -An -N16 -tx1 /dev/urandom | tr -d ' \\n')\"",
    'if [ "${#token}" -ne 32 ]; then',
    f'echo "::error::{REFUSAL}"',
    "exit 1",
    "fi",
)
#: Every flag of the two pytest command lines, in order. pytest.ini's addopts are
#: cleared and PYTEST_ADDOPTS is dropped, so these are all the options the runs get
#: (ADDOPTS_IN_CI says why each of pytest.ini's own is left out or replaced, and
#: PYTEST_INI_IN_CI what its other settings do). Each long option takes its value as
#: ``--name=value`` (test_no_pytest_option_takes_its_value_as_a_separate_token says
#: why).
PYTEST = (
    "env -u PYTEST_ADDOPTS uv run --frozen pytest -o addopts= -o log_cli=false "
    "-p no:cacheprovider -n 0 --durations=0 --durations-min=0 "
    '--basetemp="${{work}}/{out}" {module} '
    '--run-integration --run-ci-runners --ci-runner="${{LEG}}" '
    '--ci-runner-page="${{PAGE}}" --ci-runner-bin="${{RUNNER_TEMP:?}}/ci-runner-bin" '
    '--ci-runner-jenkins-dir="${{RUNNER_TEMP:?}}/ci-runner-jenkins" '
    '--ci-runner-wheel="${{WHEEL}}" --ci-runner-launch-timeout="${{LAUNCH_TIMEOUT}}" '
    '--ci-runner-out="${{out}}/{out}" --junit-xml="${{out}}/junit-{out}.xml"'
)
CHECK_JUNIT = (
    "uv run --frozen python tests/integration/docs/ci_runners/check_junit.py "
    '--junit "${out}/junit-%s.xml" --runner "${LEG}" --page "${PAGE}"'
)
#: Each wrapped step's lines before its command, and its one command. The three long
#: steps (THROUGH_THE_HELPER) load the helper first and run the command through
#: with_commands_stopped, whose return is the step's status. The short checks print the
#: token themselves: their lines before the stop-commands line come after the token
#: lines, and `2>&1 || status=$?` is the only thing after the command, and nothing else
#: assigns the status.
THROUGH_THE_HELPER = {
    "Install the leg's runner, tools and images",
    "Run the pages' pipelines",
    "Check that the pipelines can fail",
}
WRAPPED = {
    "Install the leg's runner, tools and images": (
        (
            OUT_DIR,
            "jenkins_args=()",
            'case "${LEG}" in',
            (
                "jenkinsfile-runner-*) jenkins_args=(--jenkins-dir "
                '"${RUNNER_TEMP:?}/ci-runner-jenkins") ;;'
            ),
            "esac",
        ),
        (
            "python3 -I tests/integration/docs/ci_runners/install_tools.py "
            '--runner "${LEG}" --bin-dir "${RUNNER_TEMP:?}/ci-runner-bin" '
            '--pull-log "${out}/pulls.log" "${jenkins_args[@]}"'
        ),
    ),
    "Run the pages' pipelines": (
        PYTEST_BEFORE,
        PYTEST.format(
            module="tests/integration/docs/test_docs_ci_runners.py", out="runs"
        ),
    ),
    "Check that the pipelines can fail": (
        PYTEST_BEFORE,
        PYTEST.format(
            module="tests/integration/docs/test_docs_ci_runners_can_fail.py",
            out="controls",
        ),
    ),
    "Check every image pull against the pins": (
        (OUT_DIR,),
        (
            "python3 -I tests/integration/docs/ci_runners/image_allowlist.py "
            '--events "${out}/docker-events.jsonl" --pulls "${out}/pulls.log" '
            "--manifest tests/integration/docs/ci_runners/runners.toml "
            "--built doctest-gitlab-helper:local "
            "--built registry.example.com/security/automated-security-helper:ci"
        ),
    ),
    "Check every block of the leg ran": ((OUT_DIR,), CHECK_JUNIT % "runs"),
    "Check every control ran": ((OUT_DIR,), CHECK_JUNIT % "controls" + " --controls"),
}


def test_each_check_runs_exactly_its_command_and_its_status_is_the_step_s():
    _job_id, job = _leg_job()
    steps = {step.get("name"): step for step in _steps(job)}
    for name, (before, command) in WRAPPED.items():
        assert name in steps, f"no step named {name!r}"
        lines = _logical_lines(str(steps[name].get("run", "")))
        if name in THROUGH_THE_HELPER:
            expected = [HELPER_SOURCE, *before, f"{HELPER_CALL}{command}"]
        else:
            expected = [
                *TOKEN_LINES,
                *before,
                STOP,
                "status=0",
                f"{command} 2>&1 || status=$?",
                RESUME,
                'exit "${status}"',
            ]
        assert lines == expected, f"step {name!r} runs something else: {lines}"
    pytest_env = {"WHEEL": "${{ steps.wheel.outputs.path }}"}
    for name in ("Run the pages' pipelines", "Check that the pipelines can fail"):
        assert steps[name].get("env") == pytest_env, name


#: The recorder writes the events, the stop step ends it, the allowlist reads what it
#: wrote; all three read the same files, and a recording that died early fails the leg.
RECORDER_LINES = (
    OUT_DIR,
    'mkdir -p "${out}"',
    'since="$(date +%s)"',
    (
        'docker events --since "${since}" --filter type=image --filter event=pull '
        "--format '{{json .}}' > \"${out}/docker-events.jsonl\" "
        '2> "${out}/docker-events.err" &'
    ),
    'echo "$!" > "${out}/docker-events.pid"',
)
STOP_RECORDING_LINES = (
    OUT_DIR,
    'read -r pid < "${out}/docker-events.pid"',
    'case "${pid}" in',
    "'' | *[!0-9]*)",
    'echo "::error::${out}/docker-events.pid holds no process id"',
    "exit 1",
    ";;",
    "esac",
    'if ! kill "${pid}"; then',
    'echo "::error::the image pull recording (process ${pid}) had already stopped"',
    "exit 1",
    "fi",
    "for _ in $(seq 1 30); do",
    'kill -0 "${pid}" 2> /dev/null || exit 0',
    "sleep 1",
    "done",
    (
        'echo "::error::the image pull recording (process ${pid}) did not stop '
        'within 30 seconds"'
    ),
    "exit 1",
)


def test_the_pull_recording_is_written_stopped_and_read_through_the_same_files():
    _job_id, job = _leg_job()
    steps = _steps(job)
    names = [step.get("name") for step in steps]
    by_name = dict(zip(names, steps))
    recorder = _logical_lines(str(by_name["Start recording image pulls"]["run"]))
    assert recorder == list(RECORDER_LINES)
    assert by_name["Start recording image pulls"].get("id") == "events"
    stop = _logical_lines(str(by_name["Stop recording image pulls"]["run"]))
    assert stop == list(STOP_RECORDING_LINES)
    order = [
        names.index(name)
        for name in (
            "Start recording image pulls",
            "Install the leg's runner, tools and images",
            "Check that the pipelines can fail",
            "Stop recording image pulls",
            "Check every image pull against the pins",
        )
    ]
    assert order == sorted(order), "record, install, run, stop, then check the pulls"


#: Minutes left in a leg's job budget beyond the timed steps, for the checkout, the
#: wheel build, the checks and the upload, so a timed step that runs out still leaves
#: the upload room to run.
HEADROOM = 15
ROW_KEYS = {
    "runner",
    "page",
    "timeout",
    "install_timeout",
    "runs_timeout",
    "controls_timeout",
    "launch_timeout",
}
TIMED_STEPS = {
    "Install the leg's runner, tools and images": "install_timeout",
    "Run the pages' pipelines": "runs_timeout",
    "Check that the pipelines can fail": "controls_timeout",
}


def test_each_leg_times_out_its_steps_before_its_job():
    """A job that runs out of time is cancelled, and the upload (`!cancelled()`) then
    skips; a step that runs out fails, and the upload still runs."""
    _job_id, job = _leg_job()
    assert job.get("timeout-minutes") == "${{ matrix.timeout }}"
    assert (job.get("env") or {}).get(
        "LAUNCH_TIMEOUT"
    ) == "${{ matrix.launch_timeout }}"
    steps = {step.get("name"): step for step in _steps(job)}
    for name, key in TIMED_STEPS.items():
        assert steps[name].get("timeout-minutes") == "${{ matrix." + key + " }}", name
    untimed = [
        name
        for name, step in steps.items()
        if "timeout-minutes" in step and name not in TIMED_STEPS
    ]
    assert not untimed, f"only the install, runs and controls are timed: {untimed}"
    for row in job["strategy"]["matrix"]["include"]:
        assert set(row) == ROW_KEYS, row
        numbers = [row[key] for key in sorted(ROW_KEYS - {"runner", "page"})]
        assert all(isinstance(n, int) and n > 0 for n in numbers), row
        timed = row["install_timeout"] + row["runs_timeout"] + row["controls_timeout"]
        assert timed + HEADROOM <= row["timeout"], (
            f"{row['runner']} {row['page']}: {timed} timed minutes and {HEADROOM} for the "
            f"rest do not fit in {row['timeout']}"
        )
        assert row["launch_timeout"] < 60 * min(
            row["runs_timeout"], row["controls_timeout"]
        ), f"{row['runner']}: one launch times out before the step that holds it"


#: The output directory, without the names the harness leaves out of what it copies
#: there: Jenkins' secret.key (and secret.key.not-so-secret), secrets and
#: identity.key.enc, and any *.key or *.pem file. The harness matches those names in
#: any letter case, and upload-artifact matches its patterns case-sensitively on Linux,
#: so each letter is a character set.
UPLOAD_PATH = [
    "${{ runner.temp }}/ci-runner-out",
    "!${{ runner.temp }}/ci-runner-out/**/[sS][eE][cC][rR][eE][tT].[kK][eE][yY]*",
    "!${{ runner.temp }}/ci-runner-out/**/[sS][eE][cC][rR][eE][tT][sS]",
    "!${{ runner.temp }}/ci-runner-out/**/[sS][eE][cC][rR][eE][tT][sS]/**",
    (
        "!${{ runner.temp }}/ci-runner-out/**/"
        "[iI][dD][eE][nN][tT][iI][tT][yY].[kK][eE][yY].[eE][nN][cC]"
    ),
    "!${{ runner.temp }}/ci-runner-out/**/*.[kK][eE][yY]",
    "!${{ runner.temp }}/ci-runner-out/**/*.[pP][eE][mM]",
]
#: Paths under the output directory that the upload leaves out: the secret-shaped
#: names in several letter cases.
LEFT_OUT = (
    "runs/jenkins/secret.key",
    "runs/jenkins/SECRET.KEY",
    "runs/jenkins/Secret.Key.not-so-secret",
    "runs/jenkins/secrets",
    "runs/jenkins/SECRETS",
    "runs/jenkins/Secrets/hudson.util.Secret",
    "runs/jenkins/identity.key.enc",
    "runs/jenkins/Identity.Key.ENC",
    "runs/block/deploy.key",
    "runs/block/deploy.KEY",
    "runs/block/cert.pem",
    "runs/block/cert.Pem",
)
#: Paths the upload keeps, whose names only look like the ones above.
KEPT = (
    "runs/block/junit-runs.xml",
    "runs/block/keys.txt",
    "runs/block/deploy.keys",
    "runs/block/secretsauce.log",
    "runs/block/secret.txt",
    "runs/block/pem.txt",
    "runs/block/identity.json",
)


def test_the_upload_takes_the_output_directory_and_no_hidden_or_secret_shaped_file():
    _job_id, job = _leg_job()
    uploads = [
        step
        for step in _steps(job)
        if str(step.get("uses", "")).startswith("actions/upload-artifact@")
    ]
    assert len(uploads) == 1
    options = uploads[0].get("with") or {}
    assert set(options) == {"name", "path", "retention-days"}, (
        "include-hidden-files stays at its default, false"
    )
    assert str(options["path"]).strip().split("\n") == UPLOAD_PATH


def test_the_upload_leaves_out_secret_shaped_names_in_any_letter_case():
    _check_the_glob_reader()
    _job_id, job = _leg_job()
    uploads = [
        step
        for step in _steps(job)
        if str(step.get("uses", "")).startswith("actions/upload-artifact@")
    ]
    assert len(uploads) == 1
    lines = str((uploads[0].get("with") or {}).get("path", "")).strip().split("\n")
    excluded = [
        _glob(line.strip()[1:].replace("${{ runner.temp }}", str(RUNNER_TEMP)))
        for line in lines
        if line.strip().startswith("!")
    ]
    out = RUNNER_TEMP / "ci-runner-out"
    kept = [
        path
        for path in LEFT_OUT
        if not any(e.fullmatch(f"{out}/{path}") for e in excluded)
    ]
    assert not kept, f"the upload takes these secret-shaped files: {kept}"
    dropped = [
        path for path in KEPT if any(e.fullmatch(f"{out}/{path}") for e in excluded)
    ]
    assert not dropped, f"the upload leaves out these files: {dropped}"


PYTEST_STEPS = ("Run the pages' pipelines", "Check that the pipelines can fail")


def _pytest_ini_text() -> str:
    return (REPO_ROOT / "pytest.ini").read_text(encoding="utf-8")


def _pytest_ini_addopts() -> list[str]:
    parser = configparser.ConfigParser(interpolation=None)
    parser.read_string(_pytest_ini_text())
    return shlex.split(parser.get("pytest", "addopts", fallback=""))


#: Each option of pytest.ini's addopts, in pytest.ini's order, and what both CI pytest
#: steps pass in its place: the same option with the value the runs need, or nothing.
#: Those steps clear addopts with ``-o addopts=``, so this list is the record of what
#: was decided for each; an option added to pytest.ini fails the test below until it
#: is decided here and, if the runs need it, put on the steps' command lines.
#:
#: * ``--verbose``: left out. A failure prints in full either way, and the junit file
#:   names every test. pytest.ini's live logging would turn it back on, so the steps
#:   also pass ``-o log_cli=false`` (PYTEST_INI_IN_CI).
#: * ``--junit-xml``: the step's own file under the output directory, which the census
#:   checks read and the upload takes. ``("--junit-xml=",)`` stands for the option
#:   with a value of the step's own.
#: * ``--durations``: every phase of every block, not the ten slowest, and with
#:   ``--durations-min=0`` none is hidden for taking under 5 ms, so a run shows the
#:   times its step budgets are checked against.
#: * ``-n auto``: ``-n 0``, the blocks one at a time, since they share the Docker
#:   daemon, the pull recording and the images the session builds.
#: * ``--dist worksteal``: left out. With ``-n 0`` no worker starts, so there is no work
#:   to distribute.
ADDOPTS_IN_CI = (
    (("--verbose",), ()),
    (("--junit-xml=test-results/pytest.junit.xml",), ("--junit-xml=",)),
    (("--durations=10",), ("--durations=0", "--durations-min=0")),
    (("-n", "auto"), ("-n", "0")),
    (("--dist", "worksteal"), ()),
)


def _pytest_command_tokens(step: dict) -> list[str]:
    lines = [
        line
        for line in _logical_lines(str(step.get("run", "")))
        if "uv run --frozen pytest " in line
    ]
    assert len(lines) == 1, f"step {step.get('name')!r} runs pytest once: {lines}"
    tokens = shlex.split(lines[0])
    # The command runs through the helper, which is not one of pytest's arguments.
    return tokens[1:] if tokens[:1] == [HELPER_CALL.strip()] else tokens


def _has_run(tokens: list[str], run: tuple[str, ...]) -> bool:
    return any(
        tuple(tokens[i : i + len(run)]) == run
        for i in range(len(tokens) - len(run) + 1)
    )


def _passes(tokens: list[str], ci: tuple[str, ...]) -> bool:
    """Whether the command passes ``ci``: those tokens in a row, or, for
    ``("--name=",)``, that option once, with a value of its own."""
    if len(ci) == 1 and ci[0].startswith("--") and ci[0].endswith("="):
        values = _option_values(tokens, ci[0][:-1])
        return len(values) == 1 and bool(values[0])
    return _has_run(tokens, ci)


def test_every_addopts_option_of_pytest_ini_is_decided_for_the_ci_runs():
    assert _pytest_ini_addopts() == [
        token for ini, _ci in ADDOPTS_IN_CI for token in ini
    ], (
        "pytest.ini's addopts changed. The Docs CI Runners pytest steps clear them with "
        "-o addopts=, so decide in ADDOPTS_IN_CI what those runs do with each option, "
        "and put on their command lines (PYTEST) any the runs need"
    )
    _job_id, job = _leg_job()
    steps = {step.get("name"): step for step in _steps(job)}
    for name in PYTEST_STEPS:
        tokens = _pytest_command_tokens(steps[name])
        assert _has_run(tokens, ("-o", "addopts=")), (
            f"{name}: without -o addopts=, pytest.ini's addopts apply (-n auto starts "
            "workers the blocks cannot share the Docker daemon across)"
        )
        for ini, ci in ADDOPTS_IN_CI:
            if ci:
                assert _passes(tokens, ci), f"{name} does not pass {' '.join(ci)}"
                continue
            option = ini[0].split("=", 1)[0]
            passed = [t for t in tokens if t == option or t.startswith(option + "=")]
            assert not passed, f"{name} passes {passed}, which is left out on purpose"


def test_the_pytest_steps_drop_pytest_addopts_from_their_environment():
    """pytest also reads options from PYTEST_ADDOPTS, which -o addopts= leaves in place;
    an option there such as --setup-plan would report every block and every control as
    passed without running it."""
    _job_id, job = _leg_job()
    steps = {step.get("name"): step for step in _steps(job)}
    for name in PYTEST_STEPS:
        tokens = _pytest_command_tokens(steps[name])
        assert tokens[:7] == [
            "env",
            "-u",
            "PYTEST_ADDOPTS",
            "uv",
            "run",
            "--frozen",
            "pytest",
        ], f"{name}: the command starts with env -u PYTEST_ADDOPTS: {tokens[:7]}"


#: The options the pytest steps give a value as a token of its own: pytest's -o and -p,
#: and pytest-xdist's -n, which pytest loads from its entry point. pytest knows all
#: three before it looks for any conftest.py, so it reads the next token as the value.
SEPARATE_VALUE_OPTIONS = ("-o", "-p", "-n")


def test_no_pytest_option_takes_its_value_as_a_separate_token():
    """Before pytest reads the conftest.py files that add the harness options, it takes
    each word that is neither an option nor the value of one it knows for a test path,
    and loads the conftest.py of that path's directory and of each directory above it
    that is not above the rootdir, outside the checkout too:
    ``--ci-runner-bin "${RUNNER_TEMP:?}/ci-runner-bin"`` would load one from the
    runner's temp directory, and ``--ci-runner-page "${PAGE}"`` the ones under docs/.
    Written ``--name=value``, a value is part of its option's word. pytest's own long
    options are written that way too, so the rule needs no list of the ones it knows
    early."""
    _job_id, job = _leg_job()
    steps = {step.get("name"): step for step in _steps(job)}
    for name in PYTEST_STEPS:
        tokens = _pytest_command_tokens(steps[name])
        arguments = tokens[tokens.index("pytest") + 1 :]
        words, index = [], 0
        while index < len(arguments):
            if arguments[index] in SEPARATE_VALUE_OPTIONS:
                index += 2
                continue
            if not arguments[index].startswith("-"):
                words.append(arguments[index])
            index += 1
        modules = [token for token in arguments if token.startswith("tests/")]
        assert len(modules) == 1 and words == modules, (
            f"{name}: pytest reads {words} as test paths; give each option its value "
            "as --name=value"
        )


#: The job's environment, the leg's own values, and the one variable a step adds: the
#: wheel's path, for the two pytest steps.
LEG_ENV = {
    "LEG": "${{ matrix.runner }}",
    "PAGE": "${{ matrix.page }}",
    "LAUNCH_TIMEOUT": "${{ matrix.launch_timeout }}",
}
PYTEST_ENV = {"WHEEL": "${{ steps.wheel.outputs.path }}"}
#: The checks that read files the pytest steps wrote; they run with no env of their own.
CHECK_STEPS = (
    "Check every image pull against the pins",
    "Check every block of the leg ran",
    "Check every control ran",
)
#: Ways a script sets a variable or a PATH entry for the steps after it.
SETS_FOR_LATER_STEPS = re.compile(r"GITHUB_(ENV|PATH)\b|::(set-env|add-path)\b")


def test_no_variable_reaches_a_step_but_the_leg_s_own():
    """A variable pytest or a check reads (PYTEST_ADDOPTS, PYTEST_PLUGINS and the like)
    can change what a leg runs while every pin on the command lines still holds.

    This reads the workflow's own env and scripts. The pinned actions export variables
    and PATH entries of their own (setup-uv puts uv on PATH, for one), which this test
    cannot see: each is pinned to a commit, and its inputs are pinned whole by the tests
    of the checkout, setup-uv and the upload."""
    workflow = _workflow()
    assert "env" not in workflow, f"workflow-level env: {workflow.get('env')}"
    leg_job_id, _leg = _leg_job()
    for job_id, job in _jobs().items():
        expected = LEG_ENV if job_id == leg_job_id else None
        assert job.get("env") == expected, f"job {job_id}'s env: {job.get('env')}"
        steps = {step.get("name"): step for step in _steps(job)}
        for name in CHECK_STEPS:
            if name in steps:
                assert "env" not in steps[name], (
                    f"{name} sets env: {steps[name]['env']}"
                )
        for index, step in enumerate(_steps(job)):
            expected = PYTEST_ENV if step.get("name") in PYTEST_STEPS else None
            assert step.get("env") == expected, (
                f"job {job_id} step {index} ({step.get('name')})'s env: {step.get('env')}"
            )
    setters = [
        (job_id, index, step.get("name"))
        for job_id, index, step in _all_steps()
        if SETS_FOR_LATER_STEPS.search(str(step.get("run", "")))
    ]
    assert not setters, f"scripts that set a variable for later steps: {setters}"


#: pytest.ini's [pytest] settings, in pytest.ini's order. The CI pytest steps override
#: addopts and log_cli and run with the rest as pytest.ini sets them:
#:
#: * ``testpaths``: unused, since each step names its test module.
#: * ``python_files``, ``python_classes``, ``python_functions``: apply. A change that
#:   lost a block's test fails the census check.
#: * ``addopts``: cleared with ``-o addopts=`` (ADDOPTS_IN_CI).
#: * ``markers``: applies; it registers the repository's markers.
#: * ``log_cli``: turned off with ``-o log_cli=false``. Live logging prints each record
#:   of log_cli_level or above to the job's log as it is made, and turns on verbose
#:   output. Nothing reads either: the runners write their output to files, a failing
#:   test prints the end of its runner's log and its captured records, and the junit
#:   file names every test.
#: * ``log_cli_level``: applies. With live logging off, pytest still lowers the root
#:   logger to this level for the run, so a failing test's captured-log section holds
#:   its INFO records. Pinned below, so that a lower level cannot reach the job's log
#:   unnoticed.
#: * ``log_cli_format``, ``log_cli_date_format``: unused while live logging is off.
#: * ``asyncio_default_fixture_loop_scope``: applies; it matters only to asyncio
#:   fixtures.
#:
#: A setting added to pytest.ini (log_level, junit_logging and others change what the
#: job's log and the uploaded junit files hold) fails the test below until it is decided
#: here.
PYTEST_INI_IN_CI = (
    "testpaths",
    "python_files",
    "python_classes",
    "python_functions",
    "addopts",
    "markers",
    "log_cli",
    "log_cli_level",
    "log_cli_format",
    "log_cli_date_format",
    "asyncio_default_fixture_loop_scope",
)
PYTEST_INI_PINNED = {"log_cli": "True", "log_cli_level": "INFO"}
#: The files pytest 9 reads its settings from, in the order it looks for them in each
#: directory from the first test path up; the first one holding pytest settings is the
#: one it uses.
PYTEST_CONFIG_NAMES = (
    "pytest.toml",
    ".pytest.toml",
    "pytest.ini",
    ".pytest.ini",
    "pyproject.toml",
    "tox.ini",
    "setup.cfg",
)
#: The conftest.py files pytest loads for the CI runs: those in the rootdir and in each
#: directory down to the test modules'. Each is named in the path filter.
CONFTESTS = (
    "tests/conftest.py",
    "tests/integration/conftest.py",
    "tests/integration/docs/conftest.py",
)


def _pytest_ini_settings() -> dict[str, str]:
    parser = configparser.ConfigParser(interpolation=None)
    parser.read_string(_pytest_ini_text())
    return dict(parser.items("pytest"))


def test_pytest_ini_is_what_the_ci_runs_read_and_each_of_its_settings_is_decided():
    settings = _pytest_ini_settings()
    assert list(settings) == list(PYTEST_INI_IN_CI), (
        "pytest.ini's settings changed. The Docs CI Runners pytest steps run with every "
        "setting but addopts and log_cli, so decide in PYTEST_INI_IN_CI what each one "
        f"does to those runs: {list(settings)}"
    )
    for key, value in PYTEST_INI_PINNED.items():
        assert settings[key] == value, f"pytest.ini's {key} is {settings[key]!r}"
    _job_id, job = _leg_job()
    steps = {step.get("name"): step for step in _steps(job)}
    for name in PYTEST_STEPS:
        tokens = _pytest_command_tokens(steps[name])
        assert _has_run(tokens, ("-o", "log_cli=false")), (
            f"{name}: without -o log_cli=false, pytest.ini's live logging prints every "
            "INFO record to the job's log and turns on verbose output"
        )
        modules = [t for t in tokens if t.startswith("tests/")]
        assert len(modules) == 1, f"{name} names one test module: {modules}"
        module = PurePosixPath(modules[0])
        between = [
            REPO_ROOT / parent for parent in module.parents if str(parent) != "."
        ]
        assert between, module
        found = [
            str((directory / config).relative_to(REPO_ROOT))
            for directory in between
            for config in PYTEST_CONFIG_NAMES
            if (directory / config).exists()
        ]
        assert not found, f"{name}: pytest could read its settings from {found}"
        first = [c for c in PYTEST_CONFIG_NAMES if (REPO_ROOT / c).is_file()]
        assert first[:1] == ["pytest.ini"], (
            f"{name}: pytest reads {first[:1]} at the repository's root, not pytest.ini"
        )
        conftests = sorted(
            str((directory / "conftest.py").relative_to(REPO_ROOT))
            for directory in (REPO_ROOT, *between)
            if (directory / "conftest.py").exists()
        )
        assert conftests == list(CONFTESTS), (
            f"{name}: the conftest.py files on {module}'s path are {conftests}"
        )
        paths = _workflow()["on"]["pull_request"]["paths"]
        unnamed = [conftest for conftest in conftests if conftest not in paths]
        assert not unnamed, f"{name}: the path filter does not name {unnamed}"


def _expand(word: str, values: dict[str, str]) -> str:
    """A shell word with each ``${NAME}`` or ``${NAME:?}`` replaced by its value."""

    def value(match: re.Match) -> str:
        assert match.group(1) in values, f"${{{match.group(1)}}} is not set before use"
        return values[match.group(1)]

    return re.sub(r"\$\{(\w+)(?::\?)?\}", value, word)


def _option_values(tokens: list[str], option: str) -> list[str]:
    """The values the command gives ``option``, each written ``option=value``, the one
    form the pytest steps use."""
    assert option not in tokens, f"{option} takes its value as a separate token"
    return [
        token.split("=", 1)[1] for token in tokens if token.startswith(option + "=")
    ]


def _within(path: PurePosixPath, root: PurePosixPath) -> bool:
    return path == root or root in path.parents


RUNNER_TEMP = PurePosixPath("$RUNNER_TEMP")
#: The pytest options that name a directory the session writes or reads and that must
#: outlive it: pytest deletes an existing --basetemp when it starts.
KEPT_PATHS = (
    "--ci-runner-out",
    "--junit-xml",
    "--ci-runner-bin",
    "--ci-runner-jenkins-dir",
)


def test_pytest_s_work_trees_and_every_jenkins_home_stay_out_of_the_upload():
    """The Jenkins homes live under pytest's --basetemp; the upload takes the output
    directory. Neither may hold the other, each pytest step has a work tree of its own
    (pytest deletes an existing --basetemp when it starts), and no upload path names a
    work tree or a directory above one."""
    _job_id, job = _leg_job()
    steps = {step.get("name"): step for step in _steps(job)}
    basetemps: list[PurePosixPath] = []
    kept: list[tuple[str, str, PurePosixPath]] = []
    outs: set[PurePosixPath] = set()
    for name in PYTEST_STEPS:
        values = {"RUNNER_TEMP": str(RUNNER_TEMP)}
        for line in _logical_lines(str(steps[name].get("run", ""))):
            assignment = re.fullmatch(r'(\w+)="(\$\{[^"]*)"', line)
            if assignment:
                values[assignment.group(1)] = _expand(assignment.group(2), values)
        assert "out" in values, f"{name} sets no output directory"
        outs.add(PurePosixPath(values["out"]))
        tokens = _pytest_command_tokens(steps[name])
        given = _option_values(tokens, "--basetemp")
        assert len(given) == 1, f"{name} passes one --basetemp: {given}"
        basetemp = PurePosixPath(_expand(given[0], values))
        assert _within(basetemp, RUNNER_TEMP) and basetemp != RUNNER_TEMP, (
            f"{name}: --basetemp {basetemp} is a directory under RUNNER_TEMP"
        )
        basetemps.append(basetemp)
        for option in KEPT_PATHS:
            for value in _option_values(tokens, option):
                kept.append((name, option, PurePosixPath(_expand(value, values))))
    assert len(outs) == 1, f"the pytest steps write under one output directory: {outs}"
    (out,) = outs
    first, second = basetemps
    assert not _within(first, second) and not _within(second, first), (
        f"the pytest steps share a work tree ({first}, {second}): the second session "
        "would start by deleting the first's"
    )
    for basetemp in basetemps:
        assert not _within(basetemp, out) and not _within(out, basetemp), (
            f"--basetemp {basetemp} and the output directory {out} overlap"
        )
        for name, option, path in kept:
            assert not _within(path, basetemp), (
                f"{name}: {option} {path} is under --basetemp {basetemp}, which pytest "
                "deletes when a session starts"
            )
    for name, option, path in kept:
        if option in ("--ci-runner-bin", "--ci-runner-jenkins-dir"):
            assert not _within(path, out), (
                f"{name}: {option} {path} is under the uploaded output directory"
            )
    uploads = [
        step
        for step in _steps(job)
        if str(step.get("uses", "")).startswith("actions/upload-artifact@")
    ]
    assert len(uploads) == 1
    lines = [
        line.strip()
        for line in str((uploads[0].get("with") or {}).get("path", "")).split("\n")
        if line.strip()
    ]
    assert lines, "the upload names its paths"
    for line in lines:
        assert not re.search(r"ci-runner-work|jenkins-home|ci-runner-jenkins", line), (
            f"the upload path {line!r} names a work tree, a Jenkins home or the Jenkins "
            "install"
        )
        text = line.lstrip("!").replace("${{ runner.temp }}", str(RUNNER_TEMP))
        assert "${{" not in text, f"cannot read the upload path {line!r}"
        path = PurePosixPath(text)
        if not line.startswith("!"):
            assert _within(path, out), (
                f"the upload takes {path}, outside the output directory {out}"
            )
        for basetemp in basetemps:
            assert not _within(path, basetemp) and not _within(basetemp, path), (
                f"the upload path {line!r} overlaps the work tree {basetemp}"
            )


def test_the_leg_checks_out_the_pull_request_s_head_commit():
    checkouts = [
        step
        for _job, _index, step in _all_steps()
        if str(step.get("uses", "")).startswith("actions/checkout@")
    ]
    assert len(checkouts) == 1
    assert checkouts[0].get("with") == {
        "persist-credentials": False,
        "ref": "${{ github.event.pull_request.head.sha || github.sha }}",
    }, "the wheel and the git installs test the same tree: the head commit"


def test_the_run_settings_that_keep_legs_independent_and_tokens_out():
    workflow = _workflow()
    text = _text()
    _job_id, job = _leg_job()
    assert job["strategy"].get("fail-fast") is False
    assert workflow.get("concurrency") == {
        "group": "${{ github.workflow }}-${{ github.ref }}-${{ inputs.legs || 'all' }}",
        # A newer run supersedes an older one on the same ref and leg, except on main
        # and tags, where a run is never cancelled. The expression is the one every
        # workflow shares; test_workflows_cancel_superseded_runs_outside_main.py pins
        # it across the directory.
        "cancel-in-progress": (
            "${{ github.ref != 'refs/heads/main' && !startsWith(github.ref, 'refs/tags/') }}"
        ),
    }
    assert "github.token" not in text and "GITHUB_TOKEN" not in text
    cached = [
        step.get("name")
        for _job, _index, step in _all_steps()
        if str(step.get("uses", "")).startswith("actions/cache")
    ]
    assert not cached, f"nothing restores or saves a cache: {cached}"

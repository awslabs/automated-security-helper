# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The reusable workflow's `changed-files-only` input must narrow the findings reported.

Why this file exists
--------------------
run-ash-security-scan.yml passed `--changed-files-only --base-ref origin/main` but
checked the repository out at depth 1 with no other refs. ASH scans every file and
then drops the findings in files outside `git diff --name-only <base>...HEAD`, which
needs the base and the merge base in the local history; with neither, git fails and
ASH falls back to reporting the findings in every file (utils/get_scan_set.py,
get_changed_files). So the input changed nothing, on every event.

What is asserted
----------------
* With the input on, the checkout fetches the whole history (fetch-depth 0), which
  also brings the remote branches such as origin/main.
* A step picks the base: the pull request's base commit on pull_request, the merge
  group's base commit on merge_group, and the `base-ref` input otherwise; it fails
  when that ref is not in the checkout instead of letting ASH report every file.
* The scan step passes that step's ref to `--base-ref`.
* What git prints while the step runs it is never read as a workflow command: each
  git call runs through with_commands_stopped. A git that writes a command to stderr
  on every call shows it.

The step's script is run in real clones: one with history, where ASH's own
get_changed_files then returns the diff, and one at depth 1, where the step refuses.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from tests.utils.workflow_one_line import COMMAND_TEXT, honored_commands, write_helper

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "run-ash-security-scan.yml"


def _steps() -> list[dict]:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]["ash"]["steps"]


def _step(*, name: str | None = None, step_id: str | None = None) -> dict:
    matches = [
        step
        for step in _steps()
        if (name is None or step.get("name") == name)
        and (step_id is None or step.get("id") == step_id)
    ]
    assert len(matches) == 1, (
        f"expected one step {name or step_id}, found {len(matches)}"
    )
    return matches[0]


def test_the_checkout_fetches_history_when_the_input_is_on():
    checkout = _step(name="Checkout")
    # '0' and '1' quoted: in a GitHub expression the number 0 is falsy, so
    # `inputs.changed-files-only && 0 || 1` would always yield 1.
    assert checkout.get("with", {}).get("fetch-depth") == (
        "${{ inputs.changed-files-only && '0' || '1' }}"
    ), checkout


def test_a_step_resolves_the_base_and_the_scan_uses_it():
    resolve = _step(step_id="base-ref")
    assert resolve["if"] == "inputs.changed-files-only"
    env = resolve["env"]
    assert env["PR_BASE_SHA"] == "${{ github.event.pull_request.base.sha }}"
    assert env["MERGE_GROUP_BASE_SHA"] == "${{ github.event.merge_group.base_sha }}"
    # The string inputs arrive as the input check's outputs, never as given
    # (test_an_input_cannot_add_a_workflow_command.py).
    assert env["CONFIGURED_BASE_REF"] == "${{ steps.inputs.outputs.base_ref }}"
    # github.event.before is in pull_request synchronize payloads too, so it is
    # read on push only.
    assert env["PUSH_BEFORE"] == (
        "${{ github.event_name == 'push' && github.event.before || '' }}"
    )
    # The two inputs that decide the scan's mode, as the scan step reads them.
    assert env["ASH_MODE"] == "${{ steps.inputs.outputs.ash_mode }}"
    assert env["ASH_ARGS"] == "${{ steps.inputs.outputs.ash_args }}"

    run_ash = _step(name="Run ASH")
    assert run_ash["env"]["BASE_REF"] == "${{ steps.base-ref.outputs.ref }}"
    steps = _steps()
    assert steps.index(resolve) < steps.index(run_ash)


def test_the_scan_passes_the_resolved_base_and_nothing_else():
    """ASH must diff against the ref the step resolved, not a literal.

    Read from the uvx command line itself, with its continuation lines joined: the
    step's ash-args check names --base-ref too, in its list of options that take a
    value, and that list passes nothing to ASH.
    """
    script = _step(name="Run ASH")["run"].replace("\\\n", " ")
    (scan,) = [line for line in script.splitlines() if line.lstrip().startswith("uvx ")]

    assert scan.count("--base-ref") == 1, scan
    assert '--base-ref "${BASE_REF}"' in scan, scan


posix_only = pytest.mark.skipif(
    os.name == "nt",
    reason="runs the step's bash script, which the workflow runs on Linux",
)


#: The fixtures' git ignores the invoking user's and the system's config, so a
#: commit.gpgsign=true or a credential helper there cannot break or slow them.
_GIT_ENV = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}


def _git(*args: str, cwd: Path) -> str:
    return subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],
        cwd=cwd,
        env=_GIT_ENV,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


@pytest.fixture
def upstream(tmp_path) -> tuple[Path, str]:
    """A repository with a main commit and a feature commit on top of it."""
    if shutil.which("git") is None:
        pytest.fail("git is required")
    repo = tmp_path / "upstream"
    repo.mkdir()
    _git("init", "-q", "-b", "main", cwd=repo)
    (repo / "base.py").write_text("x = 1\n", encoding="utf-8")
    _git("add", "-A", cwd=repo)
    _git("commit", "-q", "-m", "base", cwd=repo)
    base = _git("rev-parse", "HEAD", cwd=repo)
    _git("checkout", "-q", "-b", "feature", cwd=repo)
    (repo / "changed.py").write_text("y = 2\n", encoding="utf-8")
    _git("add", "-A", cwd=repo)
    _git("commit", "-q", "-m", "change", cwd=repo)
    return repo, base


def _clone(upstream: Path, target: Path, *depth: str) -> Path:
    subprocess.run(
        [
            "git",
            "clone",
            "-q",
            *depth,
            "--branch",
            "feature",
            f"file://{upstream}",
            str(target),
        ],
        env=_GIT_ENV,
        check=True,
        capture_output=True,
    )
    return target


def _run_step(cwd: Path, tmp_path: Path, bin_first: Path | None = None, **env: str):
    output = tmp_path / "github_output"
    output.write_text("", encoding="utf-8")
    # The job's definer runs before this step does, into the same RUNNER_TEMP.
    runner_temp = tmp_path / "runner_temp"
    write_helper(_steps(), runner_temp)
    path = os.environ.get("PATH", "")
    result = subprocess.run(
        [
            shutil.which("bash") or "bash",
            "-e",
            "-o",
            "pipefail",
            "-c",
            _step(step_id="base-ref")["run"],
        ],
        cwd=cwd,
        env={
            "PATH": f"{bin_first}{os.pathsep}{path}" if bin_first else path,
            "RUNNER_TEMP": str(runner_temp),
            "GITHUB_OUTPUT": str(output),
            "PR_BASE_SHA": "",
            "MERGE_GROUP_BASE_SHA": "",
            "CONFIGURED_BASE_REF": "origin/main",
            "PUSH_BEFORE": "",
            "ASH_MODE": "local",
            "ASH_ARGS": "",
            **env,
        },
        capture_output=True,
        text=True,
        check=False,
    )
    return result, output.read_text(encoding="utf-8")


def _assert_refused(result, output: str) -> str:
    """The step failed, wrote no ref, and printed exactly one workflow command.

    Counted the way the runner acts on lines, stop-commands regions included, so
    the refusal is its one `::error::` line and nothing the step prints, or git
    prints for it, adds another. Returns everything the step printed.
    """
    message = result.stdout + result.stderr
    assert result.returncode != 0, output
    assert "ref=" not in output, output
    commands = honored_commands(message)
    assert len(commands) == 1, commands
    assert commands[0].startswith("::error::"), commands
    return message


@posix_only
def test_a_merge_group_diffs_against_its_base_commit(upstream, tmp_path):
    from automated_security_helper.utils.get_scan_set import get_changed_files

    repo, base = upstream
    checkout = _clone(repo, tmp_path / "checkout")

    # A configured base that would give another answer, so the test can tell
    # which one the step took.
    result, output = _run_step(
        checkout,
        tmp_path,
        MERGE_GROUP_BASE_SHA=base,
        CONFIGURED_BASE_REF="origin/feature",
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert f"ref={base}" in output.splitlines()
    assert get_changed_files(base, cwd=checkout) == [Path("changed.py")]


@pytest.fixture
def pushed_main(tmp_path) -> tuple[Path, str]:
    """main with two commits, checked out at the tip as a push to main checks out.

    Returns the checkout and the commit before the push. The checkout also has
    origin/later, a commit on top of the tip (what `before` is after a push that
    rewound main), and origin/unrelated, a root commit with no history in common
    (what `before` is after a force-push that replaced the history).
    """
    if shutil.which("git") is None:
        pytest.fail("git is required")
    repo = tmp_path / "upstream-main"
    repo.mkdir()
    _git("init", "-q", "-b", "main", cwd=repo)
    (repo / "base.py").write_text("x = 1\n", encoding="utf-8")
    _git("add", "-A", cwd=repo)
    _git("commit", "-q", "-m", "before the push", cwd=repo)
    before = _git("rev-parse", "HEAD", cwd=repo)
    (repo / "pushed.py").write_text("y = 2\n", encoding="utf-8")
    _git("add", "-A", cwd=repo)
    _git("commit", "-q", "-m", "the push", cwd=repo)
    _git("checkout", "-q", "-b", "later", cwd=repo)
    (repo / "later.py").write_text("z = 3\n", encoding="utf-8")
    _git("add", "-A", cwd=repo)
    _git("commit", "-q", "-m", "after the tip", cwd=repo)
    _git("checkout", "-q", "--orphan", "unrelated", cwd=repo)
    _git("rm", "-q", "-r", "--cached", ".", cwd=repo)
    (repo / "other.py").write_text("w = 4\n", encoding="utf-8")
    _git("add", "other.py", cwd=repo)
    _git("commit", "-q", "-m", "another history", cwd=repo)
    _git("checkout", "-q", "-f", "main", cwd=repo)
    checkout = tmp_path / "checkout-main"
    subprocess.run(
        ["git", "clone", "-q", "--branch", "main", f"file://{repo}", str(checkout)],
        env=_GIT_ENV,
        check=True,
        capture_output=True,
    )
    assert _git("rev-parse", "origin/main", cwd=checkout) == _git(
        "rev-parse", "HEAD", cwd=checkout
    ), "control: on a push to main, origin/main is the commit being scanned"
    return checkout, before


@posix_only
def test_a_base_that_contains_head_fails_the_step(pushed_main, tmp_path):
    """A push or schedule on the default branch with the default base-ref.

    origin/main is HEAD there and `git diff origin/main...HEAD` is empty, so the
    step fails rather than run a diff scan over nothing.
    """
    from automated_security_helper.utils.get_scan_set import get_changed_files

    checkout, _ = pushed_main
    assert get_changed_files("origin/main", cwd=checkout) == [], (
        "control: the diff ASH would compute is empty"
    )

    result, output = _run_step(checkout, tmp_path, CONFIGURED_BASE_REF="origin/main")

    assert "base-ref" in _assert_refused(result, output)


@posix_only
@pytest.mark.parametrize(
    "before, reason",
    [
        ("", "not a push"),
        # Checked before anything prints it: a newline in the value must not
        # put a line of its own, which the runner would read as a command.
        ("abc\n::warning::INJECTED", "not a commit id"),
        ("0" * 40, "created a branch or tag"),
        ("1234567890abcdef1234567890abcdef12345678", "not in the checkout"),
        # Not "already contains": the error's fixed opening says that for every
        # reason, so only the rewind's own words show this branch was taken.
        ("HEAD", "rewound the branch"),
        ("origin/later", "rewound the branch"),
        ("origin/unrelated", "shares no history"),
    ],
    ids=[
        "no-push",
        "not-a-commit-id",
        "new-branch-or-tag",
        "not-fetched",
        "head",
        "descendant",
        "unrelated",
    ],
)
def test_without_a_usable_push_before_it_still_fails(
    pushed_main, tmp_path, before, reason
):
    """Every `before` the step cannot diff against, each named in the error.

    HEAD itself, or a commit on top of it (after a push that rewound the branch),
    gives an empty diff; a commit with no history in common (after a force-push
    that replaced it) makes `git diff before...HEAD` fail, and ASH then reports
    every file's findings. Neither may be used.
    """
    checkout, _ = pushed_main
    if before in ("HEAD", "origin/later", "origin/unrelated"):
        before = _git("rev-parse", before, cwd=checkout)

    result, output = _run_step(
        checkout, tmp_path, CONFIGURED_BASE_REF="origin/main", PUSH_BEFORE=before
    )

    message = _assert_refused(result, output)
    assert reason in message, message


@posix_only
@pytest.mark.parametrize(
    "variable", ["PR_BASE_SHA", "MERGE_GROUP_BASE_SHA", "CONFIGURED_BASE_REF"]
)
def test_a_base_cannot_add_a_workflow_command(upstream, tmp_path, variable):
    """A carriage return, a line feed, `::` or `##[` in the base starts no command.

    Counted the way the runner reads lines: at CR as well as LF, and `##[` anywhere.
    """
    repo, base = upstream
    checkout = _clone(repo, tmp_path / "checkout")

    result, output = _run_step(checkout, tmp_path, **{variable: base + COMMAND_TEXT})

    _assert_refused(result, output)
    (line,) = honored_commands(result.stdout + result.stderr)
    assert line.startswith("::error::changed-files-only:"), line


#: A git that writes a workflow command to stderr on every call, then runs git.
_LOUD_GIT = '#!/bin/sh\necho "::warning::from-git" >&2\nexec "{git}" "$@"\n'


@pytest.fixture
def loud_git(tmp_path) -> Path:
    real = shutil.which("git")
    if real is None:
        pytest.fail("git is required")
    bin_dir = tmp_path / "loud-git"
    bin_dir.mkdir()
    wrapper = bin_dir / "git"
    wrapper.write_text(_LOUD_GIT.format(git=real), encoding="utf-8")
    wrapper.chmod(0o755)
    return bin_dir


@posix_only
def test_what_git_prints_is_not_read_as_a_command(pushed_main, loud_git, tmp_path):
    """The push path runs all six of the step's git calls: three on the configured
    base, which contains HEAD here, and three on the commit before the push."""
    checkout, before = pushed_main

    result, output = _run_step(
        checkout,
        tmp_path,
        bin_first=loud_git,
        CONFIGURED_BASE_REF="origin/main",
        PUSH_BEFORE=before,
    )

    message = result.stdout + result.stderr
    assert result.returncode == 0, message
    assert f"ref={before}" in output.splitlines()
    assert message.count("::warning::from-git") == 6, "control: git ran 6 times"
    assert not [line for line in honored_commands(message) if "from-git" in line]


@posix_only
def test_what_git_prints_is_not_read_as_a_command_on_a_refusal(
    pushed_main, loud_git, tmp_path
):
    checkout, _ = pushed_main

    result, output = _run_step(
        checkout,
        tmp_path,
        bin_first=loud_git,
        CONFIGURED_BASE_REF="origin/main",
        PUSH_BEFORE="1234567890abcdef1234567890abcdef12345678",
    )

    message = _assert_refused(result, output)
    assert "not in the checkout" in message, message
    assert "::warning::from-git" in message, "control: the wrapper ran"


def broken_od(tmp_path: Path, fail_from: int) -> Path:
    """An od that works for the first ``fail_from - 1`` calls and then fails.

    with_commands_stopped reads its token with od, and refuses to run the command
    when it cannot, returning 1 with an ::error:: of its own.
    """
    real = shutil.which("od")
    if real is None:
        pytest.fail("od is required")
    bin_dir = tmp_path / "broken-od"
    bin_dir.mkdir()
    count = tmp_path / "od-calls"
    od = bin_dir / "od"
    od.write_text(
        "#!/bin/sh\n"
        f'n=$(cat "{count}" 2>/dev/null || echo 0); n=$((n + 1)); echo "$n" > "{count}"\n'
        f'[ "$n" -lt {fail_from} ] || exit 1\n'
        f'exec "{real}" "$@"\n',
        encoding="utf-8",
    )
    od.chmod(0o755)
    return bin_dir


@posix_only
@pytest.mark.parametrize(
    "fail_from", [1, 3], ids=["first-call", "the-is-ancestor-call"]
)
def test_a_git_call_that_could_not_run_ends_the_step(upstream, tmp_path, fail_from):
    """A call the helper refused is not git's answer.

    The third call is `git merge-base --is-ancestor HEAD <base>`, where a 1 read
    as git's "no" would let the step go on with a base it never checked.
    """
    repo, _ = upstream
    checkout = _clone(repo, tmp_path / "checkout")

    result, output = _run_step(
        checkout,
        tmp_path,
        bin_first=broken_od(tmp_path, fail_from),
        CONFIGURED_BASE_REF="origin/main",
    )

    message = _assert_refused(result, output)
    assert "no random token could be read" in message, message
    assert "changed-files-only" not in message, "only the helper's own error"


@posix_only
def test_an_unrelated_before_is_one_ash_cannot_diff(pushed_main, tmp_path):
    """Control for the unrelated case: ASH would have reported every file."""
    from automated_security_helper.utils.get_scan_set import get_changed_files

    checkout, _ = pushed_main
    unrelated = _git("rev-parse", "origin/unrelated", cwd=checkout)

    assert get_changed_files(unrelated, cwd=checkout) is None


@posix_only
@pytest.mark.parametrize(
    "variable, named",
    [
        ("PR_BASE_SHA", "pull request's base commit"),
        ("MERGE_GROUP_BASE_SHA", "merge group's base commit"),
    ],
)
def test_an_event_base_that_contains_head_names_the_event_base(
    pushed_main, tmp_path, variable, named
):
    """base-ref plays no part there, so the error must not tell the caller to set it."""
    checkout, _ = pushed_main
    head = _git("rev-parse", "HEAD", cwd=checkout)

    result, output = _run_step(checkout, tmp_path, **{variable: head})

    message = _assert_refused(result, output)
    assert named in message, message
    assert "Set base-ref" not in message, message


@posix_only
def test_a_push_diffs_against_the_commit_before_it(pushed_main, tmp_path):
    from automated_security_helper.utils.get_scan_set import get_changed_files

    checkout, before = pushed_main

    result, output = _run_step(
        checkout, tmp_path, CONFIGURED_BASE_REF="origin/main", PUSH_BEFORE=before
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert f"ref={before}" in output.splitlines()
    assert get_changed_files(before, cwd=checkout) == [Path("pushed.py")]


@posix_only
def test_a_push_keeps_a_configured_base_that_has_a_diff(upstream, tmp_path):
    """A feature-branch push is measured against base-ref, as documented."""
    repo, base = upstream
    checkout = _clone(repo, tmp_path / "checkout")

    result, output = _run_step(
        checkout, tmp_path, CONFIGURED_BASE_REF="origin/main", PUSH_BEFORE=base
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "ref=origin/main" in output.splitlines()


@posix_only
def test_a_pull_request_diffs_against_its_base_commit(upstream, tmp_path):
    from automated_security_helper.utils.get_scan_set import get_changed_files

    repo, base = upstream
    checkout = _clone(repo, tmp_path / "checkout")

    result, output = _run_step(checkout, tmp_path, PR_BASE_SHA=base)

    assert result.returncode == 0, result.stdout + result.stderr
    assert f"ref={base}" in output.splitlines()
    assert get_changed_files(base, cwd=checkout) == [Path("changed.py")]


@posix_only
def test_another_event_uses_the_configured_base(upstream, tmp_path):
    from automated_security_helper.utils.get_scan_set import get_changed_files

    repo, _ = upstream
    checkout = _clone(repo, tmp_path / "checkout")

    result, output = _run_step(checkout, tmp_path, CONFIGURED_BASE_REF="origin/main")

    assert result.returncode == 0, result.stdout + result.stderr
    assert "ref=origin/main" in output.splitlines()
    assert get_changed_files("origin/main", cwd=checkout) == [Path("changed.py")]


@posix_only
def test_a_base_missing_from_the_checkout_fails_the_step(upstream, tmp_path):
    """A depth-1 checkout, which lacks the base: ASH would report every file."""
    from automated_security_helper.utils.get_scan_set import get_changed_files

    repo, base = upstream
    shallow = _clone(repo, tmp_path / "shallow", "--depth", "1")
    assert get_changed_files(base, cwd=shallow) is None, (
        "control: in a depth-1 clone ASH cannot diff and falls back to a full report"
    )

    result, output = _run_step(shallow, tmp_path, PR_BASE_SHA=base)

    assert "is not in the checkout" in _assert_refused(result, output)


@posix_only
def test_a_base_ash_would_refuse_fails_the_step(upstream, tmp_path):
    """ASH's own check (utils/get_scan_set.py) refuses some refs git resolves.

    get_changed_files holds base_ref to letters, digits and `. _ / ~ ^ @ { } -`, and
    for anything else logs a warning and reports every file's findings. A base the
    checkout has but ASH refuses would pass a resolve-only step and still give a full
    report.
    """
    from automated_security_helper.utils.get_scan_set import get_changed_files

    repo, base = upstream
    _git("branch", "base+mirror", base, cwd=repo)
    checkout = _clone(repo, tmp_path / "checkout", "--no-single-branch")
    assert _git("rev-parse", "--verify", "origin/base+mirror", cwd=checkout)
    assert get_changed_files("origin/base+mirror", cwd=checkout) is None, (
        "control: ASH refuses this ref and falls back to a full report"
    )

    result, output = _run_step(
        checkout, tmp_path, CONFIGURED_BASE_REF="origin/base+mirror"
    )

    message = _assert_refused(result, output)
    assert "ASH accepts a base made of" in message, message
    assert "base-ref" in message, message


@posix_only
def test_a_base_with_no_history_in_common_fails_the_step(upstream, tmp_path):
    """A configured base on another history, which the checkout does have.

    `git diff <base>...HEAD` has no merge base to start from, so get_changed_files
    returns None and ASH reports the findings in every file.
    """
    from automated_security_helper.utils.get_scan_set import get_changed_files

    repo, _ = upstream
    empty_tree = _git("hash-object", "-w", "-t", "tree", os.devnull, cwd=repo)
    orphan = _git("commit-tree", empty_tree, "-m", "another history", cwd=repo)
    _git("branch", "unrelated", orphan, cwd=repo)
    checkout = _clone(repo, tmp_path / "checkout", "--no-single-branch")
    assert get_changed_files("origin/unrelated", cwd=checkout) is None, (
        "control: ASH cannot diff against it and reports every file's findings"
    )

    result, output = _run_step(
        checkout, tmp_path, CONFIGURED_BASE_REF="origin/unrelated"
    )

    message = _assert_refused(result, output)
    assert "shares no history" in message, message


@posix_only
@pytest.mark.parametrize(
    "ash_mode, ash_args",
    [
        ("container", ""),
        ("local", "--mode container"),
        ("local", "--mode=container"),
        ("local", "--exclude-scanners grype --mode container --verbose"),
        # --mode is last-value-wins, and ash-args comes after ash-mode.
        ("container", "--mode local --mode container"),
        # A `--mode` that is another option's value is not the mode: click takes
        # it as --output-dir's or --config's value, and the mode is the earlier one.
        ("local", "--mode container --output-dir --mode"),
        ("container", "--output-dir --mode --verbose"),
        ("container", "--config --mode"),
        ("container", "-c --mode"),
        # The short-option cluster reading: `-c` (alone or after `-v`) takes the
        # first `--mode` as its value, so the second `--mode` sets the mode.
        ("local", "-c --mode --mode container"),
        ("local", "-vc --mode --mode container"),
    ],
    ids=[
        "input",
        "args",
        "args-equals",
        "args-among-others",
        "args-last-wins",
        "a-value-after-container",
        "a-value-before-a-flag",
        "a-value-at-the-end",
        "a-short-option-value",
        "a-short-option-value-then-the-mode",
        "a-short-cluster-value-then-the-mode",
    ],
)
def test_container_mode_fails_the_step(upstream, tmp_path, ash_mode, ash_args):
    """ASH drops --changed-files-only in container mode and reports every file.

    run_ash_scan.py warns "--changed-files-only is not supported in container mode;
    performing full scan", so the job would read as a diff scan and be a full one.
    """
    repo, _ = upstream
    checkout = _clone(repo, tmp_path / "checkout")

    result, output = _run_step(checkout, tmp_path, ASH_MODE=ash_mode, ASH_ARGS=ash_args)

    assert "container mode" in _assert_refused(result, output)


@posix_only
def test_container_mode_is_refused_before_any_git_call(tmp_path):
    """No checkout at all: the mode is checked first, so its error is the one."""
    empty = tmp_path / "not-a-checkout"
    empty.mkdir()

    result, output = _run_step(empty, tmp_path, ASH_MODE="container")

    message = _assert_refused(result, output)
    assert "container mode" in message, message
    assert "is not in the checkout" not in message, message


@posix_only
@pytest.mark.parametrize(
    "ash_mode, ash_args",
    [
        ("local", ""),
        ("local", "--exclude-scanners grype"),
        ("container", "--mode local"),
        ("container", "--mode=local"),
        ("precommit", ""),
        # The nix wrapper re-runs ASH with the same arguments as a local scan, so
        # --changed-files-only reaches the inner run.
        ("nix", ""),
        # The word after --output-dir is its value, whatever it is.
        ("local", "--output-dir container --mode local"),
        ("container", "--output-dir x --mode local"),
    ],
    ids=[
        "local",
        "local-args",
        "args-local",
        "args-equals-local",
        "precommit",
        "nix",
        "a-value-named-container",
        "args-local-after-a-value",
    ],
)
def test_other_modes_keep_the_base(upstream, tmp_path, ash_mode, ash_args):
    repo, _ = upstream
    checkout = _clone(repo, tmp_path / "checkout")

    result, output = _run_step(checkout, tmp_path, ASH_MODE=ash_mode, ASH_ARGS=ash_args)

    assert result.returncode == 0, result.stdout + result.stderr
    assert "ref=origin/main" in output.splitlines()


@posix_only
def test_a_base_with_the_characters_ash_accepts_passes(upstream, tmp_path):
    from automated_security_helper.utils.get_scan_set import get_changed_files

    repo, _ = upstream
    checkout = _clone(repo, tmp_path / "checkout", "--no-single-branch")

    result, output = _run_step(checkout, tmp_path, CONFIGURED_BASE_REF="origin/main~0")

    assert result.returncode == 0, result.stdout + result.stderr
    assert "ref=origin/main~0" in output.splitlines()
    assert get_changed_files("origin/main~0", cwd=checkout) == [Path("changed.py")]

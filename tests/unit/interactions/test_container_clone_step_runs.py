# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The Dockerfile's clone step, run under sh, with a stand-in git and with real git.

Why this file exists
--------------------
The uv-reqs stage decides where ASH's source comes from in one RUN step: LOCAL
and a build context that is ASH's own source tree are built as they are, a full
commit id is checked out of a clone of the repository's branches and tags, if one
of them reaches it, anything else is cloned with ``git clone --branch``,
and the build context is then copied over the result. The text checks in
test_container_image_revision.py cannot tell that step from one that ends in
``; true`` or one whose LOCAL branch fails, so this runs it, the way the build
does, with the context directory pointed into a temporary directory and a git
that records its arguments and exits as told.

What this pins:

* A clone that fails fails the step, prints no LOCAL message and leaves nothing
  behind for ``uv build``.
* A build whose context is a full
  checkout (``./ash --ash-revision <rev>`` and the CDK image pipeline's build of
  its own clone) holds the tree already, so it is built without cloning.
  ``ash build-image`` is not
  one of them: for any revision but LOCAL it builds the Dockerfile packaged with
  ASH, never a checkout in the working directory.
* A commit id is never fetched by id from the ASH URL: GitHub serves a commit that
  only a fork or a pull request holds that way, and such a commit is not ASH.
  The last class runs the step with real git against a local repository with a
  commit that only refs/pull/7/head reaches, and requires exit 3 for it.

POSIX only: the step runs under the image's /bin/sh, and a Windows runner has no
such shell to stand in for it.
"""

from __future__ import annotations

import os
import shlex
import shutil
import stat
import subprocess  # nosec B404 - runs the Dockerfile's clone step under sh with a stand-in git
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple

import pytest

from automated_security_helper.interactions import run_ash_container as rac
from tests.unit.interactions.test_container_image_revision import (
    COMMIT_ID,
    _clone_step,
)

pytestmark = pytest.mark.integration

STAND_IN_GIT = """#!/bin/sh
printf '%s\\n' "$*" >> "$STUB_GIT_LOG"
exit "${STUB_GIT_RC:-0}"
"""

#: The image's python3 is the base image's, 3.12 today. Here it is the interpreter
#: running the tests, so the step parses TOML with the same Python as
#: _is_ash_source_tree does in the agreement test below. On 3.10 both use tomli,
#: which ASH declares there (utils/version_management.py).
STAND_IN_PYTHON3 = f"""#!/bin/sh
exec {shlex.quote(sys.executable)} "$@"
"""


def _prepare_step(
    tmp_path: Path, context_files: Dict[str, str], stand_ins: Dict[str, str]
) -> Tuple[str, Path, Path]:
    """The step's command with /ash-context pointed into tmp_path, and its /src.

    Returns (the command, the directory of stand-in programs, the /src directory).
    """
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name, script in stand_ins.items():
        stand_in = bin_dir / name
        stand_in.write_text(script, encoding="utf-8")
        stand_in.chmod(stand_in.stat().st_mode | stat.S_IXUSR)
    context = tmp_path / "build-context"
    context.mkdir()
    for name, text in context_files.items():
        context.joinpath(name).write_text(text, encoding="utf-8")
    src = tmp_path / "src"
    src.mkdir()
    step = _clone_step()[len("RUN ") :]
    # The step reads the context's pyproject.toml, copies the context and removes
    # it. If one of those stopped naming /ash-context, the run below would read or
    # delete the real path instead of the temporary one.
    assert step.count("/ash-context") == 3, step
    command = step.replace("/ash-context", context.as_posix())
    assert "/ash-context" not in command, command
    return command, bin_dir, src


def _sh(
    command: str, src: Path, bin_dir: Path, env: Dict[str, str]
) -> subprocess.CompletedProcess:
    return subprocess.run(  # nosec B603 B607 - sh with the Dockerfile's own step, list args
        ["sh", "-c", command],
        cwd=src,
        env={**env, "PATH": f"{bin_dir}{os.pathsep}{env['PATH']}"},
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


def _run_clone_step(
    tmp_path: Path, revision: str, context_files: Dict[str, str], git_rc: int = 0
) -> tuple:
    """Run the step as the build would, with a git that records its arguments.

    Returns (exit status, stdout, the git command lines, the files left in /src).
    """
    command, bin_dir, src = _prepare_step(
        tmp_path, context_files, {"git": STAND_IN_GIT, "python3": STAND_IN_PYTHON3}
    )
    log = tmp_path / "git.log"
    log.touch()
    proc = _sh(
        command,
        src,
        bin_dir,
        {
            **os.environ,
            "STUB_GIT_LOG": str(log),
            "STUB_GIT_RC": str(git_rc),
            "INSTALL_ASH_REVISION": revision,
            "ASH_REPO_CLONE_URL": "https://github.com/awslabs/automated-security-helper.git",
        },
    )
    calls = log.read_text(encoding="utf-8").splitlines()
    return proc.returncode, proc.stdout, calls, sorted(p.name for p in src.iterdir())


CLONE_URL = "https://github.com/awslabs/automated-security-helper.git"
ASH_PYPROJECT = '[project]\nname = "automated-security-helper"\nversion = "3.7.0"\n'
ASSETS_CONTEXT = {"Dockerfile": "FROM scratch\n", "Gemfile": "source 'x'\n"}


@pytest.mark.skipif(
    os.name == "nt", reason="the clone step runs under the image's POSIX sh"
)
class TestTheCloneStepUnderSh:
    def test_local_clones_nothing_and_builds_the_context(self, tmp_path):
        rc, out, calls, files = _run_clone_step(
            tmp_path, "LOCAL", {"pyproject.toml": ASH_PYPROJECT}
        )

        assert (rc, calls) == (0, [])
        assert "Skipping clone" in out
        assert files == ["pyproject.toml"]

    def test_an_ash_tree_context_is_built_whatever_the_revision(self, tmp_path):
        """./ash and the CDK pipeline's build of its own clone."""
        rc, out, calls, files = _run_clone_step(
            tmp_path, "v9.9.9-missing", {"pyproject.toml": ASH_PYPROJECT}, git_rc=128
        )

        assert (rc, calls) == (0, [])
        assert "instead of cloning v9.9.9-missing" in out
        assert files == ["pyproject.toml"]

    def test_another_projects_context_is_not_taken_for_ash(self, tmp_path):
        rc, _out, calls, _files = _run_clone_step(
            tmp_path, "v3.7.0", {"pyproject.toml": '[project]\nname = "other"\n'}
        )

        assert rc == 0
        assert calls == [
            "clone --branch v3.7.0 https://github.com/awslabs/automated-security-helper.git ."
        ]

    @pytest.mark.parametrize("revision", ["v3.7.0", "main"])
    def test_a_tag_or_branch_is_cloned_then_the_context_copied_over(
        self, tmp_path, revision
    ):
        rc, _out, calls, files = _run_clone_step(tmp_path, revision, ASSETS_CONTEXT)

        assert rc == 0
        assert calls == [f"clone --branch {revision} {CLONE_URL} ."]
        assert files == ["Dockerfile", "Gemfile"]

    @pytest.mark.parametrize(
        ("pyproject", "is_ash"),
        [
            pytest.param(ASH_PYPROJECT, True, id="ash"),
            pytest.param(
                "[project]\nname = 'automated-security-helper'\n",
                True,
                id="literal-string",
            ),
            pytest.param(
                '[project]\nname="automated-security-helper"\n', True, id="no-spaces"
            ),
            pytest.param(
                '[project]\nname = "Automated_Security.Helper"\n',
                True,
                id="not-normalized",
            ),
            pytest.param(
                '[project]\nname = "automated-security-helper"  # ASH\n',
                True,
                id="trailing-comment",
            ),
            pytest.param(
                '[project]\nname = "other"\n\n[tool.example]\n'
                'name = "automated-security-helper"\n',
                False,
                id="ash-name-in-another-table",
            ),
            pytest.param(
                '[project]\nname = "other"\ndescription = """\n'
                'name = "automated-security-helper"\n"""\n',
                False,
                id="ash-name-inside-a-string",
            ),
            pytest.param(
                '[tool.poetry]\nname = "automated-security-helper"\n',
                False,
                id="no-project-table",
            ),
            pytest.param(
                '[project\nname = "automated-security-helper"\n',
                False,
                id="not-toml",
            ),
            pytest.param("[project]\nname = 3\n", False, id="name-not-a-string"),
            pytest.param(
                '[project]\nname = "automated-security-helper"\n'
                'keywords = ["security", 1]\n',
                True,
                id="toml-1.0-mixed-array",
            ),
            pytest.param(None, False, id="no-pyproject"),
        ],
    )
    def test_the_step_and_the_cli_agree_on_what_an_ash_tree_is(
        self, tmp_path, pyproject, is_ash
    ):
        """_is_ash_source_tree decides whether the CLI builds a tree as ASH's own;
        the step decides whether to build the context instead of cloning. The step
        reads the [project] table's name, so another table's or a string's
        ``name`` line is not taken for ASH's, and ASH's own name written any
        valid way is.
        """
        files = {"Dockerfile": "FROM scratch\n"}
        if pyproject is not None:
            files["pyproject.toml"] = pyproject
        tree = tmp_path / "tree"
        tree.mkdir()
        for name, text in files.items():
            tree.joinpath(name).write_text(text, encoding="utf-8")
        step_root = tmp_path / "step"
        step_root.mkdir()

        rc, out, calls, _files = _run_clone_step(step_root, "v3.7.0", files)

        assert rc == 0
        assert rac._is_ash_source_tree(tree) is is_ash
        assert ("instead of cloning v3.7.0" in out) is is_ash, out
        assert calls == ([] if is_ash else [f"clone --branch v3.7.0 {CLONE_URL} ."])

    @pytest.mark.parametrize("revision", ["v9.9.9-missing", COMMIT_ID])
    def test_a_failed_clone_fails_the_step(self, tmp_path, revision):
        """The step exits non-zero, prints no "Skipping clone" and copies nothing."""
        rc, out, _calls, files = _run_clone_step(
            tmp_path, revision, ASSETS_CONTEXT, git_rc=128
        )

        assert rc != 0
        assert "Skipping clone" not in out
        assert files == []

    @pytest.mark.parametrize(
        "revision",
        [COMMIT_ID + "\n" + COMMIT_ID[::-1], COMMIT_ID + "\n", "\n" + COMMIT_ID],
        ids=["two-commit-ids", "trailing-newline", "leading-newline"],
    )
    def test_only_a_whole_value_of_forty_hex_digits_is_a_commit_id(
        self, tmp_path, revision
    ):
        """The check tests the whole value, so two ids on two lines are not a
        commit id. Anything but exactly one id goes to `git clone --branch`,
        which takes no such name."""
        _rc, _out, calls, _files = _run_clone_step(tmp_path, revision, ASSETS_CONTEXT)

        assert calls, "the step ran no git at all"
        assert calls[0].startswith("clone --branch "), calls
        assert not [call for call in calls if "--filter=blob:none" in call]

    @pytest.mark.parametrize(
        "revision",
        [
            COMMIT_ID,
            COMMIT_ID.upper(),
            COMMIT_ID[:-1],
            COMMIT_ID + "0",
            COMMIT_ID + "\n",
            COMMIT_ID[:20] + "\n" + COMMIT_ID[21:],
            COMMIT_ID[:39] + "g",
            "v3.7.0",
        ],
    )
    def test_the_step_and_the_cli_agree_on_what_a_commit_id_is(
        self, tmp_path, revision
    ):
        """The step tests the length and the characters of the whole value; the
        Python side's notion of a commit id is _COMMIT_ID_PATTERN read with
        fullmatch. Both say the same of each value. (In run_ash_container a value
        with a line break never gets as far as that pattern: _validate_ash_revision
        refuses it first.)"""
        _rc, _out, calls, _files = _run_clone_step(tmp_path, revision, ASSETS_CONTEXT)
        step_says_commit_id = bool(calls) and calls[0].startswith("clone --quiet")

        assert step_says_commit_id is bool(rac._COMMIT_ID_PATTERN.fullmatch(revision))


# ---------------------------------------------------------------------------
# A commit id, with real git against a local repository standing in for ASH's
# ---------------------------------------------------------------------------


def _isolated_git_env(tmp_path: Path) -> Dict[str, str]:
    """os.environ without GIT_* and with no system or user git configuration."""
    home = tmp_path / "home"
    home.mkdir()
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(
        HOME=str(home),
        XDG_CONFIG_HOME=str(home / ".config"),
        GIT_CONFIG_NOSYSTEM="1",
    )
    return env


def _git(cwd: Path, env: Dict[str, str], *args: str) -> str:
    return subprocess.run(  # nosec B603 B607 - fixed git argv in a temporary directory
        [
            "git",
            "-c",
            "user.name=test",
            "-c",
            "user.email=test@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "tag.gpgsign=false",
            "-c",
            "init.defaultBranch=main",
            *args,
        ],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    ).stdout.strip()


@dataclass
class StandInAshRepository:
    url: str
    on_main: str
    on_a_tag_only: str
    on_another_branch: str
    on_a_pull_request_ref_only: str
    on_no_ref: str


def _stand_in_ash_repository(
    tmp_path: Path, env: Dict[str, str]
) -> StandInAshRepository:
    """A bare repository in ASH's place, with a commit reachable each way.

    main has two commits, and the older one is the one built, so the build cannot
    pass by taking the tip. One commit is reachable only from an annotated tag, one
    only from another branch, and one only from refs/pull/7/head: that is how a
    fork's commit sits in GitHub's copy of a repository, and GitHub serves it by
    id. One more is in the server's object store with no ref at all, as a force-push
    leaves one. The server allows partial clones and any object by id, as GitHub
    does.
    """
    bare = tmp_path / "ash.git"
    _git(tmp_path, env, "init", "--quiet", "--bare", str(bare))
    _git(bare, env, "config", "uploadpack.allowFilter", "true")
    _git(bare, env, "config", "uploadpack.allowAnySHA1InWant", "true")
    work = tmp_path / "ash-work"
    _git(tmp_path, env, "init", "--quiet", str(work))

    def commit(name: str) -> str:
        work.joinpath(f"{name}.txt").write_text(f"{name}\n", encoding="utf-8")
        _git(work, env, "add", f"{name}.txt")
        _git(work, env, "commit", "--quiet", "-m", name)
        return _git(work, env, "rev-parse", "HEAD")

    on_main = commit("on-main")
    commit("main-tip")
    _git(work, env, "push", "--quiet", str(bare), "main")
    _git(work, env, "checkout", "--quiet", "-b", "release", on_main)
    on_a_tag_only = commit("tagged")
    _git(work, env, "tag", "-a", "v9.0.0", "-m", "v9.0.0")
    _git(work, env, "push", "--quiet", str(bare), "refs/tags/v9.0.0")
    _git(work, env, "checkout", "--quiet", "-b", "feature", on_main)
    on_another_branch = commit("feature")
    _git(work, env, "push", "--quiet", str(bare), "feature")
    _git(work, env, "checkout", "--quiet", "-b", "from-a-fork", on_main)
    on_a_pull_request_ref_only = commit("from-a-fork")
    _git(work, env, "push", "--quiet", str(bare), "HEAD:refs/pull/7/head")
    _git(work, env, "checkout", "--quiet", "-b", "force-pushed-away", on_main)
    on_no_ref = commit("force-pushed-away")
    _git(work, env, "push", "--quiet", str(bare), "HEAD:refs/heads/gone")
    _git(bare, env, "update-ref", "-d", "refs/heads/gone")
    assert _git(bare, env, "cat-file", "-t", on_no_ref) == "commit"
    return StandInAshRepository(
        url=bare.as_uri(),
        on_main=on_main,
        on_a_tag_only=on_a_tag_only,
        on_another_branch=on_another_branch,
        on_a_pull_request_ref_only=on_a_pull_request_ref_only,
        on_no_ref=on_no_ref,
    )


def _local_objects(src: Path, env: Dict[str, str]) -> List[str]:
    """Every object the build's clone holds, read without fetching any."""
    return _git(
        src,
        env,
        "cat-file",
        "--batch-all-objects",
        "--batch-check=%(objectname)",
    ).splitlines()


@pytest.mark.skipif(
    os.name == "nt" or shutil.which("git") is None,
    reason="the clone step runs under the image's POSIX sh, with git",
)
class TestACommitIdIsBuiltOnlyIfABranchOrTagReachesIt:
    """GitHub serves every object in a repository's fork network by id.

    The step builds a commit id only from a clone of ASH's branches and tags that
    reaches it, so an id that only a fork or a pull request holds is refused.
    """

    @pytest.fixture
    def remote(self, tmp_path) -> Tuple[Dict[str, str], StandInAshRepository]:
        env = _isolated_git_env(tmp_path)
        return env, _stand_in_ash_repository(tmp_path, env)

    @staticmethod
    def _build(
        tmp_path: Path, env: Dict[str, str], url: str, revision: str
    ) -> Tuple[subprocess.CompletedProcess, Path]:
        root = tmp_path / "build"
        root.mkdir()
        command, bin_dir, src = _prepare_step(
            root, ASSETS_CONTEXT, {"python3": STAND_IN_PYTHON3}
        )
        proc = _sh(
            command,
            src,
            bin_dir,
            {**env, "INSTALL_ASH_REVISION": revision, "ASH_REPO_CLONE_URL": url},
        )
        return proc, src

    @pytest.mark.parametrize("which", ["on_main", "on_a_tag_only", "on_another_branch"])
    def test_a_commit_a_branch_or_tag_reaches_is_built(self, tmp_path, remote, which):
        env, repository = remote
        commit = getattr(repository, which)

        proc, src = self._build(tmp_path, env, repository.url, commit)

        assert proc.returncode == 0, proc.stderr
        assert _git(src, env, "rev-parse", "HEAD") == commit
        files = sorted(p.name for p in src.iterdir() if p.name != ".git")
        assert "main-tip.txt" not in files
        assert {"on-main.txt", "Dockerfile", "Gemfile"} <= set(files)

    def test_a_commit_only_a_pull_request_ref_reaches_is_refused(
        self, tmp_path, remote
    ):
        env, repository = remote
        commit = repository.on_a_pull_request_ref_only

        proc, src = self._build(tmp_path, env, repository.url, commit)

        assert proc.returncode == 3, (proc.stdout, proc.stderr)
        [line] = proc.stderr.strip().splitlines()
        assert f"{commit} is not on a branch or tag of {repository.url}" in line
        assert not (src / "from-a-fork.txt").exists()
        assert not (src / "Gemfile").exists(), "the context was copied over a refusal"
        # Neither the pull request's ref nor its commit came into the build.
        refs = _git(src, env, "for-each-ref", "--format=%(refname)").splitlines()
        assert not [ref for ref in refs if ref.startswith("refs/pull/")]
        # Not in the assertion: env is the whole environment, which a failure
        # would print as the call's argument.
        objects = _local_objects(src, env)
        assert commit not in objects

    def test_a_commit_no_ref_reaches_is_refused_though_served_by_id(
        self, tmp_path, remote
    ):
        env, repository = remote
        commit = repository.on_no_ref

        proc, src = self._build(tmp_path, env, repository.url, commit)

        assert proc.returncode == 3, (proc.stdout, proc.stderr)
        assert f"{commit} is not on a branch or tag" in proc.stderr
        assert not (src / "force-pushed-away.txt").exists()
        # Not in the assertion: env is the whole environment, which a failure
        # would print as the call's argument.
        objects = _local_objects(src, env)
        assert commit not in objects

    def test_a_commit_the_repository_does_not_have_is_refused(self, tmp_path, remote):
        env, repository = remote

        proc, _src = self._build(tmp_path, env, repository.url, COMMIT_ID)

        assert proc.returncode == 3, (proc.stdout, proc.stderr)
        assert f"{COMMIT_ID} is not on a branch or tag" in proc.stderr

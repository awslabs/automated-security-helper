# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A ``--base-ref`` reaches git only as a revision.

``get_changed_files`` runs ``git diff --name-only -z <base_ref>...HEAD``. git reads
any argument that starts with ``-`` as an option, whatever follows it:
``--output=<file>...HEAD`` makes git write the diff into a file of that name, and
``-O<file>...HEAD`` turns the command into a different diff (the working tree
against the index) that exits 0 and prints no names, which the changed-files
filter reads as "nothing changed".

A base ref is accepted when it is a ref name that ``git check-ref-format
--allow-onelevel`` accepts, written in the characters ASH has always allowed,
optionally followed by ``~<n>`` or ``^<n>`` steps. Anything else is refused with
an error that names the value and the reason, before any git process starts.

The tests put a recording ``git`` first on ``PATH``, so "no git process saw the
value" is measured rather than inferred from a mock, and they prove with plain git
that the values they use do act as options.
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess  # nosec B404 -- builds a throwaway repository and runs git on it
from pathlib import Path
from types import SimpleNamespace

import pytest

from automated_security_helper.utils.get_scan_set import get_changed_files

#: Values git reads as an option. ``{marker}`` is a path in a directory the test
#: watches: an option that writes a file would leave it there.
OPTION_LIKE = ["--output={marker}", "-p", "--upload-pack=x", "-O{marker}"]


def _git(cwd: Path, *args: str) -> str:
    result = subprocess.run(  # nosec B603 B607 -- list argv, fixture repository only
        ["git", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=True,
        timeout=60,
    )
    return result.stdout


@pytest.fixture
def repo(tmp_path, monkeypatch):
    """``main`` with two commits; ``base`` and the tag ``v1`` name the first.

    Every ref form below diffs to the same answer, ``b.py``. The git environment
    is the test's own, so no host config decides the outcome; ASH's calls take
    the process environment, which is why it is set with monkeypatch.
    """
    if shutil.which("git") is None:
        pytest.skip("git is not available on PATH")
    home = tmp_path / "home"
    home.mkdir()
    for key in [k for k in os.environ if k.startswith("GIT_")]:
        monkeypatch.delenv(key)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    for role in ("AUTHOR", "COMMITTER"):
        monkeypatch.setenv(f"GIT_{role}_NAME", "Fixture")
        monkeypatch.setenv(f"GIT_{role}_EMAIL", "fixture@example.invalid")

    path = tmp_path / "repo"
    path.mkdir()
    _git(path, "init", "-q", "-b", "main")
    (path / "a.py").write_text("a = 1\n", encoding="utf-8")
    _git(path, "add", "a.py")
    _git(path, "commit", "-q", "-m", "one")
    _git(path, "branch", "base")
    _git(path, "tag", "v1")
    first_commit = _git(path, "rev-parse", "HEAD").strip()
    (path / "b.py").write_text("b = 2\n", encoding="utf-8")
    _git(path, "add", "b.py")
    _git(path, "commit", "-q", "-m", "two")
    return SimpleNamespace(path=path, first_commit=first_commit)


@pytest.fixture
def git_calls(repo, tmp_path, monkeypatch):
    """Put a recording ``git`` first on ``PATH``; return a reader of its calls.

    Depends on ``repo`` so the fixture repository is built before recording
    starts. Each call is the argument list that git process was given.
    """
    if os.name == "nt":
        pytest.skip("a POSIX shell script stands in for git")
    real_git = shutil.which("git")
    shim_dir = tmp_path / "recording-git"
    shim_dir.mkdir()
    log = tmp_path / "git-calls"
    shim = shim_dir / "git"
    shim.write_text(
        "#!/bin/sh\n"
        f"log={shlex.quote(str(log))}\n"
        'printf "call\\0" >> "$log"\n'
        'for arg in "$@"; do printf "%s\\0" "$arg" >> "$log"; done\n'
        f'exec {shlex.quote(real_git)} "$@"\n',
        encoding="utf-8",
    )
    shim.chmod(0o755)
    monkeypatch.setenv("PATH", f"{shim_dir}{os.pathsep}{os.environ.get('PATH', '')}")

    def calls() -> list[list[str]]:
        if not log.exists():
            return []
        recorded: list[list[str]] = []
        for part in (
            log.read_bytes().decode("utf-8", "surrogateescape").split("\0")[:-1]
        ):
            if part == "call":
                recorded.append([])
            else:
                recorded[-1].append(part)
        return recorded

    return calls


class TestPlainGitReadsTheseValuesAsOptions:
    """The controls: without ASH's check, these values change what git does."""

    def test_output_makes_git_write_a_file(self, repo, tmp_path):
        watched = tmp_path / "watched"
        watched.mkdir()

        result = subprocess.run(  # nosec B603 B607 -- list argv, fixture repository only
            ["git", "diff", "--name-only", "-z", f"--output={watched / 'diff'}...HEAD"],
            cwd=repo.path,
            capture_output=True,
            text=True,
            timeout=60,
        )

        assert result.returncode == 0, result.stderr
        assert [p.name for p in watched.iterdir()] == ["diff...HEAD"]

    def test_an_order_file_gives_a_different_diff_that_exits_zero(self, repo, tmp_path):
        result = subprocess.run(  # nosec B603 B607 -- list argv, fixture repository only
            ["git", "diff", "--name-only", "-z", f"-O{tmp_path / 'order'}...HEAD"],
            cwd=repo.path,
            capture_output=True,
            text=True,
            timeout=60,
        )

        # b.py changed since the first commit, but this diff is the working tree
        # against the index, which is clean.
        assert result.returncode == 0, result.stderr
        assert result.stdout == ""


class TestAnOptionLikeBaseRef:
    @pytest.mark.parametrize("template", OPTION_LIKE)
    def test_is_refused_before_any_git_process_starts(
        self, repo, git_calls, tmp_path, template
    ):
        watched = tmp_path / "watched"
        watched.mkdir()
        base_ref = template.format(marker=watched / "diff")

        with pytest.raises(ValueError, match=r"starts with '-'") as refused:
            get_changed_files(base_ref=base_ref, cwd=repo.path)

        assert repr(base_ref) in str(refused.value)
        assert git_calls() == []
        assert list(watched.iterdir()) == []


class TestRefsThatStillWork:
    @pytest.mark.parametrize(
        "form", ["branch", "tag", "full commit id", "ancestry step"]
    )
    def test_name_the_changed_files(self, repo, git_calls, form):
        base_ref = {
            "branch": "base",
            "tag": "v1",
            "full commit id": repo.first_commit,
            "ancestry step": "HEAD~1",
        }[form]

        assert get_changed_files(base_ref=base_ref, cwd=repo.path) == [Path("b.py")]

        (call,) = git_calls()
        assert f"{base_ref}...HEAD" in call


# ---------------------------------------------------------------------------
# validate_base_ref: the rule itself
# ---------------------------------------------------------------------------

REFUSED = {
    "empty": "",
    "a short option": "-p",
    "a long option": "--output=x",
    "a long option naming a program": "--upload-pack=x",
    "an option with an attached value": "-O/tmp/order",
    "a range": "main..HEAD",
    "an empty path component": "origin//main",
    "a leading slash": "/main",
    "a trailing slash": "main/",
    "a trailing dot": "main.",
    "a .lock name": "main.lock",
    "a .lock component": "refs/heads/x.lock/y",
    "a hidden name": ".main",
    "a hidden component": "origin/.main",
    "a lone at sign": "@",
    "a reflog step": "main@{1}",
    "an upstream shorthand": "@{u}",
    "a tilde inside the name": "a~b",
    "a peel": "HEAD^{commit}",
    "only a step": "~1",
    "a space": "ref with spaces",
    "a shell separator": "origin/main; rm -rf x",
    "a command substitution": "$(whoami)",
    "a backtick": "back`tick`",
    "a tab": "tab\there",
    "a trailing newline": "main\n",
    "a NUL": "nul\0byte",
    "a colon": "HEAD:path",
    "a glob": "main*",
    "a backslash": "back\\slash",
}

ACCEPTED = {
    "a branch": "main",
    "a remote-tracking branch": "origin/main",
    "HEAD": "HEAD",
    "a tag": "v1.2.3",
    "a dotted release branch": "release/2026.10",
    "a full ref": "refs/tags/v1",
    "punctuation git allows": "feature/a-b_c",
    "a full commit id": "0123456789abcdef0123456789abcdef01234567",
    "a short commit id": "0123abc",
    "one step back": "HEAD~1",
    "a parent": "HEAD^",
    "a second parent": "HEAD^2",
    "a bare tilde": "HEAD~",
    "steps on a remote branch": "origin/main~3",
    "mixed steps": "main~1^2",
}


@pytest.mark.parametrize("base_ref", list(REFUSED.values()), ids=list(REFUSED))
def test_validate_base_ref_refuses(base_ref):
    from automated_security_helper.utils.get_scan_set import (
        InvalidBaseRefError,
        validate_base_ref,
    )

    with pytest.raises(InvalidBaseRefError) as refused:
        validate_base_ref(base_ref)

    # The message names the value, escaped, so a control character in it cannot
    # rewrite the operator's terminal.
    assert repr(base_ref) in str(refused.value)
    assert isinstance(refused.value, ValueError)


@pytest.mark.parametrize("base_ref", list(ACCEPTED.values()), ids=list(ACCEPTED))
def test_validate_base_ref_accepts(base_ref):
    from automated_security_helper.utils.get_scan_set import validate_base_ref

    assert validate_base_ref(base_ref) == base_ref


#: Ref names (no ``~``/``^`` steps, no leading ``-``) in the characters ASH
#: allows, chosen to sit on each of git-check-ref-format(1)'s rules.
REF_NAMES = [
    "main",
    "origin/main",
    "HEAD",
    "a..b",
    "a//b",
    "/a",
    "a/",
    "a.",
    "a/b.",
    "a.lock",
    "a/b.lock",
    "x.lock/y",
    "a.lock.b",
    ".lock",
    "lock",
    ".a",
    "a/.b",
    "a/./b",
    "a./b",
    ".",
    "..",
    "@",
    "@a",
    "a@",
    "a@b",
    "a@{b",
    "@{",
    "a{b}",
    "{",
    "a~b",
    "a^b",
    "a-",
    "_a",
    "refs/heads/-x",
]


@pytest.mark.parametrize("name", REF_NAMES)
def test_the_ref_name_rule_agrees_with_git_check_ref_format(name):
    """ASH's copy of the rule gives git's answer, measured against git itself."""
    if shutil.which("git") is None:
        pytest.skip("git is not available on PATH")
    from automated_security_helper.utils.get_scan_set import validate_base_ref

    git_accepts = (
        subprocess.run(  # nosec B603 B607 -- list argv, no repository involved
            ["git", "check-ref-format", "--allow-onelevel", name],
            capture_output=True,
            timeout=60,
        ).returncode
        == 0
    )
    try:
        validate_base_ref(name)
        ash_accepts = True
    except ValueError:
        ash_accepts = False

    assert ash_accepts == git_accepts


def test_run_ash_scan_refuses_before_any_git_call_or_output(
    repo, git_calls, tmp_path, monkeypatch
):
    """The library entry refuses too, before it sets up logging or writes."""
    from automated_security_helper.interactions import run_ash_scan as module

    def _scan_started(*args, **kwargs):
        raise AssertionError("the scan started")

    monkeypatch.setattr(module, "_setup_logger", _scan_started)
    output_dir = tmp_path / "ash-output"

    with pytest.raises(ValueError, match=r"starts with '-'"):
        module.run_ash_scan(
            source_dir=repo.path,
            output_dir=output_dir,
            changed_files_only=True,
            base_ref="-p",
        )

    assert git_calls() == []
    assert not output_dir.exists()

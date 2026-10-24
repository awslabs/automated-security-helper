# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``set_source_git`` with a ``ref`` delivers the tree at that ref.

The clone is shallow (``--depth``), which also makes it single-branch: only the
remote's default branch is fetched. For any other ref the delivery fetches it
explicitly, then checks out what that fetch brought (``FETCH_HEAD``), because
the fetch records a named branch or tag there and creates no local ref for it.

The tests clone a local fixture repository through ``_clone``, with
``protocol.file.allow=always`` added to ``_GIT_ARGV`` so git accepts the
``file://`` url.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Dict, List

import pytest

from automated_security_helper.cli.mcp import source_delivery as sd


def _git_env(home: Path) -> Dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(
        {
            "HOME": str(home),
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_AUTHOR_NAME": "Fixture",
            "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
            "GIT_COMMITTER_NAME": "Fixture",
            "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
        }
    )
    return env


def _git(args: List[str], cwd: Path, env: Dict[str, str]) -> str:
    result = subprocess.run(  # nosec B603 -- list argv, fixture repository only
        ["git", *args], cwd=cwd, env=env, capture_output=True, text=True, timeout=60
    )
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


@pytest.fixture
def source(tmp_path, monkeypatch) -> Dict[str, object]:
    """main has a.py; feature adds b.py and is tagged v1; neither is main's tip."""
    home = tmp_path / "fixture-home"
    home.mkdir()
    env = _git_env(home)
    repo = tmp_path / "source"
    repo.mkdir()
    _git(["init", "-q", "-b", "main"], repo, env)
    (repo / "a.py").write_text("a = 1\n", encoding="utf-8")
    _git(["add", "a.py"], repo, env)
    _git(["commit", "-q", "-m", "one"], repo, env)
    _git(["checkout", "-q", "-b", "feature"], repo, env)
    (repo / "b.py").write_text("b = 2\n", encoding="utf-8")
    _git(["add", "b.py"], repo, env)
    _git(["commit", "-q", "-m", "two"], repo, env)
    _git(["tag", "-a", "v1", "-m", "release"], repo, env)
    feature = _git(["rev-parse", "HEAD"], repo, env)
    _git(["checkout", "-q", "main"], repo, env)
    main = _git(["rev-parse", "HEAD"], repo, env)
    monkeypatch.setattr(sd, "_GIT_ARGV", ("git", "-c", "protocol.file.allow=always"))
    session_home = tmp_path / "session-home"
    session_home.mkdir()
    return {
        "url": repo.as_uri(),
        "env": env,
        "main": main,
        "feature": feature,
        "home": session_home,
        "target": session_home / "source",
    }


def _deliver(source: Dict[str, object], ref: str) -> str:
    target = source["target"]
    sd._clone(
        source["url"],
        ref,
        depth=1,
        target=target,
        env=sd._git_environment(source["home"]),
    )
    return _git(["rev-parse", "HEAD"], target, source["env"])


@pytest.mark.parametrize("ref", ["feature", "v1"], ids=["branch", "annotated-tag"])
def test_a_ref_off_the_default_branch_is_checked_out(source, ref) -> None:
    head = _deliver(source, ref)

    assert head == source["feature"]
    assert (source["target"] / "b.py").is_file()


def test_the_default_branch_named_as_the_ref_is_checked_out(source) -> None:
    head = _deliver(source, "main")

    assert head == source["main"]
    assert not (source["target"] / "b.py").exists()


def test_a_ref_the_remote_does_not_have_fails_and_leaves_no_tree(source) -> None:
    with pytest.raises(RuntimeError, match="no-such-branch"):
        _deliver(source, "no-such-branch")

    assert not source["target"].exists()

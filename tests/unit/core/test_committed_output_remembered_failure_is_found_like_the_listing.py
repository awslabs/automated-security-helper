# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A remembered git failure is found for a directory as the listing finds it.

Why these tests exist
---------------------
``_GitFailures.known_for`` answers a directory from the failure remembered for
the repository that holds it, so a hung git costs one wait and not one per
project. It differed from ``git_index_below``, which it stands in for, in two
ways:

* it called ``Path.is_dir`` unguarded, which raises ``PermissionError`` on
  CPython 3.10 to 3.12 when a parent cannot be searched, where
  ``git_index_below`` answers such a directory as one that is not there;
* it found the repository from the directory with every link resolved, where
  ``git_index_below`` asks where a directory that is itself a link sits (its
  parent), so a link outside a repository that leads into one was given the
  repository's remembered failure although git would have been asked about no
  repository at all.

git is not run here: the failure is remembered from a hand-built answer.

Each test states the assertion that fails at the base.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from automated_security_helper.core.committed_output import _GitFailures
from automated_security_helper.utils.scan_output_dirs import GitIndexAnswer

pytestmark = pytest.mark.unit

GIT_FAILED = "git did not answer within 30 seconds"


def _remember_failure_for(repository: Path, directory: Path) -> _GitFailures:
    failures = _GitFailures()
    failures.remember(
        GitIndexAnswer(directory, repository=repository, error=GIT_FAILED)
    )
    return failures


def test_a_directory_in_the_repository_gets_the_remembered_failure(tmp_path):
    """The control: the lookup still finds the failure for a plain directory."""
    repository = (tmp_path / "repo").resolve()
    (repository / ".git").mkdir(parents=True)
    first = repository / "out"
    second = repository / "other"
    first.mkdir()
    second.mkdir()
    failures = _remember_failure_for(repository, first)

    known = failures.known_for(second)

    assert known is not None
    assert known.base == second
    assert known.repository == repository
    assert known.error == GIT_FAILED


@pytest.mark.skipif(
    os.name != "posix" or not hasattr(os, "symlink"), reason="needs symlinks"
)
def test_a_link_outside_the_repository_gets_no_remembered_failure(tmp_path):
    repository = (tmp_path / "repo").resolve()
    (repository / ".git").mkdir(parents=True)
    target = repository / "out"
    target.mkdir()
    outside = (tmp_path / "outside").resolve()
    outside.mkdir()
    link = outside / "link"
    link.symlink_to(target, target_is_directory=True)
    failures = _remember_failure_for(repository, target)

    known = failures.known_for(link)

    # Red at the base: the link's target is in the repository, so the failure
    # remembered for it was returned, although git_index_below asks about the
    # link's parent, which no repository holds, and answers "no repository".
    assert known is None


def test_a_directory_that_cannot_be_looked_up_gets_no_remembered_failure(
    tmp_path, monkeypatch
):
    repository = (tmp_path / "repo").resolve()
    (repository / ".git").mkdir(parents=True)
    first = repository / "out"
    hidden = repository / "hidden"
    first.mkdir()
    hidden.mkdir()
    failures = _remember_failure_for(repository, first)
    real_is_dir = Path.is_dir

    def is_dir(self, *args, **kwargs):
        if self == hidden:
            raise PermissionError(13, "Permission denied", str(self))
        return real_is_dir(self, *args, **kwargs)

    monkeypatch.setattr(Path, "is_dir", is_dir)

    # Red at the base: the PermissionError propagated out of known_for.
    assert failures.known_for(hidden) is None

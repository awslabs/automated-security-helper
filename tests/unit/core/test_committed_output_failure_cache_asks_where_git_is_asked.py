# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A remembered git failure is looked up for the repository git is asked about.

``git_index_below`` asks about the repository that holds a directory, and for a
directory that is itself a link, the one that holds the link: git tracks the link
as an entry of its own directory's repository. The failure cache looked the
repository up by the link's target instead, so a remembered failure for the
repository holding the link was missed and a hung git was asked again, once per
such directory, each with its own timeout.

git is not run here: the cache is filled by hand and read back.
"""

from __future__ import annotations

import sys

import pytest

from automated_security_helper.core.committed_output import _GitFailures
from automated_security_helper.utils.scan_output_dirs import GitIndexAnswer

pytestmark = pytest.mark.unit

needs_symlinks = pytest.mark.skipif(
    sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
)


def _repository(path):
    (path / ".git").mkdir(parents=True)
    return path.resolve()


def _remembering(repository):
    failures = _GitFailures()
    failures.remember(
        GitIndexAnswer(
            repository / "somewhere-else",
            repository=repository,
            error="git did not answer",
            could_not_run=False,
        )
    )
    return failures


@needs_symlinks
@pytest.mark.parametrize("target_holds", ["no repository", "another repository"])
def test_the_failure_remembered_for_the_repository_holding_a_link_answers_the_link(
    tmp_path, target_holds
):
    repository = _repository(tmp_path / "repo")
    if target_holds == "another repository":
        target = _repository(tmp_path / "other") / "out"
    else:
        target = (tmp_path / "plain").resolve() / "out"
    target.mkdir(parents=True)
    link = repository / "out"
    link.symlink_to(target, target_is_directory=True)
    failures = _remembering(repository)

    known = failures.known_for(link)

    assert known is not None
    assert known.repository == repository
    assert known.error == "git did not answer"
    assert known.base == link


def test_control_a_directory_in_the_repository_reads_the_remembered_failure(tmp_path):
    repository = _repository(tmp_path / "repo")
    inside = repository / "out"
    inside.mkdir()
    failures = _remembering(repository)

    known = failures.known_for(inside)

    assert known is not None
    assert known.repository == repository


def test_control_a_directory_in_another_repository_is_still_asked(tmp_path):
    repository = _repository(tmp_path / "repo")
    other = _repository(tmp_path / "other") / "out"
    other.mkdir()
    failures = _remembering(repository)

    assert failures.known_for(other) is None

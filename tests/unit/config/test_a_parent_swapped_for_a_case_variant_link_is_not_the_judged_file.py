# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A parent directory swapped for a link to a case-variant sibling is not the judged file.

A descriptor whose path differs from the judged path in case alone counts as the
judged file when the judged path still leads to the very file the descriptor
holds. That check read the judged path with ``os.lstat``, which refuses a link at
the last component and follows one in any parent. A repository that holds
``.ash/ash.yaml`` and, beside it, ``.ASH/ash.yaml`` on a case-sensitive file
system could therefore have ``.ash`` swapped for a link to ``.ASH`` after the
permit admitted ``.ash/ash.yaml``: the open reaches the file in ``.ASH``, the
kernel reports a path equal to the judged one in case alone, the lstat follows
the same link to the same file, and the identity of a file the permit never saw
was held and later read as the config.

The judged path must now resolve to itself before its inode is compared, so a
link in any component of it is a refusal.

Red at the base: the first id held the identity of the sibling's file. The other
ids are controls that hold at both ends: a parent swapped for a link to a
directory whose name differs in more than case, and a parent left alone.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Callable, List, Tuple

import pytest

from automated_security_helper.config.config_sources import (
    ABSENT_FILE,
    discover_config_source,
    file_identity,
)

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(
        os.name == "nt", reason="a directory link needs a privilege on Windows"
    ),
]


def _repo_with_two_case_variant_directories(tmp_path: Path) -> Tuple[Path, Path, Path]:
    """The repository, the judged config and the config in the case-variant sibling."""
    repo = Path(os.path.realpath(tmp_path)) / "repo"
    repo.mkdir()
    judged_dir = repo / ".ash"
    sibling_dir = repo / ".ASH"
    judged_dir.mkdir()
    try:
        sibling_dir.mkdir()
    except FileExistsError:
        pytest.skip("the file system ignores case, so there is no sibling to swap to")
    judged = judged_dir / "ash.yaml"
    sibling = sibling_dir / "ash.yaml"
    judged.write_text("project_name: judged\n", encoding="utf-8")
    sibling.write_text("project_name: never judged\n", encoding="utf-8")
    return repo, judged, sibling


def _a_permit_that_swaps_the_parent_once_it_admits(
    repo: Path, judged: Path, target: Path
) -> Tuple[Callable[[Path], bool], List[Path]]:
    """A permit that admits everything and, as it admits ``judged``, replaces its
    parent directory with a link to ``target``: the window after the judgment."""
    swapped: List[Path] = []

    def permit(path: Path) -> bool:
        if path == judged and not swapped:
            os.rename(judged.parent, repo / "moved-aside")
            os.symlink(target, judged.parent, target_is_directory=True)
            swapped.append(repo / "moved-aside" / judged.name)
        return True

    return permit, swapped


def test_a_parent_swapped_for_a_link_to_a_case_variant_sibling_is_held_to_nothing(
    tmp_path: Path,
) -> None:
    repo, judged, sibling = _repo_with_two_case_variant_directories(tmp_path)
    permit, swapped = _a_permit_that_swaps_the_parent_once_it_admits(
        repo, judged, sibling.parent
    )

    discovery = discover_config_source(repo, permit=permit)

    assert swapped, "premise: the parent was swapped after the judgment"
    assert file_identity(swapped[0]) != file_identity(sibling), (
        "premise: the judged file and the sibling's are two files"
    )
    assert discovery.selected is not None
    assert discovery.selected.identity != file_identity(sibling)
    assert discovery.selected.identity == ABSENT_FILE


def test_a_parent_swapped_for_a_link_to_another_name_is_held_to_nothing(
    tmp_path: Path,
) -> None:
    """The control: a directory that differs in more than case is another path."""
    repo, judged, sibling = _repo_with_two_case_variant_directories(tmp_path)
    elsewhere = repo / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "ash.yaml").write_text("project_name: elsewhere\n", encoding="utf-8")
    permit, swapped = _a_permit_that_swaps_the_parent_once_it_admits(
        repo, judged, elsewhere
    )

    discovery = discover_config_source(repo, permit=permit)

    assert swapped, "premise: the parent was swapped after the judgment"
    assert discovery.selected is not None
    assert discovery.selected.identity == ABSENT_FILE


def test_a_parent_left_alone_is_the_judged_file(tmp_path: Path) -> None:
    """The control: with a case-variant sibling present and nothing swapped, the
    judged file is held by its own identity."""
    repo, judged, sibling = _repo_with_two_case_variant_directories(tmp_path)

    discovery = discover_config_source(repo, permit=lambda path: True)

    assert discovery.selected is not None
    assert discovery.selected.identity == file_identity(judged)
    assert discovery.selected.identity != file_identity(sibling)

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Discovery opens the path its permit judged, never the name that led to it.

A discovered source is judged by the path its name resolves to, and the file is
opened afterwards to take the identity a later read is held to. That open used
the NAME. A link re-pointed between the judgment and the open therefore made the
server open a file outside the grant: no bytes were read and the identity came
out as ``ABSENT_FILE``, but the file was opened, which a name the permit refused
must never be. The open now takes the judged path itself and does not follow a
link at its last component, so a re-pointed name leaves the judged file as the
one held, and a leaf swapped for a link after the judgment is not opened through
it.

Red at the base: the re-pointed name and the swapped leaf both opened the file
outside the grant (its device and inode were among the descriptors opened), and
``open_config_for_judgment`` took no ``follow_links``. The plain admitted file is
a control that holds at both ends. On POSIX only, where a symbolic link can be
made and replaced.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import List, Tuple

import pytest

from automated_security_helper.config import config_sources
from automated_security_helper.config.config_sources import (
    ABSENT_FILE,
    discover_config_source,
    file_identity,
    open_config_for_judgment,
)

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(
        os.name == "nt", reason="a link needs a privilege there, and a file is open"
    ),
]


def _point(link: Path, target: Path) -> None:
    link.unlink()
    link.symlink_to(target)


def _record_opens(monkeypatch: pytest.MonkeyPatch) -> List[Tuple[Tuple[int, int], int]]:
    """Record the (device, inode) and the flags of every file ``os.open`` opens."""
    real_open = os.open
    seen: List[Tuple[Tuple[int, int], int]] = []

    def recording(path, flags, *args, **kwargs):
        fd = real_open(path, flags, *args, **kwargs)
        info = os.fstat(fd)
        seen.append(((info.st_dev, info.st_ino), flags))
        return fd

    monkeypatch.setattr(os, "open", recording)
    return seen


def test_a_name_re_pointed_after_the_judgment_never_opens_the_file_it_leads_to_now(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    judged = repo / "real.yaml"
    judged.write_text("project_name: judged\n", encoding="utf-8")
    outside = tmp_path / "outside.yaml"
    outside.write_text("project_name: outside\n", encoding="utf-8")
    link = repo / ".ash.yaml"
    link.symlink_to(judged)
    asked: List[Path] = []

    def permit_then_point_outside(path: Path) -> bool:
        """Admit the name, then make it lead to a file outside the grant."""
        asked.append(path)
        if len(asked) == 1:
            _point(link, outside)
        return True

    outside_identity = file_identity(outside)
    opened = _record_opens(monkeypatch)

    discovery = discover_config_source(repo, permit=permit_then_point_outside)

    assert asked, "premise: the permit judged the name"
    assert outside_identity not in [identity for identity, _ in opened]
    assert discovery.selected is not None
    # The identity is the judged file's own, so a read of the name, which leads
    # elsewhere now, is refused.
    assert discovery.selected.identity == file_identity(judged)
    with pytest.raises(OSError, match="changed after it was checked"):
        config_sources.read_config_bytes(link, expect=discovery.selected.identity)


def test_a_leaf_swapped_for_a_link_after_the_judgment_is_not_opened_through_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside.yaml"
    outside.write_text("project_name: outside\n", encoding="utf-8")
    config = repo / ".ash.yaml"
    config.write_text("project_name: judged\n", encoding="utf-8")
    asked: List[Path] = []

    def permit_then_swap_for_a_link(path: Path) -> bool:
        asked.append(path)
        if len(asked) == 1:
            _point(config, outside)
        return True

    outside_identity = file_identity(outside)
    opened = _record_opens(monkeypatch)

    discovery = discover_config_source(repo, permit=permit_then_swap_for_a_link)

    assert asked, "premise: the permit judged the file"
    assert outside_identity not in [identity for identity, _ in opened]
    assert discovery.selected is not None
    assert discovery.selected.identity == ABSENT_FILE


def test_a_plain_admitted_file_is_opened_once_and_held_to_its_own_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control: nothing is re-pointed, so the file judged is the file held."""
    repo = tmp_path / "repo"
    repo.mkdir()
    config = repo / ".ash.yaml"
    config.write_text("project_name: judged\n", encoding="utf-8")
    opened = _record_opens(monkeypatch)

    discovery = discover_config_source(repo, permit=lambda path: True)

    assert discovery.selected is not None
    assert discovery.selected.identity == file_identity(config)
    assert [identity for identity, _ in opened].count(file_identity(config)) == 1


def test_a_link_at_the_last_component_is_not_opened_when_links_are_not_followed(
    tmp_path: Path,
) -> None:
    target = tmp_path / "target.yaml"
    target.write_text("project_name: p\n", encoding="utf-8")
    link = tmp_path / "link.yaml"
    link.symlink_to(target)

    assert open_config_for_judgment(link, follow_links=False) is None
    followed = open_config_for_judgment(link)
    assert followed is not None
    followed.close()
    plain = open_config_for_judgment(target, follow_links=False)
    assert plain is not None
    plain.close()


@pytest.mark.skipif(not hasattr(os, "O_NOFOLLOW"), reason="needs O_NOFOLLOW")
def test_the_open_itself_refuses_a_link_when_links_are_not_followed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A leaf made a link between the check and the open is refused by the open,
    not only by the check before it."""
    target = tmp_path / "target.yaml"
    target.write_text("project_name: p\n", encoding="utf-8")
    opened = _record_opens(monkeypatch)

    not_following = open_config_for_judgment(target, follow_links=False)
    following = open_config_for_judgment(target)

    assert not_following is not None and following is not None
    not_following.close()
    following.close()
    flags = [flag for _, flag in opened]
    assert flags[0] & os.O_NOFOLLOW
    assert not flags[1] & os.O_NOFOLLOW

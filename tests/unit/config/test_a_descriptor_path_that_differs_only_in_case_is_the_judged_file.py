# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A descriptor path that differs from the judged path only in case is told by its inode.

A source discovery admits is opened and held to the descriptor's identity only
when the path the descriptor leads to is the path that was judged. The two paths
were compared as exact strings. A file system that ignores case can report the
on-disk case of a name the judgment spelled as typed (``/repo/.ASH.yaml`` for
``/repo/.ash.yaml``), so a legitimate config was held to ``ABSENT_FILE`` and its
read refused as changed after it was checked, a race that never happened.

A path that differs only in case now counts when the judged path is not a link
and is the very file the descriptor holds (the same device and inode). Any other
difference still holds the source to nothing.

The report is stood in for here (``_descriptor_path``), so the case is exercised
on a case-sensitive file system too.

Red at the base: the first id was held to ``ABSENT_FILE``. The other ids are
controls that hold at both ends: a path that differs in more than case, and a
case-variant path whose judged file was replaced before the compare.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from automated_security_helper.config import config_sources
from automated_security_helper.config.config_sources import (
    ABSENT_FILE,
    discover_config_source,
    file_identity,
)

pytestmark = pytest.mark.unit


def _repo_with_a_config(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".ash.yaml").write_text("project_name: judged\n", encoding="utf-8")
    return repo / ".ash.yaml"


def test_a_path_reported_in_another_case_is_the_judged_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = _repo_with_a_config(tmp_path)
    judged = Path(os.path.realpath(config))
    reported = judged.with_name(judged.name.upper())
    assert reported != judged, "premise: the spelling differs"
    monkeypatch.setattr(
        config_sources, "_descriptor_path", lambda fd, named, identity: reported
    )

    discovery = discover_config_source(config.parent, permit=lambda path: True)

    assert discovery.selected is not None
    assert discovery.selected.identity == file_identity(config)
    assert discovery.selected.identity != ABSENT_FILE


def test_a_path_that_differs_in_more_than_case_is_held_to_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control: another name is another path, whatever its case."""
    config = _repo_with_a_config(tmp_path)
    elsewhere = config.parent / "ELSEWHERE.YAML"
    monkeypatch.setattr(
        config_sources, "_descriptor_path", lambda fd, named, identity: elsewhere
    )

    discovery = discover_config_source(config.parent, permit=lambda path: True)

    assert discovery.selected is not None
    assert discovery.selected.identity == ABSENT_FILE


@pytest.mark.skipif(
    os.name == "nt", reason="a file that is open is not replaceable on Windows"
)
def test_a_case_variant_path_whose_judged_file_was_replaced_is_held_to_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control: the judged path no longer leads to the file the descriptor
    holds, so the spelling alone does not vouch for it."""
    config = _repo_with_a_config(tmp_path)
    judged = Path(os.path.realpath(config))
    reported = judged.with_name(judged.name.upper())
    fresh = config.with_name("fresh.yaml")
    fresh.write_text("project_name: replaced\n", encoding="utf-8")

    def report_after_replacing_the_judged_file(fd, named, identity):
        os.replace(fresh, config)
        return reported

    monkeypatch.setattr(
        config_sources, "_descriptor_path", report_after_replacing_the_judged_file
    )

    discovery = discover_config_source(config.parent, permit=lambda path: True)

    assert discovery.selected is not None
    assert discovery.selected.identity == ABSENT_FILE

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``check_discovered_source`` refuses a linked file on Windows unresolved.

Discovery's own check of each candidate (``_permitted``) refuses a link on
Windows without resolving it, because resolving a link there can open a
connection to the host a UNC target names. ``check_discovered_source``, the
same check made again of the selected file, resolved the link first and asked
the permit about its target. It now makes discovery's check.

The Windows branch is reached here by standing in for the platform test
(``_on_windows``), with a POSIX symbolic link, which the link test reads the
same way.

Red at the base: the linked file passed the check.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from automated_security_helper.config import config_sources
from automated_security_helper.config.config_sources import check_discovered_source
from automated_security_helper.core.exceptions import ASHConfigInputNotPermittedError

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(
        os.name == "nt",
        reason="creating a symlink needs a privilege or Developer Mode there",
    ),
]


def _files(tmp_path: Path) -> tuple[Path, Path]:
    target = tmp_path / "target.yaml"
    target.write_text("project_name: demo\n", encoding="utf-8")
    link = tmp_path / ".ash.yaml"
    link.symlink_to(target)
    return target, link


def test_a_linked_source_is_refused_without_resolving_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _target, link = _files(tmp_path)
    monkeypatch.setattr(config_sources, "_on_windows", lambda: True)
    asked: list = []

    with pytest.raises(ASHConfigInputNotPermittedError):
        check_discovered_source(link, lambda path: asked.append(path) or True)

    assert asked == [], "the permit was asked about the link's target"


def test_a_file_that_is_no_link_is_judged_by_the_permit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control: a plain file is resolved and passed to the permit."""
    target, _link = _files(tmp_path)
    monkeypatch.setattr(config_sources, "_on_windows", lambda: True)

    assert check_discovered_source(target, lambda path: True) is None

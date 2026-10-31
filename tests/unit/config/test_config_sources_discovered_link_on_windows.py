# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``check_discovered_source`` refuses a file linked to a share on Windows unresolved.

Discovery's own check of each candidate (``_permitted``) refuses a link whose
chain leads to a network share, or cannot be read, on Windows without resolving
it, because resolving a link there can open a connection to the host a UNC
target names. ``check_discovered_source``, the same check made again of the
selected file, resolved the link first and asked the permit about its target.
It now makes discovery's check. A link that leads to a local file is resolved
and judged by the permit as the file it names (see
``test_config_sources_windows_link_chain.py``).

The Windows branch is reached here by standing in for the platform test
(``_on_windows``), with a POSIX symbolic link, which the link test reads the
same way, and with ``os.readlink`` answering a UNC target for it.

Red at the base: the file linked to a share passed the check.
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


def test_a_source_linked_to_a_share_is_refused_without_resolving_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _target, link = _files(tmp_path)
    monkeypatch.setattr(config_sources, "_on_windows", lambda: True)
    real_readlink = os.readlink

    def readlink(path, *args, **kwargs):
        if Path(os.fspath(path)) == link:
            return "\\\\server\\share\\config.yaml"
        return real_readlink(path, *args, **kwargs)

    monkeypatch.setattr(os, "readlink", readlink)
    asked: list = []

    with pytest.raises(ASHConfigInputNotPermittedError):
        check_discovered_source(link, lambda path: asked.append(path) or True)

    assert asked == [], "the permit was asked about the link's target"


def test_a_source_linked_to_a_local_file_is_judged_by_the_permit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control: a chain that stays on local names is resolved and judged."""
    target, link = _files(tmp_path)
    monkeypatch.setattr(config_sources, "_on_windows", lambda: True)
    asked: list = []

    check_discovered_source(link, lambda path: asked.append(path) or True)

    assert asked == [Path(os.path.realpath(target))]


def test_a_file_that_is_no_link_is_judged_by_the_permit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control: a plain file is resolved and passed to the permit."""
    target, _link = _files(tmp_path)
    monkeypatch.setattr(config_sources, "_on_windows", lambda: True)

    assert check_discovered_source(target, lambda path: True) is None

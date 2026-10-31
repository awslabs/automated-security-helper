# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Discovery reads pyproject.toml as the file its permit check judged.

Under a caller's ``permit`` discovery checks each source by the path it
resolves to and takes the identity of the file the name led to
(``ConfigSource.identity``). The read of ``pyproject.toml`` for its
``[tool.ash]`` table took an identity of its own instead, so a name made to
lead to another file between the check and that read was read, outside the
grant. The read is now held to the identity the check took, and a file swapped
in after the check is refused as one that cannot be read.

Discovery takes that identity from the descriptor it opens once the permit has
admitted the name (``open_config_for_judgment``). The first id replaces the file
with a new one (a new inode) right after that open returns. The descriptor keeps
the original inode in use, so the new file cannot be given its number, and the
read of the table, held to the original's identity, finds another file and
refuses. It is skipped on Windows, where a file that is open is not replaceable.

Red at the base: discovery opened nothing after its permit check, so the swap
never ran and the first id's premise (a descriptor was opened and then
swapped) failed there. The property it carries, a file replaced after the check
is refused, is the one the identity-taking step of the base carried through a
name lookup.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from automated_security_helper.config import config_sources
from automated_security_helper.config.config_sources import (
    config_file_changed,
    discover_config_source,
)
from automated_security_helper.core.exceptions import ASHConfigSourceError

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _no_operator_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ASH_CONFIG", raising=False)


def _replace_with_a_new_file(path: Path, text: str) -> None:
    """Put a new file, a new inode, at ``path``."""
    fresh = path.with_name(path.name + ".new")
    fresh.write_text(text, encoding="utf-8")
    os.replace(fresh, path)


def _swap_after_the_check(monkeypatch: pytest.MonkeyPatch, pyproject: Path) -> list:
    """Swap ``pyproject`` for a new file right after the first open of it that
    follows the permit check; later opens are left alone.

    The open is the one discovery makes to take the identity the read is held to
    (``open_config_for_judgment``). The real open returns first, so the
    descriptor and its identity are those of the file the check judged.
    """
    real_open = config_sources.open_config_for_judgment
    opened_after_the_check: list = []

    def open_then_swap(path, **kwargs):
        opened = real_open(path, **kwargs)
        if (
            Path(os.path.realpath(path)) == Path(os.path.realpath(pyproject))
            and not opened_after_the_check
        ):
            opened_after_the_check.append(opened)
            _replace_with_a_new_file(
                pyproject, "[tool.ash]\nproject_name = 'swapped'\n"
            )
        return opened

    monkeypatch.setattr(config_sources, "open_config_for_judgment", open_then_swap)
    return opened_after_the_check


@pytest.mark.skipif(
    os.name == "nt", reason="a file that is open is not replaceable on Windows"
)
def test_a_pyproject_swapped_after_the_permit_check_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text("[tool.ash]\nproject_name = 'checked'\n", encoding="utf-8")
    opened_after_the_check = _swap_after_the_check(monkeypatch, pyproject)

    with pytest.raises(ASHConfigSourceError) as refused:
        discover_config_source(tmp_path, permit=lambda path: True)

    assert opened_after_the_check, "premise: discovery opened the checked pyproject"
    assert opened_after_the_check[0] is not None, "premise: the open took a file"
    assert config_file_changed(refused.value), repr(refused.value)


def test_the_pyproject_the_permit_checked_is_selected(tmp_path: Path) -> None:
    """The control: with nothing swapped the checked file is read and selected."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text("[tool.ash]\nproject_name = 'checked'\n", encoding="utf-8")

    discovery = discover_config_source(tmp_path, permit=lambda path: True)

    assert discovery.selected is not None
    assert discovery.selected.path == pyproject

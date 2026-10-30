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

Red at the base: discovery selected the swapped-in pyproject.toml without a
refusal.
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
    """Swap ``pyproject`` for a new file right after the first identity of it is
    taken, the one the permit check takes; later identities are left alone."""
    real_identity_to_hold = config_sources.identity_to_hold
    taken: list = []

    def identity_then_swap(path):
        identity = real_identity_to_hold(path)
        if Path(path) == pyproject and not taken:
            taken.append(identity)
            _replace_with_a_new_file(
                pyproject, "[tool.ash]\nproject_name = 'swapped'\n"
            )
        return identity

    monkeypatch.setattr(config_sources, "identity_to_hold", identity_then_swap)
    return taken


def test_a_pyproject_swapped_after_the_permit_check_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text("[tool.ash]\nproject_name = 'checked'\n", encoding="utf-8")
    taken = _swap_after_the_check(monkeypatch, pyproject)

    with pytest.raises(ASHConfigSourceError) as refused:
        discover_config_source(tmp_path, permit=lambda path: True)

    assert taken, "premise: the permit check took an identity"
    assert config_file_changed(refused.value), repr(refused.value)


def test_the_pyproject_the_permit_checked_is_selected(tmp_path: Path) -> None:
    """The control: with nothing swapped the checked file is read and selected."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text("[tool.ash]\nproject_name = 'checked'\n", encoding="utf-8")

    discovery = discover_config_source(tmp_path, permit=lambda path: True)

    assert discovery.selected is not None
    assert discovery.selected.path == pyproject

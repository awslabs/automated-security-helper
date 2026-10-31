# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The suppression save writes only inside the directory the config path names.

A symlinked config is written through to its target so the link stays a link,
but the target was wherever the link pointed, with no confinement: a link placed
in a repository made the inspect TUI create or edit a file outside the
repository. A link whose resolved target is outside the config path's own
directory (as resolved) is now refused in the save's left-unchanged words,
dangling or not; a link to a file inside that directory still saves.

Red at the base: the save wrote the entry into the outside target (and created
the dangling one).
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from automated_security_helper.config.ash_config import add_suppression_to_config
from automated_security_helper.models.core import AshSuppression

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(
        os.name == "nt",
        reason="creating a symlink needs a privilege or Developer Mode there",
    ),
]

NEW = AshSuppression(rule_id="NEW-1", path="a.py", reason="kept")


def test_a_link_to_a_file_outside_the_directory_is_refused(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside" / "ash.yaml"
    outside.parent.mkdir()
    outside.write_text("global_settings:\n  suppressions: []\n", encoding="utf-8")
    before = outside.read_bytes()
    config_path = repo / ".ash.yaml"
    config_path.symlink_to(outside)

    with pytest.raises(ValueError, match="outside its own directory.*is unchanged"):
        add_suppression_to_config(config_path, NEW)

    assert outside.read_bytes() == before
    assert config_path.is_symlink()


def test_a_dangling_link_outside_the_directory_creates_nothing(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    pointed = tmp_path / "elsewhere" / "ash.yaml"
    pointed.parent.mkdir()
    config_path = repo / ".ash.yaml"
    config_path.symlink_to(pointed)

    with pytest.raises(ValueError, match="is unchanged"):
        add_suppression_to_config(config_path, NEW)

    assert not pointed.exists()
    assert config_path.is_symlink()


def test_a_link_inside_the_directory_still_saves_through(tmp_path: Path) -> None:
    """The control: the documented shape, a link to a file beside it."""
    target = tmp_path / "shared" / "ash.yaml"
    target.parent.mkdir()
    target.write_text("global_settings:\n  suppressions: []\n", encoding="utf-8")
    config_path = tmp_path / ".ash.yaml"
    config_path.symlink_to(target)

    assert add_suppression_to_config(config_path, NEW) is True
    assert "NEW-1" in target.read_text(encoding="utf-8")

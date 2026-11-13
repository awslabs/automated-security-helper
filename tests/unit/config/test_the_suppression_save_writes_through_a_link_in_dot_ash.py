# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The suppression save confines a linked config to its chain's root, not its directory.

The save writes a symlinked config through to its target only when the target
stays inside a confinement. That confinement was the config path's own
directory, so the documented ``.ash/.ash.yaml`` linked to a config beside
``.ash/`` (``.ash/.ash.yaml -> ../.ash.yaml``) was refused, where it had saved
before. The root is now the one the config's own chain is confined to when a
scan resolves it with no source directory: the config's directory, or the
directory holding ``.ash/`` for a config in it, taken from the config path AS
SPELLED (where the link sits). Taken from the path's resolution it would be the
target's own directory and confine nothing, so ``default_confinement_root``,
which resolves first, is not what the save uses. A link out of that root is
still refused.

Red at the base: the save of ``.ash/.ash.yaml -> ../.ash.yaml`` raised the
left-unchanged refusal and wrote nothing. The two refusal tests were red at an
intermediate cut that took the root from the resolved path: both links saved
through.
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


def test_a_dot_ash_link_to_a_config_beside_it_saves_through(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / ".ash").mkdir(parents=True)
    target = repo / ".ash.yaml"
    target.write_text("global_settings:\n  suppressions: []\n", encoding="utf-8")
    config_path = repo / ".ash" / ".ash.yaml"
    config_path.symlink_to(Path("..") / ".ash.yaml")

    assert add_suppression_to_config(config_path, NEW) is True

    assert "NEW-1" in target.read_text(encoding="utf-8")
    assert config_path.is_symlink()


def test_a_dot_ash_link_out_of_the_repository_is_still_refused(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    (repo / ".ash").mkdir(parents=True)
    outside = tmp_path / "outside.yaml"
    outside.write_text("global_settings:\n  suppressions: []\n", encoding="utf-8")
    before = outside.read_bytes()
    config_path = repo / ".ash" / ".ash.yaml"
    config_path.symlink_to(Path("..") / ".." / "outside.yaml")

    with pytest.raises(ValueError, match="outside its own directory.*is unchanged"):
        add_suppression_to_config(config_path, NEW)

    assert outside.read_bytes() == before
    assert config_path.is_symlink()


def test_a_link_from_the_repository_root_to_a_parent_is_still_refused(
    tmp_path: Path,
) -> None:
    """The control: a config not in ``.ash/`` is confined to its own directory."""
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "shared.yaml"
    outside.write_text("global_settings:\n  suppressions: []\n", encoding="utf-8")
    config_path = repo / ".ash.yaml"
    config_path.symlink_to(Path("..") / "shared.yaml")

    with pytest.raises(ValueError, match="outside its own directory.*is unchanged"):
        add_suppression_to_config(config_path, NEW)

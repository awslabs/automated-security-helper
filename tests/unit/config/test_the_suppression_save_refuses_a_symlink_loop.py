# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The suppression save refuses a config path that is a symlink loop, by name.

A config path whose links lead back to themselves passes the save's
not-a-file check (stat fails, so the path is left to the open) and reads as a
file that does not exist yet, so the save reached its containment check with
it. There ``Path.resolve`` met the loop differently by version: 3.10 to 3.12
raised RuntimeError from the resolve, and 3.13 onward returned the path with
the loop unresolved, so the save failed at its stat with the system's ELOOP.
Neither was the save's left-unchanged refusal. The loop is now refused in the
save's own words, before anything is staged, on every supported version.

Red at the base: RuntimeError (3.10 to 3.12) or OSError with errno ELOOP (3.13
onward) escaped the save instead of its ValueError.
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


def test_a_config_path_that_is_a_symlink_loop_is_refused_by_name(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    config_path = repo / ".ash.yaml"
    other = repo / "other.yaml"
    config_path.symlink_to(other.name)
    other.symlink_to(config_path.name)
    entries_before = sorted(p.name for p in repo.iterdir())

    with pytest.raises(ValueError, match="symlink loop.*is unchanged"):
        add_suppression_to_config(config_path, NEW)

    assert sorted(p.name for p in repo.iterdir()) == entries_before
    assert config_path.is_symlink() and other.is_symlink()


def test_a_link_to_a_file_beside_it_still_saves_through(tmp_path: Path) -> None:
    """The control: a link that resolves still takes the documented route."""
    target = tmp_path / "shared.yaml"
    target.write_text("global_settings:\n  suppressions: []\n", encoding="utf-8")
    config_path = tmp_path / ".ash.yaml"
    config_path.symlink_to(target.name)

    assert add_suppression_to_config(config_path, NEW) is True
    assert "NEW-1" in target.read_text(encoding="utf-8")
    assert config_path.is_symlink()

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The shim that makes a name's link walk end without an answer.

Tests of an unfinished walk make one directory component unexaminable for the link
walk's own ``lstat`` (``tests.utils.helpers.link_walk_cannot_examine``). The shim
finds the walk's read by the name of the function that makes it, so if that function
is renamed, or its ``lstat`` call moves out of the first frames, the shim does nothing
and every test that relies on it runs against a walk that finished. Those tests then
fail for another reason, or pass checks that no longer check anything.

The shim therefore proves at install that the walk's own read of the component is
refused, and fails there when it is not. These tests pin that: the walk's read is
refused and counted, every other read stays real, and a walk read that the shim
cannot find fails loudly.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from automated_security_helper.config import sandbox_grants
from automated_security_helper.config.sandbox_grants import (
    forget_unverifiable_warnings,
)
from tests.utils.helpers import link_walk_cannot_examine


@pytest.fixture(autouse=True)
def _fresh_warnings() -> None:
    forget_unverifiable_warnings()
    yield
    forget_unverifiable_warnings()


def _component(tmp_path: Path) -> Path:
    component = tmp_path / "gate"
    component.mkdir()
    (component / "cfg.yaml").write_text("project_name: x\n", encoding="utf-8")
    return component


def test_the_walks_read_of_the_component_is_refused_and_counted(tmp_path, monkeypatch):
    component = _component(tmp_path)
    refused = link_walk_cannot_examine(monkeypatch, component)
    assert refused.asked == 0

    links, decided = sandbox_grants._walk_links(component / "cfg.yaml")

    assert decided is False
    assert links == []
    assert refused.asked >= 1


def test_every_other_read_of_the_component_and_every_other_path_stays_real(
    tmp_path, monkeypatch
):
    component = _component(tmp_path)
    other = tmp_path / "other"
    other.mkdir()
    refused = link_walk_cannot_examine(monkeypatch, component)

    assert os.lstat(component).st_mode == component.stat().st_mode
    assert sandbox_grants._link_state(other) is False
    assert sandbox_grants._walk_links(other / "x.yaml")[1] is True
    assert refused.asked == 0


def test_a_walk_read_the_shim_cannot_find_fails_at_install(tmp_path, monkeypatch):
    """With the walk's read made by a function of another name, the walk would
    finish. The shim says so when it is installed, not after a test has passed
    against a walk that never stopped."""
    component = _component(tmp_path)

    def _examine(path):
        try:
            return sandbox_grants._is_link_stat(os.lstat(path))
        except OSError:
            return None

    monkeypatch.setattr(sandbox_grants, "_link_state", _examine)

    with pytest.raises(AssertionError, match="was not refused"):
        link_walk_cannot_examine(monkeypatch, component)

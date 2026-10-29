# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Two readings of ``config/sandbox_grants.py``.

* ``scanned_checkouts`` takes the outermost checkout from every name the scan
  root has, the shell's ``$PWD`` name included, as ``scanned_trees`` does: after
  ``cd work/vendor && ash scan`` where ``vendor`` is a link out of the checkout
  ``work``, the kernel names the root outside ``work`` while the shell names it
  inside, and the superproject the operator-tier judgment reads has to be the
  same one the other trust checks count.
* ``tree_holding`` finds the links a name passes through with this module's own
  walk (``_walk_links``), which counts a Windows junction as the link it is, so
  a file reached through one is judged by the tree the junction sits in.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.config import sandbox_grants
from automated_security_helper.config.sandbox_grants import (
    scanned_checkouts,
    tree_holding,
)
from tests.utils.helpers import mark_git_checkout

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _tmp_path_is_outside_every_checkout(tmp_path):
    from automated_security_helper.config.sandbox_grants import in_any_checkout

    assert not in_any_checkout(tmp_path), (
        f"{tmp_path} is inside a git checkout; run with --basetemp outside one"
    )


def test_the_outermost_checkout_is_found_through_the_shells_name(tmp_path, monkeypatch):
    work = tmp_path / "work"
    mark_git_checkout(work)
    elsewhere = tmp_path / "elsewhere" / "vendor"
    elsewhere.mkdir(parents=True)
    try:
        (work / "vendor").symlink_to(elsewhere, target_is_directory=True)
    except (OSError, NotImplementedError) as error:
        pytest.skip(f"symlinks are not available here: {error}")
    # The shell's name for the working directory goes through the link; the
    # kernel's does not.
    monkeypatch.chdir(elsewhere)
    monkeypatch.setenv("PWD", str(work / "vendor"))

    found = scanned_checkouts(Path(elsewhere))

    assert work in found, found


def test_tree_holding_reads_the_modules_own_link_walk(tmp_path, monkeypatch):
    tree = tmp_path / "tree"
    tree.mkdir()
    outside = tmp_path / "outside" / "cfg.yaml"
    outside.parent.mkdir()
    outside.write_text("# placeholder\n", encoding="utf-8")
    # The control: a name that passes through no link is inside no tree.
    assert tree_holding(outside, [tree]) is None

    junction = tree / "junction"
    monkeypatch.setattr(sandbox_grants, "_walk_links", lambda path: ([junction], True))

    assert tree_holding(outside, [tree]) == tree

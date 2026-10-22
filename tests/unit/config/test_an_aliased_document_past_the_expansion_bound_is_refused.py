# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A document whose anchors multiply past the expansion bound is refused.

The loader admits nested, non-recursive anchors, and the chain gives every
aliased place its own container before merging (``_unaliased``), so a file a
few hundred bytes long can demand a number of containers exponential in its
depth: each level of a stack of anchored mappings multiplies the copies of
the level below. The chain charges the expansion's budgets before the
rebuild (``refuse_past_expansion_bound``: every place, scalars included,
and each string's length) and refuses the file as a source error once a
budget is passed, so the cost of a hostile file is the bound, not the
file's product.

The other side -- an alias is never a reason to refuse a loadable config,
and modest sharing loads exactly as its alias-free spelling -- is pinned by
``test_a_yaml_alias_never_makes_a_config_unloadable.py``; those cells are
this one's must-not-flag control, and nothing here duplicates them.
"""

import pytest

from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.core.exceptions import ASHConfigSourceError
from tests.utils.helpers import mark_git_checkout


def _bomb_text() -> str:
    """A small document that expands to well over the bound: nine aliases
    of the level below at each of six levels on top of a leaf mapping."""
    lines = ["project_name: bounded", "a0: &a0 {leaf: 1}"]
    for level in range(1, 7):
        refs = ", ".join(f"k{j}: *a{level - 1}" for j in range(9))
        lines.append(f"a{level}: &a{level} {{{refs}}}")
    return "\n".join(lines) + "\n"


def test_a_document_past_the_expansion_bound_is_refused(tmp_path, monkeypatch):
    src = tmp_path / "src"
    mark_git_checkout(src)
    config = tmp_path / "ash.yaml"
    config.write_text(_bomb_text(), encoding="utf-8")
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.chdir(src)

    with pytest.raises(ASHConfigSourceError) as refused:
        resolve_config(config_path=config, source_dir=src, trusted_config_path=config)

    said = str(refused.value)
    assert "anchors" in said and "expands" in said, said

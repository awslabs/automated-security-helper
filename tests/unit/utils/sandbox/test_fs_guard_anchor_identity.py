# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The guard's anchor is the root itself, however the write spells it.

A write below a registered root may spell the root through a link above it
(``/alias/out/x`` for the root ``/real/out``). The guard then anchors on the
ancestor that resolves to the root and opens every component below it without
following a link. Two things have to hold for that: the anchor is the OUTERMOST
spelling of the root (a link planted below the root that points back at it must
be a refused component, never the anchor), and the directory the anchor opens
by name is the root itself at the moment it is opened, not wherever a link above
it has been re-pointed meanwhile.
"""

import os
import sys

import pytest

from automated_security_helper.utils.sandbox import fs_guard
from automated_security_helper.utils.sandbox.fs_guard import (
    OutputLinkRefused,
    open_for_write,
    register_writable_root,
    release_writable_root,
)

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlinks"),
]


@pytest.fixture
def aliased_root(tmp_path):
    """A root ``real/out`` and a link ``alias -> real`` above it, so the root is
    also spelled ``alias/out``."""
    real = tmp_path / "real"
    out = real / "out"
    (out / "sub").mkdir(parents=True)
    alias = tmp_path / "alias"
    alias.symlink_to(real)
    root = register_writable_root(out)
    try:
        yield out, alias / "out"
    finally:
        release_writable_root(root)


def test_the_outermost_spelling_of_the_root_is_the_anchor(aliased_root):
    """With ``out/sub/back -> out`` planted, both ``alias/out`` and
    ``alias/out/sub/back`` resolve to the root; the outer one is the anchor, so
    ``back`` is a component below it and the guard refuses it as a link."""
    out, aliased = aliased_root
    (out / "sub" / "back").symlink_to(out)

    anchored = fs_guard._root_anchor(aliased / "sub" / "back" / "x", [out])

    assert anchored == (out, aliased)


def test_a_link_below_the_root_that_points_back_at_it_is_refused_not_followed(
    aliased_root,
):
    out, aliased = aliased_root
    (out / "sub" / "back").symlink_to(out)

    with pytest.raises(OutputLinkRefused):
        open_for_write(aliased / "sub" / "back" / "x")

    assert not (out / "x").exists(), "nothing was written through the planted link"


def test_nothing_below_a_root_matched_by_spelling_is_resolved(
    aliased_root, monkeypatch
):
    """A write spelled through the root's own name needs no resolution at all;
    the ancestors below the matched root are never looked at."""
    out, _aliased = aliased_root
    (out / "sub" / "deeper").mkdir()
    resolved = []
    real_realpath = os.path.realpath

    def recording_realpath(p, *args, **kwargs):
        resolved.append(os.fspath(p))
        return real_realpath(p, *args, **kwargs)

    monkeypatch.setattr(os.path, "realpath", recording_realpath)

    anchored = fs_guard._root_anchor(out / "sub" / "deeper" / "x", [out])

    assert anchored == (out, out)
    assert resolved == []

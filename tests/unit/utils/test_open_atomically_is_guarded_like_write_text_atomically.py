# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``open_atomically`` refuses a link where ``write_text_atomically`` refuses one.

``open_atomically`` staged its write through ``fs_guard.open_for_write`` and renamed
the staging file over the target by name, so only the staging file's own name was
guarded: below a root the caller named, a link at the target was replaced by the
rename and never refused, where ``write_text_atomically`` raised
``OutputLinkRefused`` and left the link in place. Both now write through
``fs_guard.open_for_atomic_write``.

``write_text_atomically`` also takes open()'s ``newline``, so content that carries
its own line endings is written as given on every platform.

Every path here is under ``tmp_path``.
"""

from __future__ import annotations

import sys

import pytest

from automated_security_helper.utils.atomic_write import (
    open_atomically,
    write_text_atomically,
)
from automated_security_helper.utils.sandbox.fs_guard import OutputLinkRefused

pytestmark = pytest.mark.unit

needs_symlinks = pytest.mark.skipif(
    sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
)


@needs_symlinks
def test_a_link_at_the_target_below_the_root_is_refused_and_kept(tmp_path):
    root = tmp_path / "out"
    root.mkdir()
    elsewhere = tmp_path / "elsewhere.txt"
    elsewhere.write_text("kept\n", encoding="utf-8")
    target = root / "results.json"
    target.symlink_to(elsewhere)

    with pytest.raises(OutputLinkRefused):
        with open_atomically(target, root=root) as handle:
            handle.write("new\n")

    assert target.is_symlink()
    assert elsewhere.read_text(encoding="utf-8") == "kept\n"
    assert [entry.name for entry in root.iterdir()] == ["results.json"]


@needs_symlinks
def test_a_link_on_the_way_to_the_target_below_the_root_is_refused(tmp_path):
    root = tmp_path / "out"
    (root / "real").mkdir(parents=True)
    (tmp_path / "elsewhere").mkdir()
    (root / "link").symlink_to(tmp_path / "elsewhere")

    with pytest.raises(OutputLinkRefused):
        with open_atomically(root / "link" / "results.json", root=root) as handle:
            handle.write("new\n")

    assert list((tmp_path / "elsewhere").iterdir()) == []


def test_control_a_streamed_write_replaces_the_target_whole(tmp_path):
    target = tmp_path / "results.json"
    target.write_text("old\n", encoding="utf-8")

    with open_atomically(target, root=tmp_path) as handle:
        handle.write("new ")
        assert target.read_text(encoding="utf-8") == "old\n"
        handle.write("content\n")

    assert target.read_text(encoding="utf-8") == "new content\n"
    assert [entry.name for entry in tmp_path.iterdir()] == ["results.json"]


def test_control_a_block_that_raises_leaves_the_target_as_it_was(tmp_path):
    target = tmp_path / "results.json"
    target.write_text("old\n", encoding="utf-8")

    with pytest.raises(RuntimeError):
        with open_atomically(target) as handle:
            handle.write("partial")
            raise RuntimeError("stopped")

    assert target.read_text(encoding="utf-8") == "old\n"
    assert [entry.name for entry in tmp_path.iterdir()] == ["results.json"]


def test_content_with_its_own_line_endings_is_written_as_given(tmp_path):
    target = tmp_path / "report.csv"

    write_text_atomically(target, "a,b\r\n1,2\r\n", newline="")

    assert target.read_bytes() == b"a,b\r\n1,2\r\n"

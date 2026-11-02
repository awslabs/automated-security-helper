# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The ``..`` comparison of ``linked_output_component`` is for a spelling with a ``..``.

An output directory spelled with a ``..`` can name two directories: the one the
lookup reaches, and the one the text names once ``os.path.abspath`` has applied
the ``..``. ``linked_output_component`` compares the two and refuses the spelling
when they differ. A spelling with no ``..`` has one reading, so asking is wasted
work, and it cost two real-path lookups on every call, the per-scanner
``refuse_symlinked_output_dir`` among them. On Windows it did worse:
``os.path.abspath`` drops a trailing dot or space from the last component while
the lookup's path keeps it, so a plain ``out.`` was refused as stepping back
through a link, a reason that has nothing to do with it.

Every path here is under ``tmp_path``.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from automated_security_helper.utils import output_dir_links
from automated_security_helper.utils.output_dir_links import linked_output_component

pytestmark = pytest.mark.unit

needs_symlinks = pytest.mark.skipif(
    sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
)


def test_a_spelling_with_no_dotdot_asks_for_no_real_path(tmp_path, monkeypatch):
    asked = []
    real = output_dir_links._real_path

    def counting(path):
        asked.append(os.fspath(path))
        return real(path)

    monkeypatch.setattr(output_dir_links, "_real_path", counting)
    output_dir = Path(os.path.realpath(tmp_path)) / "out"

    assert linked_output_component(None, output_dir) is None
    assert asked == []


def test_a_trailing_dot_is_not_refused_as_stepping_back_through_a_link(
    tmp_path, monkeypatch
):
    """Windows' ``abspath`` drops a trailing dot or space; the path the lookup
    reaches keeps it. The stand-in does what Windows does to the last component."""
    real_abspath = os.path.abspath

    def windows_abspath(path):
        head, tail = os.path.split(real_abspath(path))
        return os.path.join(head, tail.rstrip(". ") or tail)

    monkeypatch.setattr(os.path, "abspath", windows_abspath)
    output_dir = Path(os.path.realpath(tmp_path)) / "out."

    assert linked_output_component(None, output_dir) is None
    assert linked_output_component(tmp_path, output_dir) is None


@needs_symlinks
def test_control_a_dotdot_through_a_link_to_another_directory_is_still_refused(
    tmp_path,
):
    tree = Path(os.path.realpath(tmp_path))
    (tree / "real" / "sub").mkdir(parents=True)
    (tree / "alias").symlink_to(tree / "real" / "sub")
    output_dir = tree / "alias" / ".." / "out"

    found = linked_output_component(None, output_dir)

    assert found is not None
    assert "steps back through a link with .." in found
    assert (tree / "real" / "out").as_posix() in found
    assert (tree / "out").as_posix() in found


def test_control_a_dotdot_between_plain_directories_is_still_accepted(tmp_path):
    tree = Path(os.path.realpath(tmp_path))
    (tree / "a").mkdir()
    (tree / "out").mkdir()

    assert linked_output_component(None, tree / "a" / ".." / "out") is None

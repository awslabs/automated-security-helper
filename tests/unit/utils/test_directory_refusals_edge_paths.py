# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Three paths the directory refusals answered wrongly or not at all.

An empty --output-dir answered "will be made": ``os.stat("")`` raises
FileNotFoundError, which the walk for a dangling link read as a path that is not
there, while the run wrote into the current directory. A path holding a NUL made
``os.stat`` raise ValueError, which escaped both refusals. And the dangling-link
walk ran over ``os.path.abspath`` of the path, which folds ``..`` lexically, so
after a symbolic link it judged a sibling of the link instead of a sibling of the
directory the link leads to, the one mkdir reaches.
"""

from __future__ import annotations

import os

import pytest

from automated_security_helper.utils.directory_refusals import (
    output_dir_refusal,
    source_dir_refusal,
)

pytestmark = pytest.mark.unit


def test_an_empty_output_dir_is_refused_as_mkdir_refuses_it():
    refusal = output_dir_refusal("")
    assert refusal is not None
    assert refusal.startswith("Output directory cannot be created:  (")


def test_a_path_holding_a_nul_is_refused_not_raised():
    assert source_dir_refusal("a\x00b") == "Source directory does not exist: a\x00b"
    refusal = output_dir_refusal("a\x00b")
    assert refusal is not None
    assert refusal.startswith("Output directory cannot be created: a\x00b (")


def _link(link, target) -> None:
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError) as exc:  # pragma: no cover - Windows
        pytest.skip(f"symlink creation unavailable on this platform: {exc}")


def test_a_dot_dot_after_a_link_is_judged_where_the_os_takes_it(tmp_path):
    real = tmp_path / "real"
    other = tmp_path / "other"
    real.mkdir()
    other.mkdir()
    # The link points one level inside "other", so "lnk/.." is "other" itself: a
    # link to "other" would make "lnk/.." its parent, this test's own directory.
    (other / "inner").mkdir()
    _link(real / "lnk", other / "inner")
    _link(other / "dangling", tmp_path / "nowhere")
    _link(real / "dangling", tmp_path / "nowhere")

    # As written, real/lnk/.. is "other", whose "dangling" link mkdir would meet.
    # Folded lexically it is "real", whose "dangling" link mkdir never reaches.
    through_other = os.path.join(str(real), "lnk", "..", "dangling", "out")
    assert output_dir_refusal(through_other) is not None

    # The other way round: lexically the path meets real/dangling, but the OS walks
    # real/lnk/.. into "other", where "fresh" is simply not there yet.
    (other / "fresh").mkdir()
    (other / "fresh").rmdir()
    through_fresh = os.path.join(str(real), "lnk", "..", "fresh", "out")
    assert output_dir_refusal(through_fresh) is None
    lexical_twin = os.path.join(str(real), "dangling", "out")
    assert output_dir_refusal(lexical_twin) is not None

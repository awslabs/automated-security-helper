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

import errno
import os
import stat
import sys

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
    assert (
        source_dir_refusal("a\x00b") == "Source directory is not a valid path: a\x00b"
    )
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


def test_a_file_on_the_way_is_not_a_directory_where_stat_only_says_not_found(
    tmp_path, monkeypatch
):
    """Windows stat answers "not found" for ``<file>\\ash_output``, where POSIX
    answers ENOTDIR. The refusal walks up to the first part that is there, so both
    give ``Not a directory``, and neither lets the output directory be made."""
    blocker = tmp_path / ".ash"
    blocker.write_text("a file\n", encoding="utf-8")
    output = blocker / "ash_output"
    fresh = tmp_path / "fresh" / "ash_output"
    (tmp_path / "fresh").mkdir()
    real_stat = os.stat

    def stat_that_only_says_not_found(path, *args, **kwargs):
        if os.fspath(path) in (str(output), str(fresh)):
            raise FileNotFoundError(2, "The system cannot find the path", str(path))
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(os, "stat", stat_that_only_says_not_found)

    refusal = output_dir_refusal(output)

    assert refusal == f"Output directory cannot be created: {output} (Not a directory)"
    # The control: a missing directory under a directory is still made, not refused.
    assert output_dir_refusal(fresh) is None


class _ReparsePoint:
    """The lstat of a Windows junction: the directory's own answer, with the
    reparse-point attribute that ``os.path.islink`` does not look at."""

    def __init__(self, real: os.stat_result) -> None:
        self._real = real
        self.st_file_attributes = stat.FILE_ATTRIBUTE_REPARSE_POINT

    def __getattr__(self, name: str):
        return getattr(self._real, name)


def test_a_junction_to_nothing_on_the_way_is_a_link_to_nothing(tmp_path, monkeypatch):
    """The stand-in for a junction whose target was removed: lexists, no symbolic
    link, not a directory that resolves, a reparse point. It is refused as a link
    to nothing is (``File exists``, EEXIST), not as a file on the way."""
    junction = tmp_path / "junction"
    junction.mkdir()
    real_lstat = os.lstat
    real_exists = os.path.exists

    def lstat(path, *args, **kwargs):
        result = real_lstat(path, *args, **kwargs)
        return _ReparsePoint(result) if os.fspath(path) == str(junction) else result

    def exists(path):
        return False if os.fspath(path) == str(junction) else real_exists(path)

    monkeypatch.setattr(os, "lstat", lstat)
    monkeypatch.setattr(os.path, "exists", exists)
    output = junction / "ash_output"

    refusal = output_dir_refusal(output)

    assert refusal == (
        f"Output directory cannot be created: {output} ({os.strerror(errno.EEXIST)})"
    )
    assert refusal.error_number == errno.EEXIST


@pytest.mark.skipif(
    sys.platform != "win32", reason="a junction is made on Windows only"
)
def test_a_real_junction_to_a_removed_directory_is_a_link_to_nothing(tmp_path):
    import _winapi

    target = tmp_path / "target"
    target.mkdir()
    junction = tmp_path / "junction"
    _winapi.CreateJunction(str(target), str(junction))
    target.rmdir()

    # Below the junction, so the first stat goes through it and the walk ascends.
    output = junction / "ash_output"

    refusal = output_dir_refusal(output)

    assert refusal == (
        f"Output directory cannot be created: {output} ({os.strerror(errno.EEXIST)})"
    )
    assert refusal.error_number == errno.EEXIST

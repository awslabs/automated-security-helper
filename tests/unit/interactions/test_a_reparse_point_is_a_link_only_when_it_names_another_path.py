# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A Windows reparse point is a link to the config gate only when it names
another path.

These cells build no symbolic links: a regular file is given the stat a
reparse point reports (the reparse attribute and a tag), so they run on every
platform, Windows included. They live apart from the POSIX link layouts for
that reason.
"""

from __future__ import annotations

import os
import stat

import pytest

from automated_security_helper.config import config_sources
from automated_security_helper.interactions import run_ash_container
from automated_security_helper.interactions.run_ash_container import (
    ContainerInputError,
)


class _AsReparsePoint:
    """A file's stat, as Windows reports a reparse point with the given tag."""

    def __init__(self, real, tag):
        self._real = real
        self.st_file_attributes = stat.FILE_ATTRIBUTE_REPARSE_POINT
        self.st_reparse_tag = tag

    def __getattr__(self, name):
        return getattr(self._real, name)


#: (id, reparse tag, whether the place is a link). A tag with the name
#: surrogate bit (0x20000000) names another path: a symbolic link, a junction.
#: A OneDrive placeholder and a deduplicated file carry tags without it, and
#: are the file they appear to be.
_REPARSE_TAGS = [
    pytest.param(0x9000001A, False, id="cloud-placeholder"),
    pytest.param(0x80000013, False, id="deduplicated-file"),
    pytest.param(0xA000000C, True, id="symbolic-link-tag"),
    pytest.param(0xA0000003, True, id="junction-tag"),
]


@pytest.mark.parametrize(("tag", "names_another_path"), _REPARSE_TAGS)
def test_a_reparse_point_that_resolves_to_itself_is_a_loop_only_when_it_is_a_link(
    tag, names_another_path, tmp_path, monkeypatch
):
    """The stat of an ordinary file is reported with the reparse attribute and
    a tag, which is what the repo's link test and the name-surrogate test read.
    A reparse point is a link to the walk (it refuses on one), and the collapse
    leaves it where it is, so what decides is whether the place is still a link
    after the collapse: a name surrogate is, a placeholder is not."""
    synced = tmp_path / "synced"
    synced.mkdir()
    config = synced / "ash.yaml"
    config.write_text("project_name: mine\n")
    source = tmp_path / "src"
    source.mkdir()
    real_lstat = os.lstat

    def lstat(path, *args, **kwargs):
        info = real_lstat(path, *args, **kwargs)
        if os.fspath(path) == str(config):
            return _AsReparsePoint(info, tag)
        return info

    monkeypatch.setattr(os, "lstat", lstat)
    if names_another_path:
        with pytest.raises(ContainerInputError, match="cannot be resolved"):
            run_ash_container._refuse_config_linked_out_of_the_tree(str(config), source)
    else:
        run_ash_container._refuse_config_linked_out_of_the_tree(str(config), source)


def _stat_as_reparse_point(monkeypatch, target, tag):
    real_lstat = os.lstat

    def lstat(path, *args, **kwargs):
        info = real_lstat(path, *args, **kwargs)
        if os.fspath(path) == str(target):
            return _AsReparsePoint(info, tag)
        return info

    monkeypatch.setattr(os, "lstat", lstat)


@pytest.mark.parametrize(("tag", "names_another_path"), _REPARSE_TAGS)
def test_the_two_link_tests_differ_only_in_which_reparse_points_they_read_as_links(
    tag, names_another_path, tmp_path, monkeypatch
):
    """The walk reads any reparse point as a link; the check after a collapse
    reads only one that names another path. Both come from one lstat helper, so
    nothing else about them differs."""
    place = tmp_path / "ash.yaml"
    place.write_text("project_name: mine\n")
    _stat_as_reparse_point(monkeypatch, place, tag)

    assert config_sources._is_a_link(place) is True
    assert run_ash_container._collapse_left_undecided(place) is names_another_path


def test_both_link_tests_read_an_absent_place_as_no_link(tmp_path):
    assert config_sources._is_a_link(tmp_path / "absent") is False
    assert run_ash_container._collapse_left_undecided(tmp_path / "absent") is False

#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The one Windows link-chain reading both callers use.

``cli/mcp/sandbox.py`` and ``config/config_sources.py`` each carried a copy of
the reading that refuses a path whose resolution would open a network share.
The copies differed in their link test (every reparse point, or only one that
names another path) and in how much of the path they read (every component, or
the last one). This module pins the shared reading: the stricter link test, the
component walk on the lexically collapsed spelling, and the chain reading with
its hop bound as a parameter.

Links are made with ``symlink_to``, whose target text ``os.readlink`` returns
unresolved, so a Windows share spelling can be a target on any platform.
"""

from __future__ import annotations

import os
import stat
from types import SimpleNamespace

import pytest

from automated_security_helper.utils import link_chain
from automated_security_helper.utils.scanned_tree import _is_link_stat as tree_test

pytestmark = pytest.mark.unit

REPARSE_POINT = 0x400
NAME_SURROGATE = 0x20000000


def _stat(mode: int, attributes: int = 0, tag: int = 0):
    return SimpleNamespace(
        st_mode=mode, st_file_attributes=attributes, st_reparse_tag=tag
    )


class TestTheLinkTestIsTheStricterOfTheTwo:
    def test_a_symbolic_link_is_a_link(self):
        assert link_chain.is_link_stat(_stat(stat.S_IFLNK)) is True

    def test_a_plain_directory_is_not(self):
        assert link_chain.is_link_stat(_stat(stat.S_IFDIR)) is False

    def test_a_reparse_point_that_names_a_path_is_a_link(self):
        info = _stat(stat.S_IFDIR, REPARSE_POINT, NAME_SURROGATE)
        assert link_chain.is_link_stat(info) is True

    def test_a_reparse_point_that_names_no_path_is_a_link_here(self):
        """The stricter reading: the tree reader follows such an entry as plain
        (its tag is no name surrogate); this reading counts it, so the chain
        reading answers None for it and the caller refuses it unresolved."""
        info = _stat(stat.S_IFDIR, REPARSE_POINT, 0)

        assert link_chain.is_link_stat(info) is True
        assert tree_test(info) is False


class TestTheShareSpelling:
    @pytest.mark.parametrize(
        "text",
        [
            "\\\\server\\share",
            "//server/share",
            "\\\\?\\UNC\\server\\share",
            "\\\\.\\pipe\\ash",
            "\\\\?\\C:repo",
            "\\\\.\\C:",
            "\\\\.\\C:\\..\\UNC\\server\\share\\tree",
            "\\??\\C:\\repo\\..\\..\\UNC\\server\\share",
        ],
    )
    def test_a_share_or_device_spelling_is_judged_as_one(self, text):
        assert link_chain.names_a_windows_share(text) is True

    @pytest.mark.parametrize(
        "text",
        [
            "C:\\repo",
            "\\\\?\\C:\\repo",
            "\\\\.\\C:\\repo..\\x",
            "C:\\repo\\..\\other",
            "/tmp/x",
        ],
    )
    def test_a_local_spelling_is_not(self, text):
        assert link_chain.names_a_windows_share(text) is False

    def test_a_drive_spelling_needs_its_separator(self):
        assert link_chain.is_a_drive_spelling("C:\\") is True
        assert link_chain.is_a_drive_spelling("C:\\repo") is True
        assert link_chain.is_a_drive_spelling("C:") is False
        assert link_chain.is_a_drive_spelling("C:repo") is False


def test_the_components_run_from_the_anchor_down():
    assert link_chain.components_down_to("/a/b/c") == ["/a", "/a/b", "/a/b/c"]
    assert link_chain.components_down_to("rel/x") == ["rel", "rel/x"]
    assert link_chain.components_down_to("/") == ["/"]


class TestTheWalk:
    def test_a_share_link_in_a_parent_is_the_answer(self, tmp_path):
        granted = tmp_path / "granted"
        granted.mkdir()
        (granted / "lnk").symlink_to("\\\\server\\share")

        found = link_chain.first_unsafe_link(str(granted / "lnk" / "repo"))

        assert found is not None
        assert found.component == str(granted / "lnk")
        assert found.is_last is False
        assert found.reaches_a_share is True

    def test_a_share_link_as_the_path_itself_is_last(self, tmp_path):
        link = tmp_path / "link"
        link.symlink_to("\\\\server\\share")

        found = link_chain.first_unsafe_link(str(link))

        assert found is not None
        assert found.is_last is True
        assert found.reaches_a_share is True

    def test_a_local_link_in_a_parent_is_followed(self, tmp_path):
        real = tmp_path / "real"
        (real / "repo").mkdir(parents=True)
        (tmp_path / "lnk").symlink_to(real)

        assert link_chain.first_unsafe_link(str(tmp_path / "lnk" / "repo")) is None

        (real / "deep").symlink_to("\\\\server\\share")
        found = link_chain.first_unsafe_link(str(tmp_path / "lnk" / "deep" / "tree"))
        assert found is not None
        assert found.reaches_a_share is True

    def test_a_missing_component_stepped_back_over_hides_nothing(self, tmp_path):
        """The collapsed spelling is judged, as Win32 judges it: ``missing/..``
        is never examined, and the share link after it is found."""
        granted = tmp_path / "granted"
        granted.mkdir()
        (granted / "lnk").symlink_to("\\\\server\\share")

        found = link_chain.first_unsafe_link(
            str(granted / "missing" / ".." / "lnk" / "repo")
        )

        assert found is not None
        assert found.component == str(granted / "lnk")
        assert found.is_last is False

    def test_a_link_stepped_back_over_is_not_opened(self, tmp_path):
        granted = tmp_path / "granted"
        (granted / "other").mkdir(parents=True)
        (granted / "lnk").symlink_to("\\\\server\\share")

        assert (
            link_chain.first_unsafe_link(str(granted / "lnk" / ".." / "other")) is None
        )

    def test_a_missing_component_ends_the_walk_unjudged(self, tmp_path):
        assert link_chain.first_unsafe_link(str(tmp_path / "missing" / "repo")) is None

    def test_a_link_whose_target_cannot_be_read_is_the_answer_with_none(
        self, tmp_path, monkeypatch
    ):
        """A reparse point ``os.readlink`` refuses (no symbolic link, no junction)
        is read as a link whose target cannot be told."""
        link = tmp_path / "link"
        link.symlink_to(tmp_path / "real")

        def not_a_symlink(path, *args, **kwargs):
            raise ValueError("not a symbolic link")

        monkeypatch.setattr(os, "readlink", not_a_symlink)

        found = link_chain.first_unsafe_link(str(link))

        assert found is not None
        assert found.reaches_a_share is None

    def test_the_hop_bound_is_the_callers(self, tmp_path):
        third = tmp_path / "third"
        third.mkdir()
        second = tmp_path / "second"
        second.symlink_to(third)
        first = tmp_path / "first"
        first.symlink_to(second)

        assert link_chain.link_chain_names_a_windows_share(str(first)) is False
        assert link_chain.link_chain_names_a_windows_share(str(first), hops=1) is None
        found = link_chain.first_unsafe_link(str(first), hops=1)
        assert found is not None
        assert found.reaches_a_share is None

    def test_a_chain_ending_at_a_share_is_judged_through_local_hops(self, tmp_path):
        second = tmp_path / "second"
        second.symlink_to("\\\\server\\share")
        first = tmp_path / "first"
        first.symlink_to(second)

        assert link_chain.link_chain_names_a_windows_share(str(first)) is True

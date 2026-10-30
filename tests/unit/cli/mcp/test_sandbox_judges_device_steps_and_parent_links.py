#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Two ways a Windows path reached a share past the pre-resolve check.

The check that keeps the server from opening a network share before any gate
has judged the path read two spellings as local. A device-prefixed path with a
drive letter in front was local whatever followed, so ``\\\\.\\C:\\..\\UNC\\server\\share``,
which Win32 normalizes to the share, and ``\\\\.\\C:\\..\\pipe\\ash`` passed and were
resolved. And the link check read only the path's last component: ``os.lstat`` on
the whole path follows a link in a parent component, so ``granted\\lnk\\repo`` with
``lnk`` a link to a share opened the share at the check meant to prevent it.
A ``..`` component behind a device prefix is now refused, and every component of
the path is read for links, from the anchor down.

Windows is emulated as the neighbouring module does: ``_running_on_windows`` is
patched True, and links are made with ``symlink_to``, whose target text is read
back by ``os.readlink`` without being resolved.
"""

from __future__ import annotations

import pytest

from automated_security_helper.cli.mcp import sandbox

pytestmark = pytest.mark.unit


class TestAStepBehindADevicePrefixIsNotLocal:
    @pytest.mark.parametrize(
        "text",
        [
            "\\\\.\\C:\\..\\UNC\\server\\share\\tree",
            "\\\\.\\C:\\..\\pipe\\ash",
            "\\\\?\\C:\\..\\UNC\\server\\share",
            "\\??\\C:\\repo\\..\\..\\UNC\\server\\share",
            "//./C:/../UNC/server/share",
        ],
    )
    def test_a_dot_dot_component_behind_the_prefix_is_judged_as_a_share(self, text):
        """Red at the base: a drive letter after the prefix read as local whatever followed."""
        assert sandbox._names_a_windows_share(text) is True

    @pytest.mark.parametrize(
        "text",
        [
            "\\\\.\\C:\\repo",
            "\\\\?\\C:\\repo\\..x\\y",
            "\\\\.\\C:\\repo..\\x",
            "C:\\repo\\..\\other",
        ],
    )
    def test_a_local_spelling_without_the_step_stays_local(self, text):
        """Controls: a name that merely contains dots, and a ``..`` with no device
        prefix in front (the ordinary gates resolve that one), stay local."""
        assert sandbox._names_a_windows_share(text) is False


class TestALinkInAParentComponentIsJudged:
    @pytest.fixture(autouse=True)
    def _on_windows(self, monkeypatch):
        monkeypatch.setattr(sandbox, "_running_on_windows", lambda: True)

    def test_a_parent_that_links_to_a_share_refuses_the_path(self, tmp_path):
        """Red at the base: lstat on the whole path followed the parent link and,
        finding nothing at its target here, judged nothing."""
        granted = tmp_path / "granted"
        granted.mkdir()
        (granted / "lnk").symlink_to("\\\\server\\share")

        refusal = sandbox._refusal_before_resolving(
            "Scan target", granted / "lnk" / "repo"
        )

        assert refusal is not None
        assert "component" in str(refusal)
        assert "leads to a network share" in str(refusal)

    def test_a_parent_that_links_to_a_local_directory_is_followed(self, tmp_path):
        """Control: a local link in a parent is followed, and the components under
        it are judged; a share link below it is still found."""
        real = tmp_path / "real"
        (real / "repo").mkdir(parents=True)
        (tmp_path / "lnk").symlink_to(real)

        assert (
            sandbox._refusal_before_resolving("Scan target", tmp_path / "lnk" / "repo")
            is None
        )

        (real / "deep").symlink_to("\\\\server\\share")
        refusal = sandbox._refusal_before_resolving(
            "Scan target", tmp_path / "lnk" / "deep" / "tree"
        )
        assert refusal is not None
        assert "leads to a network share" in str(refusal)

    def test_the_last_component_keeps_its_own_wording(self, tmp_path):
        """Control: a share link as the path itself is refused as before, as a link."""
        link = tmp_path / "link"
        link.symlink_to("\\\\server\\share\\tree")

        refusal = sandbox._refusal_before_resolving("Scan target", link)

        assert refusal is not None
        assert "It is a link that leads to a network share" in str(refusal)

    def test_a_path_with_nothing_at_a_parent_is_left_to_the_gates(self, tmp_path):
        """Control: a parent that is not there ends the walk with no refusal."""
        assert (
            sandbox._refusal_before_resolving(
                "Scan target", tmp_path / "missing" / "repo"
            )
            is None
        )


def test_the_components_run_from_the_anchor_down():
    components = sandbox._components_down_to("/a/b/c")
    assert components == ["/a", "/a/b", "/a/b/c"]
    assert sandbox._components_down_to("rel/x") == ["rel", "rel/x"]

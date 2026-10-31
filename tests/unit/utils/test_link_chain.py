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
from pathlib import Path
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
    """Spelled through ``Path``: the components carry the OS's own separator, so
    on Windows ``/a/b/c`` walks as ``\\a``, ``\\a\\b``, ``\\a\\b\\c``. The anchor
    alone is given back as the caller spelled it."""
    assert link_chain.components_down_to("/a/b/c") == [
        str(Path(p)) for p in ("/a", "/a/b", "/a/b/c")
    ]
    assert link_chain.components_down_to("rel/x") == [
        str(Path("rel")),
        str(Path("rel/x")),
    ]
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


class TestAHopsTargetIsJudgedThroughItsParents:
    """A hop's target is examined with ``os.lstat``, which follows a link in a
    PARENT component of the target. A config linked as ``.ash/ash.yaml ->
    ../vendor/cfg.yaml`` with ``vendor`` a junction to a share had that lstat
    open the share, and when nothing answered there the chain read "not there"
    and judged the link LOCAL. The target's parent components are judged first."""

    def test_a_share_junction_in_the_targets_parent_is_the_answer(
        self, tmp_path, monkeypatch
    ):
        """Red at the first module: ``vendor`` is a dangling link here, so the
        lstat of ``vendor/cfg.yaml`` raised FileNotFoundError and the chain
        answered False (local); the walk then admitted the path."""
        dot_ash = tmp_path / ".ash"
        dot_ash.mkdir()
        (tmp_path / "vendor").symlink_to("\\\\server\\share\\vendor")
        (dot_ash / "ash.yaml").symlink_to(os.path.join("..", "vendor", "cfg.yaml"))
        examined = []
        real_lstat = os.lstat

        def recording_lstat(path, *args, **kwargs):
            examined.append(str(path))
            return real_lstat(path, *args, **kwargs)

        monkeypatch.setattr(os, "lstat", recording_lstat)

        assert (
            link_chain.link_chain_names_a_windows_share(str(dot_ash / "ash.yaml"))
            is True
        )
        found = link_chain.first_unsafe_link(str(dot_ash / "ash.yaml"))

        assert found is not None
        assert found.component == str(dot_ash / "ash.yaml")
        assert found.reaches_a_share is True
        # Nothing under the junction was ever asked about.
        assert str(tmp_path / "vendor" / "cfg.yaml") not in examined

    def test_a_local_link_in_the_targets_parent_is_followed(self, tmp_path):
        """Control: a parent that is a local link leaves the hop local."""
        real = tmp_path / "real"
        real.mkdir()
        (real / "cfg.yaml").write_text("x")
        (tmp_path / "vendor").symlink_to(real)
        dot_ash = tmp_path / ".ash"
        dot_ash.mkdir()
        (dot_ash / "ash.yaml").symlink_to(os.path.join("..", "vendor", "cfg.yaml"))

        assert (
            link_chain.link_chain_names_a_windows_share(str(dot_ash / "ash.yaml"))
            is False
        )
        assert link_chain.first_unsafe_link(str(dot_ash / "ash.yaml")) is None

    def test_an_unreadable_link_in_the_targets_parent_is_unjudged(
        self, tmp_path, monkeypatch
    ):
        real = tmp_path / "real"
        real.mkdir()
        (tmp_path / "vendor").symlink_to(real)
        dot_ash = tmp_path / ".ash"
        dot_ash.mkdir()
        (dot_ash / "ash.yaml").symlink_to(os.path.join("..", "vendor", "cfg.yaml"))
        real_readlink = os.readlink

        def vendor_unreadable(path, *args, **kwargs):
            if os.path.basename(os.fspath(path)) == "vendor":
                raise ValueError("not a symbolic link")
            return real_readlink(path, *args, **kwargs)

        monkeypatch.setattr(os, "readlink", vendor_unreadable)

        assert (
            link_chain.link_chain_names_a_windows_share(str(dot_ash / "ash.yaml"))
            is None
        )

    def test_the_hop_budget_is_shared_with_the_parent_walks(
        self, tmp_path, monkeypatch
    ):
        """One budget for the whole judgment: a self-looping link spends it to
        the last read and no further, and the parent walks of each hop draw on
        the same budget rather than their own."""
        loop = tmp_path / "loop"
        loop.symlink_to(loop)
        reads = []
        real_readlink = os.readlink

        def counting_readlink(path, *args, **kwargs):
            reads.append(str(path))
            return real_readlink(path, *args, **kwargs)

        monkeypatch.setattr(os, "readlink", counting_readlink)

        assert link_chain.link_chain_names_a_windows_share(str(loop), hops=5) is None
        assert len(reads) == 5

        reads.clear()
        found = link_chain.first_unsafe_link(str(loop), hops=3)
        assert found is not None
        assert found.reaches_a_share is None
        assert len(reads) == 3


class TestAComponentThatCannotBeExaminedIsRefused:
    """A component ``os.lstat`` refuses is not a local name. The first module
    answered None for it (no unsafe link found), and the callers went on to
    resolve the path, where the loader's own walk had refused an entry it could
    not judge. The doubt is now the answer: the component is reported as
    unexaminable, and both callers refuse it."""

    def test_a_component_that_cannot_be_examined_is_the_answer(
        self, tmp_path, monkeypatch
    ):
        """Red at the first module: the walk answered None and ``repo`` under the
        unexaminable component was left for the resolver."""
        granted = tmp_path / "granted"
        (granted / "mid" / "repo").mkdir(parents=True)
        examined = []
        real_lstat = os.lstat

        def refusing_lstat(path, *args, **kwargs):
            examined.append(str(path))
            if os.path.basename(os.fspath(path)) == "mid":
                raise PermissionError(13, "Permission denied", str(path))
            return real_lstat(path, *args, **kwargs)

        monkeypatch.setattr(os, "lstat", refusing_lstat)

        found = link_chain.first_unsafe_link(str(granted / "mid" / "repo"))

        assert found is not None
        assert found.component == str(granted / "mid")
        assert found.is_last is False
        assert found.reaches_a_share is None
        assert found.unexaminable is True
        # Nothing under the unexaminable component was asked about.
        assert str(granted / "mid" / "repo") not in examined

    def test_the_path_itself_unexaminable_is_last(self, tmp_path, monkeypatch):
        target = tmp_path / "target"
        target.mkdir()
        real_lstat = os.lstat

        def refusing_lstat(path, *args, **kwargs):
            if os.path.basename(os.fspath(path)) == "target":
                raise PermissionError(13, "Permission denied", str(path))
            return real_lstat(path, *args, **kwargs)

        monkeypatch.setattr(os, "lstat", refusing_lstat)

        found = link_chain.first_unsafe_link(str(target))

        assert found is not None
        assert found.is_last is True
        assert found.unexaminable is True

    def test_an_embedded_nul_in_a_component_is_the_answer(self, tmp_path):
        """Red at the first module: ``os.lstat`` raises ValueError for a NUL,
        which the walk's ``except OSError`` let escape to the caller."""
        bad = tmp_path / "bad\x00name"

        found = link_chain.first_unsafe_link(str(bad / "repo"))

        assert found is not None
        assert found.component == str(bad)
        assert found.reaches_a_share is None
        assert found.unexaminable is True

    def test_a_component_that_is_not_there_still_ends_the_walk_unjudged(self, tmp_path):
        """Controls: nothing is there to follow, so resolving opens nothing and
        the caller's gates judge the path; a file in a directory's place is the
        same."""
        plain = tmp_path / "file.txt"
        plain.write_text("x")

        assert link_chain.first_unsafe_link(str(tmp_path / "missing" / "repo")) is None
        assert link_chain.first_unsafe_link(str(plain / "repo")) is None

    def test_a_hops_target_whose_spelling_the_filesystem_refuses_is_unjudged(
        self, tmp_path, monkeypatch
    ):
        """Red at the module as cut for the component walk: a hop target carrying
        a NUL made ``os.lstat`` raise ValueError past the chain's ``except
        OSError``, out through both callers. The chain is unjudged instead, and
        the walk reports the link with its chain unread."""
        link = tmp_path / "link"
        link.symlink_to(tmp_path / "real")
        real_readlink = os.readlink

        def nul_target(path, *args, **kwargs):
            if os.path.basename(os.fspath(path)) == "link":
                return "real\x00name"
            return real_readlink(path, *args, **kwargs)

        monkeypatch.setattr(os, "readlink", nul_target)

        assert link_chain.link_chain_names_a_windows_share(str(link)) is None
        found = link_chain.first_unsafe_link(str(link))
        assert found is not None
        assert found.reaches_a_share is None
        assert found.unexaminable is False

    def test_an_unexaminable_parent_of_a_hops_target_leaves_the_chain_unjudged(
        self, tmp_path, monkeypatch
    ):
        """Red at the first module: the parent walk answered None for ``vendor``,
        the hop's target was then lstat'd, found missing, and the chain read
        LOCAL."""
        (tmp_path / "vendor").mkdir()
        dot_ash = tmp_path / ".ash"
        dot_ash.mkdir()
        (dot_ash / "ash.yaml").symlink_to(os.path.join("..", "vendor", "cfg.yaml"))
        real_lstat = os.lstat

        def refusing_lstat(path, *args, **kwargs):
            if os.path.basename(os.fspath(path)) == "vendor":
                raise PermissionError(13, "Permission denied", str(path))
            return real_lstat(path, *args, **kwargs)

        monkeypatch.setattr(os, "lstat", refusing_lstat)

        assert (
            link_chain.link_chain_names_a_windows_share(str(dot_ash / "ash.yaml"))
            is None
        )
        found = link_chain.first_unsafe_link(str(dot_ash / "ash.yaml"))
        assert found is not None
        assert found.component == str(dot_ash / "ash.yaml")
        assert found.reaches_a_share is None
        # The link itself was examined; its chain is what cannot be told.
        assert found.unexaminable is False


class TestARelativeHopIsTakenFromTheDirectoryItWasReachedIn:
    """A relative link target is taken from the directory the link is in.

    ``repo/a`` is a link to ``b/c``, so ``repo/a/l3`` is the entry ``repo/b/c/l3``,
    and its target ``../x`` is ``repo/b/x``. The walk joined the target to the
    path as the caller spelled it, ``repo/a``, which read ``repo/x`` (not there:
    local), then asked ``os.lstat`` about ``repo/a/l3/sub``, and the OS followed
    ``l3`` to ``repo/b/x``, a link to a share, inside the check.
    """

    @staticmethod
    def _tree(tmp_path: Path, *, share: bool) -> Path:
        repo = tmp_path / "repo"
        (repo / "b" / "c").mkdir(parents=True)
        (repo / "a").symlink_to(os.path.join("b", "c"))
        (repo / "b" / "c" / "l3").symlink_to(os.path.join("..", "x"))
        if share:
            (repo / "b" / "x").symlink_to("\\\\server\\share")
        else:
            (repo / "b" / "x").mkdir()
        return repo

    def test_a_share_behind_a_relative_hop_under_a_link_is_found(self, tmp_path):
        repo = self._tree(tmp_path, share=True)

        found = link_chain.first_unsafe_link(str(repo / "a" / "l3" / "sub"))

        assert found is not None
        assert found.component == str(repo / "a" / "l3")
        assert found.is_last is False
        assert found.reaches_a_share is True

    def test_the_same_tree_with_a_local_target_is_not_refused(self, tmp_path):
        """Control: ``x`` is a plain directory, so nothing is unsafe, and the
        hop read from where the link is leads to it."""
        repo = self._tree(tmp_path, share=False)

        assert link_chain.first_unsafe_link(str(repo / "a" / "l3" / "sub")) is None
        assert (
            link_chain.link_chain_names_a_windows_share(str(repo / "b" / "c" / "l3"))
            is False
        )

    def test_the_link_in_a_target_is_judged_from_its_own_directory(self, tmp_path):
        """The chain reading starts from the link's own location: ``l3`` in
        ``repo/b/c`` leads to ``repo/b/x``, a share."""
        repo = self._tree(tmp_path, share=True)

        assert (
            link_chain.link_chain_names_a_windows_share(str(repo / "b" / "c" / "l3"))
            is True
        )

    def test_lstat_is_never_asked_through_a_link(self, tmp_path, monkeypatch):
        """No entry the walk examines sits below a link: every parent of every
        path handed to ``os.lstat`` is a real directory."""
        repo = self._tree(tmp_path, share=True)
        examined = []
        real_lstat = os.lstat

        def recording_lstat(path, *args, **kwargs):
            examined.append(os.fspath(path))
            return real_lstat(path, *args, **kwargs)

        monkeypatch.setattr(os, "lstat", recording_lstat)

        found = link_chain.first_unsafe_link(str(repo / "a" / "l3" / "sub"))

        assert found is not None
        assert examined, "the walk examined nothing"
        through_a_link = [
            path
            for path in examined
            if any(
                stat.S_ISLNK(real_lstat(str(parent)).st_mode)
                for parent in Path(path).parents
            )
        ]
        assert through_a_link == []


class TestAStepBackInsideATargetIsTakenByText:
    """A ``..`` inside a link's target is collapsed by text, as the caller's own
    spelling is, and not walked up from wherever a link in front of it led.

    ``cfg`` is a link to ``sub/lnk/../z``. By text that is ``sub/z``, and ``lnk``
    is never examined. The walk followed ``lnk`` to a directory elsewhere and
    went up from there, looked for ``z`` beside it, found nothing, and passed a
    path whose collapsed spelling is a link to a share. The module reads
    spellings the way Win32 does, so a Linux run discriminates through the text
    of the targets only: the links here are made with ``symlink_to`` and read
    back by ``os.readlink`` unresolved.
    """

    @staticmethod
    def _tree(tmp_path: Path, *, share: bool) -> Path:
        root = tmp_path / "d"
        (root / "sub").mkdir(parents=True)
        elsewhere = tmp_path / "elsewhere" / "deep"
        elsewhere.mkdir(parents=True)
        (root / "sub" / "lnk").symlink_to(elsewhere)
        if share:
            (root / "sub" / "z").symlink_to("\\\\server\\share")
        else:
            (root / "sub" / "z").mkdir()
        (root / "cfg").symlink_to(os.path.join("sub", "lnk", "..", "z"))
        return root

    def test_a_share_behind_a_step_back_over_a_link_is_found(self, tmp_path):
        """Red at the base: the walk went up from the link's destination, so it
        looked for ``z`` in ``elsewhere``, found nothing, and answered None."""
        root = self._tree(tmp_path, share=True)

        found = link_chain.first_unsafe_link(str(root / "cfg"))

        assert found is not None
        assert found.component == str(root / "cfg")
        assert found.is_last is True
        assert found.reaches_a_share is True

    def test_the_chain_reading_collapses_the_target_the_same_way(self, tmp_path):
        """Red at the base: the chain answered False (local) for the same tree."""
        root = self._tree(tmp_path, share=True)

        assert link_chain.link_chain_names_a_windows_share(str(root / "cfg")) is True

    def test_a_link_stepped_back_over_in_a_target_is_not_opened(self, tmp_path):
        """``lnk`` is a link to a share here, and a target that steps back over it
        never opens it, so a local ``z`` leaves the path local. Red at the base
        the other way: the walk went into ``lnk`` and refused a local path."""
        root = self._tree(tmp_path, share=False)
        (root / "sub" / "lnk").unlink()
        (root / "sub" / "lnk").symlink_to("\\\\server\\share")

        assert link_chain.first_unsafe_link(str(root / "cfg")) is None
        assert link_chain.link_chain_names_a_windows_share(str(root / "cfg")) is False

    def test_a_missing_name_stepped_back_over_in_a_target_hides_nothing(self, tmp_path):
        """Red at the base: ``missing/../x`` ended the walk at ``missing`` with
        nothing judged, and ``x``, a link to a share, was never read."""
        root = tmp_path / "d"
        root.mkdir()
        (root / "x").symlink_to("\\\\server\\share")
        (root / "cfg").symlink_to(os.path.join("missing", "..", "x"))

        found = link_chain.first_unsafe_link(str(root / "cfg"))

        assert found is not None
        assert found.reaches_a_share is True

    def test_a_step_up_at_the_front_of_a_target_still_goes_up_from_the_link(
        self, tmp_path
    ):
        """Control: a leading ``..`` is taken from the directory the link is in."""
        (tmp_path / "vendor").mkdir()
        (tmp_path / "vendor" / "cfg.yaml").symlink_to("\\\\server\\share")
        dot_ash = tmp_path / ".ash"
        dot_ash.mkdir()
        (dot_ash / "ash.yaml").symlink_to(os.path.join("..", "vendor", "cfg.yaml"))

        found = link_chain.first_unsafe_link(str(dot_ash / "ash.yaml"))

        assert found is not None
        assert found.reaches_a_share is True

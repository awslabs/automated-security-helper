# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for ``utils/scanned_tree.py``, the check every scanned-tree reader goes through.

Each case builds a small tree next to a "host" directory holding a file with a marker
string, so a test can tell from the bytes it got back whether the read stayed inside
the tree. Every behavioral case runs twice: once through the descriptor walk Linux and
macOS use, and once through the check-then-verify path Windows uses, forced here by
switching the descriptor walk off.
"""

from __future__ import annotations

import os
import stat
import sys
import threading
from pathlib import Path

import pytest

from automated_security_helper.utils import scanned_tree
from automated_security_helper.utils.scanned_tree import (
    REASON_CHANGED,
    REASON_HARDLINK,
    REASON_NOT_REGULAR,
    REASON_OUTSIDE,
    REASON_PARENT_TRAVERSAL,
    REASON_SYMLINK,
    TreeInputRefused,
    open_in_scanned_tree,
    refusal_reason,
    relative_display,
)

MARKER = b"HOST-ONLY-CONTENT-7c1e"
IN_TREE = b"in-tree content\n"

needs_symlinks = pytest.mark.skipif(
    sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
)


@pytest.fixture(params=["descriptor-walk", "checked-path"])
def walk(request, monkeypatch):
    """Run the test under each of the two implementations."""
    if request.param == "descriptor-walk":
        if not scanned_tree._DESCRIPTOR_WALK:
            pytest.skip("this platform has no O_NOFOLLOW/dir_fd descriptor walk")
    else:
        monkeypatch.setattr(scanned_tree, "_DESCRIPTOR_WALK", False)
    return request.param


@pytest.fixture
def layout(tmp_path):
    """A tree and, beside it, a host directory the tree must not reach."""
    host = tmp_path / "host"
    tree = tmp_path / "tree"
    (host / "dir").mkdir(parents=True)
    (tree / "real" / "deep").mkdir(parents=True)
    (host / "secret.txt").write_bytes(MARKER)
    (host / "dir" / "secret.txt").write_bytes(MARKER)
    (tree / "real" / "deep" / "ok.txt").write_bytes(IN_TREE)
    (tree / "top.txt").write_bytes(IN_TREE)
    return tree, host


def read(path, root) -> bytes:
    with open_in_scanned_tree(path, root) as handle:
        return handle.read()


def refused(path, root) -> TreeInputRefused:
    with pytest.raises(TreeInputRefused) as excinfo:
        read(path, root)
    return excinfo.value


class TestAccepted:
    def test_a_regular_file_in_the_tree_is_read(self, walk, layout):
        tree, _ = layout
        assert read(tree / "top.txt", tree) == IN_TREE
        assert read(tree / "real" / "deep" / "ok.txt", tree) == IN_TREE

    def test_relative_paths_against_a_relative_root(self, walk, layout, monkeypatch):
        tree, _ = layout
        monkeypatch.chdir(tree.parent)
        assert read(Path("tree") / "real" / "deep" / "ok.txt", "tree") == IN_TREE

    @needs_symlinks
    def test_a_root_reached_through_a_symlink_is_trusted(self, walk, layout, tmp_path):
        """The root is the operator's choice; only links below it are refused."""
        tree, _ = layout
        alias = tmp_path / "alias"
        alias.symlink_to(tree, target_is_directory=True)
        assert read(alias / "top.txt", alias) == IN_TREE
        # And a path spelled through the root's real location is still inside it.
        assert read(tree / "top.txt", alias) == IN_TREE

    def test_a_root_spelled_with_dotdot_is_the_operators_and_is_honored(
        self, walk, layout
    ):
        """``ashx scan --source-dir ../proj`` yields scan-set paths that contain '..'.

        The scan root is made absolute without folding '..', and scan_set joins onto
        it, so every path it returns carries the root's '..'. Only a '..' below the
        root is refused.
        """
        tree, _ = layout
        root = tree / "real" / ".." / ".." / tree.name
        assert read(root / "top.txt", root) == IN_TREE
        assert read(root / "real" / "deep" / "ok.txt", root) == IN_TREE
        assert relative_display(root / "real" / "deep" / "ok.txt", root) == (
            "real/deep/ok.txt"
        )
        assert refused(root / "real" / ".." / "top.txt", root).reason == (
            REASON_PARENT_TRAVERSAL
        )

    def test_the_handle_is_positioned_at_the_start(self, walk, layout):
        tree, _ = layout
        with open_in_scanned_tree(tree / "top.txt", tree) as handle:
            assert handle.tell() == 0
            assert handle.read(2) == IN_TREE[:2]


@needs_symlinks
class TestSymlinks:
    def test_a_symlink_to_a_host_file_is_refused(self, walk, layout):
        tree, host = layout
        (tree / "link.txt").symlink_to(host / "secret.txt")

        refusal = refused(tree / "link.txt", tree)

        assert refusal.reason == REASON_SYMLINK
        assert refusal.path == "link.txt"

    def test_a_symlink_to_a_file_inside_the_tree_is_refused_too(self, walk, layout):
        tree, _ = layout
        (tree / "alias.txt").symlink_to(tree / "top.txt")
        assert refused(tree / "alias.txt", tree).reason == REASON_SYMLINK

    def test_a_dangling_symlink_is_refused(self, walk, layout):
        tree, _ = layout
        (tree / "dangling.txt").symlink_to(tree / "does-not-exist")
        assert refused(tree / "dangling.txt", tree).reason == REASON_SYMLINK

    def test_a_symlinked_parent_directory_is_refused_and_named(self, walk, layout):
        tree, host = layout
        (tree / "linked").symlink_to(host / "dir", target_is_directory=True)

        refusal = refused(tree / "linked" / "secret.txt", tree)

        assert refusal.reason == "its parent directory 'linked' is a symbolic link"
        assert refusal.path == "linked/secret.txt"

    def test_a_symlinked_directory_deeper_down_is_refused(self, walk, layout):
        tree, host = layout
        (tree / "real" / "linked").symlink_to(host / "dir", target_is_directory=True)

        refusal = refused(tree / "real" / "linked" / "secret.txt", tree)

        assert refusal.reason == (
            "its parent directory 'real/linked' is a symbolic link"
        )

    def test_following_links_inside_accepts_only_targets_in_the_tree(
        self, walk, layout
    ):
        tree, host = layout
        (tree / "alias.txt").symlink_to(tree / "top.txt")
        (tree / "aliasdir").symlink_to(tree / "real", target_is_directory=True)
        (tree / "link.txt").symlink_to(host / "secret.txt")
        (tree / "linked").symlink_to(host / "dir", target_is_directory=True)

        def follow(path):
            with open_in_scanned_tree(path, tree, follow_links_inside=True) as h:
                return h.read()

        assert follow(tree / "alias.txt") == IN_TREE
        assert follow(tree / "aliasdir" / "deep" / "ok.txt") == IN_TREE
        for outside in (tree / "link.txt", tree / "linked" / "secret.txt"):
            with pytest.raises(TreeInputRefused) as excinfo:
                follow(outside)
            assert excinfo.value.reason == (
                "it is a symbolic link that resolves outside the scanned tree"
            )

    @pytest.mark.skipif(not hasattr(os, "link"), reason="no hard links")
    def test_following_links_inside_accepts_a_hard_link(self, walk, layout):
        """The lookups that follow in-tree links read a hard-linked file too."""
        tree, _ = layout
        os.link(tree / "top.txt", tree / "hard.txt")
        with open_in_scanned_tree(
            tree / "hard.txt", tree, follow_links_inside=True
        ) as handle:
            assert handle.read() == IN_TREE
        assert refused(tree / "hard.txt", tree).reason == REASON_HARDLINK

    def test_refusal_reason_agrees_with_the_open(self, walk, layout):
        tree, host = layout
        (tree / "link.txt").symlink_to(host / "secret.txt")
        assert refusal_reason(tree / "link.txt", tree) == REASON_SYMLINK
        assert refusal_reason(tree / "top.txt", tree) is None


class TestPathShape:
    def test_a_parent_traversal_is_refused_on_the_text(self, walk, layout):
        tree, _ = layout
        refusal = refused(tree / ".." / "host" / "secret.txt", tree)
        assert refusal.reason == REASON_PARENT_TRAVERSAL

    def test_traversal_that_lands_back_inside_is_still_refused(self, walk, layout):
        tree, _ = layout
        refusal = refused(tree / "real" / ".." / "top.txt", tree)
        assert refusal.reason == REASON_PARENT_TRAVERSAL

    def test_an_absolute_path_outside_the_root_is_refused(self, walk, layout):
        tree, host = layout
        assert refused(host / "secret.txt", tree).reason == REASON_OUTSIDE

    def test_a_sibling_with_a_common_prefix_is_outside(self, walk, layout, tmp_path):
        tree, _ = layout
        sibling = tmp_path / "tree-other"
        sibling.mkdir()
        (sibling / "x.txt").write_bytes(MARKER)
        assert refused(sibling / "x.txt", tree).reason == REASON_OUTSIDE

    def test_the_root_itself_is_not_a_file(self, walk, layout):
        tree, _ = layout
        assert refused(tree, tree).reason == REASON_NOT_REGULAR


class TestFileType:
    def test_a_directory_is_refused(self, walk, layout):
        tree, _ = layout
        assert refused(tree / "real", tree).reason == REASON_NOT_REGULAR

    @pytest.mark.skipif(not hasattr(os, "link"), reason="no hard links")
    def test_a_hard_link_is_refused(self, walk, layout):
        tree, host = layout
        try:
            os.link(host / "secret.txt", tree / "hard.txt")
        except OSError as exc:  # pragma: no cover - filesystem without hard links
            pytest.skip(f"cannot create a hard link here: {exc}")
        assert refused(tree / "hard.txt", tree).reason == REASON_HARDLINK

    @pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="no FIFOs")
    def test_a_fifo_is_refused_without_blocking(self, walk, layout):
        tree, _ = layout
        os.mkfifo(tree / "pipe.yaml")
        outcome = {}

        def attempt():
            try:
                read(tree / "pipe.yaml", tree)
            except TreeInputRefused as exc:
                outcome["reason"] = exc.reason

        thread = threading.Thread(target=attempt, daemon=True)
        thread.start()
        thread.join(timeout=10)
        assert not thread.is_alive(), "opening a FIFO blocked"
        assert outcome == {"reason": REASON_NOT_REGULAR}

    def test_a_missing_file_is_an_oserror_not_a_refusal(self, walk, layout):
        tree, _ = layout
        with pytest.raises(FileNotFoundError):
            read(tree / "missing.txt", tree)
        assert refusal_reason(tree / "missing.txt", tree) is None


@needs_symlinks
class TestReplacedAfterTheCheck:
    """A component swapped for a link between the check and the read is not followed."""

    def test_descriptor_walk_does_not_follow_a_file_swapped_before_its_open(
        self, layout, monkeypatch
    ):
        if not scanned_tree._DESCRIPTOR_WALK:
            pytest.skip("this platform has no O_NOFOLLOW/dir_fd descriptor walk")
        tree, host = layout
        target = tree / "real" / "deep" / "ok.txt"
        real_open = os.open

        def swap_then_open(path, flags, *args, **kwargs):
            if path == "ok.txt" and kwargs.get("dir_fd") is not None:
                target.unlink()
                target.symlink_to(host / "secret.txt")
            return real_open(path, flags, *args, **kwargs)

        monkeypatch.setattr(scanned_tree.os, "open", swap_then_open)

        assert refused(target, tree).reason == REASON_SYMLINK

    def test_descriptor_walk_does_not_follow_a_directory_swapped_mid_walk(
        self, layout, monkeypatch
    ):
        if not scanned_tree._DESCRIPTOR_WALK:
            pytest.skip("this platform has no O_NOFOLLOW/dir_fd descriptor walk")
        tree, host = layout
        real_open = os.open

        def swap_then_open(path, flags, *args, **kwargs):
            if path == "deep" and kwargs.get("dir_fd") is not None:
                (tree / "real" / "deep" / "ok.txt").unlink()
                (tree / "real" / "deep").rmdir()
                (tree / "real" / "deep").symlink_to(
                    host / "dir", target_is_directory=True
                )
            return real_open(path, flags, *args, **kwargs)

        monkeypatch.setattr(scanned_tree.os, "open", swap_then_open)

        refusal = refused(tree / "real" / "deep" / "secret.txt", tree)
        assert refusal.reason == "its parent directory 'real/deep' is a symbolic link"

    def test_checked_path_notices_a_file_swapped_after_lstat(self, layout, monkeypatch):
        tree, host = layout
        monkeypatch.setattr(scanned_tree, "_DESCRIPTOR_WALK", False)
        target = tree / "top.txt"
        real_open = os.open

        def swap_then_open(path, flags, *args, **kwargs):
            if Path(path) == target:
                target.unlink()
                target.symlink_to(host / "secret.txt")
            return real_open(path, flags, *args, **kwargs)

        monkeypatch.setattr(scanned_tree.os, "open", swap_then_open)

        assert refused(target, tree).reason == REASON_CHANGED


class TestHelpers:
    def test_relative_display_is_posix_and_relative(self, layout):
        tree, host = layout
        assert relative_display(tree / "real" / "deep" / "ok.txt", tree) == (
            "real/deep/ok.txt"
        )
        assert relative_display(host / "secret.txt", tree) == (
            (host / "secret.txt").as_posix()
        )

    @pytest.mark.parametrize(
        "attributes, tag, is_link",
        [
            # A junction (IO_REPARSE_TAG_MOUNT_POINT) and a symlink: both name
            # another path, and both carry the name-surrogate bit.
            (stat.FILE_ATTRIBUTE_REPARSE_POINT, 0xA0000003, True),
            (stat.FILE_ATTRIBUTE_REPARSE_POINT, 0xA000000C, True),
            # A OneDrive placeholder (IO_REPARSE_TAG_CLOUD_6) and a deduplicated
            # file (IO_REPARSE_TAG_DEDUP): reparse points that are the file itself.
            (stat.FILE_ATTRIBUTE_REPARSE_POINT, 0x9000601A, False),
            (stat.FILE_ATTRIBUTE_REPARSE_POINT, 0x80000013, False),
            (0, 0, False),
        ],
    )
    def test_only_a_reparse_point_that_names_another_path_is_a_link(
        self, attributes, tag, is_link
    ):
        class FakeStat:
            st_mode = stat.S_IFDIR | 0o755
            st_file_attributes = attributes
            st_reparse_tag = tag

        assert scanned_tree._is_link_stat(FakeStat()) is is_link  # type: ignore[arg-type]

    def test_a_refusal_never_carries_file_content(self, walk, layout):
        tree, host = layout
        if sys.platform != "win32":
            (tree / "link.txt").symlink_to(host / "secret.txt")
            assert MARKER.decode() not in str(refused(tree / "link.txt", tree))
        assert MARKER.decode() not in str(refused(host / "secret.txt", tree))

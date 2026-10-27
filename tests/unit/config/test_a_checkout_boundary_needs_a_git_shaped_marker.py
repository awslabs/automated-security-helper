# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A checkout boundary moves only for a .git entry git itself would honor.

``sandbox_grants`` finds "the scanned tree" by walking the scan root's parents
for a ``.git`` entry, and that tree decides what the sandbox treats as the
scanned repository's: config trust, tool config paths, and which
``ash_plugin_modules`` entries an in-tree file may add. A bare empty ``.git``
directory is nothing git's own discovery would open -- git wants a gitfile or
a directory with ``HEAD`` -- but it is exactly what a stray ``mkdir`` or a
transient mount point leaves in a shared parent such as the system temp
directory. Counting one widens the boundary to a directory the scanned
repository never controlled, so only a placed marker counts: a regular file
(a linked worktree's gitfile), a link -- a symlink even dangling (the landed
dangling-symlink cell in test_repo_config_cannot_widen_sandbox pins that
side) or a Windows junction -- a directory holding ``HEAD``, or a directory
whose contents the scanning user cannot read, which fails closed with a
warning naming the entry. In a directory that group members or other users
can write, any of those shapes counts only when the ``.git`` belongs to the
scanning user, to root, or to the directory's own owner: there a stranger
can leave a ``.git`` of any shape, and counting one would move the boundary
to the shared parent for every scan under it. A foreign owner cannot be
created by an unprivileged run, so those cells inject the owner through a
stand-in ``lstat`` result.
"""

from __future__ import annotations

import contextvars
import errno
import logging
import os
import subprocess
import sys
import threading
from pathlib import Path

import pytest

import automated_security_helper.config.sandbox_grants as sandbox_grants
from automated_security_helper.config.sandbox_grants import (
    in_a_checkout,
    scanned_trees,
)
from automated_security_helper.utils.log import (
    current_run_log_scope,
    end_run_log_scope,
    open_run_log_scope,
)
from tests.utils.helpers import importing_this_checkout, mark_git_checkout

_POSIX_MODES_NEEDED = pytest.mark.skipif(
    os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0),
    reason="directory modes do not refuse or gate the lookup here (Windows, or root)",
)


def _reported_owner(monkeypatch, path, uid) -> None:
    """``lstat`` stand-in: ``path`` reports ``uid`` as its owner. An
    unprivileged run cannot create a foreign-owned file, so the foreign
    shapes inject one."""
    real = os.lstat
    target = os.fspath(path)

    def lstat(name, *args, **kwargs):
        result = real(name, *args, **kwargs)
        if os.fspath(name) == target:
            fields = list(result)
            fields[4] = uid  # st_uid
            return os.stat_result(fields)
        return result

    monkeypatch.setattr(os, "lstat", lstat)


def _reported_directory_owner(monkeypatch, path, uid) -> None:
    """``stat`` stand-in for the directory holding a ``.git``."""
    real = os.stat
    target = os.fspath(path)

    def fake_stat(name, *args, **kwargs):
        result = real(name, *args, **kwargs)
        if os.fspath(name) == target:
            fields = list(result)
            fields[4] = uid  # st_uid
            return os.stat_result(fields)
        return result

    monkeypatch.setattr(os, "stat", fake_stat)


def _a_stranger() -> int:
    """A uid that is neither the scanning user, root, nor a tmp_path owner."""
    return os.geteuid() + 1


def test_an_empty_git_directory_does_not_move_the_boundary(tmp_path):
    """The widening shape: an empty .git above the scan root must not make the
    parent "the scanned tree". With it counted, everything beside the scan
    root -- an operator config placed outside the tree, a plugin module on
    sys.path -- reads as repository-controlled and is refused or distrusted
    for a reason the operator cannot see."""
    (tmp_path / ".git").mkdir()
    root = tmp_path / "proj" / "src"
    root.mkdir(parents=True)

    assert tmp_path not in scanned_trees(root), scanned_trees(root)


def test_an_empty_git_directory_is_not_a_checkout(tmp_path):
    """The same bar for in_a_checkout, which judges where a config NAME sits."""
    (tmp_path / ".git").mkdir()
    inside = tmp_path / "proj" / "x.yaml"
    inside.parent.mkdir(parents=True)
    inside.write_text("project_name: demo\n", encoding="utf-8")

    assert in_a_checkout(inside) is False


def test_a_real_checkout_still_bounds_the_tree(tmp_path):
    """Must not fire: a .git directory with HEAD is a checkout, and the
    outermost one still wins over a nested one."""
    mark_git_checkout(tmp_path)
    root = tmp_path / "proj" / "src"
    root.mkdir(parents=True)

    assert tmp_path in scanned_trees(root), scanned_trees(root)
    inside = root / "x.yaml"
    inside.write_text("project_name: demo\n", encoding="utf-8")
    assert in_a_checkout(inside) is True


def test_a_worktree_gitfile_still_bounds_the_tree(tmp_path):
    """Must not fire: a linked worktree's .git is a regular file, and it marks
    the checkout exactly as the directory form does."""
    (tmp_path / ".git").write_text("gitdir: /elsewhere/.git/worktrees/wt\n")
    root = tmp_path / "proj" / "src"
    root.mkdir(parents=True)

    assert tmp_path in scanned_trees(root), scanned_trees(root)


def _symlink_or_skip(link, target) -> None:
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError) as error:
        pytest.skip(f"symlinks unavailable: {error}")


def test_a_symlinked_head_still_marks_the_checkout(tmp_path):
    """Must not fire: git can keep HEAD as a symbolic link to the ref file,
    so the lookup asks only that the name exist -- dangling included. A test
    on HEAD being a regular file would unmark such a checkout."""
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    _symlink_or_skip(git_dir / "HEAD", "refs/heads/main")
    root = tmp_path / "proj" / "src"
    root.mkdir(parents=True)

    assert tmp_path in scanned_trees(root), scanned_trees(root)


def _chain_of_links(tmp_path, length, in_checkout):
    """A chain of ``length`` file symlinks, head first, ending at a plain file
    outside any checkout. Link ``n`` (1-based) sits in the checkout when ``n``
    is in ``in_checkout``, else in a plain directory. Returns (head, links)."""
    plain = tmp_path / "plain"
    plain.mkdir()
    checkout = tmp_path / "co"
    checkout.mkdir()
    mark_git_checkout(checkout)
    target = plain / "target.yaml"
    target.write_text("project_name: demo\n", encoding="utf-8")
    links = [
        (checkout if n in in_checkout else plain) / f"l{n}"
        for n in range(1, length + 1)
    ]
    for here, after in zip(links, [*links[1:], target]):
        _symlink_or_skip(here, after)
    return links[0], links


def test_a_chain_cut_at_the_link_bound_is_judged_in_a_checkout(tmp_path):
    """Must fire: the links that sit in a checkout lie beyond the bound the walk
    stops at, so the walk never saw them and cannot rule them out."""
    bound = sandbox_grants._MAX_LINKS
    head, links = _chain_of_links(
        tmp_path, bound + 6, in_checkout=range(bound + 1, bound + 5)
    )

    assert sandbox_grants._walk_links(head)[1] is False
    assert in_a_checkout(head) is True


def test_a_chain_cut_at_an_unreadable_link_is_judged_in_a_checkout(
    tmp_path, monkeypatch
):
    """Must fire: a link that cannot be read ends the walk, and the links past
    it, which sit in a checkout, were never seen."""
    head, links = _chain_of_links(tmp_path, 4, in_checkout={3, 4})
    unreadable = str(links[1])
    real_readlink = os.readlink

    def readlink(path, *args, **kwargs):
        if str(path) == unreadable:
            raise PermissionError(errno.EACCES, "Permission denied", unreadable)
        return real_readlink(path, *args, **kwargs)

    monkeypatch.setattr(os, "readlink", readlink)

    assert sandbox_grants._walk_links(head)[1] is False
    assert in_a_checkout(head) is True


def test_a_checkout_link_inside_the_bound_is_still_found(tmp_path):
    """Must not fire: the same length of chain, with its checkout links inside
    the bound, is decided and judged in a checkout by what the walk saw."""
    bound = sandbox_grants._MAX_LINKS
    head, links = _chain_of_links(tmp_path, bound + 6, in_checkout=range(2, 6))

    assert in_a_checkout(head) is True


def test_a_short_chain_outside_every_checkout_is_not_in_one(tmp_path):
    """Must not fire: a walk that reached the end and saw no link in a checkout
    stays outside, so only an undecided walk is judged the other way."""
    head, links = _chain_of_links(tmp_path, 4, in_checkout=set())

    assert sandbox_grants._walk_links(head)[1] is True
    assert in_a_checkout(head) is False


def test_a_junction_git_still_marks_the_checkout(tmp_path):
    """Must not fire, Windows only: a junction named .git is placed content
    like a symlink and counts without HEAD, dangling included. Not run
    locally; first measured on the Windows CI legs."""
    if os.name != "nt":
        pytest.skip(
            "junctions exist on Windows only; first measured on the Windows CI legs"
        )
    import _winapi

    target = tmp_path / "target"
    target.mkdir()
    _winapi.CreateJunction(str(target), str(tmp_path / ".git"))
    root = tmp_path / "proj" / "src"
    root.mkdir(parents=True)

    assert tmp_path in scanned_trees(root), scanned_trees(root)
    # Dangling: removing the target leaves the junction in place, and it
    # still marks the checkout.
    target.rmdir()
    assert tmp_path in scanned_trees(root), scanned_trees(root)


@_POSIX_MODES_NEEDED
def test_an_unsearchable_git_directory_still_bounds_the_tree(tmp_path, caplog):
    """A .git directory the scanning user cannot search gives the lookup no
    answer, and failing open would hand the repository's own config, named
    from a subdirectory scan, the operator's trust. The conservative answer
    stands: an unanswerable .git bounds the tree, and a warning names the
    entry the boundary rests on."""
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    os.chmod(git_dir, 0)
    try:
        root = tmp_path / "proj" / "src"
        root.mkdir(parents=True)

        with caplog.at_level(logging.WARNING, logger="ash"):
            assert tmp_path in scanned_trees(root), scanned_trees(root)
        assert any(
            git_dir.as_posix() in record.getMessage() for record in caplog.records
        ), [record.getMessage() for record in caplog.records]
    finally:
        os.chmod(git_dir, 0o755)


#: Directory modes someone other than their owner can write into: the system
#: temp directory's own shape first, then the shapes that differ from it by
#: exactly one of its bits -- no sticky bit, group-writable instead of
#: world-writable (with and without sticky or setgid), and other-writable
#: without group-writable -- so a predicate reading only part of the mode
#: fails one of them.
_WRITABLE_BY_OTHERS = {
    "sticky-world-writable": 0o1777,
    "world-writable": 0o777,
    "sticky-group-writable": 0o1775,
    "setgid-group-writable": 0o2775,
    "other-writable-only": 0o703,
}


@_POSIX_MODES_NEEDED
@pytest.mark.parametrize("name", sorted(_WRITABLE_BY_OTHERS))
def test_a_strangers_unsearchable_git_in_a_writable_directory_does_not_widen(
    name, tmp_path, monkeypatch
):
    """Anyone can leave an unsearchable .git in a directory others can
    write, so there the unanswerable lookup counts only for an owner the
    scan already trusts. Counting a stranger's would move the checkout
    boundary to the shared parent for every scan under it, so the boundary
    stays at the scan root."""
    shared = tmp_path / "shared"
    shared.mkdir()
    git_dir = shared / ".git"
    git_dir.mkdir()
    os.chmod(git_dir, 0)
    root = shared / "proj" / "src"
    root.mkdir(parents=True)
    os.chmod(shared, _WRITABLE_BY_OTHERS[name])
    _reported_owner(monkeypatch, git_dir, _a_stranger())
    try:
        assert scanned_trees(root) == [root], scanned_trees(root)
    finally:
        monkeypatch.undo()
        os.chmod(shared, 0o755)
        os.chmod(git_dir, 0o755)


@_POSIX_MODES_NEEDED
@pytest.mark.parametrize("kind", ["directory-with-head", "gitfile", "symlink"])
def test_a_strangers_readable_git_in_a_shared_drop_does_not_widen(
    kind, tmp_path, monkeypatch
):
    """The readable shapes a stranger can leave in the system temp
    directory -- `git init /tmp` under an ordinary umask leaves a searchable
    .git with HEAD, and a gitfile or a symlink costs one call -- must not
    move the boundary any more than the unsearchable one does."""
    shared = tmp_path / "shared"
    shared.mkdir()
    git_dir = shared / ".git"
    if kind == "directory-with-head":
        git_dir.mkdir()
        (git_dir / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    elif kind == "gitfile":
        git_dir.write_text("gitdir: /elsewhere/.git/worktrees/wt\n", encoding="utf-8")
    else:
        _symlink_or_skip(git_dir, "does-not-exist")
    root = shared / "proj" / "src"
    root.mkdir(parents=True)
    os.chmod(shared, 0o1777)
    _reported_owner(monkeypatch, git_dir, _a_stranger())
    try:
        assert scanned_trees(root) == [root], scanned_trees(root)
    finally:
        monkeypatch.undo()
        os.chmod(shared, 0o755)


@_POSIX_MODES_NEEDED
def test_a_checkout_rooted_in_a_shared_shaped_directory_still_bounds(tmp_path, caplog):
    """Must not fire open: a real checkout whose root directory is itself
    sticky and world-writable, with its own unsearchable .git, is still that
    user's checkout. Dropping the entry for the directory's mode alone would
    hand the repository's own config the operator's trust with no warning;
    the owner is the scanning user, so the entry counts, fail-closed, and
    the warning names it."""
    repo = tmp_path / "repo"
    repo.mkdir()
    git_dir = repo / ".git"
    git_dir.mkdir()
    (git_dir / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    os.chmod(git_dir, 0)
    root = repo / "proj" / "src"
    root.mkdir(parents=True)
    os.chmod(repo, 0o1777)
    try:
        with caplog.at_level(logging.WARNING, logger="ash"):
            assert repo in scanned_trees(root), scanned_trees(root)
        assert any(
            git_dir.as_posix() in record.getMessage() for record in caplog.records
        ), [record.getMessage() for record in caplog.records]
    finally:
        os.chmod(repo, 0o755)
        os.chmod(git_dir, 0o755)


@_POSIX_MODES_NEEDED
def test_roots_git_in_a_writable_directory_still_counts(tmp_path, monkeypatch):
    """Must not fire: root places system checkouts in shared places, and a
    scan under one keeps its boundary."""
    shared = tmp_path / "shared"
    shared.mkdir()
    mark_git_checkout(shared)
    root = shared / "proj" / "src"
    root.mkdir(parents=True)
    os.chmod(shared, 0o1777)
    _reported_owner(monkeypatch, shared / ".git", 0)
    try:
        assert shared in scanned_trees(root), scanned_trees(root)
    finally:
        monkeypatch.undo()
        os.chmod(shared, 0o755)


@_POSIX_MODES_NEEDED
def test_the_directory_owners_git_still_counts(tmp_path, monkeypatch):
    """Must not fire: whose directory it is, their .git to place -- a shared
    drop's owner can root a checkout in it."""
    shared = tmp_path / "shared"
    shared.mkdir()
    mark_git_checkout(shared)
    root = shared / "proj" / "src"
    root.mkdir(parents=True)
    os.chmod(shared, 0o1777)
    stranger = _a_stranger()
    _reported_owner(monkeypatch, shared / ".git", stranger)
    _reported_directory_owner(monkeypatch, shared, stranger)
    try:
        assert shared in scanned_trees(root), scanned_trees(root)
    finally:
        monkeypatch.undo()
        os.chmod(shared, 0o755)


@_POSIX_MODES_NEEDED
def test_a_directory_reached_through_a_link_is_judged_as_itself(
    tmp_path, monkeypatch, caplog
):
    """Must not fire: whether others can write the directory holding a .git
    is a question about the directory, so one reached through a symlink is
    judged by what it is, not by the link, whose own mode says anyone can
    write. The real directory here is private, so the stranger-owned entry
    still counts by its shape."""
    real = tmp_path / "real"
    real.mkdir()
    git_dir = real / ".git"
    git_dir.mkdir()
    os.chmod(git_dir, 0)
    root_below = real / "proj" / "src"
    root_below.mkdir(parents=True)
    link = tmp_path / "link"
    _symlink_or_skip(link, real)
    _reported_owner(monkeypatch, link / ".git", _a_stranger())
    try:
        with caplog.at_level(logging.WARNING, logger="ash"):
            trees = scanned_trees(link / "proj" / "src")
        assert link in trees, trees
    finally:
        monkeypatch.undo()
        os.chmod(git_dir, 0o755)


@_POSIX_MODES_NEEDED
def test_the_warning_names_the_lookups_failure(tmp_path, monkeypatch, caplog):
    """The lookup can fail for more reasons than a mode: the warning names
    the failure it actually got, not "permission denied" for all of them."""
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    real = os.lstat
    head = os.fspath(git_dir / "HEAD")

    def lstat(name, *args, **kwargs):
        if os.fspath(name) == head:
            raise OSError(errno.EIO, os.strerror(errno.EIO), head)
        return real(name, *args, **kwargs)

    monkeypatch.setattr(os, "lstat", lstat)
    root = tmp_path / "proj" / "src"
    root.mkdir(parents=True)
    with caplog.at_level(logging.WARNING, logger="ash"):
        assert tmp_path in scanned_trees(root), scanned_trees(root)
    monkeypatch.undo()
    messages = [
        record.getMessage()
        for record in caplog.records
        if git_dir.as_posix() in record.getMessage()
    ]
    assert messages, [record.getMessage() for record in caplog.records]
    assert all(os.strerror(errno.EIO) in message for message in messages), messages
    assert all("permission denied" not in message.lower() for message in messages), (
        messages
    )


@_POSIX_MODES_NEEDED
def test_the_warning_prints_once_per_scan(tmp_path, caplog):
    """One scan walks the same parents many times, so the warning prints
    once per entry within it -- and a long-lived process starts a new window
    per scan, so the next scan's log says it again rather than nothing."""
    # Imported here: the cell is about this API existing, so the module
    # still collects where it does not.
    from automated_security_helper.config.sandbox_grants import (
        forget_unverifiable_warnings,
    )

    forget_unverifiable_warnings()
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    os.chmod(git_dir, 0)
    try:
        root = tmp_path / "proj" / "src"
        root.mkdir(parents=True)

        def warned() -> int:
            return sum(
                git_dir.as_posix() in record.getMessage() for record in caplog.records
            )

        with caplog.at_level(logging.WARNING, logger="ash"):
            scanned_trees(root)
            scanned_trees(root)
            in_a_checkout(root / "x.yaml")
            assert warned() == 1, [r.getMessage() for r in caplog.records]
            forget_unverifiable_warnings()
            scanned_trees(root)
        assert warned() == 2, [r.getMessage() for r in caplog.records]
    finally:
        os.chmod(git_dir, 0o755)


@_POSIX_MODES_NEEDED
def test_your_own_git_under_anothers_shared_directory_still_counts(
    tmp_path, monkeypatch
):
    """Must not fire, and the security direction: the scanning user's own
    checkout under a shared directory someone else owns (root's temp
    directory, a team share) is counted by the scanning-user arm alone,
    since the holder's owner here is a stranger. Dropping that arm would
    uncount the user's own repository and hand its config the operator's
    trust."""
    shared = tmp_path / "shared"
    shared.mkdir()
    mark_git_checkout(shared)
    root = shared / "proj" / "src"
    root.mkdir(parents=True)
    os.chmod(shared, 0o1777)
    _reported_directory_owner(monkeypatch, shared, _a_stranger())
    try:
        assert shared in scanned_trees(root), scanned_trees(root)
    finally:
        monkeypatch.undo()
        os.chmod(shared, 0o755)


@_POSIX_MODES_NEEDED
def test_an_unattributable_git_in_a_writable_directory_does_not_widen(
    tmp_path, monkeypatch
):
    """A race-only branch, pinned by a stand-in: the owner lookup itself
    can be refused (the entry replaced between the shape reads and this
    one). In a directory anyone can write, an entry that cannot be
    attributed to anyone does not count."""
    shared = tmp_path / "shared"
    shared.mkdir()
    mark_git_checkout(shared)
    git_dir = shared / ".git"
    root = shared / "proj" / "src"
    root.mkdir(parents=True)
    os.chmod(shared, 0o1777)
    real = os.lstat
    target = os.fspath(git_dir)

    def lstat(name, *args, **kwargs):
        if os.fspath(name) == target:
            raise PermissionError(errno.EACCES, "Permission denied", target)
        return real(name, *args, **kwargs)

    monkeypatch.setattr(os, "lstat", lstat)
    try:
        assert scanned_trees(root) == [root], scanned_trees(root)
    finally:
        monkeypatch.undo()
        os.chmod(shared, 0o755)


@_POSIX_MODES_NEEDED
def test_an_unstattable_directory_keeps_the_shape_rule(tmp_path, monkeypatch):
    """A race-only branch, pinned by a stand-in: when the directory holding
    the .git cannot be stat'ed, nothing says others can write it, so the
    entry's shape decides -- the conservative side."""
    holder = tmp_path / "w"
    holder.mkdir()
    mark_git_checkout(holder)
    root = holder / "proj" / "src"
    root.mkdir(parents=True)
    real = os.stat
    target = os.fspath(holder)

    def fake_stat(name, *args, **kwargs):
        if os.fspath(name) == target:
            raise PermissionError(errno.EACCES, "Permission denied", target)
        return real(name, *args, **kwargs)

    monkeypatch.setattr(os, "stat", fake_stat)
    try:
        assert holder in scanned_trees(root), scanned_trees(root)
    finally:
        monkeypatch.undo()


def test_a_scan_run_starts_a_fresh_warning_window(monkeypatch):
    """run_ash_scan opens the per-run warning window before it builds its
    options, so a long-lived process's second scan logs its boundary
    entries again."""
    import automated_security_helper.config.sandbox_grants as sandbox_grants
    import automated_security_helper.interactions.run_ash_scan as scan_module

    calls = []
    real = sandbox_grants.forget_unverifiable_warnings

    def recorder():
        calls.append(True)
        real()

    monkeypatch.setattr(sandbox_grants, "forget_unverifiable_warnings", recorder)

    class _Stop(Exception):
        pass

    def stop(*args, **kwargs):
        raise _Stop

    monkeypatch.setattr(scan_module, "ScanOptions", stop)
    with pytest.raises(_Stop):
        scan_module.run_ash_scan()
    assert calls == [True]


@_POSIX_MODES_NEEDED
def test_each_runs_log_scope_warns_for_its_own_boundary(tmp_path, caplog):
    """Two runs in one process, the hosting server's shape: each run's log
    must name the boundary entry it rests on, so the warning window follows
    the run's log scope rather than the process."""
    from automated_security_helper.utils.log import run_log_scope

    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    os.chmod(git_dir, 0)
    try:
        root = tmp_path / "proj" / "src"
        root.mkdir(parents=True)
        with caplog.at_level(logging.WARNING, logger="ash"):
            with run_log_scope():
                scanned_trees(root)
                scanned_trees(root)
            with run_log_scope():
                scanned_trees(root)
        warned = [
            record
            for record in caplog.records
            if git_dir.as_posix() in record.getMessage()
        ]
        assert len(warned) == 2, [r.getMessage() for r in caplog.records]
    finally:
        os.chmod(git_dir, 0o755)


_POSIX_NAMES_NEEDED = pytest.mark.skipif(
    os.name == "nt", reason="POSIX path spellings in the fabricated entries"
)


class _WarningRecorder:
    """ASH_LOGGER stand-in recording (the logging context's run scope, text):
    the per-run cells count a specific run's lines, which caplog cannot."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.lines: list = []

    def warning(self, message, *args, **kwargs) -> None:
        with self.lock:
            self.lines.append((current_run_log_scope(), message))

    def count(self, name, scope) -> int:
        with self.lock:
            return sum(
                1 for seen, message in self.lines if name in message and seen == scope
            )


@pytest.fixture
def _recorder(monkeypatch):
    recorder = _WarningRecorder()
    monkeypatch.setattr(sandbox_grants, "ASH_LOGGER", recorder)
    return recorder


def _hosted():
    """A run scope opened the way the hosting server's tool opens one, in a
    context of its own."""
    context = contextvars.copy_context()
    scope, token = context.run(open_run_log_scope)
    return context, scope, token


def _closed(context, scope, token) -> None:
    context.run(end_run_log_scope, scope, token)


def _refused() -> OSError:
    return PermissionError(errno.EACCES, "Permission denied")


@_POSIX_NAMES_NEEDED
def test_the_bound_sweep_drops_only_other_runs_windows(_warned_window, _recorder):
    """Past the bound, the sweeping run keeps its own window and drops the
    others', so a live concurrent run warns its entry again -- the safe
    direction, extra warnings rather than silence. A sweep that never fired,
    or one keeping the others' keys instead, would leave run A's window in
    place and warn once."""
    a_run = _hosted()
    b_run = _hosted()
    entry = Path("/nonexistent-window/a/.git")
    try:
        a_run[0].run(sandbox_grants._warn_unverifiable_git, entry, _refused())
        for i in range(sandbox_grants._WARNED_BOUND):
            b_run[0].run(
                sandbox_grants._warn_unverifiable_git,
                Path(f"/nonexistent-window/b{i}/.git"),
                _refused(),
            )
        a_run[0].run(sandbox_grants._warn_unverifiable_git, entry, _refused())
    finally:
        _closed(*a_run)
        _closed(*b_run)
    assert _recorder.count(entry.as_posix(), a_run[1]) == 2, _recorder.lines


@_POSIX_NAMES_NEEDED
def test_the_bound_holds_and_a_runs_own_window_survives_it(_warned_window, _recorder):
    """The memo never grows past its bound, and the sweep keeps the sweeping
    run's own keys: its first entry stays deduplicated across the sweep its
    second entry fires from a full set."""
    sizes = []
    for s in range(40):
        run = _hosted()
        try:
            for i in range(100):
                run[0].run(
                    sandbox_grants._warn_unverifiable_git,
                    Path(f"/nonexistent-window/s{s}/e{i}/.git"),
                    _refused(),
                )
                sizes.append(len(_warned_window))
        finally:
            _closed(*run)
    assert max(sizes) <= sandbox_grants._WARNED_BOUND, max(sizes)
    _warned_window.clear()
    for i in range(sandbox_grants._WARNED_BOUND - 1):
        _warned_window.add((f"dead-{i}", "git", f"/nonexistent-window/dead{i}/.git"))
    run = _hosted()
    first = Path("/nonexistent-window/c/first/.git")
    try:
        run[0].run(sandbox_grants._warn_unverifiable_git, first, _refused())
        run[0].run(
            sandbox_grants._warn_unverifiable_git,
            Path("/nonexistent-window/c/second/.git"),
            _refused(),
        )
        after_sweep = len(_warned_window)
        run[0].run(sandbox_grants._warn_unverifiable_git, first, _refused())
    finally:
        _closed(*run)
    assert after_sweep == 2, sorted(_warned_window)
    assert _recorder.count(first.as_posix(), run[1]) == 1, _recorder.lines


@_POSIX_NAMES_NEEDED
def test_forget_leaves_another_runs_window(_warned_window, _recorder):
    """One run's fresh window must not silence or reopen another's: run B
    forgetting between run A's two walks leaves A's entry deduplicated."""
    a_run = _hosted()
    b_run = _hosted()
    entry = Path("/nonexistent-window/q/.git")
    try:
        a_run[0].run(sandbox_grants._warn_unverifiable_git, entry, _refused())
        b_run[0].run(sandbox_grants.forget_unverifiable_warnings)
        a_run[0].run(sandbox_grants._warn_unverifiable_git, entry, _refused())
    finally:
        _closed(*a_run)
        _closed(*b_run)
    assert _recorder.count(entry.as_posix(), a_run[1]) == 1, _recorder.lines


@_POSIX_NAMES_NEEDED
def test_a_runs_window_opens_safely_beside_a_concurrent_warning(
    _warned_window, _recorder
):
    """Hosted runs forget and warn from concurrent executor threads, and the
    memo is shared: iterating it unlocked against a concurrent add raises
    "Set changed size during iteration", and forget is a scan's first call,
    so that scan would die at start. With the memo locked, a window opening
    beside a warning does so without an error, at the tightest switch
    interval and from the long-lived server's shape (a backlog of dead
    runs' keys)."""
    for i in range(1000):
        _warned_window.add((f"dead-{i}", "git", f"/nonexistent-window/dead{i}/.git"))
    completed = {"forget": 0, "warn": 0}
    failures: list = []
    stop = threading.Event()

    def forgetter():
        run = _hosted()
        try:
            while not stop.is_set():
                # Any exception counts, not only the iteration RuntimeError: a
                # failure of another type would otherwise die silently in this
                # thread, and the cell would pass with no denominator.
                try:
                    run[0].run(sandbox_grants.forget_unverifiable_warnings)
                    completed["forget"] += 1
                except Exception as error:  # noqa: BLE001 -- recorded, asserted
                    failures.append(("forget", repr(error)))
        finally:
            _closed(*run)

    def warner():
        i = 0
        while not stop.is_set():
            run = _hosted()
            try:
                for _ in range(50):
                    i += 1
                    try:
                        run[0].run(
                            sandbox_grants._warn_unverifiable_git,
                            Path(f"/nonexistent-window/w/{i}/.git"),
                            _refused(),
                        )
                        completed["warn"] += 1
                    except Exception as error:  # noqa: BLE001 -- recorded, asserted
                        failures.append(("warn", repr(error)))
            finally:
                _closed(*run)

    old = sys.getswitchinterval()
    threads = [threading.Thread(target=forgetter), threading.Thread(target=warner)]
    try:
        sys.setswitchinterval(1e-6)
        for thread in threads:
            thread.start()
        stop.wait(1.5)
    finally:
        stop.set()
        for thread in threads:
            thread.join(60)
        sys.setswitchinterval(old)
    assert not any(thread.is_alive() for thread in threads)
    assert failures == [], (len(failures), failures[:5])
    # The denominator: both sides actually ran, so an empty failure list means
    # contention happened and survived, not that nothing was tried.
    assert completed["forget"] > 0 and completed["warn"] > 0, completed


@_POSIX_NAMES_NEEDED
def test_the_warning_logger_runs_outside_the_memo_lock(tmp_path):
    """A design property, pinned: the logger call stays outside the memo
    lock. A logging handler is user-extensible and can walk a tree itself,
    re-entering the warning; held across that call, the non-reentrant lock
    would deadlock. The probe runs in a subprocess with a timeout, because
    in-process the stuck thread would keep the lock and block every later
    cell."""
    program = (
        "import errno\n"
        "from pathlib import Path\n"
        "import automated_security_helper.config.sandbox_grants as sg\n"
        "class Reentering:\n"
        "    def __init__(self):\n"
        "        self.inside = False\n"
        "    def warning(self, *args, **kwargs):\n"
        "        if self.inside:\n"
        "            return\n"
        "        self.inside = True\n"
        "        sg._warn_unverifiable_git(\n"
        "            Path('/nonexistent-reenter/b/.git'),\n"
        "            PermissionError(errno.EACCES, 'Permission denied'),\n"
        "        )\n"
        "sg.ASH_LOGGER = Reentering()\n"
        "sg._warn_unverifiable_git(\n"
        "    Path('/nonexistent-reenter/a/.git'),\n"
        "    PermissionError(errno.EACCES, 'Permission denied'),\n"
        ")\n"
        "print('completed')\n"
    )
    probe = subprocess.run(  # nosec B603 -- our own interpreter, our program
        [sys.executable, "-I", "-c", importing_this_checkout(program)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert probe.returncode == 0 and "completed" in probe.stdout, (
        probe.returncode,
        probe.stdout,
        probe.stderr,
    )


@_POSIX_MODES_NEEDED
def test_the_warning_shows_a_hostile_name_on_one_line(tmp_path, caplog):
    """The warned name is the scanned side's to choose: a newline in it
    would start a forged log line, so the message holds the whole warning on
    one line, and it is logged without markup."""
    holder = tmp_path / "evil\n[bold red]x"
    holder.mkdir()
    git_dir = holder / ".git"
    git_dir.mkdir()
    os.chmod(git_dir, 0)
    try:
        root = holder / "proj" / "src"
        root.mkdir(parents=True)
        with caplog.at_level(logging.WARNING, logger="ash"):
            assert holder in scanned_trees(root)
        records = [
            record
            for record in caplog.records
            if "checkout boundary" in record.getMessage()
        ]
        assert records, [record.getMessage() for record in caplog.records]
        assert all("\n" not in record.getMessage() for record in records), [
            repr(record.getMessage()) for record in records
        ]
        assert all(record.markup is False for record in records), records
    finally:
        os.chmod(git_dir, 0o755)

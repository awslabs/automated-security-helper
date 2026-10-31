# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A results directory the sweep cannot list is refused, never skipped.

os.fwalk and os.walk call ``onerror`` for a subdirectory they cannot open and
otherwise pass over it in silence. Called without one, fs_guard's sweep left every
link below such a directory in place while reporting nothing, and the check that
runs before a sandboxed scanner (refuse_links_below) passed a link it never saw.

The refusal is logged where it is met and the sweep continues: the siblings of the
refused directory and the other writable roots are still swept, the removals are
counted, and one OSError is raised at the end whose text is the logged line (so it
names no tool-chosen path the warning did not, and chains nothing that would).
A directory the process can read but not search lists its entries and refuses
their lstat; that is a refusal too, not a skip.

These run in-process on tmp_path only; the directory modes they set are POSIX,
and root lists every directory, so they skip where neither holds.
"""

import errno
import logging
import os
import sys

import pytest

from automated_security_helper.utils.output_dir_links import OutputDirLinkRefused
from automated_security_helper.utils.sandbox import fs_guard

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(
        sys.platform == "win32", reason="POSIX directory modes and symlinks"
    ),
]


def _skip_as_root():
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        pytest.skip("root can list and search a directory whatever its mode")


@pytest.fixture
def unprivileged():
    """Skip, as root, a test that takes a mode away from a directory: root lists
    and searches it anyway, so nothing would be refused. The tests that set no mode
    (a link at the root, an injected error, a vanished directory) run as root too."""
    _skip_as_root()


needs_unprivileged = pytest.mark.usefixtures("unprivileged")


def _warnings(caplog, head):
    return [
        record.getMessage()
        for record in caplog.records
        if record.getMessage().startswith(head)
    ]


def _record_os_walk(monkeypatch):
    """Wrap os.walk; return the list of roots it was called with. Taking
    ``os.fwalk`` away selects the by-name branch, but a test only measures that
    branch if it can say os.walk ran (and, on the descriptor leg, that it did not)."""
    walked = []
    real_walk = os.walk

    def recording(top, *args, **kwargs):
        walked.append(os.fspath(top))
        return real_walk(top, *args, **kwargs)

    monkeypatch.setattr(os, "walk", recording)
    return walked


@pytest.fixture
def locked_tree(tmp_path):
    """A results directory holding a subdirectory that cannot be listed, with a
    symlink inside it made before the mode was taken away. The mode is restored
    afterwards so tmp_path can be removed."""
    _skip_as_root()
    root = tmp_path / "results"
    locked = root / "locked"
    locked.mkdir(parents=True)
    (locked / "escape").symlink_to(tmp_path)
    locked.chmod(0o000)
    try:
        yield root, locked
    finally:
        locked.chmod(0o700)


@pytest.fixture
def readable_locked_tree(tmp_path):
    """The same, but the subdirectory can be read and not searched (0o600): its
    entries list, and their lstat is refused."""
    _skip_as_root()
    root = tmp_path / "results"
    locked = root / "locked"
    locked.mkdir(parents=True)
    (locked / "escape").symlink_to(tmp_path)
    locked.chmod(0o600)
    try:
        yield root, locked
    finally:
        locked.chmod(0o700)


def test_the_sweep_refuses_a_directory_it_cannot_list(locked_tree, caplog):
    root, locked = locked_tree

    with caplog.at_level(logging.WARNING, logger="ash"):
        with pytest.raises(PermissionError) as refused:
            fs_guard.sweep_writable([root], ("SWEEPSECRET-4471",))

    assert "locked" in str(refused.value)
    assert refused.value.__cause__ is None, "the raw OSError is not chained"
    assert _warnings(caplog, "Could not list"), [
        record.getMessage() for record in caplog.records
    ]
    locked.chmod(0o700)
    assert os.path.lexists(locked / "escape"), "the refused link is left as found"


@needs_unprivileged
def test_the_sweep_refusal_hides_an_env_read_value(tmp_path, caplog):
    """The refusal names the directory and the root, and a tool can name a
    directory after an option it was given: the warning is redacted with the
    sweep's values, as the could-not-remove warning is, and so is the raised
    exception, whose text travels into the scanner's row and results file."""
    value = "SWEEPSECRET-4472"
    root = tmp_path / "results"
    locked = root / f"dir-{value}"
    locked.mkdir(parents=True)
    locked.chmod(0o000)
    try:
        with caplog.at_level(logging.WARNING, logger="ash"):
            with pytest.raises(PermissionError) as refused:
                fs_guard.sweep_writable([root], (value,))
    finally:
        locked.chmod(0o700)

    lines = _warnings(caplog, "Could not list")
    assert lines, [record.getMessage() for record in caplog.records]
    assert not any(value in line for line in lines), lines
    assert value not in str(refused.value), str(refused.value)
    assert refused.value.__cause__ is None


@needs_unprivileged
def test_the_sweep_refusal_is_value_free_when_the_values_could_not_be_read(
    tmp_path, caplog
):
    """With the plugin's values unread nothing can be redacted, so neither the
    warning nor the exception names the directory: the executor's handler can
    only redact the exception with the same values it could not read."""
    root = tmp_path / "results"
    locked = root / "dir-SWEEPSECRET-4473"
    locked.mkdir(parents=True)
    locked.chmod(0o000)
    try:
        with caplog.at_level(logging.WARNING, logger="ash"):
            with pytest.raises(PermissionError) as refused:
                fs_guard.sweep_writable([root], (), values_unread=True)
    finally:
        locked.chmod(0o700)

    lines = _warnings(caplog, "Could not list")
    assert lines, [record.getMessage() for record in caplog.records]
    assert all("SWEEPSECRET-4473" not in line for line in lines), lines
    assert all("redaction values could not be read" in line for line in lines), lines
    text = str(refused.value)
    assert "SWEEPSECRET-4473" not in text, text
    assert str(root) not in text, text
    assert "redaction values could not be read" in text, text
    assert refused.value.__cause__ is None
    assert refused.value.__context__ is None or refused.value.__suppress_context__


@needs_unprivileged
def test_a_root_the_sweep_cannot_open_is_refused_through_the_same_path(
    tmp_path, caplog
):
    """os.fwalk raises for a root it cannot open without calling ``onerror``, so
    the raw error, root path included, left the sweep with no warning at all;
    the sweep's own walk reports the root like any directory."""
    root = tmp_path / "results-SWEEPSECRET-4477"
    root.mkdir()
    (root / "escape").symlink_to(tmp_path)
    root.chmod(0o000)
    try:
        with caplog.at_level(logging.WARNING, logger="ash"):
            with pytest.raises(PermissionError) as refused:
                fs_guard.sweep_writable([root], (), values_unread=True)
    finally:
        root.chmod(0o700)

    lines = _warnings(caplog, "Could not list")
    assert lines, [record.getMessage() for record in caplog.records]
    assert "SWEEPSECRET-4477" not in str(refused.value), str(refused.value)
    assert refused.value.__cause__ is None
    assert os.path.lexists(root / "escape"), "the link behind the mode is left"


def test_a_refusal_does_not_end_the_sweep_of_siblings_or_other_roots(
    tmp_path, caplog, monkeypatch
):
    """One unlistable directory used to end the whole walk and the loop over the
    policy's writable roots, so every link after it survived and the count of
    removals was lost. The sweep now continues and raises once at the end.

    The directory that is refused is whichever subdirectory the walk opens first
    (the failure is injected on that open, not set as a mode on a named
    directory), so the test does not depend on the order the filesystem lists
    entries in: the sibling that comes after the refused one is always there."""
    first = tmp_path / "results"
    for name in ("one", "two"):
        (first / name).mkdir(parents=True)
        (first / name / "escape").symlink_to(tmp_path)
    (first / "z-escape").symlink_to(tmp_path)
    second = tmp_path / "other-results"
    second.mkdir()
    (second / "escape").symlink_to(tmp_path)
    real_open = os.open
    refused_names = []

    def refuse_the_first_subdirectory(path, flags, *args, **kwargs):
        if (
            kwargs.get("dir_fd") is not None
            and flags & os.O_DIRECTORY
            and not refused_names
        ):
            refused_names.append(os.fspath(path))
            raise PermissionError(errno.EACCES, "Permission denied", os.fspath(path))
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", refuse_the_first_subdirectory)

    with caplog.at_level(logging.WARNING, logger="ash"):
        with pytest.raises(PermissionError) as refused:
            fs_guard.sweep_writable([first, second], ("SWEEPSECRET-4478",))

    (refused_name,) = refused_names
    sibling = "two" if refused_name == "one" else "one"
    assert os.path.lexists(first / refused_name / "escape"), "the refused one is left"
    assert not os.path.lexists(first / sibling / "escape"), "a sibling's link is swept"
    assert not os.path.lexists(first / "z-escape"), "an entry beside them is swept"
    assert not os.path.lexists(second / "escape"), "the next root is swept"
    assert refused_name in str(refused.value)
    summaries = _warnings(caplog, "Scanner sandbox: removed")
    assert summaries and "removed 3 " in summaries[0], summaries


@needs_unprivileged
def test_several_refusals_raise_once_with_the_others_counted(tmp_path, caplog):
    root = tmp_path / "results"
    for name in ("a-locked", "b-locked"):
        (root / name).mkdir(parents=True)
    for name in ("a-locked", "b-locked"):
        (root / name).chmod(0o000)
    try:
        with caplog.at_level(logging.WARNING, logger="ash"):
            with pytest.raises(PermissionError) as refused:
                fs_guard.sweep_writable([root])
    finally:
        for name in ("a-locked", "b-locked"):
            (root / name).chmod(0o700)

    assert len(_warnings(caplog, "Could not list")) == 2
    assert "and 1 more" in str(refused.value), str(refused.value)


def test_the_spawn_cleanup_still_releases_after_a_refused_sweep(locked_tree):
    """scope.py appends the sweep and then the release to the spawn plan's
    cleanup; a sweep that raises must not keep the release from running."""
    from automated_security_helper.utils.sandbox.backends import SpawnPlan

    root, _locked = locked_tree
    released = []
    plan = SpawnPlan(
        argv=[],
        env={},
        cleanup=[lambda: fs_guard.sweep_writable([root]), lambda: released.append(1)],
    )

    plan.run_cleanup()

    assert released == [1]


def test_a_readable_but_unsearchable_directory_is_refused_not_passed_over(
    readable_locked_tree, caplog
):
    """A directory with read but not search permission lists its entries, and
    the lstat of each fails with EACCES. The sweep read that as nothing to
    examine and passed the link over; it is a refusal, like a listing failure."""
    root, locked = readable_locked_tree

    with caplog.at_level(logging.WARNING, logger="ash"):
        with pytest.raises(PermissionError) as refused:
            fs_guard.sweep_writable([root], ("SWEEPSECRET-4479",))

    assert "locked/escape" in str(refused.value), str(refused.value)
    assert _warnings(caplog, "Could not examine"), [
        record.getMessage() for record in caplog.records
    ]
    locked.chmod(0o700)
    assert os.path.lexists(locked / "escape"), "the link is left as found"


def test_refuse_links_below_refuses_a_readable_but_unsearchable_directory(
    readable_locked_tree,
):
    root, _locked = readable_locked_tree

    with pytest.raises(PermissionError) as refused:
        fs_guard.refuse_links_below(root)

    assert "locked/escape" in str(refused.value), str(refused.value)


@needs_unprivileged
def test_the_refusal_names_the_directory_by_its_path_below_the_root(tmp_path, caplog):
    """fwalk's ``onerror`` saw a bare entry name, so "cache" under the root could
    be a/cache or b/cache; the walk reports the path below the root."""
    root = tmp_path / "results"
    (root / "a" / "cache").mkdir(parents=True)
    (root / "b" / "cache").mkdir(parents=True)
    (root / "a" / "cache").chmod(0o000)
    try:
        with caplog.at_level(logging.WARNING, logger="ash"):
            with pytest.raises(PermissionError) as refused:
                fs_guard.sweep_writable([root])
    finally:
        (root / "a" / "cache").chmod(0o700)

    assert "a/cache" in str(refused.value), str(refused.value)
    assert "b/cache" not in str(refused.value), str(refused.value)
    assert any("a/cache" in line for line in _warnings(caplog, "Could not list"))


def test_the_os_walk_fallback_refuses_a_directory_it_cannot_list(
    locked_tree, monkeypatch
):
    """The platform without fwalk takes the os.walk branch, which skips an
    unopenable directory the same way; it is given the same refusal."""
    root, _locked = locked_tree
    monkeypatch.delattr(os, "fwalk")
    walked = _record_os_walk(monkeypatch)

    with pytest.raises(PermissionError):
        fs_guard.sweep_writable([root])

    assert walked == [os.fspath(root)], "the os.walk branch ran"


def test_the_os_walk_fallback_records_a_failed_removal_sweeps_on_and_refuses(
    tmp_path, monkeypatch, caplog
):
    """A removal that fails is a refusal: logged, the sweep continues to the next
    entry (the os.walk fallback once let the OSError abort the whole sweep, so a
    link after the failed one survived), and the sweep raises once at the end,
    since the link it could not remove is still there for a reader to follow.
    Measured by taking fwalk away and failing the first removal, whichever entry
    that is: both names carry the value, so the redaction check holds for the one
    that fails, and the test does not depend on the order the entries are listed
    in."""
    value = "SWEEPSECRET-4476"
    root = tmp_path / "results"
    root.mkdir()
    names = (f"aaa-{value}", f"zzz-{value}")
    for name in names:
        (root / name).symlink_to(tmp_path)
    real_unlink = os.unlink
    failed = []

    def failing_unlink(path, *args, **kwargs):
        if not failed:
            failed.append(os.path.basename(os.fspath(path)))
            raise OSError(1, "the first removal fails", os.fspath(path))
        return real_unlink(path, *args, **kwargs)

    monkeypatch.delattr(os, "fwalk")
    monkeypatch.setattr(os, "unlink", failing_unlink)
    walked = _record_os_walk(monkeypatch)

    with caplog.at_level(logging.WARNING, logger="ash"):
        with pytest.raises(PermissionError) as refused:
            fs_guard.sweep_writable([root], (value,))

    assert walked == [os.fspath(root)], "the os.walk branch ran"
    (failed_name,) = failed
    other_name = names[1] if failed_name == names[0] else names[0]
    assert not os.path.lexists(root / other_name), "the sweep must continue past it"
    assert os.path.lexists(root / failed_name), "the failed one is left as found"
    lines = _warnings(caplog, "Could not remove")
    assert lines, [record.getMessage() for record in caplog.records]
    assert not any("SWEEPSECRET-4476" in line for line in lines), lines
    assert "SWEEPSECRET-4476" not in str(refused.value), str(refused.value)
    summaries = _warnings(caplog, "Scanner sandbox: removed")
    assert summaries and "removed 1 " in summaries[0], summaries


@needs_unprivileged
def test_a_link_the_sweep_cannot_remove_is_refused_not_passed_over(tmp_path, caplog):
    """A scanner can plant a link and take the write bit off its directory:
    the listing and the lstat work, the unlink fails with EACCES, and the sweep
    used to return normally with the link in place. It is a refusal."""
    root = tmp_path / "results"
    locked = root / "d"
    locked.mkdir(parents=True)
    (locked / "out.sarif").symlink_to(tmp_path)
    locked.chmod(0o555)
    try:
        with caplog.at_level(logging.WARNING, logger="ash"):
            with pytest.raises(PermissionError) as refused:
                fs_guard.sweep_writable([root], ("SWEEPSECRET-4480",))
    finally:
        locked.chmod(0o755)

    assert "out.sarif" in str(refused.value), str(refused.value)
    assert _warnings(caplog, "Could not remove"), [
        record.getMessage() for record in caplog.records
    ]
    assert os.path.lexists(locked / "out.sarif"), "the link is left as found"


@needs_unprivileged
@pytest.mark.parametrize("walk", ["descriptors", "by-name"])
def test_a_readable_but_unsearchable_directory_is_refused_once_not_once_per_entry(
    tmp_path, caplog, monkeypatch, walk
):
    """Search permission belongs to the directory, so the lstat of every entry in
    it fails the same way. One warning and one stored error for the directory,
    naming its first entry, not one per entry (a scanner's directory of 100,000
    files was 100,000 log lines)."""
    root = tmp_path / "results"
    locked = root / "locked"
    locked.mkdir(parents=True)
    for index in range(30):
        (locked / f"entry-{index}").write_text("x")
    locked.chmod(0o600)
    if walk == "by-name":
        monkeypatch.delattr(os, "fwalk")
    walked = _record_os_walk(monkeypatch)
    try:
        with caplog.at_level(logging.WARNING, logger="ash"):
            with pytest.raises(PermissionError) as refused:
                fs_guard.sweep_writable([root])
    finally:
        locked.chmod(0o700)

    assert bool(walked) == (walk == "by-name"), (walk, walked)
    assert len(_warnings(caplog, "Could not examine")) == 1, [
        record.getMessage() for record in caplog.records
    ]
    assert "; and " not in str(refused.value), str(refused.value)


@needs_unprivileged
def test_refusals_past_the_warning_limit_are_counted_and_said_once(
    tmp_path, caplog, monkeypatch
):
    monkeypatch.setattr(fs_guard, "_SWEEP_WARNING_LIMIT", 2)
    root = tmp_path / "results"
    locked = [root / f"locked-{index}" for index in range(5)]
    for directory in locked:
        directory.mkdir(parents=True)
        directory.chmod(0o000)
    try:
        with caplog.at_level(logging.WARNING, logger="ash"):
            with pytest.raises(PermissionError) as refused:
                fs_guard.sweep_writable([root])
    finally:
        for directory in locked:
            directory.chmod(0o700)

    assert len(_warnings(caplog, "Could not list")) == 2
    assert len(_warnings(caplog, "Scanner sandbox: 3 more refusal(s)")) == 1, [
        record.getMessage() for record in caplog.records
    ]
    text = str(refused.value)
    assert "and 4 more" in text and "first 2" in text, text


@needs_unprivileged
@pytest.mark.parametrize("walk", ["descriptors", "by-name"])
def test_a_failed_removal_names_the_entry_by_its_path_below_the_root(
    tmp_path, caplog, monkeypatch, walk
):
    """Two entries called ``cache`` in different directories, one of which cannot
    be removed: the warning says which, as the walks' own refusals name a
    directory (``a/cache``), not the bare name both share."""
    root = tmp_path / "results"
    for directory in ("a", "b"):
        (root / directory).mkdir(parents=True)
        (root / directory / "cache").symlink_to(tmp_path)
    (root / "a").chmod(0o555)
    if walk == "by-name":
        monkeypatch.delattr(os, "fwalk")
    walked = _record_os_walk(monkeypatch)
    try:
        with caplog.at_level(logging.WARNING, logger="ash"):
            with pytest.raises(PermissionError) as refused:
                fs_guard.sweep_writable([root])
    finally:
        (root / "a").chmod(0o755)

    assert bool(walked) == (walk == "by-name"), (walk, walked)

    (line,) = _warnings(caplog, "Could not remove")
    assert line.startswith("Could not remove a/cache under "), line
    assert "a/cache" in str(refused.value), str(refused.value)
    assert os.path.lexists(root / "a" / "cache"), "the unremovable link is left"
    assert not os.path.lexists(root / "b" / "cache"), "its namesake is removed"


def test_a_directory_removed_during_the_walk_is_not_a_refusal(tmp_path, monkeypatch):
    """A subdirectory that vanished between its listing and its open reads as
    ENOENT; nothing is below it, so the sweep continues without a word."""
    root = tmp_path / "results"
    (root / "gone").mkdir(parents=True)
    (root / "zzz-link").symlink_to(tmp_path)
    real_open = os.open
    vanished = []

    def vanishing_open(path, flags, *args, **kwargs):
        if os.fspath(path) == "gone" and kwargs.get("dir_fd") is not None:
            vanished.append(os.fspath(path))
            raise FileNotFoundError(2, "No such file or directory", "gone")
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", vanishing_open)

    removed = fs_guard.sweep_writable([root])

    assert vanished == ["gone"], (
        "the walk opened the directory and was told it was gone"
    )
    assert removed == 1
    assert not os.path.lexists(root / "zzz-link")


def test_refuse_links_below_refuses_a_directory_it_cannot_list(locked_tree):
    root, _locked = locked_tree

    with pytest.raises(PermissionError) as refused:
        fs_guard.refuse_links_below(root)

    assert "locked" in str(refused.value)
    # Not chained: the walk's own error carries the full path in ``filename``,
    # which the sweep's refusals drop for the same reason (the tests below).
    assert refused.value.__cause__ is None


@needs_unprivileged
def test_refuse_links_below_hides_an_env_read_value(tmp_path, caplog):
    """The pre-check names the directory it could not list, and a tool can name a
    directory after an option it was given: the warning and the raised exception
    are redacted with the caller's values, as the sweep's are, and nothing is
    chained that would carry the path in ``filename``."""
    value = "PRECHECKSECRET-9921"
    root = tmp_path / "results"
    locked = root / f"dir-{value}"
    locked.mkdir(parents=True)
    locked.chmod(0o000)
    try:
        with caplog.at_level(logging.WARNING, logger="ash"):
            with pytest.raises(PermissionError) as refused:
                fs_guard.refuse_links_below(root, (value,))
    finally:
        locked.chmod(0o700)

    lines = _warnings(caplog, "Could not list")
    assert lines, [record.getMessage() for record in caplog.records]
    assert not any(value in line for line in lines), lines
    assert value not in str(refused.value), str(refused.value)
    assert refused.value.__cause__ is None
    assert refused.value.__suppress_context__


@needs_unprivileged
def test_refuse_links_below_is_value_free_when_the_values_could_not_be_read(
    tmp_path, caplog
):
    value = "PRECHECKSECRET-9922"
    root = tmp_path / "results"
    locked = root / f"dir-{value}"
    locked.mkdir(parents=True)
    locked.chmod(0o000)
    try:
        with caplog.at_level(logging.WARNING, logger="ash"):
            with pytest.raises(PermissionError) as refused:
                fs_guard.refuse_links_below(root, values_unread=True)
    finally:
        locked.chmod(0o700)

    lines = _warnings(caplog, "Could not list")
    assert lines, [record.getMessage() for record in caplog.records]
    assert all(value not in line for line in lines), lines
    text = str(refused.value)
    assert value not in text, text
    assert str(root) not in text, text
    assert "redaction values could not be read" in text, text
    assert refused.value.__cause__ is None


def test_refuse_links_below_refuses_a_root_it_cannot_check(tmp_path, monkeypatch):
    """The root was read with ``Path.is_dir``, which since Python 3.14 reads every
    OSError as False: a root the process could not check returned in silence and
    the scanner ran without the pre-check. Measured with the error injected at
    lstat, so it holds on every interpreter."""
    root = tmp_path / "results"
    root.mkdir()
    real_lstat = os.lstat

    def refusing_lstat(path, *args, **kwargs):
        if os.fspath(path) == os.fspath(root) and not kwargs.get("dir_fd"):
            raise PermissionError(13, "Permission denied", os.fspath(path))
        return real_lstat(path, *args, **kwargs)

    monkeypatch.setattr(os, "lstat", refusing_lstat)

    with pytest.raises(PermissionError):
        fs_guard.refuse_links_below(root)


def test_refuse_links_below_refuses_a_root_that_is_itself_a_link(tmp_path):
    """``Path.is_dir`` followed a link at the root, and fwalk, told not to follow
    links, then yielded nothing for it: a linked results directory passed the
    pre-check in silence. It is the link the check exists to refuse."""
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    root = tmp_path / "results"
    root.symlink_to(elsewhere)

    with pytest.raises(OutputDirLinkRefused):
        fs_guard.refuse_links_below(root)


@pytest.mark.skipif(not os.path.isdir("/proc/self/fd"), reason="counts fds via procfs")
def test_a_refused_pre_check_leaves_no_directory_descriptor_open(tmp_path):
    """The pre-check raises out of the walk from two directories down; the walk's
    open descriptors are closed on the way out (the generator is closed, not
    left to finalization, which another interpreter can defer)."""
    root = tmp_path / "results"
    (root / "a" / "b").mkdir(parents=True)
    (root / "a" / "b" / "escape").symlink_to(tmp_path)
    before = len(os.listdir("/proc/self/fd"))

    with pytest.raises(OutputDirLinkRefused):
        fs_guard.refuse_links_below(root)

    assert len(os.listdir("/proc/self/fd")) == before


@needs_unprivileged
def test_a_root_that_cannot_be_checked_is_refused_not_skipped(tmp_path, caplog):
    """The sibling route at the root: ``Path.is_symlink`` already reads a missing
    root as False, so the handler around it only ever met the other errors (a
    parent the process cannot search, a link loop) and passed the whole root
    over in silence. Those are refused, logged as the other sweep failures are."""
    parent = tmp_path / "unsearchable"
    root = parent / "results"
    root.mkdir(parents=True)
    (root / "escape").symlink_to(tmp_path)
    parent.chmod(0o000)
    try:
        with caplog.at_level(logging.WARNING, logger="ash"):
            with pytest.raises(PermissionError):
                fs_guard.sweep_writable([root], ("SWEEPSECRET-4474",))
    finally:
        parent.chmod(0o700)

    assert _warnings(caplog, "Could not check or remove the root"), [
        record.getMessage() for record in caplog.records
    ]
    assert os.path.lexists(root / "escape"), "the link is left as found"


def test_a_root_check_error_is_refused_on_every_interpreter(
    tmp_path, monkeypatch, caplog
):
    """The root check reads the root with os.lstat, not Path.is_symlink: since
    Python 3.14 is_symlink is os.path.islink, which turns every OSError into
    False, so the refusal above would never fire there and the error would come
    unlogged from the walk instead. Measured here with the error injected at
    lstat, so the pin holds whatever the interpreter and platform."""
    root = tmp_path / "results"
    root.mkdir()
    real_lstat = os.lstat

    def refusing_lstat(path, *args, **kwargs):
        if os.fspath(path) == os.fspath(root) and not kwargs.get("dir_fd"):
            raise PermissionError(13, "Permission denied", os.fspath(path))
        return real_lstat(path, *args, **kwargs)

    monkeypatch.setattr(os, "lstat", refusing_lstat)

    with caplog.at_level(logging.WARNING, logger="ash"):
        with pytest.raises(PermissionError):
            fs_guard.sweep_writable([root], ("SWEEPSECRET-4475",))

    assert _warnings(caplog, "Could not check or remove the root"), [
        record.getMessage() for record in caplog.records
    ]

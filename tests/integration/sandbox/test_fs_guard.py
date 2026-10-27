# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""ASH's own writes into a results directory never follow a link placed there."""

import errno
import os
import stat
import threading

import pytest

from automated_security_helper.utils.sandbox import fs_guard

#: These exercise POSIX filesystem behavior (directory-fd walks, FIFOs, mode bits),
#: so they live with the sandbox integration tests, which CI runs on Linux and macOS
#: where the sandbox backends exist.
pytestmark = pytest.mark.integration


@pytest.fixture
def tree(tmp_path):
    root = tmp_path / "results"
    (root / "source").mkdir(parents=True)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    fs_guard.register_writable_root(root)
    return root, elsewhere


def test_a_parent_component_replaced_by_a_link_is_refused(tree):
    root, elsewhere = tree
    (root / "source").rmdir()
    (root / "source").symlink_to(elsewhere, target_is_directory=True)
    with pytest.raises(fs_guard.OutputLinkRefused):
        with fs_guard.open_for_write(root / "source" / "out.log") as f:
            f.write("x")
    assert list(elsewhere.iterdir()) == []


def test_a_link_at_the_file_name_is_refused_not_followed(tree):
    root, elsewhere = tree
    linked = elsewhere / "linked.txt"
    linked.write_text("original\n")
    target = root / "source" / "out.log"
    target.symlink_to(linked)
    with pytest.raises(fs_guard.OutputLinkRefused):
        fs_guard.open_for_write(target)
    assert linked.read_text() == "original\n"
    assert target.is_symlink(), "the refusal leaves the link where it was"


def test_a_link_below_a_results_directory_is_refused_before_a_scan(tree):
    root, elsewhere = tree
    (root / "source" / "regular.txt").write_text("x")
    fs_guard.refuse_links_below(root)
    (root / "source" / "linked").symlink_to(elsewhere, target_is_directory=True)
    with pytest.raises(fs_guard.OutputLinkRefused):
        fs_guard.refuse_links_below(root)


def test_a_fifo_at_the_file_name_is_refused_without_blocking(tree):
    root, _ = tree
    fifo = root / "source" / "out.log"
    os.mkfifo(fifo)
    outcome = []

    def attempt():
        try:
            fs_guard.open_for_write(fifo).close()
            outcome.append("opened")
        except OSError as e:
            outcome.append(e)

    # In a thread with a deadline: a plain open() of a FIFO blocks until a reader
    # appears, and the test must fail rather than hang if that comes back.
    worker = threading.Thread(target=attempt, daemon=True)
    worker.start()
    worker.join(timeout=5)
    if worker.is_alive():
        with open(fifo, "rb"):  # unblock the writer so the thread can finish
            pass
        pytest.fail("opening a FIFO blocked")
    assert outcome and isinstance(outcome[0], OSError), outcome


def test_the_mode_matches_open(tree):
    root, _ = tree
    previous = os.umask(0o002)
    try:
        with fs_guard.open_for_write(root / "source" / "a.log") as f:
            f.write("x")
        with open(root / "source" / "b.log", "w") as f:
            f.write("x")
    finally:
        os.umask(previous)
    a = stat.S_IMODE(os.stat(root / "source" / "a.log").st_mode)
    b = stat.S_IMODE(os.stat(root / "source" / "b.log").st_mode)
    assert a == b


def test_the_sweep_removes_links_and_does_not_enter_them(tree):
    root, elsewhere = tree
    keep = elsewhere / "keep-link"
    keep.symlink_to(elsewhere / "nothing")
    (root / "source" / "dirlink").symlink_to(elsewhere, target_is_directory=True)
    (root / "source" / "filelink").symlink_to(elsewhere / "nothing")
    (root / "source" / "regular.txt").write_text("x")
    removed = fs_guard.sweep_writable([root])
    assert removed == 2
    assert (root / "source" / "regular.txt").exists()
    # The sweep did not walk into the linked directory and remove links there.
    assert keep.is_symlink()


def test_outside_a_registered_root_it_is_plain_open(tmp_path):
    """No sandbox, no change: the write follows a link exactly as open() does."""
    linked = tmp_path / "linked.txt"
    linked.write_text("original\n")
    target = tmp_path / "unregistered" / "out.log"
    target.parent.mkdir()
    target.symlink_to(linked)
    with fs_guard.open_for_write(target) as f:
        f.write("written\n")
    assert linked.read_text() == "written\n"


def test_bytes_are_written_unchanged_and_a_link_at_the_name_is_not_followed(tree):
    """open_for_write_bytes keeps open_for_write's rule and writes bytes as given."""
    root, elsewhere = tree
    victim = elsewhere / "victim.bin"
    victim.write_bytes(b"original")
    target = root / "source" / "copy.bin"
    target.symlink_to(victim)
    payload = bytes(range(256)) + b"\r\n\n"
    with fs_guard.open_for_write_bytes(target) as f:
        f.write(payload)
    assert victim.read_bytes() == b"original"
    assert not target.is_symlink()
    assert target.read_bytes() == payload


def test_bytes_outside_a_registered_root_are_plain_open(tmp_path):
    target = tmp_path / "unregistered" / "copy.bin"
    target.parent.mkdir()
    with fs_guard.open_for_write_bytes(target) as f:
        f.write(b"\x00\xff")
    assert target.read_bytes() == b"\x00\xff"


# -- reading back a file ASH wrote there ------------------------------------------


def test_a_read_back_through_a_linked_parent_is_refused(tree):
    root, elsewhere = tree
    (elsewhere / "out.log").write_text("a host file\n")
    (root / "source").rmdir()
    (root / "source").symlink_to(elsewhere, target_is_directory=True)

    with pytest.raises(OSError):
        fs_guard.read_bytes_at_most(root / "source" / "out.log", 100)


@pytest.mark.parametrize("registered", [True, False], ids=["in-a-root", "outside"])
def test_a_read_back_of_a_link_at_the_file_name_is_refused(tree, tmp_path, registered):
    root, elsewhere = tree
    victim = elsewhere / "victim.txt"
    victim.write_text("a host file\n")
    directory = root / "source" if registered else tmp_path / "unregistered"
    directory.mkdir(exist_ok=True)
    (directory / "out.log").symlink_to(victim)

    with pytest.raises(OSError):
        fs_guard.read_bytes_at_most(directory / "out.log", 100)


def test_a_read_back_of_a_fifo_is_refused_without_blocking(tree):
    root, _ = tree
    fifo = root / "source" / "out.log"
    os.mkfifo(fifo)
    outcome = []

    def attempt():
        try:
            outcome.append(fs_guard.read_bytes_at_most(fifo, 100))
        except OSError as e:
            outcome.append(e)

    worker = threading.Thread(target=attempt, daemon=True)
    worker.start()
    worker.join(timeout=5)
    if worker.is_alive():
        with open(fifo, "wb"):  # unblock the reader so the thread can finish
            pass
        pytest.fail("reading a FIFO blocked")
    assert outcome and isinstance(outcome[0], OSError), outcome


@pytest.mark.parametrize("registered", [True, False], ids=["in-a-root", "outside"])
def test_control_a_regular_file_is_read_up_to_the_limit(tree, tmp_path, registered):
    root, _ = tree
    directory = root / "source" if registered else tmp_path / "unregistered"
    directory.mkdir(exist_ok=True)
    (directory / "out.log").write_bytes(b"0123456789")

    assert fs_guard.read_bytes_at_most(directory / "out.log", 4) == b"0123"
    assert fs_guard.read_bytes_at_most(directory / "out.log", 100) == b"0123456789"


def test_a_directory_unlinked_with_eperm_is_classified_by_the_condition(
    tree, monkeypatch
):
    """``unlink_beneath``'s contract: a directory at the final name raises
    IsADirectoryError on every platform. Linux's unlink says EISDIR itself, so
    the normalization that reads the condition - an lstat confirming a
    directory - only runs where unlink says EPERM instead (macOS). This cell
    simulates that answer, so a Linux run exercises the arm too."""
    root, _ = tree
    (root / "source" / "worker.json").mkdir()

    def _eperm(*args, **kwargs):
        raise PermissionError(errno.EPERM, "Operation not permitted")

    monkeypatch.setattr(os, "unlink", _eperm)

    with pytest.raises(IsADirectoryError):
        fs_guard.unlink_beneath(root, ("source", "worker.json"))
    assert (root / "source" / "worker.json").is_dir()


def test_a_file_unlinked_with_eperm_keeps_its_own_error(tree, monkeypatch):
    """The control for the cell above: EPERM over a regular file is a
    permission problem, not a directory, and is raised as it came."""
    root, _ = tree
    (root / "source" / "worker.json").write_text("{}", encoding="utf-8")

    def _eperm(*args, **kwargs):
        raise PermissionError(errno.EPERM, "Operation not permitted")

    monkeypatch.setattr(os, "unlink", _eperm)

    with pytest.raises(PermissionError) as excinfo:
        fs_guard.unlink_beneath(root, ("source", "worker.json"))
    assert not isinstance(excinfo.value, IsADirectoryError)

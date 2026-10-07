# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""ASH's own writes into a results directory never follow a link placed there."""

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
    with pytest.raises(OSError):
        with fs_guard.open_for_write(root / "source" / "out.log") as f:
            f.write("x")
    assert list(elsewhere.iterdir()) == []


def test_a_link_at_the_file_name_is_replaced_not_followed(tree):
    root, elsewhere = tree
    victim = elsewhere / "victim.txt"
    victim.write_text("original\n")
    target = root / "source" / "out.log"
    target.symlink_to(victim)
    with fs_guard.open_for_write(target) as f:
        f.write("written\n")
    assert victim.read_text() == "original\n"
    assert not target.is_symlink()
    assert target.read_text() == "written\n"


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

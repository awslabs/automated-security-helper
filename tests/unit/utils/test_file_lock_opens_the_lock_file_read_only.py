# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``exclusive_lock`` opens its lock file read-only.

The lock file is created 0o644 and never removed, so when two users share a
tool's cache the second one finds a lock file the first one owns: readable, not
writable. ``flock`` works on a read-only descriptor, so opening the file for
reading serializes the second user's update; opening it for writing raised
``PermissionError`` before the lock was ever taken, and the content-database
refresh failed.
"""

from __future__ import annotations

import os
import stat
import sys

import pytest

from automated_security_helper.utils import file_lock

pytestmark = pytest.mark.unit


def test_the_lock_file_is_opened_for_reading_only(tmp_path, monkeypatch):
    opened = []
    real_open = os.open

    def recording_open(path, flags, *args, **kwargs):
        opened.append((os.fspath(path), flags))
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(file_lock.os, "open", recording_open)

    with file_lock.exclusive_lock(tmp_path / "cache" / ".lock"):
        pass

    (path, flags), *_ = [
        entry for entry in opened if entry[0].endswith(os.path.join("cache", ".lock"))
    ]
    assert flags & os.O_CREAT
    assert flags & os.O_ACCMODE == os.O_RDONLY
    assert (tmp_path / "cache" / ".lock").is_file()


@pytest.mark.skipif(
    sys.platform == "win32" or (hasattr(os, "geteuid") and os.geteuid() == 0),
    reason="a read-only file is writable to the superuser and to Windows' owner",
)
def test_a_lock_file_this_user_cannot_write_is_still_locked(tmp_path):
    lock_file = tmp_path / "shared" / ".lock"
    lock_file.parent.mkdir()
    lock_file.touch()
    lock_file.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)

    entered = False
    with file_lock.exclusive_lock(lock_file):
        entered = True

    assert entered

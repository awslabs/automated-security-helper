# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An atomic write of a long target name does not fail at its staging file.

open_for_atomic_write writes through a staging file named after the target plus
the pid, 32 hex digits and ``.tmp``, about 46 more bytes. A target whose name a
plain open accepts (up to NAME_MAX, 255 bytes) could therefore fail with
ENAMETOOLONG at the staging open. The staging name is now shortened to fit.
"""

import os
import sys

import pytest

from automated_security_helper.utils.sandbox import fs_guard

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(
        sys.platform == "win32", reason="MAX_PATH bounds the whole path, not the name"
    ),
]


def _long_name(length: int) -> str:
    return "n" * (length - len(".out")) + ".out"


def test_a_staging_name_fits_name_max_whatever_the_target_name():
    for length in (1, 200, 209, 210, 220, 255):
        staging = fs_guard._staging_name(_long_name(length))
        assert len(os.fsencode(staging)) <= fs_guard._NAME_MAX, (length, staging)
        assert staging.startswith(".") and staging.endswith(".tmp"), staging
        assert f".{os.getpid()}." in staging, staging


def test_a_short_target_name_keeps_the_whole_name_in_its_staging_name():
    staging = fs_guard._staging_name("report.json")
    assert staging.startswith(".report.json."), staging


def test_two_staging_names_for_one_long_target_differ():
    name = _long_name(255)
    assert fs_guard._staging_name(name) != fs_guard._staging_name(name)


def test_a_target_name_a_plain_open_accepts_is_written_atomically(tmp_path):
    target = tmp_path / _long_name(255)
    try:
        with open(target, "w") as handle:
            handle.write("plain\n")
    except OSError as error:
        pytest.skip(f"this filesystem refuses a 255-byte name: {error}")

    with fs_guard.open_for_atomic_write(target) as handle:
        handle.write("atomic\n")

    assert target.read_text() == "atomic\n"
    assert sorted(p.name for p in tmp_path.iterdir()) == [target.name], (
        "no staging file is left behind"
    )


def test_replace_without_following_accepts_a_target_name_a_plain_open_accepts(
    tmp_path,
):
    """The operator-named destination writer (``ash get-genai-guide --output``)
    stages through the same name shape, so the same bound applies to it."""
    target = tmp_path / _long_name(255)
    try:
        with open(target, "w") as handle:
            handle.write("plain\n")
    except OSError as error:
        pytest.skip(f"this filesystem refuses a 255-byte name: {error}")

    fs_guard.replace_without_following(target, "replaced\n")

    assert target.read_text() == "replaced\n"
    assert sorted(p.name for p in tmp_path.iterdir()) == [target.name], (
        "no staging file is left behind"
    )


def test_a_staging_name_fits_the_directorys_own_name_limit(tmp_path, monkeypatch):
    """A filesystem can accept fewer bytes than NAME_MAX (eCryptfs accepts 143):
    the staging name fits the limit the target's directory reports."""

    def pathconf(path, name):
        assert name == "PC_NAME_MAX"
        assert os.fspath(path) == os.fspath(tmp_path)
        return 143

    monkeypatch.setattr(os, "pathconf", pathconf, raising=False)

    staging = fs_guard._staging_name(_long_name(140), tmp_path)

    assert len(os.fsencode(staging)) <= 143, staging
    assert staging.endswith(".tmp") and f".{os.getpid()}." in staging, staging


def test_the_name_limit_falls_back_to_name_max_when_it_cannot_be_read(
    tmp_path, monkeypatch
):
    def failing_pathconf(path, name):
        raise OSError(22, "Invalid argument", os.fspath(path))

    monkeypatch.setattr(os, "pathconf", failing_pathconf, raising=False)

    assert fs_guard._name_max(tmp_path) == fs_guard._NAME_MAX
    assert fs_guard._name_max(None) == fs_guard._NAME_MAX


def test_a_name_limit_above_name_max_is_capped(tmp_path, monkeypatch):
    monkeypatch.setattr(os, "pathconf", lambda path, name: 1020, raising=False)

    assert fs_guard._name_max(tmp_path) == fs_guard._NAME_MAX


def test_the_writers_ask_the_targets_directory_for_its_limit(tmp_path, monkeypatch):
    """Both staging writers pass the target's directory, so a directory whose
    filesystem accepts fewer bytes gets a staging name that fits it."""
    asked = []
    real_pathconf = getattr(os, "pathconf", None)

    def pathconf(path, name):
        asked.append(os.fspath(path))
        if real_pathconf is None:
            return fs_guard._NAME_MAX
        return real_pathconf(path, name)

    monkeypatch.setattr(os, "pathconf", pathconf, raising=False)
    target = tmp_path / "report.json"

    with fs_guard.open_for_atomic_write(target) as handle:
        handle.write("atomic\n")
    fs_guard.replace_without_following(target, "replaced\n")

    assert asked == [os.fspath(tmp_path), os.fspath(tmp_path)], asked
    assert target.read_text() == "replaced\n"


@pytest.mark.skipif(not hasattr(os, "fpathconf"), reason="asks through a descriptor")
def test_a_guarded_atomic_write_asks_the_open_directory_for_its_limit(
    tmp_path, monkeypatch
):
    """Below a root the atomic writer holds the target's directory open, created
    a moment ago when it was missing; the limit is asked through that descriptor.
    Asked by the spelled name before the directory existed, pathconf failed and
    the limit fell back to the ceiling, which is the case the limit is for."""
    root = fs_guard.register_writable_root(tmp_path / "out")
    asked_by_fd = []
    asked_by_name = []
    real_fpathconf = os.fpathconf

    def fpathconf(fd, name):
        asked_by_fd.append(name)
        return 143 if name == "PC_NAME_MAX" else real_fpathconf(fd, name)

    def pathconf(path, name):
        asked_by_name.append(os.fspath(path))
        return 255

    monkeypatch.setattr(os, "fpathconf", fpathconf)
    monkeypatch.setattr(os, "pathconf", pathconf, raising=False)
    target = root / "new" / _long_name(140)
    try:
        with fs_guard.open_for_atomic_write(target) as handle:
            handle.write("atomic\n")
    finally:
        fs_guard.release_writable_root(root)

    assert asked_by_fd == ["PC_NAME_MAX"], asked_by_fd
    assert asked_by_name == [], asked_by_name
    assert target.read_text() == "atomic\n"
    assert sorted(p.name for p in target.parent.iterdir()) == [target.name]

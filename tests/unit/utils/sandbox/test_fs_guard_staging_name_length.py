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

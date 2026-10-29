# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scan of a directory below ``/src`` inside the ASH image counts as launched.

``_started_by_the_launcher`` recognized a hand-written ``docker run`` of the image
only when the scanned directory was exactly ``/src``. A scan of ``/src/<sub>``, or
of a workspace project below the mount, was taken for a host scan, so git inside
the container labeled it: the mount's own relative path, or the absolute ``/src``
path, which no repository on the host has. The directory is inside the same mount,
so it is judged as the mount is: launched, and with no ASH_SCAN_SOURCE it records
no label rather than the container's.
"""

from __future__ import annotations

import sys

import pytest

from automated_security_helper.utils.scan_source import _started_by_the_launcher

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(
        sys.platform == "win32", reason="the container's /src mount is a POSIX path"
    ),
]

IN_CONTAINER = {"ASH_IN_CONTAINER": "YES"}


@pytest.mark.parametrize("source_dir", ["/src/sub", "/src/projects/api", "/src/a/b/c"])
def test_a_directory_below_the_mount_is_launched(source_dir):
    assert _started_by_the_launcher(source_dir, IN_CONTAINER)


def test_control_the_mount_itself_is_launched():
    assert _started_by_the_launcher("/src", IN_CONTAINER)


@pytest.mark.parametrize("source_dir", ["/srcx", "/src2/sub", "/other/src"])
def test_control_a_look_alike_outside_the_mount_is_not(source_dir):
    assert not _started_by_the_launcher(source_dir, IN_CONTAINER)


def test_control_outside_the_container_nothing_is_launched():
    assert not _started_by_the_launcher("/src/sub", {})

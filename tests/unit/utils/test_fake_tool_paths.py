# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A path a test gives a fake tool is one the host's lookup counts as absolute.

ASH starts a program given by path only when the path names a place without
reference to the working directory (``subprocess_utils._is_anchored``). On Windows
that takes a drive or a UNC share, and ``/usr/bin/firejail`` has neither, so the
lookup reads it as rooted on whichever drive is current, refuses it, and a test that
stood a fake at that path never reaches the code it is about.

``fake_tool_path`` spells such a path so every host anchors it. The tests below read
both spellings with Windows rules (``ntpath``) and POSIX rules (``posixpath``), so
they hold on every host and show why the helper exists.
"""

import ntpath
import posixpath
from types import SimpleNamespace

import pytest

from automated_security_helper.utils.subprocess_utils import _is_anchored
from tests.utils import fake_tool_paths
from tests.utils.fake_tool_paths import fake_tool_path


def test_a_posix_spelling_is_not_anchored_on_windows():
    assert not _is_anchored("/usr/bin/firejail", ntpath)


def test_the_windows_spelling_is_anchored_on_windows():
    assert _is_anchored(fake_tool_path("/usr/bin/firejail", windows=True), ntpath)


def test_the_posix_spelling_is_anchored_on_posix():
    assert _is_anchored(fake_tool_path("/usr/bin/firejail", windows=False), posixpath)


def test_off_windows_the_path_is_returned_as_given():
    assert fake_tool_path("/opt/uv/bin/uv", windows=False) == "/opt/uv/bin/uv"


def test_on_windows_the_path_keeps_its_directories_and_its_name():
    spelled = fake_tool_path("/opt/uv/bin/uv", windows=True)

    assert ntpath.dirname(spelled) == "C:/opt/uv/bin"
    assert ntpath.basename(spelled) == "uv"


@pytest.mark.parametrize(
    "os_name, expected",
    [("nt", "C:/usr/bin/firejail"), ("posix", "/usr/bin/firejail")],
)
def test_the_host_is_read_when_the_path_is_spelled(monkeypatch, os_name, expected):
    """A host that reports itself after the module was imported is the one followed.

    ASH asks the real ``os.path`` whether a path is anchored, and that module is
    chosen by ``os.name``. Only the helper's name for the module is replaced here, so
    nothing else sees a different ``os.name``.
    """
    monkeypatch.setattr(fake_tool_paths, "os", SimpleNamespace(name=os_name))

    assert fake_tool_path("/usr/bin/firejail") == expected


@pytest.mark.parametrize("windows", [False, True])
@pytest.mark.parametrize("relative", ["bin/uv", "uv", ""])
def test_a_path_that_is_not_absolute_is_refused(relative, windows):
    with pytest.raises(ValueError, match="absolute POSIX path"):
        fake_tool_path(relative, windows=windows)

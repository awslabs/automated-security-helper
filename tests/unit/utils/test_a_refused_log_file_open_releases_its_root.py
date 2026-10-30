# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A log file whose open the guard refuses raises the refusal and keeps no root.

Why this exists
---------------
LogFileHandler registers the directory holding its file as a guarded root, then
lets FileHandler open the file. FileHandler opens it before the base class makes
the handler's lock, so a refusal from the guard's open raised out of __init__
with no ``lock`` attribute yet. The except branch released the root under the
handler's lock, read ``self.lock``, and the AttributeError it raised replaced the
guard's refusal; the release never ran, so the output directory stayed a guarded
root for the life of the process.
"""

from __future__ import annotations

import pytest

from automated_security_helper.utils.log import LogFileHandler
from automated_security_helper.utils.sandbox import fs_guard

pytestmark = pytest.mark.unit


class Refusal(OSError):
    """Stands for the guard's refusal of an open."""


def _registered(directory) -> bool:
    return directory.absolute() in set(fs_guard.registered_roots())


def test_a_refused_open_raises_the_refusal_and_releases_the_root(tmp_path, monkeypatch):
    directory = tmp_path / "output"
    directory.mkdir()

    def refuse(*args, **kwargs):
        raise Refusal("a link in the way")

    monkeypatch.setattr(fs_guard, "open_for_write", refuse)

    with pytest.raises(Refusal, match="a link in the way"):
        LogFileHandler(str(directory / "ash.log"))

    assert not _registered(directory)


def test_a_handler_that_opened_releases_its_root_once_on_close(tmp_path):
    directory = tmp_path / "output"
    directory.mkdir()

    handler = LogFileHandler(str(directory / "ash.log"))
    try:
        assert _registered(directory)
    finally:
        handler.close()
        handler.close()

    assert not _registered(directory)

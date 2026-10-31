# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The staging file of a config write is as private as the config it replaces.

Why this file exists
--------------------
``ash config`` commands write a config through a staging file beside it and
rename the staging file over the config. The staging file is created with the
mode a plain open gives (0o666 less the umask), and the config's own mode was put
on it only after the new text had been written. A 0o600 config that holds
secrets was therefore written into a 0o644 file for as long as the write took,
which another local user could open and read once the text was flushed. The
config's mode is now put on the staging file before the first byte is written.
"""

from __future__ import annotations

import os
import stat
from contextlib import contextmanager
from pathlib import Path
from typing import Any, List

import pytest

from automated_security_helper.cli.config import _write_config_text
from automated_security_helper.utils.sandbox import fs_guard

pytestmark = pytest.mark.unit


class _WatchedHandle:
    """A staging handle that notes the file's mode when the first text arrives."""

    def __init__(self, handle: Any, modes: List[int]) -> None:
        self._handle = handle
        self._modes = modes

    def fileno(self) -> int:
        return self._handle.fileno()

    def write(self, data: Any) -> int:
        if not self._modes:
            status = os.fstat(self._handle.fileno())
            self._modes.append(stat.S_IMODE(status.st_mode))
        return self._handle.write(data)


@pytest.mark.skipif(os.name == "nt", reason="file modes are POSIX modes")
@pytest.mark.skipif(not hasattr(os, "link"), reason="the platform has no hard links")
def test_the_staging_file_has_the_configs_mode_before_the_first_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Red at the base: the mode was carried after ``handle.write``, so the first
    write met a file with the umask-derived mode (0o644 here).

    The config has a second name, which is the case the guard's own mode carry
    skips (it carries the mode of a file with one name only), so the mode the
    first write meets is the one this command sets.
    """
    config = tmp_path / ".ash.yaml"
    config.write_text("token: old\n", encoding="utf-8")
    config.chmod(0o600)
    try:
        os.link(config, tmp_path / "second-name.yaml")
    except OSError as refused:
        pytest.skip(f"this host refuses hard links: {refused}")

    modes: List[int] = []
    real = fs_guard.open_for_atomic_write

    @contextmanager
    def watching(path: Any, *args: Any, **kwargs: Any):
        with real(path, *args, **kwargs) as handle:
            yield _WatchedHandle(handle, modes)

    monkeypatch.setattr(fs_guard, "open_for_atomic_write", watching)
    previous = os.umask(0o022)
    try:
        _write_config_text(config, "token: new\n")
    finally:
        os.umask(previous)

    assert modes == [0o600]
    assert config.read_text(encoding="utf-8") == "token: new\n"
    assert stat.S_IMODE(config.stat().st_mode) == 0o600

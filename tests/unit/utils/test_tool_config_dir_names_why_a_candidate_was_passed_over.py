# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""_new_directory (utils/tool_config_dir.py) names every candidate it passed over.

mkdtemp's OSError used to be dropped, so a full disk or a permission error on a
candidate left the warning and the final error listing only the other candidates'
privacy reasons, with advice to fix TMPDIR's permissions, and an output directory
that did not exist yet was dropped with no entry at all.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from automated_security_helper.utils import tool_config_dir

pytestmark = pytest.mark.unit


@pytest.fixture
def private_everywhere(monkeypatch):
    monkeypatch.setattr(tool_config_dir, "_changeable_by_others", lambda path: None)


def _failing_mkdtemp(failing: Path, error: OSError):
    real = tool_config_dir.tempfile.mkdtemp

    def mkdtemp(prefix="", **kwargs):
        parent = kwargs.get("dir")
        if parent is not None and Path(parent) == failing:
            raise error
        return real(prefix=prefix, **kwargs)

    return mkdtemp


def test_the_warning_names_the_outside_candidate_that_could_not_be_made_in(
    private_everywhere, tmp_path, monkeypatch, caplog
):
    """The temporary directory outside the tree is full; the output directory
    inside it is used, and the warning says why the first was passed over."""
    scan = tmp_path / "scan"
    out = scan / "out"
    out.mkdir(parents=True)
    temp = tmp_path / "temp"
    temp.mkdir()
    monkeypatch.setattr(tool_config_dir.tempfile, "gettempdir", lambda: str(temp))
    monkeypatch.setattr(
        tool_config_dir.tempfile,
        "mkdtemp",
        _failing_mkdtemp(temp.resolve(), OSError(28, "No space left on device")),
    )

    with caplog.at_level(logging.WARNING):
        made = tool_config_dir._new_directory(scan, out)

    assert made.parent == out.resolve()
    assert "No space left on device" in caplog.text, caplog.text
    assert temp.resolve().as_posix() in caplog.text


def test_the_final_error_names_the_mkdtemp_failure_not_only_privacy(
    private_everywhere, tmp_path, monkeypatch
):
    temp = tmp_path / "temp"
    temp.mkdir()
    monkeypatch.setattr(tool_config_dir.tempfile, "gettempdir", lambda: str(temp))
    monkeypatch.setattr(
        tool_config_dir.tempfile,
        "mkdtemp",
        _failing_mkdtemp(temp.resolve(), OSError(30, "Read-only file system")),
    )

    with pytest.raises(OSError) as raised:
        tool_config_dir._new_directory(tmp_path / "scan", None)

    message = str(raised.value)
    assert "Read-only file system" in message, message
    assert temp.resolve().as_posix() in message, message


def test_an_output_directory_that_does_not_exist_yet_is_named(
    private_everywhere, tmp_path, monkeypatch
):
    temp = tmp_path / "temp"
    temp.mkdir()
    monkeypatch.setattr(tool_config_dir.tempfile, "gettempdir", lambda: str(temp))
    monkeypatch.setattr(
        tool_config_dir.tempfile,
        "mkdtemp",
        _failing_mkdtemp(temp.resolve(), OSError(13, "Permission denied")),
    )
    missing = tmp_path / "not-yet"

    with pytest.raises(OSError) as raised:
        tool_config_dir._new_directory(tmp_path / "scan", missing)

    assert "is not a directory yet" in str(raised.value), str(raised.value)
    assert missing.as_posix() in str(raised.value)

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A record that could not be taken says why, and says it at the right level.

Where the platform has no directory descriptors there are no records and no
sweep, and a container-mode run there says nothing about it. A state directory
that cannot be made (a read-only or missing home) is reported as that, at debug
level; the warning that a directory is another user's, or a symlink, is for the
directory that is.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import List

import pytest

from automated_security_helper.interactions import container_leftovers
from automated_security_helper.utils.log import ASH_LOGGER


class _Records(logging.Handler):
    def __init__(self) -> None:
        super().__init__(level=logging.DEBUG)
        self.records: List[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)

    def at(self, level: int) -> List[str]:
        return [r.getMessage() for r in self.records if r.levelno == level]


@pytest.fixture
def logged():
    handler = _Records()
    previous = ASH_LOGGER.level
    ASH_LOGGER.addHandler(handler)
    ASH_LOGGER.setLevel(logging.DEBUG)
    try:
        yield handler
    finally:
        ASH_LOGGER.removeHandler(handler)
        ASH_LOGGER.setLevel(previous)


def test_a_platform_without_directory_descriptors_takes_no_record_and_says_nothing(
    monkeypatch, logged
):
    monkeypatch.setattr(sys, "platform", "win32")

    assert container_leftovers.state_dir() is None
    assert container_leftovers.record_container("ash-scan-1-0a1b2c3d") is None
    assert container_leftovers.sweep_leftover_containers(["unused"]) == []

    assert logged.at(logging.WARNING) == [], logged.at(logging.WARNING)


def test_a_state_directory_that_cannot_be_made_is_reported_as_that_at_debug(
    monkeypatch, logged
):
    def refuse(self, *args, **kwargs):
        raise PermissionError(13, "Permission denied", str(self))

    monkeypatch.setattr(Path, "mkdir", refuse)

    assert container_leftovers.record_container("ash-scan-1-0a1b2c3d") is None

    assert logged.at(logging.WARNING) == [], logged.at(logging.WARNING)
    reasons = [m for m in logged.at(logging.DEBUG) if "could not create" in m]
    assert len(reasons) == 1, logged.at(logging.DEBUG)
    assert "ash-scan-1-0a1b2c3d" in reasons[0]


def test_a_state_directory_that_is_a_symlink_still_gets_the_warning(
    tmp_path, monkeypatch, logged
):
    """The control: the warning stays for the case it describes."""
    real = tmp_path / "real-state"
    real.mkdir()
    link = tmp_path / "linked-state"
    link.symlink_to(real, target_is_directory=True)
    monkeypatch.setenv(container_leftovers.STATE_DIR_ENV, str(link))

    assert container_leftovers.record_container("ash-scan-1-0a1b2c3d") is None

    warnings = logged.at(logging.WARNING)
    assert len(warnings) == 1, warnings
    assert "not a directory of this user's" in warnings[0]

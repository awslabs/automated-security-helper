# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Fixtures shared by the config cells.

``_warned_window`` lived as two copies, one per test file, differing only in
whether the yield handed the set back. The set-yielding form serves both: the
cells that only need isolation ignore the value.

``unjudgeable`` and ``ash_log`` serve the tests for a config file whose directory
walk did not finish: one made the walk unreadable with its own copy of the same
frame check, and each collected ASH_LOGGER's warnings with its own handler. The
frame check now lives once, in ``tests.utils.helpers.link_walk_cannot_examine``, and
``unjudgeable`` calls it.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Callable, Iterator, List

import pytest

from automated_security_helper.config import sandbox_grants
from automated_security_helper.utils.log import ASH_LOGGER
from tests.utils.helpers import ExaminationRefused, link_walk_cannot_examine


@pytest.fixture
def _warned_window():
    """The module's warned set, cleared for the cell and restored after it."""
    saved = set(sandbox_grants._UNVERIFIABLE_WARNED)
    sandbox_grants._UNVERIFIABLE_WARNED.clear()
    try:
        yield sandbox_grants._UNVERIFIABLE_WARNED
    finally:
        sandbox_grants._UNVERIFIABLE_WARNED.clear()
        sandbox_grants._UNVERIFIABLE_WARNED.update(saved)


@pytest.fixture
def unjudgeable(monkeypatch) -> Callable[[Path], ExaminationRefused]:
    """A function that makes one directory component of a name walk unjudgeable.

    ``unjudgeable(component)`` makes ``os.lstat`` of exactly *component* fail as
    an unsearchable parent does, for the link walk's own read. ``_link_state``
    reads the failure as "may be a link nobody here can see", so the walk stops
    undecided. The refusal is scoped to ``_link_state``'s frame: the load of the
    file itself stays real (in production the same EACCES can also end the load,
    which is a refusal of its own and not the sentence under test), and every
    other path and caller keeps the real ``os.lstat``.

    This is ``tests.utils.helpers.link_walk_cannot_examine``, the one shim: it
    checks when it is installed that the walk's read is refused, and returns the
    count of reads it refused.
    """

    def refuse(component: Path) -> ExaminationRefused:
        return link_walk_cannot_examine(monkeypatch, component)

    return refuse


@pytest.fixture
def ash_log() -> Iterator[List[logging.LogRecord]]:
    """ASH_LOGGER's warnings; it does not propagate, so caplog would see none."""
    records: List[logging.LogRecord] = []

    class _Collect(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    handler = _Collect(level=logging.WARNING)
    previous = ASH_LOGGER.level
    ASH_LOGGER.addHandler(handler)
    ASH_LOGGER.setLevel(logging.DEBUG)
    try:
        yield records
    finally:
        ASH_LOGGER.removeHandler(handler)
        ASH_LOGGER.setLevel(previous)

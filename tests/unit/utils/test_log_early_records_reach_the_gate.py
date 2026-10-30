# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A record logged before get_logger reaches the last resort at the set level.

An entry point sets the last resort's level (configure_last_resort_level), and
a record no handler takes is shown when it clears that level. Before
get_logger pins the "ash" logger low, the logger has no level of its own and
takes the root logger's WARNING, which refused an INFO or DEBUG record before
it could reach a level set below WARNING. Setting the level now lowers a
logger that has none; a level somebody set on the logger stays.
"""

import logging

import pytest

from automated_security_helper.utils import log as ash_log
from automated_security_helper.utils.log import ASH_LOGGER

pytestmark = pytest.mark.unit


class _Recording(logging.Handler):
    def __init__(self) -> None:
        # The level the real last resort holds when this is built, so the
        # routing under test reads the configured value and not this stub's.
        super().__init__(level=ash_log._LAST_RESORT.level)
        self.records: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record.getMessage())


@pytest.fixture
def logger_before_get_logger(monkeypatch):
    """The "ash" logger as a process has it before get_logger runs: no level of
    its own, the root logger at WARNING, and no handler on it."""
    root = logging.getLogger()
    root_level = root.level
    ash_level = ASH_LOGGER.level
    held_back = list(ASH_LOGGER.handlers)
    for handler in held_back:
        ASH_LOGGER.removeHandler(handler)
    monkeypatch.setattr(ASH_LOGGER, "propagate", False)
    root.setLevel(logging.WARNING)
    ASH_LOGGER.setLevel(logging.NOTSET)
    yield
    ASH_LOGGER.setLevel(ash_level)
    root.setLevel(root_level)
    for handler in held_back:
        if handler not in ASH_LOGGER.handlers:
            ASH_LOGGER.addHandler(handler)


def test_an_info_line_logged_early_reaches_a_level_set_to_info(
    logger_before_get_logger, monkeypatch
):
    ash_log.configure_last_resort_level(logging.INFO)
    recording = _Recording()
    monkeypatch.setattr(ash_log, "_LAST_RESORT", recording)

    ASH_LOGGER.info("an early info line")

    assert recording.records == ["an early info line"]


def test_a_level_set_on_the_logger_stays(logger_before_get_logger):
    ASH_LOGGER.setLevel(logging.ERROR)

    ash_log.configure_last_resort_level(logging.INFO)

    assert ASH_LOGGER.level == logging.ERROR


def test_a_level_the_logger_already_admits_leaves_it_without_one(
    logger_before_get_logger,
):
    ash_log.configure_last_resort_level(logging.ERROR)

    assert ASH_LOGGER.level == logging.NOTSET

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A plain logger made under "ash" before utils.log was imported becomes an ASHLogger.

Why this exists
---------------
logging gives a logger the class set at the moment it is first asked for.
``utils.severity_ladder`` takes ``logging.getLogger("ash")`` at import, by name
rather than through ``utils.log`` (the import would be a cycle), and
``core.constants`` imports it first in every CLI process, so the "ash" logger was a
plain ``logging.Logger`` before ``utils.log`` could set ``ASHLogger`` as the class:
``isinstance(ASH_LOGGER, ASHLogger)`` read False and ``ASHLogger.callHandlers``, the
run-scoped last-resort walk, never ran for ASH's records. ``utils.log`` now adopts
such a logger in place, at import and at every ``get_logger``.
"""

from __future__ import annotations

import logging

import pytest

from automated_security_helper.utils import log as ash_log
from automated_security_helper.utils.log import ASHLogger

pytestmark = pytest.mark.unit


def _made_before_the_import(monkeypatch, name: str) -> logging.Logger:
    """A plain Logger registered under ``name`` as logging registers one made
    before any setLoggerClass; removed from the registry when the test ends."""
    # A plain Logger on purpose: getLogger would build an ASHLogger now that
    # utils.log has set the class, and the subject is one made before it did.
    plain = logging.Logger(name)  # noqa: LOG001
    monkeypatch.setitem(logging.Logger.manager.loggerDict, name, plain)
    return plain


def test_a_plain_ash_logger_is_adopted_in_place(monkeypatch):
    plain = _made_before_the_import(monkeypatch, "ash.made_before_the_import")
    assert type(plain) is logging.Logger

    ash_log.adopt_early_ash_loggers()

    adopted = logging.getLogger("ash.made_before_the_import")
    assert adopted is plain
    assert isinstance(adopted, ASHLogger)
    assert callable(adopted.verbose) and callable(adopted.trace)


def test_the_ash_logger_itself_made_before_the_import_is_adopted(monkeypatch):
    """The bug as it was: the logger named "ash", not one under it, was the plain
    Logger severity_ladder made at import."""
    plain = _made_before_the_import(monkeypatch, "ash")
    assert type(plain) is logging.Logger

    ash_log.adopt_early_ash_loggers()

    assert logging.getLogger("ash") is plain
    assert isinstance(plain, ASHLogger)
    # The method that never ran for ASH's records while it was plain.
    assert type(plain).callHandlers is ASHLogger.callHandlers


def test_the_adopted_logger_keeps_what_it_had(monkeypatch):
    plain = _made_before_the_import(monkeypatch, "ash.made_with_state")
    handler = logging.NullHandler()
    plain.addHandler(handler)
    plain.setLevel(logging.WARNING)
    plain.propagate = False

    ash_log.adopt_early_ash_loggers()

    assert isinstance(plain, ASHLogger)
    assert plain.handlers == [handler]
    assert plain.level == logging.WARNING
    assert plain.propagate is False


def test_a_logger_outside_ash_is_left_alone(monkeypatch):
    other = _made_before_the_import(monkeypatch, "ashes.not_ours")
    unrelated = _made_before_the_import(monkeypatch, "other.made_before")

    ash_log.adopt_early_ash_loggers()

    assert type(other) is logging.Logger
    assert type(unrelated) is logging.Logger


def test_another_librarys_logger_class_under_ash_is_left_alone(monkeypatch):
    class LibraryLogger(logging.Logger):
        pass

    theirs = LibraryLogger("ash.a_library_made_this")
    monkeypatch.setitem(logging.Logger.manager.loggerDict, theirs.name, theirs)

    ash_log.adopt_early_ash_loggers()

    assert type(theirs) is LibraryLogger


def test_get_logger_adopts_the_logger_it_sets_up(monkeypatch):
    plain = _made_before_the_import(monkeypatch, "ash.made_before_setup")

    configured = ash_log.get_logger("ash.made_before_setup", level="INFO")

    assert configured is plain
    assert isinstance(configured, ASHLogger)

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A handler tagged with a retired run scope takes no record and homes none.

A thread still in a closed run's context can put a handler on the logger (a
run adds its handlers through run_handler), and nothing closes that run again
to take it off. Such an orphan must be inert: it must not take the server's
own lines, and it must not count as a record's home, which would keep the
record from the last resort.
"""

import logging
import threading

import pytest

from automated_security_helper.utils import log as ash_log
from automated_security_helper.utils.log import ASH_LOGGER, ash_handler

pytestmark = pytest.mark.unit


class _Recording(logging.Handler):
    def __init__(self) -> None:
        super().__init__(level=logging.WARNING)
        self.records = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record.getMessage())


def test_a_retired_scopes_handler_takes_nothing_and_homes_nothing(monkeypatch):
    last_resort = _Recording()
    monkeypatch.setattr(ash_log, "_LAST_RESORT", last_resort)
    held_back = list(ASH_LOGGER.handlers)
    for handler in held_back:
        ASH_LOGGER.removeHandler(handler)
    monkeypatch.setattr(ASH_LOGGER, "propagate", False)

    # A hosted run that opened and closed, as a cancelled scan's does.
    scope, token = ash_log.open_run_log_scope()
    ash_log.end_run_log_scope(scope, token)

    # The orphan: a handler a thread still in that run's context would add,
    # tagged and filtered as run_handler tags one.
    orphan = _Recording()
    setattr(orphan, ash_log._RUN_SCOPE_ATTR, scope)
    orphan.addFilter(ash_log._RunScopedFilter(scope))
    ASH_LOGGER.addHandler(ash_handler(orphan))
    try:

        def a_line_no_scan_owns() -> None:
            ASH_LOGGER.warning("a retired-scope marker no scan owns")

        outside = threading.Thread(target=a_line_no_scan_owns)
        outside.start()
        outside.join(30)
    finally:
        ASH_LOGGER.removeHandler(orphan)
        for handler in held_back:
            if handler not in ASH_LOGGER.handlers:
                ASH_LOGGER.addHandler(handler)

    assert not orphan.records, "the retired scope's handler took the line"
    assert any("retired-scope marker" in text for text in last_resort.records), (
        "the line found no live home and never reached the last resort"
    )

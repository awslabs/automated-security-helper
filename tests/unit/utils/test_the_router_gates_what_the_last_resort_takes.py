# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""logging's last resort routes ash records at the configured gate.

A logger under "ash" that is not an ASHLogger -- one made before this package
imported, or after a library set another logger class -- misses
ASHLogger.callHandlers, so its homeless records go to logging.lastResort,
which this package replaces with a router. The router must apply the same
gate the stand-in's own path applies: the configured level, read live. A gate
frozen at the router's construction admits what a quieter configuration
refused and drops what a more verbose one asked for.
"""

import logging

from automated_security_helper.utils import log as ash_log


class _Recording(logging.Handler):
    def __init__(self) -> None:
        super().__init__(level=ash_log._LAST_RESORT.level)
        self.records = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record.getMessage())


def _a_plain_ash_logger() -> logging.Logger:
    """A logger under "ash" that is not an ASHLogger: built directly, with no
    handlers and no parent, so its records go to logging.lastResort."""
    # Direct construction is the probe: getLogger would hand back an ASHLogger,
    # whose own callHandlers path is the one this file is NOT testing.
    return logging.Logger("ash.plain-probe")  # noqa: LOG001


def test_a_record_below_the_configured_gate_is_not_written(monkeypatch):
    real_last_resort = ash_log._LAST_RESORT
    gate_before = real_last_resort.level
    try:
        ash_log.configure_last_resort_level(logging.ERROR)
        recorder = _Recording()
        monkeypatch.setattr(ash_log, "_LAST_RESORT", recorder)
        _a_plain_ash_logger().warning("a warning below the configured gate")
        assert recorder.records == [], (
            "the router wrote a record below the configured gate"
        )
    finally:
        real_last_resort.setLevel(gate_before)


def test_a_record_at_the_configured_gate_is_written(monkeypatch):
    real_last_resort = ash_log._LAST_RESORT
    gate_before = real_last_resort.level
    try:
        ash_log.configure_last_resort_level(logging.INFO)
        recorder = _Recording()
        monkeypatch.setattr(ash_log, "_LAST_RESORT", recorder)
        _a_plain_ash_logger().info("an info line the configuration asked for")
        assert any(
            "the configuration asked for" in text for text in recorder.records
        ), "the router dropped a record the configured gate admits"
    finally:
        real_last_resort.setLevel(gate_before)


def test_a_record_for_another_logger_goes_to_the_kept_fallback(monkeypatch):
    """The router keeps logging's own last resort for everything outside ash,
    at that handler's own level."""
    taken = []

    class _Fallback(logging.Handler):
        def __init__(self) -> None:
            super().__init__(logging.WARNING)

        def emit(self, record: logging.LogRecord) -> None:
            taken.append(record.getMessage())

    router = type(logging.lastResort)(_Fallback())
    router.handle(
        logging.LogRecord("elsewhere", logging.WARNING, __file__, 1, "kept", (), None)
    )
    router.handle(
        logging.LogRecord("elsewhere", logging.DEBUG, __file__, 1, "dropped", (), None)
    )
    assert taken == ["kept"], taken

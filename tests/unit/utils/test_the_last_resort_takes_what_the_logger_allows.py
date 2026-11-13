# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The last resort takes homeless records at the level the operator configured.

A homeless record -- no live handler on the way takes it -- is shown on
stderr when its level clears the configured one: the level the process's
entry point gave configure_last_resort_level, or ASH_LOG_LEVEL read when that
runs, WARNING by default. The gate cannot be the "ash" logger's own level:
get_logger pins that logger at its lowest level so handlers decide, so a gate
read from it would write every tool's debug line to stderr once a scan's
handlers came off. And get_logger must not move the gate either: the MCP
server runs get_logger for every hosted scan (cli/mcp_tools.py starts
interactions/run_ash_scan.py), so a gate set there would clobber the server's
own, process-wide, at the first hosted scan.
"""

import logging
import threading

import pytest

from automated_security_helper.utils import log as ash_log
from automated_security_helper.utils.log import ASH_LOGGER, get_logger

pytestmark = pytest.mark.unit


class _Recording(logging.Handler):
    def __init__(self) -> None:
        # The production stand-in's own level, so the routing gate under test
        # reads the configured value and not this stub's.
        super().__init__(level=ash_log._LAST_RESORT.level)
        self.records = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record.getMessage())


def _only_the_last_resort(monkeypatch):
    last_resort = _Recording()
    monkeypatch.setattr(ash_log, "_LAST_RESORT", last_resort)
    held_back = list(ASH_LOGGER.handlers)
    for handler in held_back:
        ASH_LOGGER.removeHandler(handler)
    monkeypatch.setattr(ASH_LOGGER, "propagate", False)
    return last_resort, held_back


def _put_back(held_back) -> None:
    for handler in held_back:
        if handler not in ASH_LOGGER.handlers:
            ASH_LOGGER.addHandler(handler)


def _an_info_line_logged_outside_every_run(monkeypatch):
    """The homeless INFO line, logged during a hosted scan: what the recording
    last resort saw."""
    last_resort, held_back = _only_the_last_resort(monkeypatch)
    scope, token = ash_log.open_run_log_scope()
    try:

        def an_info_line_no_scan_owns() -> None:
            ASH_LOGGER.info("an info-level homeless marker")

        outside = threading.Thread(target=an_info_line_no_scan_owns)
        outside.start()
        outside.join(30)
    finally:
        ash_log.end_run_log_scope(scope, token)
        _put_back(held_back)
    return last_resort.records


def test_an_info_line_reaches_the_last_resort_once_the_entry_point_asked_for_info(
    monkeypatch,
):
    """Declared the way a process declares it: its entry point configures the
    gate once (the real handler's level, restored by the suite's guard)."""
    real_last_resort = ash_log._LAST_RESORT
    level_before = ASH_LOGGER.level
    gate_before = real_last_resort.level
    try:
        ash_log.configure_last_resort_level(logging.INFO)
        records = _an_info_line_logged_outside_every_run(monkeypatch)
    finally:
        real_last_resort.setLevel(gate_before)
        ASH_LOGGER.setLevel(level_before)

    assert any("info-level homeless marker" in text for text in records), (
        "the entry point asked for INFO and the last resort still dropped it"
    )


def test_a_hosted_scans_logger_setup_leaves_the_gate_alone(monkeypatch):
    """get_logger runs inside the MCP server for every hosted scan
    (cli/mcp_tools.py starts interactions/run_ash_scan.py, whose logger setup
    calls it with the scan's level). The process-wide gate belongs to the
    server's entry point, so the scan's logger setup must not move it."""
    real_last_resort = ash_log._LAST_RESORT
    level_before = ASH_LOGGER.level
    gate_before = real_last_resort.level
    try:
        ash_log.configure_last_resort_level(logging.ERROR)
        get_logger("ash", level=logging.DEBUG, show_progress=True)
        assert real_last_resort.level == logging.ERROR, (
            "a hosted scan's get_logger moved the process-wide gate"
        )
    finally:
        real_last_resort.setLevel(gate_before)
        ASH_LOGGER.setLevel(level_before)


def test_a_logger_setups_own_records_reach_its_handlers_not_the_last_resort(
    monkeypatch, tmp_path
):
    """A process legitimately at INFO (its entry point configured it) runs a
    scan's logger setup: the setup's own records -- "Show debug info" among
    them -- belong to the handlers that setup attaches, and none may fall
    through to the last resort. Logged before the handlers attach they are
    homeless, so the process wrote them to stderr for every logger setup, a
    hosted scan's included; a run of wide tests showed the same line on every
    snapshot's stderr once an earlier setup had run on the worker, which is
    the ordering this cell replays."""
    real_last_resort = ash_log._LAST_RESORT
    gate_before = real_last_resort.level
    level_before = ASH_LOGGER.level
    # The suite's own capture handlers would home every record; held back, as
    # in a real process, where the setup being measured attaches the handlers.
    held_back = list(ASH_LOGGER.handlers)
    for handler in held_back:
        ASH_LOGGER.removeHandler(handler)
    monkeypatch.setattr(ASH_LOGGER, "propagate", False)
    try:
        # The earlier setup on this worker (another test's, in the ordered
        # failure), then the process's own configuration.
        get_logger("ash", level=logging.DEBUG, show_progress=True)
        ash_log.configure_last_resort_level(logging.INFO)
        recorder = _Recording()
        monkeypatch.setattr(ash_log, "_LAST_RESORT", recorder)
        get_logger(
            "ash",
            level=logging.INFO,
            output_dir=str(tmp_path / "out"),
            show_progress=False,
        )
        assert recorder.records == [], (
            "a logger setup's own records fell through to the last resort",
            recorder.records,
        )
    finally:
        real_last_resort.setLevel(gate_before)
        ASH_LOGGER.setLevel(level_before)
        ash_log.remove_ash_handlers(ASH_LOGGER)
        _put_back(held_back)


def test_an_unconfigured_processes_last_resort_stays_at_warning(monkeypatch):
    """With nothing configured, the gate is WARNING: the "ash" logger itself
    runs wide open (get_logger pins it low so handlers decide), so a gate any
    lower writes every tool's debug line to stderr."""
    real_last_resort = ash_log._LAST_RESORT
    level_before = ASH_LOGGER.level
    gate_before = real_last_resort.level
    monkeypatch.delenv("ASH_LOG_LEVEL", raising=False)
    try:
        ash_log.configure_last_resort_level()
        ASH_LOGGER.setLevel(5)  # as get_logger leaves it: the handlers decide
        records = _an_info_line_logged_outside_every_run(monkeypatch)
    finally:
        real_last_resort.setLevel(gate_before)
        ASH_LOGGER.setLevel(level_before)

    assert not any("info-level homeless marker" in text for text in records), (
        "an unconfigured last resort took a line below WARNING"
    )


def test_the_environment_configures_the_gate_when_the_entry_point_names_no_level(
    monkeypatch,
):
    """A process whose entry point names no level reads ASH_LOG_LEVEL when
    configure_last_resort_level runs -- at the start, not at import, so an
    environment set after the module loaded still counts."""
    real_last_resort = ash_log._LAST_RESORT
    gate_before = real_last_resort.level
    try:
        monkeypatch.setenv("ASH_LOG_LEVEL", "INFO")
        ash_log.configure_last_resort_level()
        assert real_last_resort.level == logging.INFO
        monkeypatch.setenv("ASH_LOG_LEVEL", "not-a-level")
        ash_log.configure_last_resort_level()
        assert real_last_resort.level == logging.WARNING
        monkeypatch.delenv("ASH_LOG_LEVEL")
        ash_log.configure_last_resort_level()
        assert real_last_resort.level == logging.WARNING
    finally:
        real_last_resort.setLevel(gate_before)

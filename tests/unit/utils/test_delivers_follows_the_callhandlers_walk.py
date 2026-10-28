# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``delivers`` answers what ``ASHLogger.callHandlers`` will do with a record.

The dump gates (a failed command's stderr dump, a config dump) build
DEBUG-only records exactly when ``delivers`` says something would receive
them. So its walk must match callHandlers': a handler scoped to another run
drops what it is handed (_RunScopedFilter), so it is no delivery, and a
record NO handler on the walk would take goes to the last resort. Counting
any handler as a possible home meant that on the MCP server -- hosted scans
active, their handlers scoped to their runs -- a record of no run's read as
undeliverable while callHandlers in fact hands it to the last resort: the
dump was never built, and the server's own line went missing. Each cell
asks ``delivers`` first, then logs a real record and reads where it landed,
so the two can never drift apart silently.
"""

from __future__ import annotations

import io
import logging

from automated_security_helper.utils import log as log_module


def _fresh_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    # Bound the walk to this cell's handlers: the suite's own "ash" handlers
    # must not home the record.
    logger.propagate = False
    assert not logger.handlers, logger.handlers
    return logger


def test_a_foreign_runs_handler_is_no_delivery(monkeypatch, capsys):
    """A hosted run's handler takes only its run's records: for a record of
    no run's it is not a home, and callHandlers hands the record to the last
    resort. ``delivers`` must say so, or the work is skipped while the
    record it would have built had a reader."""
    logger = _fresh_logger("ash.test_delivers_foreign_run")
    scope, token = log_module.open_run_log_scope()
    handler = logging.StreamHandler(io.StringIO())
    handler.setLevel(logging.INFO)
    log_module.run_handler(handler)
    logger.addHandler(handler)
    # The server's own context: the scan's scope stays active and hosted,
    # but this context belongs to no run, as the MCP tool's does after it
    # hands the scope to the runner.
    log_module.disown_run_log_scope(token)
    monkeypatch.setattr(log_module._LAST_RESORT, "level", logging.DEBUG)
    try:
        predicted = log_module.delivers(logger, logging.DEBUG)
        logger.debug("marker-the-last-resort-takes")
    finally:
        logger.removeHandler(handler)
        log_module.close_run_log_scope(scope)

    landed = "marker-the-last-resort-takes" in capsys.readouterr().err
    assert landed, "the last resort did not take the no-run record"
    assert predicted is True, "delivers denied a record callHandlers delivers"


def test_a_homed_handler_above_the_level_blocks_the_last_resort(monkeypatch, capsys):
    """Control: a scope-free handler is a home even when its level refuses
    the record. callHandlers runs no last resort then, the record lands
    nowhere, and ``delivers`` says False."""
    logger = _fresh_logger("ash.test_delivers_homed_above")
    handler = logging.StreamHandler(io.StringIO())
    handler.setLevel(logging.INFO)
    logger.addHandler(handler)
    monkeypatch.setattr(log_module._LAST_RESORT, "level", logging.DEBUG)
    try:
        predicted = log_module.delivers(logger, logging.DEBUG)
        logger.debug("marker-nobody-takes")
    finally:
        logger.removeHandler(handler)

    assert "marker-nobody-takes" not in capsys.readouterr().err
    assert predicted is False, "delivers promised a delivery nothing makes"


def test_an_admitting_handler_still_delivers(capsys):
    """Control: the plain case is unchanged -- an attached handler whose
    level admits the record is the delivery."""
    logger = _fresh_logger("ash.test_delivers_admitting")
    buffer = io.StringIO()
    handler = logging.StreamHandler(buffer)
    handler.setLevel(logging.DEBUG)
    logger.addHandler(handler)
    try:
        predicted = log_module.delivers(logger, logging.DEBUG)
        logger.debug("marker-the-handler-takes")
    finally:
        logger.removeHandler(handler)

    assert "marker-the-handler-takes" in buffer.getvalue()
    assert predicted is True

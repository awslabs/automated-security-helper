# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Fixtures the ``ash report`` and ``ash merge`` tests share."""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from tests.unit.cli.off_host_plugin_support import (
    DECLARED_ON_PLUGIN,
    DECLARED_ON_SOURCE,
    DECLARED_PLUGIN,
    DECLARED_SOURCE,
    PLUGIN,
    PLUGIN_SOURCE,
    make_plugin_site,
)


@pytest.fixture
def capture(caplog):
    """Route ASH's logger at WARNING into caplog.

    ASH's configured handler renders to a console and leaves nothing in
    ``caplog.records``, so its handlers are swapped for pytest's capture handlers
    for the duration, and the logger's own level is set, since
    ``caplog.at_level`` with no ``logger=`` lowers the root logger only and a
    merge that ran earlier in the process may have left ``ash`` higher. A test
    that asserts ``records == []`` through plain ``caplog`` passes with no capture
    at all; through this fixture the absence is a measurement.

    Here, in the directory's conftest, so every merge test module gets it by
    name without importing another test module for it (``test_merge`` carried
    it, and a module that took it from there had to bind it under its own name
    for pytest to register it).
    """
    from automated_security_helper.utils.log import ASH_LOGGER

    saved_handlers = ASH_LOGGER.handlers
    saved_propagate = ASH_LOGGER.propagate
    capture_handlers = [
        handler
        for handler in saved_handlers
        if isinstance(handler, type(caplog.handler))
    ]
    if caplog.handler not in capture_handlers:
        capture_handlers.append(caplog.handler)
    ASH_LOGGER.handlers = capture_handlers
    ASH_LOGGER.propagate = False
    caplog.set_level(logging.WARNING, logger=ASH_LOGGER.name)
    try:
        yield caplog
    finally:
        ASH_LOGGER.handlers = saved_handlers
        ASH_LOGGER.propagate = saved_propagate


@pytest.fixture
def plugin_site(tmp_path: Path) -> Path:
    """An installed plugin package, outside every scanned tree in these tests.

    The package holds the stand-in off-host reporter that declares no destination
    options (``off_host_plugin_support``); a test makes it importable in a
    subprocess with ``plugin_environment(plugin_site)``.
    """
    return make_plugin_site(tmp_path, PLUGIN, PLUGIN_SOURCE)


@pytest.fixture
def declared_site(tmp_path: Path) -> Path:
    """The stand-in that declares ``endpoint`` as a destination option, off by default."""
    return make_plugin_site(tmp_path, DECLARED_PLUGIN, DECLARED_SOURCE)


@pytest.fixture
def declared_on_site(tmp_path: Path) -> Path:
    """The same stand-in with ``enabled`` on by default."""
    return make_plugin_site(tmp_path, DECLARED_ON_PLUGIN, DECLARED_ON_SOURCE)

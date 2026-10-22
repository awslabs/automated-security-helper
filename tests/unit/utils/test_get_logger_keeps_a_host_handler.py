# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""ASH replaces the logging handlers it added, and only those.

Why this exists
---------------
``get_logger`` and the ``ash`` command's ``reset_logging_config`` run on the
process-wide ``ash`` logger: ``get_logger`` from each CLI command's callback and
from the scan's logger setup (``run_ash_scan._setup_logger``). An application that
embeds ASH may put its own handler on ``ash``, to collect ASH's records into its own
log. Each handler ASH adds is marked, and only marked handlers are replaced or
removed, so the application's handler stays through every scan and command;
calling ``get_logger`` again leaves one of each of ASH's own.
The live progress display's handler is marked too, so a later ``get_logger``
replaces it with the rest.

pytest's capture handlers sit on ``ash`` while a test runs, and they are a host's
handlers as much as the test's own. So each test takes the handlers ``ash`` has
when its body starts, and checks that every one of them ASH did not add is there
at its end, and that ASH's own are gone: replaced, as ASH replaces those an
earlier command left. Neither check assumes ``ash`` starts with no ASH handler on
it.
"""

from __future__ import annotations

import logging

import pytest
from typer.testing import CliRunner

from automated_security_helper.utils.log import added_by_ash, get_logger


class _HostHandler(logging.Handler):
    """A handler an application that embeds ASH puts on a logger."""

    def __init__(self) -> None:
        super().__init__(level=logging.DEBUG)
        self.records: list = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


class _Ash:
    """The ``ash`` logger's handlers when the test body started, and what it added."""

    def __init__(self) -> None:
        self.logger = logging.getLogger("ash")
        self.before = list(self.logger.handlers)

    def added(self) -> list:
        """The handlers on ``ash`` at this point that neither a host nor anything
        before the test put there."""
        return [
            h
            for h in self.logger.handlers
            if not isinstance(h, _HostHandler) and h not in self.before
        ]

    def kept_every_handler_ash_did_not_add(self) -> bool:
        return all(
            h in self.logger.handlers for h in self.before if not added_by_ash(h)
        )

    def replaced_ashs_own(self) -> bool:
        """None of the handlers ASH had added before the test body is still there."""
        return not [
            h for h in self.before if added_by_ash(h) and h in self.logger.handlers
        ]


@pytest.fixture
def cleanup():
    """Afterwards, the host handlers taken off ``ash`` and the root logger, and the
    handlers ASH added during the test closed and taken off. The lists are not
    assigned back: pytest swaps its own capture handlers between the phases of a
    test, and an old list would put back one it had already removed."""
    states: list = []
    yield states
    root = logging.getLogger()
    for logger in (logging.getLogger("ash"), root):
        for handler in [h for h in logger.handlers if isinstance(h, _HostHandler)]:
            logger.removeHandler(handler)
    for state in states:
        for handler in state.added():
            handler.close()
            state.logger.removeHandler(handler)


def _console(**kwargs):
    return get_logger(
        level=logging.INFO, show_progress=False, use_color=False, **kwargs
    )


def test_a_handler_on_ash_survives_get_logger(cleanup):
    ash = _Ash()
    cleanup.append(ash)
    host = _HostHandler()
    ash.logger.addHandler(host)

    logger = _console()
    logger.warning("after get_logger")

    assert logger is ash.logger
    assert host in ash.logger.handlers
    assert ash.kept_every_handler_ash_did_not_add()
    assert ash.replaced_ashs_own()
    assert "after get_logger" in [record.getMessage() for record in host.records]


def test_repeated_get_logger_calls_leave_one_of_ashs_handlers_beside_the_host(
    cleanup, tmp_path
):
    ash = _Ash()
    cleanup.append(ash)
    host = _HostHandler()
    ash.logger.addHandler(host)

    for _ in range(3):
        _console(output_dir=tmp_path, log_format="BOTH")

    assert ash.logger.handlers.count(host) == 1
    assert ash.kept_every_handler_ash_did_not_add()
    assert ash.replaced_ashs_own()
    assert sorted(type(h).__name__ for h in ash.added()) == [
        "ConsoleHandler",
        "LogFileHandler",
        "LogFileHandler",
    ]


def test_get_logger_replaces_the_progress_displays_handler(cleanup):
    from automated_security_helper.core.progress import LiveProgressDisplay

    ash = _Ash()
    cleanup.append(ash)
    host = _HostHandler()
    ash.logger.addHandler(host)
    # Shown, because only a shown display puts its handler on the logger (an
    # unshown one adds none); not started, so no live display runs.
    display = LiveProgressDisplay(show_progress=True)

    # The control: the display put its handler on ash.
    assert display.log_handler in ash.logger.handlers

    _console()

    assert display.log_handler not in ash.logger.handlers
    assert added_by_ash(display.log_handler)
    assert host in ash.logger.handlers


def test_a_handler_on_ash_survives_the_scans_logger_setup(cleanup, tmp_path):
    from automated_security_helper.interactions import run_ash_scan as run_module

    ash = _Ash()
    cleanup.append(ash)
    host = _HostHandler()
    ash.logger.addHandler(host)
    (tmp_path / "src").mkdir()

    run_module._setup_logger(
        run_module.ScanOptions(source_dir=tmp_path / "src", output_dir=tmp_path / "out")
    )

    # The control: the setup did attach ASH's file handler.
    assert any(type(h).__name__ == "LogFileHandler" for h in ash.added())
    assert host in ash.logger.handlers
    assert ash.kept_every_handler_ash_did_not_add()
    assert ash.replaced_ashs_own()


def test_a_handler_on_ash_survives_an_ash_command(cleanup, tmp_path, monkeypatch):
    from automated_security_helper.cli import report as report_module
    from automated_security_helper.cli.main import app

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    calls: list = []
    original = report_module.get_logger

    def recording(*args, **kwargs):
        calls.append(kwargs)
        return original(*args, **kwargs)

    monkeypatch.setattr(report_module, "get_logger", recording)
    ash = _Ash()
    cleanup.append(ash)
    host = _HostHandler()
    ash.logger.addHandler(host)

    # No results there, so the command refuses; it has set up the logger by then.
    CliRunner().invoke(
        app, ["report", "--format", "sarif", "--output-dir", str(tmp_path)]
    )

    # The control: the command's get_logger ran.
    assert calls, "ash report did not set up its logger"
    assert host in ash.logger.handlers


def test_reset_logging_config_removes_only_ashs_handlers(cleanup):
    from automated_security_helper.cli.main import reset_logging_config

    ash = _Ash()
    cleanup.append(ash)
    root = logging.getLogger()
    _console()
    # The control: get_logger attached a handler of ASH's own.
    assert ash.added()
    host, root_host = _HostHandler(), _HostHandler()
    ash.logger.addHandler(host)
    root.addHandler(root_host)
    root_before = [h for h in root.handlers if h is not root_host]

    reset_logging_config()

    assert host in ash.logger.handlers
    assert root_host in root.handlers
    assert ash.kept_every_handler_ash_did_not_add()
    assert ash.replaced_ashs_own()
    assert all(h in root.handlers for h in root_before if not added_by_ash(h))
    assert not [h for h in root_before if added_by_ash(h) and h in root.handlers]
    assert ash.added() == []

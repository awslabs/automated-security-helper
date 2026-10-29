# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""route_library_handlers_through_command_check routes a library's handlers on the
std streams, and leaves every other handler as it was.

Why this exists
---------------
The MCP server calls it after the SDK and uvicorn configure their logging, so the
text a client sent is written with its CI commands broken
(tests/unit/cli/mcp/test_library_log_lines_are_not_ci_commands.py runs the server).
These cells pin what it touches: a RichHandler or a StreamHandler on stdout or
stderr that ASH did not add. A handler ASH added, one writing to a file or a
buffer, and one already routed are left exactly as they were.
"""

from __future__ import annotations

import io
import logging
import sys

import pytest
from rich.console import Console
from rich.logging import RichHandler

from automated_security_helper.utils.command_safe_stream import CommandSafeStream
from automated_security_helper.utils.log import (
    ash_handler,
    route_library_handlers_through_command_check,
)

pytestmark = pytest.mark.unit

LINE = "x ##vso[task.setvariable variable=x]CANB"


@pytest.fixture
def library_logger(tmp_path):
    """A logger of its own, with one handler of each kind, taken off afterwards."""
    logger = logging.getLogger("tests.a_library_handler")
    logger.propagate = False
    handlers = {
        "ash_rich": ash_handler(RichHandler(console=Console(stderr=True))),
        "ash_stream": ash_handler(logging.StreamHandler(sys.stderr)),
        "library_rich": RichHandler(console=Console(stderr=True)),
        "library_stream": logging.StreamHandler(sys.stderr),
        "file": logging.FileHandler(tmp_path / "library.log", encoding="utf-8"),
        "buffer": logging.StreamHandler(io.StringIO()),
    }
    for handler in handlers.values():
        logger.addHandler(handler)
    yield logger, handlers
    for handler in handlers.values():
        logger.removeHandler(handler)
        handler.close()
    logger.propagate = True


def _targets(handlers):
    return {
        name: handler.console if isinstance(handler, RichHandler) else handler.stream
        for name, handler in handlers.items()
    }


def test_only_a_librarys_handlers_on_the_std_streams_are_routed(library_logger):
    _, handlers = library_logger
    before = _targets(handlers)

    route_library_handlers_through_command_check()
    after = _targets(handlers)

    for name in ("ash_rich", "ash_stream", "file", "buffer"):
        assert after[name] is before[name], name
    assert isinstance(handlers["library_stream"].stream, CommandSafeStream)
    assert handlers["library_stream"].stream.target is before["library_stream"]
    assert isinstance(handlers["library_rich"].console.file, CommandSafeStream)


def test_a_second_call_changes_nothing(library_logger):
    _, handlers = library_logger
    route_library_handlers_through_command_check()
    routed = _targets(handlers)

    route_library_handlers_through_command_check()

    assert _targets(handlers) == routed
    assert all(_targets(handlers)[name] is routed[name] for name in routed)


def test_a_handler_on_an_already_checked_std_stream_is_not_wrapped_again(monkeypatch):
    """The server's start wraps sys.stderr before uvicorn builds its handlers,
    so a library handler can hold the wrap itself: routing leaves it as it is.
    A second wrap repeated the check with a line state of its own."""
    target = io.TextIOWrapper(io.BytesIO(), encoding="utf-8", write_through=True)
    wrap = CommandSafeStream(lambda: target)
    monkeypatch.setattr(sys, "stderr", wrap)
    logger = logging.getLogger("tests.a_library_handler.checked")
    logger.propagate = False
    handler = logging.StreamHandler(sys.stderr)
    logger.addHandler(handler)
    try:
        route_library_handlers_through_command_check()
        stream = handler.stream
    finally:
        logger.removeHandler(handler)
        logger.propagate = True

    assert stream is wrap, stream


def test_a_routed_rich_handler_keeps_its_console_width_and_theme(capsys):
    """Only the stream under the library's console is wrapped: its width, color
    and theme are the library's own, and a console of ASH's in its place lost
    them."""
    from rich.style import Style
    from rich.theme import Theme

    console = Console(
        stderr=True, width=123, theme=Theme({"logging.level.warning": "magenta"})
    )
    handler = RichHandler(console=console)
    logger = logging.getLogger("tests.a_library_handler.rich")
    logger.propagate = False
    logger.addHandler(handler)
    try:
        route_library_handlers_through_command_check()
        kept = (
            handler.console is console,
            handler.console.width,
            handler.console.get_style("logging.level.warning"),
        )
        logger.warning(LINE)
        err = capsys.readouterr().err
    finally:
        logger.removeHandler(handler)
        logger.propagate = True

    assert kept == (True, 123, Style.parse("magenta")), kept
    # The control: the line was written.
    assert "CANB" in err, err
    assert "##vso[" not in err, err


def test_a_routed_handler_writes_the_line_with_its_command_broken(capsys):
    # Built in the test body: capsys's sys.stderr during setup is not the one the
    # body has.
    logger = logging.getLogger("tests.a_library_handler.routed")
    logger.propagate = False
    handler = logging.StreamHandler(sys.stderr)
    logger.addHandler(handler)
    try:
        route_library_handlers_through_command_check()
        logger.warning(LINE)
        err = capsys.readouterr().err
    finally:
        logger.removeHandler(handler)
        logger.propagate = True

    # The control: the line was written.
    assert "CANB" in err, err
    assert "##vso[" not in err, err

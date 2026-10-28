# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""get_logger's console writes no color escapes off a terminal, on Windows as elsewhere.

A child ``ash`` run by a test or a script has its output captured through a
pipe. On Linux and macOS get_logger built its console with Rich's "auto" color
system, which detects no terminal behind a pipe and writes plain text. On
Windows it asked for the "windows" color system by name, and an explicit color
system is used whatever the file is, so the same captured output carried
``\\x1b[`` escapes around every level name and, through Rich's highlighter,
around every number inside a message: a test that looked for
"ParserError at line 2" in the child's output found
"ParserError at line \\x1b[1;36m2\\x1b[0m" instead, on Windows only.

The console is built as get_logger builds it, with the platform standing in
for Windows and the console's stream a plain in-memory file (not a terminal),
and a record with a number in it is logged. The POSIX platform is the control:
it reads the same before and after the change.
"""

from __future__ import annotations

import io
import itertools
import logging
import sys

import pytest

from automated_security_helper.utils import log
from automated_security_helper.utils.log import get_logger
from tests.utils.windows_console import windows_logging_kept_in_the_test

_names = itertools.count()

#: Holds a number, which the highlighter colors on a terminal. Rich lays a log
#: record out in columns and wraps the message at the console width (80 off a
#: terminal), so the output is compared with its whitespace squeezed out, as
#: the tests that read a child's output do.
MESSAGE = "ParserError at line 2, column 1"


def _squeezed(text: str) -> str:
    return "".join(text.split())


def _console_output(monkeypatch: pytest.MonkeyPatch, platform_name: str) -> str:
    """What get_logger's console writes for one error record on *platform_name*,
    into a stream that is not a terminal."""
    monkeypatch.delenv("ASH_LOG_TO_STDERR", raising=False)
    monkeypatch.delenv("ASH_IN_CONTAINER", raising=False)
    monkeypatch.setattr(log.platform, "system", lambda: platform_name)
    # configure_windows_safe_logging takes its Windows branch for a Windows
    # platform; the helper keeps what it sets inside this test.
    windows_logging_kept_in_the_test(monkeypatch)
    stream = io.StringIO()
    assert not stream.isatty()
    monkeypatch.setattr(sys, "stdout", stream)
    logger = get_logger(
        name=f"ash-pipe-escapes-test-{next(_names)}",
        level=logging.INFO,
        show_progress=False,
        use_color=True,
        simple_format=False,
    )
    try:
        logger.error(MESSAGE)
        for handler in logger.handlers:
            handler.flush()
    finally:
        for handler in logger.handlers:
            handler.close()
        logger.handlers = []
    return stream.getvalue()


@pytest.mark.parametrize("platform_name", ["Windows", "Linux"])
def test_the_console_writes_no_escapes_into_a_stream_that_is_not_a_terminal(
    monkeypatch, platform_name
):
    written = _console_output(monkeypatch, platform_name)

    assert "\x1b[" not in written, ascii(written)
    assert _squeezed(MESSAGE) in _squeezed(written), ascii(written)
    assert "ERROR" in written, ascii(written)

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A converter's refusal warning shows a name's undecodable byte as one escape.

record_refused_input shows the whole warning with shown_on_one_line, so a lone
surrogate in a name is written ``\\udce9`` and the message is a ShownText. The
console and ash.log leave a ShownText as it is (utils/log.py's console_text), so
each shows that escape once, as it reads in the record, and not with its backslash
doubled, as text shown twice would. The record holds the same text as a plain str.
"""

from __future__ import annotations

import logging

import pytest

from automated_security_helper.plugin_modules.ash_builtin.converters.archive_converter import (
    ArchiveConverter,
    ArchiveConverterConfig,
)
from automated_security_helper.utils.log import TextFileFormatter, console_text
from automated_security_helper.utils.scanned_tree import TreeInputRefused
from automated_security_helper.utils.terminal_text import ShownText

pytestmark = pytest.mark.unit


@pytest.fixture
def ash_warnings():
    records: list[logging.LogRecord] = []

    class _Collector(logging.Handler):
        def emit(self, record):
            records.append(record)

    handler = _Collector(level=logging.WARNING)
    logger = logging.getLogger("ash")
    logger.addHandler(handler)
    try:
        yield records
    finally:
        logger.removeHandler(handler)


@pytest.mark.parametrize("member", [None, "secr\udce9t/m.js"], ids=["input", "member"])
def test_the_console_and_ash_log_show_the_escape_once(
    test_plugin_context, ash_warnings, member
):
    converter = ArchiveConverter(
        context=test_plugin_context, config=ArchiveConverterConfig()
    )

    converter.record_refused_input(
        TreeInputRefused("lib/b\udce9.tar", "it is a symbolic link"), member=member
    )

    (warning,) = ash_warnings
    assert isinstance(warning.msg, ShownText) and not warning.args
    message = warning.getMessage()
    for shown in (
        console_text(warning, message),
        TextFileFormatter("%(message)s").format(warning),
    ):
        shown.encode("utf-8")
        assert "'lib/b\\udce9.tar'" in shown
        assert "\\\\udce9" not in shown
        if member is not None:
            assert "'secr\\udce9t/m.js'" in shown
    (refused,) = converter.refused_inputs
    assert refused.path == "lib/b\\udce9.tar"
    assert type(refused.path) is str


@pytest.mark.parametrize(
    "name",
    ["x\n::add-mask::secret.js", "::warning::secret.js", "x\r\n##[group]secret.js"],
    ids=["newline-then-command", "command-first", "crlf-then-hash-command"],
)
def test_the_warning_is_one_line_with_no_command_in_it(
    test_plugin_context, ash_warnings, name
):
    """A name's line break is written as its escape, so the warning is one line on
    the console and in ash.log: the "::" after it starts no line, and a "##[",
    which is a command anywhere in a line, is broken. A CI runner reads no command
    in it."""
    converter = ArchiveConverter(
        context=test_plugin_context, config=ArchiveConverterConfig()
    )

    converter.record_refused_input(
        TreeInputRefused(f"lib/{name}", "it is a symbolic link"), member=name
    )

    (warning,) = ash_warnings
    message = warning.getMessage()
    for shown in (
        console_text(warning, message),
        TextFileFormatter("%(message)s").format(warning),
    ):
        assert "\n" not in shown and "\r" not in shown, ascii(shown)
        assert shown.startswith("Skipped"), shown
        assert "##[" not in shown, shown
        assert "secret.js" in shown, shown

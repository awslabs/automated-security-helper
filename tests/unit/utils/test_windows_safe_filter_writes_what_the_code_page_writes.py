# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""WindowsSafeFilter escapes only what the console's code page cannot write.

The filter is on for every console whose encoding cannot write ASH's own emoji,
which is every code page but UTF-8, and it put the whole message in ASCII: a
cp1252 console showed "é" as ``\\xe9``, a cp1251 console Cyrillic and a cp932
console Japanese as ``\\uNNNN``. And the doubled backslash that tells an escape
the filter wrote from the same text in the message covered only U+0080 to U+00FF,
so JSON's ``\\u0151`` in a suggested command was doubled on every code page.

The filter now asks the console's streams what they write. A CI runner, whose
log is read by something else, and a stream that names no encoding Python knows
keep the ASCII rule.
"""

from __future__ import annotations

import io
import logging

import pytest

from automated_security_helper.utils import log
from automated_security_helper.utils.log import WindowsSafeFilter
from automated_security_helper.utils.terminal_text import (
    shown_in_ascii,
    shown_not_obeyed,
)

pytestmark = pytest.mark.unit

E_ACUTE = "\N{LATIN SMALL LETTER E WITH ACUTE}"
O_DOUBLE_ACUTE = "\N{LATIN SMALL LETTER O WITH DOUBLE ACUTE}"
ZHE = "\N{CYRILLIC CAPITAL LETTER ZHE}"
SUN = "\N{CJK UNIFIED IDEOGRAPH-65E5}"


def _stream(encoding: str) -> io.TextIOWrapper:
    return io.TextIOWrapper(io.BytesIO(), encoding=encoding, errors="strict")


def _console(monkeypatch, stdout: str, stderr: str | None = None) -> None:
    monkeypatch.setattr(log, "_on_a_ci_runner", lambda: False)
    monkeypatch.setattr("sys.stdout", _stream(stdout))
    monkeypatch.setattr("sys.stderr", _stream(stderr or stdout))


def _active_filter(monkeypatch, stdout: str, stderr: str | None = None):
    _console(monkeypatch, stdout, stderr)
    monkeypatch.setattr(log, "_detect_encoding_issues", lambda: True)
    return WindowsSafeFilter()


def _shown(windows: WindowsSafeFilter, message: str) -> str:
    record = logging.LogRecord("ash", logging.INFO, __file__, 1, message, (), None)
    assert windows.filter(record)
    return str(record.msg)


@pytest.mark.parametrize(
    ("encoding", "writes", "does_not_write"),
    [
        ("cp1252", E_ACUTE, ZHE),
        ("cp1251", ZHE, E_ACUTE),
        ("cp932", SUN, E_ACUTE),
        ("cp1250", O_DOUBLE_ACUTE, ZHE),
    ],
)
def test_the_console_writes_what_its_code_page_encodes(
    monkeypatch, encoding, writes, does_not_write
):
    _console(monkeypatch, encoding)

    writes_it = log._console_writes()

    assert writes_it is not None
    assert writes_it(writes) is True
    assert writes_it(does_not_write) is False


def test_a_character_is_written_only_when_both_streams_write_it(monkeypatch):
    _console(monkeypatch, "cp1251", "cp1252")

    writes_it = log._console_writes()

    assert writes_it is not None
    assert writes_it(ZHE) is False
    assert writes_it(E_ACUTE) is False


def test_a_ci_runner_keeps_the_ascii_rule(monkeypatch):
    _console(monkeypatch, "cp1252")
    monkeypatch.setattr(log, "_on_a_ci_runner", lambda: True)

    assert log._console_writes() is None


def test_a_stream_naming_no_known_encoding_keeps_the_ascii_rule(monkeypatch):
    _console(monkeypatch, "cp1252")

    class _Unnamed:
        encoding = "not-a-codec"

    monkeypatch.setattr("sys.stderr", _Unnamed())

    assert log._console_writes() is None


def test_the_filter_escapes_only_what_the_code_page_cannot_write(monkeypatch):
    windows = _active_filter(monkeypatch, "cp1252")

    shown = _shown(windows, f"caf{E_ACUTE} {O_DOUBLE_ACUTE} {SUN}")

    assert shown == f"caf{E_ACUTE} \\u0151 \\u65e5"


def test_a_message_the_code_page_writes_whole_is_left_as_logged(monkeypatch):
    windows = _active_filter(monkeypatch, "cp1251")
    message = f"{ZHE} was scanned"

    assert _shown(windows, message) == message


def test_a_filter_with_no_stream_knowledge_still_puts_everything_in_ascii(
    monkeypatch,
):
    windows = _active_filter(monkeypatch, "cp1252")
    windows._writes = None

    assert _shown(windows, f"caf{E_ACUTE} {SUN}") == "caf\\xe9 \\u65e5"


def test_a_json_escape_of_a_character_the_console_writes_is_left_as_it_is(
    monkeypatch,
):
    # The message quotes a path raw and as JSON's escape, as a suggested
    # --config-overrides command does. cp1250 writes the letter, so the escape
    # text is no escape the filter writes for it, and its backslash is single.
    windows = _active_filter(monkeypatch, "cp1250")

    shown = _shown(windows, f"{O_DOUBLE_ACUTE} {SUN} \\u0151")

    assert shown == f"{O_DOUBLE_ACUTE} \\u65e5 \\u0151"


def test_an_escape_text_the_filter_would_write_is_still_told_apart(monkeypatch):
    # cp1252 cannot write this character, so the filter writes ``日`` for it
    # and the message's own text of the same escape has its backslash doubled.
    windows = _active_filter(monkeypatch, "cp1252")

    shown = _shown(windows, f"{SUN} \\u65e5")

    assert shown == "\\u65e5 \\\\u65e5"


def test_a_shown_text_keeps_the_characters_the_stream_writes():
    shown = shown_not_obeyed(f"{E_ACUTE} {SUN}", writable=lambda c: c == E_ACUTE)

    assert shown_in_ascii(shown, {}, lambda c: c == E_ACUTE) == f"{E_ACUTE} \\u65e5"
    assert shown_in_ascii(shown, {}) == "\\xe9 \\u65e5"


def test_an_emoji_the_console_writes_is_not_replaced(monkeypatch):
    windows = _active_filter(monkeypatch, "cp932")

    # cp932 writes the arrows, and not the check mark.
    assert _shown(windows, "a \N{RIGHTWARDS ARROW} b \N{CHECK MARK}") == (
        "a \N{RIGHTWARDS ARROW} b [CHECK]"
    )

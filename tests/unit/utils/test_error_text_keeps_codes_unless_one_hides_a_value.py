# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Escape codes survive redaction in a stream unless a code was concealing a value.

text_without_values redacts the text as written, strips its complete CSI and
OSC sequences, and redacts again. If the second pass hid nothing more than the
first, the first result returns with its codes intact: an unrelated
environment value no longer costs a stream its colors or a progress redraw
("clear line, cursor up"). If stripping exposed a further match (a code
splitting a value), the stripped, redacted text returns, so that value is still
hidden.

error_text, traceback_text and redact_then_split feed results, reports and MCP
payloads, which are not terminals, so they remove every complete code whether
or not a value was hidden: the same error prints the same with no values and
with values that match nothing in it, and neither holds a code.

Control characters are built with chr() here, so this file holds none itself.
"""

import pytest

from automated_security_helper.utils.error_text import (
    error_text,
    redact_then_split,
    shown_tool_stderr,
    text_without_values,
    traceback_text,
)

ESC = chr(0x1B)
RED = ESC + "[31m"
RESET = ESC + "[0m"
CLEAR_LINE = ESC + "[2K"
CURSOR_UP = ESC + "[1A"
CSI_K = ESC + "[K"
LINK = ESC + "]8;;https://example.invalid" + ESC + chr(0x5C)

UNRELATED = ["an-unrelated-environment-value"]


def _raised(error: BaseException) -> BaseException:
    try:
        raise error
    except BaseException as caught:
        return caught


MESSAGES = [
    "bad " + RED + "red" + RESET + " thing",
    "see " + LINK + "link" + LINK + " here",
]


@pytest.mark.parametrize("message", MESSAGES, ids=["csi", "osc"])
def test_error_text_prints_the_same_with_and_without_unrelated_values(message):
    error = RuntimeError(message)

    without = error_text(error, ())
    with_values = error_text(error, UNRELATED)

    assert without == with_values, (without, with_values)
    assert ESC not in without, repr(without)
    assert ESC not in with_values, repr(with_values)


@pytest.mark.parametrize("message", MESSAGES, ids=["csi", "osc"])
def test_traceback_text_prints_the_same_with_and_without_unrelated_values(message):
    error = _raised(RuntimeError(message))

    without = traceback_text(error, ())
    with_values = traceback_text(error, UNRELATED)

    assert without == with_values, (without, with_values)
    assert ESC not in without, repr(without)
    assert ESC not in with_values, repr(with_values)


def test_a_file_name_holding_a_complete_code_loses_the_code_not_the_name():
    """Names as given, minus the complete code: with no values, or values that
    match nothing in the name, the saved text holds no code."""
    name = "/out/a" + RED + "b"
    error = FileNotFoundError(2, "No such file or directory", name)
    expected = "[Errno 2] No such file or directory: '/out/ab'"

    assert error_text(error, ()) == expected
    assert error_text(error, UNRELATED) == expected


def test_a_file_name_holding_a_clear_screen_or_a_link_is_not_saved_raw():
    """The case that matters: a repository chooses a file name, an OSError on it
    is saved into the results file, and the name must not carry a code."""
    for code in (ESC + "[2J", LINK):
        error = _raised(FileNotFoundError(2, "No such file", "/src/a" + code + "b"))

        assert ESC not in error_text(error, ()), repr(error_text(error, ()))
        assert ESC not in traceback_text(error, ()), repr(traceback_text(error, ()))


def test_redact_then_split_removes_codes_with_no_values():
    text = RED + "stored" + RESET + " line\n" + LINK + "two" + LINK + "\n"

    lines = redact_then_split(text, ())

    assert lines == ["stored line", "two"], lines


def test_a_file_name_whose_code_splits_a_value_is_stripped_and_hidden():
    """The security side: a code in the name splits the value, so stripping
    is what hides it, and the stripped text returns."""
    value = "EDGESECRET"
    name = "/out/EDGE" + CSI_K + "SECRET"
    error = FileNotFoundError(2, "No such file or directory", name)

    shown = error_text(error, [value])

    assert value not in shown, repr(shown)
    assert ESC not in shown, repr(shown)


def test_a_value_split_by_a_code_in_a_traceback_is_hidden():
    value = "EDGESECRET"
    error = _raised(RuntimeError("token=EDGE" + CSI_K + "SECRET end"))

    shown = traceback_text(error, [value])

    assert value not in shown, repr(shown)
    assert "SECRET" not in shown, repr(shown)
    assert ESC not in shown, repr(shown)


def test_a_color_line_with_a_value_elsewhere_keeps_its_codes():
    """The streamed container line: colors survive an unrelated value, and the
    value that is present is still hidden."""
    value = "hunter2hunter2"
    line = RED + "scanning" + RESET + " with " + value + " done\n"

    shown = text_without_values(line, [value])

    assert value not in shown, repr(shown)
    assert RED + "scanning" + RESET in shown, repr(shown)


def test_a_progress_redraw_survives_a_value_it_does_not_conceal():
    line = CLEAR_LINE + CURSOR_UP + "progress 40%\r"

    assert text_without_values(line, UNRELATED) == line
    assert text_without_values(line, ()) == line


def test_a_line_whose_code_splits_a_value_is_stripped():
    """The split-value cell: the code is in the TEXT, so the stripped pass
    finds a match the raw pass could not."""
    value = "EDGESECRET"
    line = RED + "token=EDGE" + CSI_K + "SECRET" + RESET + " end\n"

    shown = text_without_values(line, [value])

    assert "SECRET" not in shown, repr(shown)
    assert ESC not in shown, repr(shown)


def test_a_line_with_no_values_is_unchanged():
    line = RED + "plain" + RESET + "\n"

    assert text_without_values(line, ()) == line


def test_a_code_free_error_is_unchanged():
    """The control: nothing to keep or strip, with or without values."""
    error = _raised(RuntimeError("plain failure"))

    assert error_text(error, ()) == "plain failure"
    assert error_text(error, UNRELATED) == "plain failure"
    assert traceback_text(error, ()).endswith("RuntimeError: plain failure\n")
    assert traceback_text(error, ()) == traceback_text(error, UNRELATED)


ABSENT = ["a-value-this-text-never-holds"]

#: Text with no code in it, and the characters a redaction could disturb:
#: quotes, a backslash, a tab, non-ASCII and both line endings.
CODE_FREE = 'it\'s "quoted" back\\slash\ttab café line one\r\nline two\n'


def test_text_without_values_passes_text_through_byte_for_byte():
    """A value that does not occur adds nothing and strips nothing: the output
    is the input, codes included."""
    coded = RED + "kept" + RESET + CLEAR_LINE + " line\n"

    assert text_without_values(CODE_FREE, ABSENT) == CODE_FREE
    assert text_without_values(coded, ABSENT) == coded


def test_the_report_layers_pass_code_free_text_through_byte_for_byte():
    """The control for the storage layers: they strip codes by contract, so on
    text with none the output is the input (redact_then_split as its lines)."""
    assert shown_tool_stderr(CODE_FREE, ABSENT) == CODE_FREE
    assert redact_then_split(CODE_FREE, ABSENT) == CODE_FREE.splitlines()


def test_report_storage_layers_still_remove_every_code():
    """shown_tool_stderr and redact_then_split feed stored report lines, not a
    terminal: their no-codes contract is unchanged by the compare."""
    text = RED + "stored" + RESET + " line\n"

    assert shown_tool_stderr(text, UNRELATED) == "stored line\n"
    assert shown_tool_stderr(text, ()) == "stored line\n"
    assert redact_then_split(text, UNRELATED) == ["stored line"]
    hidden = redact_then_split(text, ["stored"])
    assert "stored" not in "".join(hidden), hidden
    assert ESC not in "".join(hidden), hidden

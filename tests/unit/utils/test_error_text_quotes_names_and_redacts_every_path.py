# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Seven readings of error_text's text, each wrong at the base by one line.

An OSError's file was always rewritten between single quotes, so a name Python
quoted with double quotes (it holds a single quote) came back mismatched. A bare
ValidationError's description was redacted once as written and then stripped of
escape codes, so a value a code split was re-joined in clear. The OSC strip's body
crossed line breaks, so an unterminated OSC on one line deleted every line up to a
BEL lines later. os_error_without_named_file raised for a descriptor filename,
dropped the second file of a two-file error and headed a Windows error with its
mapped errno. log_unexpected_error probed __notes__ on the top error only, logged
an OSError that names a file with exc_info (so the handler's formatter rendered
the name by repr) and logged a ValidationError chain's frames at DEBUG with no
redaction. The values here are placeholders.
"""

from __future__ import annotations

import traceback
from unittest.mock import MagicMock

import pytest
from pydantic import BaseModel, ValidationError

from automated_security_helper.config import config_validator
from automated_security_helper.utils import error_text as module
from automated_security_helper.utils.error_text import (
    carry_environment_values,
    error_text,
    log_unexpected_error,
    os_error_without_named_file,
)

pytestmark = pytest.mark.unit

CANARY = "ash-canary-value-7f3e"


class _Unhidden(BaseModel):
    flag: bool


def _refused() -> ValidationError:
    try:
        _Unhidden.model_validate({"flag": CANARY})
    except ValidationError as error:
        return error
    raise AssertionError("the canary was accepted")


def test_a_file_name_keeps_the_quotes_python_chose():
    error = OSError(2, "No such file or directory", "it's.yaml")
    assert str(error).endswith('"it\'s.yaml"'), "the control: repr double-quotes it"
    assert error_text(error) == '[Errno 2] No such file or directory: "it\'s.yaml"'
    both = OSError(2, "No such file or directory", "a'b", None, 'c"d')
    assert error_text(both).endswith(": \"a'b\" -> 'c\"d'")


def test_a_bare_validation_error_is_redacted_after_the_strip_too(monkeypatch):
    monkeypatch.setattr(
        config_validator,
        "describe_validation_error",
        lambda error, values=(): "Invalid value at 'SEC\x1b[KRET.flag': refused",
    )
    text = error_text(_refused(), ["SECRET"])
    assert "SECRET" not in text, text
    assert "\x1b[" not in text, text


def test_an_unterminated_osc_does_not_swallow_the_lines_behind_it():
    text = "first \x1b]8;;https://host\nsecond line\nthird \x07 line"
    stripped = module._without_escape_codes(text)
    assert "second line" in stripped and "third" in stripped, stripped
    # A terminated one on one line is still removed whole.
    assert module._without_escape_codes("a\x1b]8;;https://host\x07b") == "ab"


def test_os_error_without_named_file_keeps_the_second_file_and_the_code():
    error = OSError(2, "No such file or directory", "a.yaml", None, "b.yaml")
    assert (
        os_error_without_named_file(error, "a.yaml")
        == "[Errno 2] No such file or directory -> 'b.yaml'"
    )
    descriptor = OSError(9, "Bad file descriptor", 3)
    assert os_error_without_named_file(descriptor, "a.yaml") == error_text(descriptor)

    class _Windows(OSError):
        winerror = 3

    windows = _Windows(2, "The system cannot find the path specified", "a.yaml")
    assert os_error_without_named_file(windows, "a.yaml") == (
        "[WinError 3] The system cannot find the path specified"
    )


class _NotesRaise(Exception):
    @property
    def __notes__(self):
        raise RuntimeError("no notes today")


def _raised(error: BaseException) -> BaseException:
    try:
        raise error
    except BaseException as raised:
        return raised


def test_a_raising_notes_lookup_on_a_cause_is_logged_pre_rendered():
    cause = _raised(_NotesRaise("inner"))
    try:
        raise RuntimeError("outer") from cause
    except RuntimeError as error:
        outer = error
    logger = MagicMock()
    log_unexpected_error(logger, outer)
    (message,), kwargs = logger.error.call_args
    assert "exc_info" not in kwargs, kwargs
    assert "Traceback" in str(message) and "outer" in str(message), message


def test_an_os_error_naming_a_file_is_logged_with_the_name_as_given():
    error = _raised(OSError(2, "No such file or directory", "out\\x1b"))
    logger = MagicMock()
    log_unexpected_error(logger, error)
    (message,), kwargs = logger.error.call_args
    assert "exc_info" not in kwargs, kwargs
    assert "'out\\x1b'" in str(message), message
    assert "\\\\x1b" not in str(message), message


def test_the_debug_frames_of_a_validation_error_chain_are_redacted(monkeypatch):
    refused = _refused()
    try:
        raise RuntimeError("wrapped") from refused
    except RuntimeError as error:
        wrapped = error
    carry_environment_values(wrapped, [CANARY])
    monkeypatch.setattr(
        traceback,
        "format_tb",
        lambda tb: [f'  File "/work/{CANARY}/config.py", line 1, in load\n'],
    )
    logger = MagicMock()
    log_unexpected_error(logger, wrapped)
    (frames,), _ = logger.debug.call_args
    assert CANARY not in str(frames), frames
    assert "config.py" in str(frames), frames

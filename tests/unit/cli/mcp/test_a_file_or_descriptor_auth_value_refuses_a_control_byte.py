# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A file or descriptor auth value with a control byte is refused, as the command line refuses it.

An HTTP field value holds visible characters, spaces, tabs and the bytes 0x80 to
0xFF; a control byte (0x00 to 0x1F except the tab, and 0x7F) is not part of one, and a
conforming client never sends it. The command-line form takes visible ASCII only, so it
already refuses all of them. The file and descriptor forms refused only a carriage
return, a line feed and NUL, so ``tok`` plus a form feed started a server that no
conforming client could authenticate against.

The two forms now refuse every control byte but the tab, and keep every byte from 0x80
to 0xFF, which they have always carried exactly.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from automated_security_helper.cli.mcp import (
    _auth_value_from_bytes,
    _resolve_auth_header_value,
)
from automated_security_helper.core.exceptions import ASHValidationError

pytestmark = pytest.mark.unit

#: The refusal for such a value, whichever form carried it.
CONTROL_MESSAGE = "control character"

#: Control bytes, each with its name. The tab is not one: it is legal in a value.
CONTROLS = {
    "nul": b"\x00",
    "start-of-heading": b"\x01",
    "backspace": b"\x08",
    "line-feed": b"\n",
    "vertical-tab": b"\x0b",
    "form-feed": b"\x0c",
    "carriage-return": b"\r",
    "escape": b"\x1b",
    "unit-separator": b"\x1f",
    "delete": b"\x7f",
}

#: The controls that can end a value without being read as its line ending.
ENDING_CONTROLS = {
    name: byte for name, byte in CONTROLS.items() if byte not in (b"\n", b"\r")
}

#: Every byte value a header value may not hold.
REFUSED_BYTES = frozenset([*range(0x09), *range(0x0A, 0x20), 0x7F])


def _from_file(tmp_path: Path, content: bytes) -> str:
    path = tmp_path / "header-value"
    path.write_bytes(content)
    path.chmod(0o600)
    return _resolve_auth_header_value(None, path, None)


def _from_descriptor(content: bytes) -> str:
    read_end, write_end = os.pipe()
    os.write(write_end, content)
    os.close(write_end)
    return _resolve_auth_header_value(None, None, read_end)


@pytest.mark.parametrize("control", CONTROLS.values(), ids=CONTROLS.keys())
def test_a_file_with_a_control_byte_inside_the_value_is_refused(
    tmp_path, control: bytes
) -> None:
    with pytest.raises(ASHValidationError, match=CONTROL_MESSAGE):
        _from_file(tmp_path, b"tok" + control + b"-a\n")


@pytest.mark.parametrize("control", CONTROLS.values(), ids=CONTROLS.keys())
def test_a_descriptor_with_a_control_byte_inside_the_value_is_refused(
    control: bytes,
) -> None:
    with pytest.raises(ASHValidationError, match=CONTROL_MESSAGE):
        _from_descriptor(b"tok" + control + b"-a\n")


@pytest.mark.parametrize("control", CONTROLS.values(), ids=CONTROLS.keys())
def test_a_control_byte_at_the_start_of_the_value_is_refused(
    tmp_path, control: bytes
) -> None:
    with pytest.raises(ASHValidationError, match=CONTROL_MESSAGE):
        _from_file(tmp_path, control + b"tok-a\n")
    with pytest.raises(ASHValidationError, match=CONTROL_MESSAGE):
        _from_descriptor(control + b"tok-a\n")


@pytest.mark.parametrize(
    "control", ENDING_CONTROLS.values(), ids=ENDING_CONTROLS.keys()
)
def test_a_control_byte_at_the_end_of_the_value_is_refused(
    tmp_path, control: bytes
) -> None:
    """A trailing form feed is not a line ending, so it stays in the value and is refused."""
    with pytest.raises(ASHValidationError, match=CONTROL_MESSAGE):
        _from_file(tmp_path, b"tok-a" + control + b"\n")
    with pytest.raises(ASHValidationError, match=CONTROL_MESSAGE):
        _from_descriptor(b"tok-a" + control)


@pytest.mark.parametrize("byte", range(256), ids=lambda byte: f"0x{byte:02x}")
def test_every_byte_is_refused_or_carried_by_its_class(byte: int) -> None:
    """Every byte between other characters: a control is refused, any other is kept
    exactly, as the character latin-1 gives for it."""
    data = b"tok" + bytes([byte]) + b"-a"

    if byte in REFUSED_BYTES:
        with pytest.raises(ASHValidationError, match=CONTROL_MESSAGE):
            _auth_value_from_bytes(data, "the value")
    else:
        assert _auth_value_from_bytes(data, "the value") == "tok" + chr(byte) + "-a"


def test_a_control_refusal_does_not_repeat_the_value(tmp_path) -> None:
    with pytest.raises(ASHValidationError) as from_file:
        _from_file(tmp_path, b"zq9distinct\x0c\n")
    with pytest.raises(ASHValidationError) as from_descriptor:
        _from_descriptor(b"zq9distinct\x0c\n")

    assert "zq9distinct" not in str(from_file.value)
    assert "zq9distinct" not in str(from_descriptor.value)


@pytest.mark.parametrize("control", CONTROLS.values(), ids=CONTROLS.keys())
def test_the_command_line_refuses_the_same_bytes(control: bytes) -> None:
    """Control: the command-line form takes visible ASCII only, so it already refuses
    every byte the other two forms now refuse."""
    value = "tok" + control.decode("latin-1") + "-a"

    with pytest.raises(ASHValidationError, match="visible ASCII"):
        _resolve_auth_header_value(value, None, None)


@pytest.mark.parametrize(
    ("content", "expected"),
    [
        pytest.param(b"tok\tvalue\n", "tok\tvalue", id="tab-between-characters"),
        pytest.param(
            b"tok-\x80\xa0\xe9\xff\n", "tok-\x80\xa0\xe9\xff", id="bytes-above-0x7f"
        ),
        pytest.param(b"Bearer abc 123\r\n", "Bearer abc 123", id="crlf-line-ending"),
        pytest.param(b"!~\n", "!~", id="visible-ends-of-ascii"),
    ],
)
def test_what_the_two_forms_carried_before_is_still_carried(
    tmp_path, content: bytes, expected: str
) -> None:
    """Control: the control check leaves a tab inside the value, the high bytes and a
    line ending alone."""
    assert _from_file(tmp_path, content) == expected
    assert _from_descriptor(content) == expected

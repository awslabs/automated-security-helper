# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A command-line auth value is checked in the bytes the header will carry.

``--auth-header-value-file`` and ``--auth-header-value-fd`` hand the server the
header's bytes, decoded as latin-1, and refuse a line break or NUL. The command-line
form came from the terminal's text instead: Python decodes ``argv`` with the
filesystem encoding, so ``caf`` plus an accented ``e`` was one character that
latin-1 carries as the single byte 0xE9, while a client that sends UTF-8 sends two
bytes. The option check passed it, and no such client could ever match it. A line
break or NUL passed too, where the file route refuses them.

The command-line form takes visible ASCII (letters, digits and punctuation, with
spaces or tabs between them) and nothing else; any other byte goes in a file or a
descriptor, where the bytes are exact. A value in the form the file route would
carry is unchanged.

A space or tab at either end of the value is refused on all three forms. An HTTP
implementation drops that whitespace from a header value, so a value that has it
can never be matched by a request, and every request would be answered 401. The
file and descriptor forms read ``tok`` plus a space and a newline as ``tok`` plus
a space; they refuse it as the command line does. A tab between other characters
is a legal header value and is accepted. The command line takes at most as many
bytes as the other two forms.
"""

from __future__ import annotations

import io
import os
from pathlib import Path
from typing import Dict

import pytest
import typer
from rich.console import Console

from automated_security_helper.cli.mcp import (
    _resolve_auth_header_value,
    mcp_command,
)
from automated_security_helper.core.constants import ASH_EXIT_USAGE_ERROR
from automated_security_helper.core.exceptions import ASHValidationError

HEADER = "X-Ash-Token"
#: A character latin-1 carries as one byte, and two it does not carry, by code point.
E_ACUTE = chr(0xE9)
OUTSIDE_LATIN_1 = chr(0x4E2D) + chr(0x6587)
#: What the filesystem decoding gives for the lone byte 0xE9 in argv.
ESCAPED_BYTE = chr(0xDCE9)

#: Values that are not visible ASCII, each with the reason it is one.
REFUSED = {
    "latin-1-letter": "tok-" + "caf" + E_ACUTE,
    "outside-latin-1": "tok-" + OUTSIDE_LATIN_1,
    "c1-control": "tok-" + chr(0x85),
    "escaped-byte": "tok-" + ESCAPED_BYTE,
    "carriage-return": "tok-a\rb",
    "line-feed": "tok-a\nb",
    "nul": "tok-a\x00b",
    "delete": "tok-a\x7fb",
}

#: Values that start or end with a space or a tab, each with the end it is on.
EDGE_BLANK = {
    "leading-space": " tok-a",
    "trailing-space": "tok-a ",
    "both-spaces": " tok-a ",
    "leading-tab": "\ttok-a",
    "trailing-tab": "tok-a\t",
    "only-a-space": " ",
    "only-a-tab": "\t",
}

#: The refusal for such a value, whichever form carried it.
EDGE_BLANK_MESSAGE = "starts or ends with a space or tab"

#: Longest value any of the three forms takes, in bytes.
LONGEST_VALUE = 16 * 1024


class _Ctx:
    resilient_parsing = False


@pytest.mark.parametrize("value", REFUSED.values(), ids=REFUSED.keys())
def test_a_value_that_is_not_visible_ascii_is_refused(value: str) -> None:
    with pytest.raises(ASHValidationError, match="visible ASCII"):
        _resolve_auth_header_value(value, None, None)


def test_the_refusal_does_not_repeat_the_value() -> None:
    value = "zq9distinct-" + OUTSIDE_LATIN_1

    with pytest.raises(ASHValidationError) as caught:
        _resolve_auth_header_value(value, None, None)

    assert "zq9distinct" not in str(caught.value)
    assert OUTSIDE_LATIN_1 not in str(caught.value)


def test_the_refusal_names_the_forms_that_carry_other_bytes() -> None:
    with pytest.raises(ASHValidationError) as caught:
        _resolve_auth_header_value("caf" + E_ACUTE, None, None)

    assert "--auth-header-value-file" in str(caught.value)
    assert "--auth-header-value-fd" in str(caught.value)


@pytest.mark.parametrize(
    "value",
    [
        "ascii-token",
        "Bearer abc 123",
        "a=b/c+d_e-f.g~h",
        "".join(chr(code) for code in range(0x21, 0x7F)),
        "tok\tvalue",
        "x" * LONGEST_VALUE,
    ],
    ids=[
        "token",
        "scheme-and-space",
        "base64-like",
        "every-visible-character",
        "tab-between-characters",
        "longest-value",
    ],
)
def test_a_visible_ascii_value_is_returned_unchanged(value: str) -> None:
    """Control: nothing visible ASCII carries, ends excepted, is refused or altered."""
    assert _resolve_auth_header_value(value, None, None) == value


@pytest.mark.parametrize("value", EDGE_BLANK.values(), ids=EDGE_BLANK.keys())
def test_a_command_line_value_with_a_space_or_tab_at_an_end_is_refused(
    value: str,
) -> None:
    with pytest.raises(ASHValidationError, match=EDGE_BLANK_MESSAGE):
        _resolve_auth_header_value(value, None, None)


def test_a_command_line_value_over_the_longest_value_is_refused() -> None:
    with pytest.raises(ASHValidationError, match=f"more than {LONGEST_VALUE} bytes"):
        _resolve_auth_header_value("x" * (LONGEST_VALUE + 1), None, None)


def test_the_end_refusal_does_not_repeat_the_value() -> None:
    with pytest.raises(ASHValidationError) as caught:
        _resolve_auth_header_value("zq9distinct ", None, None)

    assert "zq9distinct" not in str(caught.value)


# -- the file and descriptor forms refuse the same ends ----------------------


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


#: What a file or a descriptor can hold that starts or ends with a space or tab.
EDGE_BLANK_BYTES = {
    "leading-space": b" tok-a\n",
    "trailing-space": b"tok-a \n",
    "trailing-space-before-crlf": b"tok-a \r\n",
    "trailing-space-without-newline": b"tok-a ",
    "leading-tab": b"\ttok-a\n",
    "trailing-tab": b"tok-a\t\n",
    "only-a-space": b" \n",
}

#: Values the two forms carry unchanged, with the string each reads as.
CARRIED_BYTES = {
    "token": (b"tok-a\n", "tok-a"),
    "space-inside": (b"Bearer abc 123\n", "Bearer abc 123"),
    "tab-inside": (b"tok\tvalue\n", "tok\tvalue"),
    "latin-1-letter": (b"caf\xe9\n", "caf" + E_ACUTE),
}


@pytest.mark.parametrize(
    "content", EDGE_BLANK_BYTES.values(), ids=EDGE_BLANK_BYTES.keys()
)
def test_a_file_with_a_space_or_tab_at_an_end_is_refused(
    tmp_path, content: bytes
) -> None:
    with pytest.raises(ASHValidationError, match=EDGE_BLANK_MESSAGE):
        _from_file(tmp_path, content)


@pytest.mark.parametrize(
    "content", EDGE_BLANK_BYTES.values(), ids=EDGE_BLANK_BYTES.keys()
)
def test_a_descriptor_with_a_space_or_tab_at_an_end_is_refused(
    content: bytes,
) -> None:
    with pytest.raises(ASHValidationError, match=EDGE_BLANK_MESSAGE):
        _from_descriptor(content)


@pytest.mark.parametrize(
    ("content", "expected"), CARRIED_BYTES.values(), ids=CARRIED_BYTES.keys()
)
def test_a_file_or_descriptor_value_without_such_an_end_is_carried(
    tmp_path, content: bytes, expected: str
) -> None:
    """Control: the end check leaves what the two forms carried before alone."""
    assert _from_file(tmp_path, content) == expected
    assert _from_descriptor(content) == expected


def test_the_file_end_refusal_does_not_repeat_the_value(tmp_path) -> None:
    with pytest.raises(ASHValidationError) as caught:
        _from_file(tmp_path, b"zq9distinct \n")

    assert "zq9distinct" not in str(caught.value)


def test_an_absent_or_empty_value_is_left_to_the_option_check() -> None:
    """Control: the pairing check, not this one, answers an empty or missing value."""
    assert _resolve_auth_header_value(None, None, None) is None
    assert _resolve_auth_header_value("", None, None) == ""


# -- ash mcp stops at startup, before anything is built ---------------------


@pytest.fixture
def started(monkeypatch) -> Dict[str, object]:
    """Record what the server would be built and served with; capture stderr."""
    record: Dict[str, object] = {"stderr": io.StringIO()}
    for name in ("ASH_MCP_TRANSPORT", "ASH_CONFIG"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(
        "automated_security_helper.cli.mcp._stderr",
        Console(file=record["stderr"], width=400, color_system=None),
    )

    def build(**kwargs):
        record["built"] = True
        return object()

    monkeypatch.setattr(
        "automated_security_helper.cli.mcp.build_streamable_http_app", build
    )
    monkeypatch.setattr(
        "automated_security_helper.cli.mcp._run_uvicorn",
        lambda *a, **k: record.update(served=True),
    )
    return record


def _start(value: str) -> None:
    mcp_command(
        ctx=_Ctx(),
        transport="streamable-http",
        host="127.0.0.1",
        port=8765,
        auth_header_name=HEADER,
        auth_header_value=value,
        quiet=True,
    )


@pytest.mark.parametrize(
    "value",
    [
        REFUSED["latin-1-letter"],
        REFUSED["outside-latin-1"],
        REFUSED["carriage-return"],
        EDGE_BLANK["leading-space"],
        EDGE_BLANK["trailing-space"],
        EDGE_BLANK["trailing-tab"],
    ],
    ids=[
        "latin-1-letter",
        "outside-latin-1",
        "carriage-return",
        "leading-space",
        "trailing-space",
        "trailing-tab",
    ],
)
def test_ash_mcp_refuses_such_a_value_before_it_builds_anything(
    started, value: str
) -> None:
    with pytest.raises(typer.Exit) as excinfo:
        _start(value)

    assert excinfo.value.exit_code == ASH_EXIT_USAGE_ERROR
    assert "built" not in started
    assert "served" not in started
    assert "tok-" not in started["stderr"].getvalue()


def test_ash_mcp_serves_a_visible_ascii_value(started) -> None:
    """Control: the same call with a value the form carries builds and serves."""
    _start("tok-visible 1")

    assert started.get("built") is True
    assert started.get("served") is True

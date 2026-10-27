# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``escape_controls_in`` escapes a quoted value inside a message, and only it.

A config error quotes the file's path inside text of ASH's or a parser's. The path
is the user's choice and may hold a newline or a terminal escape; the rest of the
message keeps its own line breaks.
"""

from pathlib import Path

from automated_security_helper.config.config_sources import describe_config_path
from automated_security_helper.utils.display_text import (
    escape_controls_in,
    path_spellings,
)

NAME = "/configs/op\x1b[31mred\nnext.yaml"


def test_the_value_is_escaped_where_it_is_quoted():
    message = f'while parsing\n  in "{NAME}", line 1\nexpected ","'

    shown = escape_controls_in(message, [NAME])

    assert shown == (
        'while parsing\n  in "/configs/op\\x1b[31mred\\nnext.yaml", line 1\n'
        'expected ","'
    )


def test_a_value_inside_a_longer_one_is_escaped_once():
    longer = NAME + ".bak"

    shown = escape_controls_in(f"{longer} and {NAME}", [NAME, longer])

    assert shown == (
        "/configs/op\\x1b[31mred\\nnext.yaml.bak and /configs/op\\x1b[31mred\\nnext.yaml"
    )


def test_a_value_without_controls_leaves_the_message_as_it_is():
    assert escape_controls_in("a\nb /plain.yaml", ["/plain.yaml"]) == "a\nb /plain.yaml"


def test_the_spellings_include_the_path_as_given_and_posix_style():
    spellings = path_spellings(NAME)

    assert NAME in spellings
    assert Path(NAME).as_posix() in spellings


def test_describe_config_path_names_the_path_raw_for_its_sink_to_show():
    """The sink shows the message once (shown_on_one_line writes the newline
    ``\\x0a``); a path escaped here first was shown twice (``\\\\x1b``)."""
    assert describe_config_path(Path(NAME)) == NAME

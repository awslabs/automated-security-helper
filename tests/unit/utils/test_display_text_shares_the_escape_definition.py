# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""display_text escapes what terminal_text escapes, and spells it the same way.

``escape_controls`` kept a category set of its own, which left a lone surrogate (a
file name that is not UTF-8), a private-use and an unassigned code point raw, and
wrote a format character above U+FFFF as ``\\u`` with five or six hex digits, an
escape that reads as another character and a digit. It now reads
``terminal_text.is_shown_as_escape`` and writes ``terminal_text.escape_for``.
``markdown_code_span`` lost a leading and a trailing space of a text edged by
spaces, which CommonMark strips from such a span; it is padded as a backtick-edged
text is. ``path_spellings`` called ``Path.absolute`` outside the guard that covers
``resolve``, so a printer raised when the working directory was gone. The probe
characters are spelled with chr(), so this file holds no invisible character.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from automated_security_helper.utils.display_text import (
    escape_controls,
    markdown_code_span,
    path_spellings,
)

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    ("character", "escape"),
    [
        (chr(0x1D173), "\\U0001d173"),  # a format character above U+FFFF
        (chr(0xDCE9), "\\udce9"),  # a lone surrogate: a byte that is not UTF-8
        (chr(0xE000), "\\ue000"),  # private use
        (chr(0x0378), "\\u0378"),  # unassigned
        (chr(0x1B), "\\x1b"),
        (chr(0x2028), "\\u2028"),  # the line separator
        ("\n", "\\n"),
    ],
)
def test_escape_controls_writes_terminal_texts_escapes(character, escape):
    assert escape_controls(f"a{character}b") == f"a{escape}b"


def test_escape_controls_leaves_ordinary_text_as_it_is():
    assert escape_controls("plain/path.yaml é 中") == "plain/path.yaml é 中"


@pytest.mark.parametrize(
    ("text", "span"),
    [
        (" a ", "`  a  `"),
        ("  ", "`  `"),  # all spaces: CommonMark strips nothing
        (" a", "` a`"),
        ("a ", "`a `"),
        ("`a", "`` `a ``"),
        ("a", "`a`"),
    ],
)
def test_markdown_code_span_keeps_edge_spaces(text, span):
    assert markdown_code_span(text) == span


def test_path_spellings_survives_a_working_directory_that_is_gone(monkeypatch):
    def gone():
        raise FileNotFoundError(2, "No such file or directory")

    monkeypatch.setattr(os, "getcwd", gone)
    assert path_spellings(Path("rel") / "name.yaml")[:3] == [
        os.path.join("rel", "name.yaml"),
        os.path.join("rel", "name.yaml"),
        "rel/name.yaml",
    ]

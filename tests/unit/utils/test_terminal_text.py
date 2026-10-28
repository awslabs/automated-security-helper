# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What a console or CI log shows for text ASH did not write.

shown_not_obeyed writes each character a terminal acts on as an escape, and
breaks what a CI runner reads as a command. The escapes have to stay one to one:
a file name that holds the text "\\x1b" must not print like a real ESC, so a run
of backslashes before text that reads as an escape is doubled. Decoding the
output gives back the input exactly.
"""

from __future__ import annotations

import random
import re
import unicodedata

import pytest

from automated_security_helper.utils.terminal_text import (
    controls_shown,
    escape_for,
    is_shown_as_escape,
    shown_not_obeyed,
)

#: The bidirectional and format controls the console shows: they reorder or hide
#: the text around them, so they are written as escapes like any other control.
BIDI_AND_FORMAT = (
    [chr(c) for c in range(0x202A, 0x202F)]
    + [chr(c) for c in range(0x2066, 0x206A)]
    + ["\N{LEFT-TO-RIGHT MARK}", "\N{RIGHT-TO-LEFT MARK}", "\N{ARABIC LETTER MARK}"]
)

#: A line of output that GitHub Actions or Azure Pipelines would read as a command:
#: "::" at its start, or "##" with an optional name and "[" anywhere.
COMMAND = re.compile(r"^\s*::|##[A-Za-z]*\[", re.MULTILINE)

_ESCAPE = re.compile(r"(\\+)(x[0-9a-f]{2}|u[0-9a-f]{4}|U[0-9a-f]{8})")


#: The categories a character must be shown as an escape in, written out here
#: rather than read from terminal_text, so a set that loses one fails the checks
#: that use this oracle instead of agreeing with itself.
_EXPECTED_SHOWN = frozenset({"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"})


def _unshown(text: str) -> list[str]:
    """The characters of *text* a terminal acts on, those that lay text out aside."""
    return [
        character
        for index, character in enumerate(text)
        if unicodedata.category(character) in _EXPECTED_SHOWN
        and character not in "\t\n"
        and not (character == "\r" and text[index + 1 : index + 2] == "\n")
    ]


def _decoded(shown: str) -> str:
    """Read shown_not_obeyed's output back: an odd run of backslashes ends in an escape."""

    def one(match: re.Match) -> str:
        run, token = match.group(1), match.group(2)
        literal = "\\" * (len(run) // 2)
        if len(run) % 2 == 0:
            return literal + token
        return literal + chr(int(token[1:], 16))

    return _ESCAPE.sub(one, shown)


@pytest.mark.parametrize(
    "character, escape",
    [
        # Written as \N and \U escapes, so this file holds none of these characters.
        pytest.param("\N{ZERO WIDTH SPACE}", "\\u200b", id="zero-width-space"),
        pytest.param("\N{LINE SEPARATOR}", "\\u2028", id="line-separator"),
        pytest.param("\N{PARAGRAPH SEPARATOR}", "\\u2029", id="paragraph-separator"),
        pytest.param("\N{ZERO WIDTH NO-BREAK SPACE}", "\\ufeff", id="byte-order-mark"),
        pytest.param("\N{SOFT HYPHEN}", "\\xad", id="soft-hyphen"),
        pytest.param("\U000e0041", "\\U000e0041", id="tag-character"),
        pytest.param("\U0000d800", "\\ud800", id="lone-surrogate"),
        pytest.param("\U0000e000", "\\ue000", id="private-use"),
        pytest.param("\U0000fffe", "\\ufffe", id="noncharacter"),
        pytest.param("\U0000fdd0", "\\ufdd0", id="noncharacter-block"),
    ],
)
def test_a_format_or_separator_character_is_shown_as_its_code(character, escape):
    """Every control and format character, the line and paragraph separators and a
    lone surrogate are shown as their code by the console and by ash merge
    alike. A line separator ends a line in some log viewers."""
    assert shown_not_obeyed(f"a{character}b") == f"a{escape}b"
    assert _decoded(shown_not_obeyed(f"\\{escape[1:]}{character}")) == (
        f"\\{escape[1:]}{character}"
    )


def test_shard_text_is_shown_with_the_same_set():
    """One definition of a character that is shown and not printed: a shard's name
    and the console use the same set, so U+200B, U+2028 and U+2029 are shown as
    their codes. Shard text also writes out tab, newline and carriage return,
    which lay other text out."""
    from automated_security_helper.core.sharding import shown_shard_text

    sample = list(range(0x3000)) + [0xFEFF, 0xFFF9, 0xE0001, 0xE0041, 0x1D173]
    for code in sample:
        character = chr(code)
        expected = escape_for(character) if is_shown_as_escape(character) else character
        assert shown_shard_text(f"a{character}b") == f"a{expected}b", hex(code)


@pytest.mark.parametrize("control", BIDI_AND_FORMAT)
def test_a_bidi_or_format_control_is_shown_as_its_code(control):
    shown = shown_not_obeyed(f"a{control}b")

    assert control not in shown
    assert shown == "a\\u%04xb" % ord(control)


@pytest.mark.parametrize(
    "text, shown",
    [
        pytest.param("C:\\x1b\\out", "C:\\\\x1b\\out", id="escape-lookalike"),
        pytest.param("a\\u202eb", "a\\\\u202eb", id="unicode-lookalike"),
        pytest.param("a\\\x1b", "a\\\\\\x1b", id="backslash-before-a-control"),
        pytest.param("C:\\out\\dir", "C:\\out\\dir", id="other-backslashes-left"),
        # Intended: a Windows path segment that reads as an escape is shown with
        # its backslash doubled, so "\x1b" text never passes for a real ESC.
        pytest.param(
            "C:\\Python\\x64\\Lib\\a.py",
            "C:\\Python\\\\x64\\Lib\\a.py",
            id="windows-x64-segment",
        ),
        pytest.param(
            "C:\\Program Files (x86)\\x86\\a.py",
            "C:\\Program Files (x86)\\\\x86\\a.py",
            id="windows-x86-segment",
        ),
    ],
)
def test_text_that_reads_as_an_escape_is_not_shown_as_one(text, shown):
    assert shown_not_obeyed(text) == shown
    assert _decoded(shown_not_obeyed(text)) == text


@pytest.mark.parametrize(
    "text",
    [
        pytest.param("see ##[add-mask]hidden", id="legacy-command"),
        pytest.param("see ##vso[task.setvariable variable=x]y", id="azure-command"),
        pytest.param("a\\##[add-mask]b", id="backslash-before-it"),
        pytest.param("x ##teamcity[message text='y']", id="teamcity-command"),
        pytest.param("x\n  ::add-mask::hidden", id="line-start"),
        pytest.param("x\n##[group]g", id="line-start-group"),
        pytest.param("x ##VSO[task.complete]", id="upper-case-name"),
    ],
)
def test_a_ci_command_is_broken(text):
    shown = shown_not_obeyed(text)

    assert not COMMAND.search(shown), shown
    assert _decoded(shown) == text


@pytest.mark.parametrize(
    "text",
    [
        pytest.param("## Scan Metadata", id="heading"),
        pytest.param("x\n  ## a line that starts with two hashes", id="indented"),
        pytest.param("x ## y", id="mid-line"),
    ],
)
def test_a_bare_double_hash_is_no_command(text):
    """A "##" with no name and "[" after it, a Markdown heading's, is no command
    to any runner, at a line start or anywhere: it is left as written."""
    assert shown_not_obeyed(text) == text


@pytest.mark.parametrize(
    "character, escape",
    [
        pytest.param(chr(0x200D), "u200d", id="zero-width-joiner-in-an-emoji"),
        pytest.param(chr(0x200C), "u200c", id="zero-width-non-joiner"),
        pytest.param(chr(0xAD), "xad", id="soft-hyphen"),
    ],
)
def test_a_format_character_in_ordinary_text_is_written_out(character, escape):
    """Accepted, as the module docstring says: no exception between letters or
    emoji in a sink that exists for safety."""
    text = chr(0x1F468) + character + chr(0x1F4BB)

    assert shown_not_obeyed(text) == chr(0x1F468) + "\\" + escape + chr(0x1F4BB)


def test_an_arn_is_left_readable():
    """Only a "::" at a line start is a command; an ARN holds one mid-line."""
    arn = "role arn:aws:iam::123456789012:role/scan"

    assert shown_not_obeyed(arn) == arn


def test_every_string_decodes_back_and_shows_no_control():
    """A probe over the characters that interact: backslashes, escape-like text,
    controls, newlines and the command prefixes."""
    alphabet = ["\\", "x", "u", "1", "b", "2", "0", "e", "a", ":", "#", "[", "v"]
    alphabet += ["s", "o", " ", "\n", "\r", "\x1b", "\x9b", "\x7f", "\u202e"]
    alphabet += ["\u2066", "\u200f", "U", "0", "\N{ZERO WIDTH SPACE}"]
    alphabet += ["\N{LINE SEPARATOR}", "\N{SOFT HYPHEN}", "\U000e0041"]
    # A surrogate (Cs), private use (Co), unassigned and a noncharacter (Cn), and
    # the paragraph separator (Zp), so each category of the set comes up.
    alphabet += [chr(c) for c in (0xD800, 0xE000, 0xF0000, 0x0378, 0x10FFFE, 0x2029)]
    chooser = random.Random(20261012)
    for _ in range(20000):
        text = "".join(chooser.choice(alphabet) for _ in range(chooser.randint(0, 14)))
        shown = shown_not_obeyed(text)

        assert not _unshown(shown), (text, shown)
        assert not COMMAND.search(shown), (text, shown)
        assert _decoded(shown) == text, (text, shown)


@pytest.mark.parametrize(
    "text, shown",
    [
        pytest.param("## heading", "## heading", id="bare-heading-left"),
        pytest.param("  ## heading", "  ## heading", id="indented-heading-left"),
        pytest.param("##[group]x", "\\x23#[group]x", id="legacy-group"),
        pytest.param(
            "##vso[task.setvariable variable=x]y",
            "\\x23#vso[task.setvariable variable=x]y",
            id="azure-command",
        ),
        pytest.param(
            "see ##VSO[task.complete]", "see \\x23#VSO[task.complete]", id="upper"
        ),
        pytest.param("::warning::x", "\\x3a:warning::x", id="workflow-command"),
        pytest.param("a\n## b", "a\\x0a## b", id="heading-after-a-newline"),
    ],
)
def test_one_line_text_breaks_the_commands_a_runner_reads(text, shown):
    """On one line, the forms a runner reads as a command are broken: "::" at the
    start, and "##" with an optional name and "[" anywhere, in any case. A "##"
    with neither, a Markdown heading's, is no command and is left."""
    from automated_security_helper.utils.terminal_text import shown_on_one_line

    assert shown_on_one_line(text) == shown
    assert _decoded(shown_on_one_line(text)) == text


def test_controls_shown_alone_leaves_commands_to_the_caller():
    """For a terminal-only sink, such as a report shown on a terminal."""
    assert controls_shown("\n::error::x") == "\n::error::x"

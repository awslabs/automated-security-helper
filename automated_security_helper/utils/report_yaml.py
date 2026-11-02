# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""YAML in which no line is a CI workflow command.

A report carries text from the scanned repository: a refused input's file or
member name, a finding's message. A config file can too: a project name, the path
of a finding a suppression names. A CI runner reads a line of its log that starts,
after its indentation, with ``::`` (a GitHub Actions workflow command such as
``::add-mask::``) as a command when the file is printed there, and the ``##``
forms with a name and ``[`` (Azure Pipelines' ``##[group]`` and ``##vso[``,
TeamCity's ``##teamcity[``) anywhere in a line, as utils/terminal_text.py says.
PyYAML writes a value holding a line break as a block of lines, each the text
after a break, and folds a long value at a space onto the next line, so a name
such as ``x\\n::add-mask::...`` would start a line of the file with the command.

:class:`NoCommandLineDumper`, listed before a dumper class, writes every string in
which "::" or "##" starts the text or follows whitespace (a line break is
whitespace, and a plain or single-quoted value is folded only at a space), and
every string holding a ``##name[`` form, as a double-quoted scalar, in which a
line break is the escape ``\\n``. PyYAML can split a double-quoted value after an
escape and start the next line with the character that follows it, so a
double-quoted value holding "::" or "##" is written on one line; a line can then
start only with its quote or its indentation. The first "#" of each ``##name[``
form is written as YAML's own escape ``\\x23``, which no runner reads as the
command and the loader reads back as "#". Every value reads back as it was.
Every other value, a tag such as ``tool_name::bandit`` or a text with a line
break and no such "::" or "##", is written as the dumper writes it, by the
dumper's own representers. :func:`report_yaml` writes a report with it; the
config dumpers (``config.ash_config._ConfigDumper``,
``config.config_writer.IndentableYamlDumper``) are built on it, each with its
own quoting representer on top: a genuine reference is written plain, so the
loader reads it as one again (``config.config_writer._AsWrittenYamlDumper``),
and a
string that would only read back as one is quoted. Those representers build
their nodes through ``represent_scalar``, so a value holding a command start is
double-quoted here whichever representer asked, and whatever style it asked
for.
"""

from __future__ import annotations

import re
from typing import Any, Optional

import yaml
from yaml.emitter import Emitter

from automated_security_helper.utils.terminal_text import NAMED_HASH_COMMAND

#: A "::" or "##" at the start of the text or after whitespace, line breaks
#: included: the places a line of the value, or a line PyYAML folds it onto, could
#: start with it.
_COMMAND_START = re.compile(r"(?:^|\s)(?:::|##)")

#: What a line of the file must not start with, after its indentation.
_COMMAND_PREFIXES = ("::", "##")

#: What a double-quoted value writes as a named escape, as PyYAML's emitter does.
_NAMED_ESCAPES = Emitter.ESCAPE_REPLACEMENTS

#: The characters the emitter always writes as escapes inside double quotes: the
#: quote, the backslash, NEL, the line and paragraph separators and the byte
#: order mark. Spelled with chr(), so this file holds no invisible characters.
_ALWAYS_ESCAPED = frozenset(
    {'"', "\\", chr(0x85), chr(0x2028), chr(0x2029), chr(0xFEFF)}
)

#: The non-ASCII ranges the emitter writes as they are when unicode is allowed.
_FIRST_PRINTABLE = chr(0xA0)
_LAST_BEFORE_SURROGATES = chr(0xD7FF)
_FIRST_AFTER_SURROGATES = chr(0xE000)
_LAST_PRINTABLE = chr(0xFFFD)


class NoCommandLineDumper:
    """A mixin for a ``yaml`` dumper class, listed before it, so that no line the
    dumper writes is a CI workflow command.

    Every scalar node passes through ``represent_scalar``, whichever representer
    builds it, so a string in which a command starts the text or follows
    whitespace, or that holds a ``##name[`` form anywhere, is given the
    double-quoted style there and the dumper's own representers stay as they
    are. ``write_double_quoted`` writes a double-quoted value that holds a
    command prefix on one line, and the first "#" of each ``##name[`` form as
    ``\\x23``.
    """

    def represent_scalar(
        self, tag: str, value: Any, style: Optional[str] = None
    ) -> yaml.ScalarNode:
        if isinstance(value, str) and (
            _COMMAND_START.search(value) or NAMED_HASH_COMMAND.search(value)
        ):
            style = '"'
        return super().represent_scalar(tag, value, style)  # type: ignore[misc]

    def write_double_quoted(self, text: str, split: bool = True) -> None:
        if NAMED_HASH_COMMAND.search(text):
            self._write_double_quoted_with_hashes_escaped(text)
            return
        if any(prefix in text for prefix in _COMMAND_PREFIXES):
            split = False
        super().write_double_quoted(text, split)  # type: ignore[misc]

    def _write_double_quoted_with_hashes_escaped(self, text: str) -> None:
        """*text* as one double-quoted scalar on one line, each character the
        emitter would escape written as it writes it, and the first "#" of each
        ``##name[`` form written as ``\\x23``.

        The emitter's own writer escapes by character and has no way to escape a
        printable one, so the scalar is written here, through the same stream and
        column accounting the emitter uses for its indicators.
        """
        escaped_hashes = {match.end(1) for match in NAMED_HASH_COMMAND.finditer(text)}
        pieces = []
        for index, character in enumerate(text):
            if index in escaped_hashes:
                pieces.append("\\x23")
            elif character in _NAMED_ESCAPES:
                pieces.append("\\" + _NAMED_ESCAPES[character])
            elif self._written_as_itself(character):
                pieces.append(character)
            else:
                code = ord(character)
                if code <= 0xFF:
                    pieces.append("\\x%02X" % code)
                elif code <= 0xFFFF:
                    pieces.append("\\u%04X" % code)
                else:
                    pieces.append("\\U%08X" % code)
        self.write_indicator('"', True)  # type: ignore[attr-defined]
        data = "".join(pieces)
        self.column += len(data)  # type: ignore[attr-defined]
        if self.encoding:  # type: ignore[attr-defined]
            data = data.encode(self.encoding)  # type: ignore[attr-defined, assignment]
        self.stream.write(data)  # type: ignore[attr-defined]
        self.write_indicator('"', False)  # type: ignore[attr-defined]

    def _written_as_itself(self, character: str) -> bool:
        """Whether the emitter writes *character* inside double quotes as it is:
        printable ASCII other than the quote and the backslash, and, when the
        dumper allows unicode, the printable non-ASCII ranges it admits."""
        if character in _ALWAYS_ESCAPED:
            return False
        if "\x20" <= character <= "\x7e":
            return True
        return bool(self.allow_unicode) and (  # type: ignore[attr-defined]
            _FIRST_PRINTABLE <= character <= _LAST_BEFORE_SURROGATES
            or _FIRST_AFTER_SURROGATES <= character <= _LAST_PRINTABLE
        )


class _ReportDumper(NoCommandLineDumper, yaml.Dumper):
    """yaml.Dumper, with no line of what it writes a workflow command."""


def report_yaml(data: Any, **options: Any) -> str:
    """``yaml.dump(data, **options)``, with no line of it a workflow command."""
    return yaml.dump(data, Dumper=_ReportDumper, **options)

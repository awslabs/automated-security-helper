# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""YAML in which no line is a CI workflow command.

A report carries text from the scanned repository: a refused input's file or
member name, a finding's message. A config file can too: a project name, the path
of a finding a suppression names. A CI runner reads a line of its log that starts,
after its indentation, with ``::`` (a GitHub Actions workflow command such as
``::add-mask::``) or ``##`` (Azure Pipelines' ``##[group]`` and ``##vso[``,
TeamCity's ``##teamcity[``) as a command when the file is printed there. PyYAML
writes a value holding a line break as a block of lines, each the text after a
break, and folds a long value at a space onto the next line, so a name such as
``x\\n::add-mask::...`` would start a line of the file with the command.

:class:`NoCommandLineDumper`, listed before a dumper class, writes every string in
which "::" or "##" starts the text or follows whitespace (a line break is
whitespace, and a plain or single-quoted value is folded only at a space) as a
double-quoted scalar, in which a line break is the escape ``\\n``. PyYAML can split
a double-quoted value after an escape and start the next line with the character
that follows it, so a double-quoted value holding "::" or "##" is written on one
line; a line can then start only with its quote or its indentation. Every value
reads back as it was. Every other value, a tag such as ``tool_name::bandit`` or a
text with a line break and no such "::" or "##", is written as the dumper writes
it, by the dumper's own representers. :func:`report_yaml` writes a report with it;
the config dumpers (``config.ash_config._ConfigDumper``,
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

#: A "::" or "##" at the start of the text or after whitespace, line breaks
#: included: the places a line of the value, or a line PyYAML folds it onto, could
#: start with it.
_COMMAND_START = re.compile(r"(?:^|\s)(?:::|##)")

#: What a line of the file must not start with, after its indentation.
_COMMAND_PREFIXES = ("::", "##")


class NoCommandLineDumper:
    """A mixin for a ``yaml`` dumper class, listed before it, so that no line the
    dumper writes is a CI workflow command.

    Every scalar node passes through ``represent_scalar``, whichever representer
    builds it, so a string in which a command starts the text or follows
    whitespace is given the double-quoted style there and the dumper's own
    representers stay as they are. ``write_double_quoted`` writes a double-quoted
    value that holds a command prefix on one line.
    """

    def represent_scalar(
        self, tag: str, value: Any, style: Optional[str] = None
    ) -> yaml.ScalarNode:
        if isinstance(value, str) and _COMMAND_START.search(value):
            style = '"'
        return super().represent_scalar(tag, value, style)  # type: ignore[misc]

    def write_double_quoted(self, text: str, split: bool = True) -> None:
        if any(prefix in text for prefix in _COMMAND_PREFIXES):
            split = False
        super().write_double_quoted(text, split)  # type: ignore[misc]


class _ReportDumper(NoCommandLineDumper, yaml.Dumper):
    """yaml.Dumper, with no line of what it writes a workflow command."""


def report_yaml(data: Any, **options: Any) -> str:
    """``yaml.dump(data, **options)``, with no line of it a workflow command."""
    return yaml.dump(data, Dumper=_ReportDumper, **options)

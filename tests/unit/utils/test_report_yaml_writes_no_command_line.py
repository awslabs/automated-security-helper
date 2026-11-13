# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""No line of utils/report_yaml.py's YAML is a CI workflow command.

A CI runner reads a line of its log that starts, after its indentation, with
``::`` (GitHub Actions: ``::add-mask::``) or ``##`` (Azure Pipelines' ``##[`` and
``##vso[``, TeamCity's ``##teamcity[``) as a command. A report value comes from the
scanned tree, so it can hold any of them first, after whitespace, or after a
character YAML writes as an escape, and a long one is folded onto the next line.
Each value must still read back as it was.
"""

from __future__ import annotations

import re
from typing import Any, Callable, Dict, List

import pytest
import yaml

from automated_security_helper.utils.report_yaml import report_yaml

pytestmark = pytest.mark.unit

#: One command of each form a runner reads.
FORMS: Dict[str, str] = {
    "add-mask": "::add-mask::secret",
    "group": "##[group]x",
    "vso": "##vso[task.setvariable variable=x]y",
    "teamcity": "##teamcity[message text='x']",
}

#: U+2028, a line break to YAML and to Python's str.splitlines.
LINE_SEPARATOR = chr(0x2028)

#: Where in a value the command sits: first, after whitespace, or after a
#: character YAML writes as an escape in a double-quoted value.
PLACES: Dict[str, Callable[[str], str]] = {
    "first": lambda command: command,
    "after-a-space": lambda command: "a " + command,
    "after-a-tab": lambda command: "a\t" + command,
    "after-a-line-break": lambda command: "x\n" + command,
    "after-a-carriage-return": lambda command: "x\r" + command,
    "after-a-bell": lambda command: "x\a" + command,
    "after-a-quote": lambda command: 'x"' + command,
    "after-a-backslash": lambda command: "x\\" + command,
    "after-a-next-line": lambda command: "x\x85" + command,
    "after-a-line-separator": lambda command: "x" + LINE_SEPARATOR + command,
}

#: The options the YAML and S3 reporters pass.
OPTIONS: List[Dict[str, Any]] = [{"indent": 2}, {"default_flow_style": False}]

#: Long enough a prefix that every value is folded at or after the command.
FOLD_PREFIXES = range(121)

CASES = [
    pytest.param(FORMS[form], place, id=f"{form}-{place}")
    for form in FORMS
    for place in PLACES
]


#: The ``##name[`` form a runner reads anywhere in a line, not only at its start
#: (test_report_yaml_breaks_named_hash_commands_anywhere.py).
NAMED_HASH = re.compile(r"##[A-Za-z]*\[")


def _command_lines(text: str) -> List[str]:
    return [
        line for line in text.splitlines() if line.lstrip().startswith(("::", "##"))
    ]


def _containers(value: str) -> List[Any]:
    """The value where a report holds one: a mapping's value, a refused input's
    row in a converter's results, a list item and a mapping's key."""
    return [
        {"name": value},
        {
            "converter_results": {
                "archive": {"refused_inputs": [{"member": value, "path": value}]}
            }
        },
        [value],
        {value: "x"},
    ]


def _assert_no_command_and_read_back(data: Any) -> None:
    for options in OPTIONS:
        text = report_yaml(data, **options)
        assert _command_lines(text) == [], text
        # The rule for the forms read anywhere in a line, at every fold length,
        # place and container this helper is run over.
        assert NAMED_HASH.search(text) is None, text
        assert yaml.safe_load(text) == data, text


@pytest.mark.parametrize(("command", "place"), CASES)
def test_a_command_starts_no_line(command, place):
    value = PLACES[place](command)

    for data in _containers(value):
        _assert_no_command_and_read_back(data)


@pytest.mark.parametrize(("command", "place"), CASES)
def test_a_long_value_folded_at_any_point_starts_no_line_with_a_command(command, place):
    for length in FOLD_PREFIXES:
        value = "A" * length + PLACES[place](command) + " and more " + "B" * length
        for data in _containers(value):
            _assert_no_command_and_read_back(data)


@pytest.mark.parametrize(
    "value",
    [
        "x\n::add-mask::y",
        "a" * 70 + " ::x",
        "x\n##[group]y",
        "x\n##vso[task.setvariable variable=x]y",
        "A" * 68 + "\n::add-mask::x",
    ],
)
def test_the_value_reads_back_byte_for_byte(value):
    for options in OPTIONS:
        loaded = yaml.safe_load(report_yaml({"name": value}, **options))["name"]

        assert loaded.encode("utf-8") == value.encode("utf-8")


@pytest.mark.parametrize(
    "value",
    [
        "tool_name::bandit",
        "a plain value",
        "C# and F# code",
        "x\ny",
        "x\n:y",
        "x\n#y",
        "\abell",
        "no command here " * 12,
        "a::b " * 30,
        "a##b " * 30,
    ],
)
def test_a_value_without_a_command_is_written_as_yaml_dump_writes_it(value):
    for data in _containers(value):
        for options in OPTIONS:
            assert report_yaml(data, **options) == yaml.dump(data, **options)


class _DoubleQuoted(yaml.Dumper):
    """yaml.Dumper writing every str double-quoted, split as PyYAML splits it."""


_DoubleQuoted.add_representer(
    str,
    lambda dumper, value: dumper.represent_scalar(
        "tag:yaml.org,2002:str", value, style='"'
    ),
)


@pytest.mark.parametrize(("command", "place"), CASES)
def test_a_short_value_with_a_command_is_double_quoted_as_yaml_dump_quotes_it(
    command, place
):
    """Control for the one-line rule: a value too short to fold is written as a
    plain double-quoted dump writes it. After a quote or a backslash a "::"
    command cannot start a line of a plain value, so those are written as
    yaml.dump writes them. A "##name[" form is read by its runner anywhere in a
    line, so it is double-quoted wherever it sits, with its first "#" written as
    YAML's escape ``\\x23`` (test_report_yaml_breaks_named_hash_commands_anywhere)."""
    value = PLACES[place](command)
    plain = place in ("after-a-quote", "after-a-backslash")
    named_hash = command.startswith("##")

    for data in (value, [value], [[value]]):
        for options in OPTIONS:
            if named_hash:
                expected = yaml.dump(data, Dumper=_DoubleQuoted, **options).replace(
                    "##", "\\x23#", 1
                )
            else:
                expected = yaml.dump(
                    data, Dumper=yaml.Dumper if plain else _DoubleQuoted, **options
                )
            assert report_yaml(data, **options) == expected

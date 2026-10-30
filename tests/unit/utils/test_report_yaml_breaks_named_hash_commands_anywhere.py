# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""utils/report_yaml.py writes no ``##name[`` command form anywhere in a line.

The runners that read ``##[cmd]``, ``##vso[`` and ``##teamcity[`` match the form
anywhere in a line, as utils/terminal_text.py's model says, so neutralizing only
a line's start left a value such as ``x##vso[task.setvariable ...]`` in the file
as written. The first "#" of each form is now written as YAML's own escape
``\\x23`` inside a double-quoted scalar, which the loader reads back as "#".
"""

from __future__ import annotations

import re

import pytest
import yaml

from automated_security_helper.utils.report_yaml import report_yaml

pytestmark = pytest.mark.unit

#: The form a runner reads, anywhere in a line (terminal_text's model).
NAMED_HASH = re.compile(r"##[A-Za-z]*\[")

FORMS = {
    "vso": "##vso[task.setvariable variable=x]y",
    "group": "##[group]x",
    "teamcity": "##teamcity[message text='x']",
}

PLACES = {
    "mid-line": lambda command: "x" + command,
    "after-a-quote": lambda command: 'x"' + command,
    "after-a-backslash": lambda command: "x\\" + command,
    "after-text-and-a-space": lambda command: "a b" + command + " c",
    "twice": lambda command: "x" + command + "y" + command,
}


def _containers(value: str):
    return [{"name": value}, [value], {value: "x"}, {"a": {"b": [value]}}]


@pytest.mark.parametrize("form", sorted(FORMS))
@pytest.mark.parametrize("place", sorted(PLACES))
def test_a_named_hash_form_anywhere_is_written_broken_and_reads_back(form, place):
    value = PLACES[place](FORMS[form])

    for data in _containers(value):
        for options in ({"indent": 2}, {"default_flow_style": False}):
            text = report_yaml(data, **options)

            assert NAMED_HASH.search(text) is None, text
            assert "\\x23" in text, text
            assert yaml.safe_load(text) == data, text


def test_a_long_value_with_a_named_hash_form_stays_one_line():
    value = "A" * 100 + "##vso[task.setvariable variable=x]y" + " and more " + "B" * 100

    text = report_yaml({"name": value}, indent=2)

    assert NAMED_HASH.search(text) is None, text
    assert len(text.rstrip("\n").splitlines()) == 1, text
    assert yaml.safe_load(text) == {"name": value}


@pytest.mark.parametrize(
    "value",
    [
        "a##b " * 30,
        "C# and F# code",
        "scan## metadata",
        "x##1[",
        "tool_name::bandit",
    ],
)
def test_a_value_without_a_named_hash_form_is_written_as_yaml_dump_writes_it(value):
    # A value that starts a line with "##" or "::" is a command start, which the
    # dumper has always double-quoted (test_report_yaml_writes_no_command_line
    # covers it), so no control here begins with either.
    for data in _containers(value):
        assert report_yaml(data, indent=2) == yaml.dump(data, indent=2)


def test_non_ascii_text_beside_a_named_hash_form_reads_back(tmp_path):
    value = "caf" + chr(0xE9) + " " + chr(0x1F600) + " ##vso[x]" + chr(0x2028) + "y"

    for allow_unicode in (True, False):
        text = report_yaml({"name": value}, allow_unicode=allow_unicode)

        assert NAMED_HASH.search(text) is None, text
        assert yaml.safe_load(text) == {"name": value}, text

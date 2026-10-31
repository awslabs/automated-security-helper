# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""npm lockfile entries: line numbers the scanners agree with, and a lockfile that
cannot be parsed answers None.

``load_npm_lock_entries`` numbers each key's line so a scanner's reported line
range can be matched to its entry. The scanners count lines at ``\\n``;
``str.splitlines`` also breaks on U+2028, U+2029, U+0085 and a lone CR, so a
string value holding one of those shifted every later key's line and attributed
a location to the wrong entry. A lockfile nested past the interpreter's recursion
limit raised RecursionError out of json.loads, past the ``except`` that turns an
unreadable lockfile into None, and failed the whole scanner run.
"""

from __future__ import annotations

import json

import pytest

from automated_security_helper.utils.package_identity import load_npm_lock_entries

pytestmark = pytest.mark.unit


def _lockfile(tmp_path, text: str):
    path = tmp_path / "package-lock.json"
    path.write_text(text, encoding="utf-8")
    return path


def test_a_line_separator_inside_a_string_does_not_shift_later_keys(tmp_path):
    # A description holding U+2028 (LINE SEPARATOR) on line 4; the node_modules
    # key is on line 5 by the scanners' count, since U+2028 is no line break to
    # them. Built with chr() so the character is in the string, not the source.
    description = "one" + chr(0x2028) + "two"
    text = (
        "{\n"
        '  "name": "demo",\n'
        '  "packages": {\n'
        f'    "": {{"name": "demo", "description": "{description}"}},\n'
        '    "node_modules/left-pad": {\n'
        '      "version": "1.3.0"\n'
        "    }\n"
        "  }\n"
        "}\n"
    )
    # The separator has to be a line break to str.splitlines() and not to the
    # scanners' "\n" count. The old comparison against len(text.split("\n"))
    # was equal by coincidence: splitlines() drops the empty piece after the
    # final "\n" that split("\n") keeps, so both read the same length and the
    # precondition never held. One line more than there are "\n" characters is
    # what the separator adds.
    assert len(text.splitlines()) == text.count("\n") + 1, "the fixture must differ"
    entries = load_npm_lock_entries(_lockfile(tmp_path, text))
    assert entries is not None
    by_key = {entry.key: entry for entry in entries}
    assert by_key["node_modules/left-pad"].line == 5


def test_a_lockfile_nested_past_the_recursion_limit_answers_none(tmp_path):
    depth = 100_000
    nested = "[" * depth + "]" * depth
    text = '{"packages": {"node_modules/a": {"version": "1"}}, "deep": ' + nested + "}"
    with pytest.raises(RecursionError):
        json.loads(text)
    assert load_npm_lock_entries(_lockfile(tmp_path, text)) is None

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An extension and a report file name are held to one rule.

``is_filename_suffix`` (the extension) and ``is_report_file_name`` (the file the
run checks and writes) each kept their own list of characters a name cannot hold,
and the list of the first had no colon. The extension's rule is now the file-name
rule asked of ``ash.<extension>``.
"""

from __future__ import annotations

import pytest

from automated_security_helper.base.reporter_plugin import is_filename_suffix
from automated_security_helper.utils.report_path_links import is_report_file_name

pytestmark = pytest.mark.unit

_FORBIDDEN = ["/", "\\", ":", "\x00"]


@pytest.mark.parametrize("character", _FORBIDDEN)
def test_a_character_the_file_name_rule_refuses_is_refused_in_an_extension(character):
    for value in (f"json{character}", f"{character}json", f"js{character}on"):
        assert is_report_file_name(f"ash.{value}") is False
        assert is_filename_suffix(value) is False, value


@pytest.mark.parametrize(
    "value", ["json", "summary.md", "findings.txt", "ocsf.json", "a-b_c", ""]
)
def test_an_extension_the_file_name_rule_accepts_is_accepted(value):
    assert is_report_file_name(f"ash.{value}") is True
    assert is_filename_suffix(value) is True


@pytest.mark.parametrize("value", ["..", "a..b", "json..", "../json"])
def test_a_dot_dot_is_refused_in_an_extension(value):
    assert is_filename_suffix(value) is False


@pytest.mark.parametrize("value", [None, 1, ["json"], b"json"])
def test_a_value_that_is_not_a_string_is_refused(value):
    assert is_filename_suffix(value) is False


def test_the_two_rules_agree_over_every_character_of_a_small_alphabet():
    alphabet = ["a", ".", *_FORBIDDEN]
    for first in alphabet:
        for second in alphabet:
            value = f"x{first}{second}"
            if ".." in value:
                continue
            assert is_filename_suffix(value) == is_report_file_name(f"ash.{value}"), (
                repr(value)
            )

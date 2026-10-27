# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A pattern matches a name that is not UTF-8 as the report shows it or as the name itself.

On POSIX a file name is bytes. A latin-1 ``secr\\xe9t.py`` is listed with one lone
surrogate for the byte that is not UTF-8 (``secr\\udce9t.py`` as one character) and
recorded with that surrogate written as the six characters ``\\udce9``. A pattern
matches when it matches either form, so a config can name the file by the name as
it is, with ``?`` for the one byte (``secr?t.py``), or as the report shows it, with
``?`` for the escape's backslash (``secr?udce9t.py``). The file a scan lists and the
finding a scanner reports for it, which carries the recorded form, get one answer.
"""

from __future__ import annotations

import os

import pytest

from automated_security_helper.utils.suppression_matcher import ignore_path_matches

#: The name as the scan lists it: one lone surrogate for the byte.
LISTED = os.fsdecode(b"secr\xe9t.py")
#: The name as a result records it: the surrogate as six characters.
RECORDED = "secr\\udce9t.py"

SIDES = [pytest.param(LISTED, id="listed"), pytest.param(RECORDED, id="recorded")]


@pytest.mark.parametrize("name", SIDES)
def test_a_question_mark_for_the_one_byte_matches_the_name(name):
    """``?`` stands for one character of the name itself: the byte."""
    assert ignore_path_matches(name, "secr?t.py")


@pytest.mark.parametrize("name", SIDES)
def test_control_the_spelling_the_report_shows_matches_the_name(name):
    """``?`` stands for one character of the shown escape: its backslash."""
    assert ignore_path_matches(name, "secr?udce9t.py")


@pytest.mark.parametrize("name", SIDES)
def test_control_a_pattern_naming_another_file_matches_neither_form(name):
    assert not ignore_path_matches(name, "secr?x.py")
    assert not ignore_path_matches(name, "secret.py")

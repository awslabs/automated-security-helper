# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Two edges of utils/path_matching.

A bracket expression that holds the stand-in for one file name byte that is not
UTF-8 names that byte and nothing else, and a directory that is only separators has
no spelling to advise.
"""

import pytest

from automated_security_helper.utils.path_matching import (
    _class_holds_surrogate,
    _path_pattern_matches,
    directory_spelling,
)

pytestmark = pytest.mark.unit

#: A pattern whose class holds the lone surrogate U+DCE9, the stand-in for the byte
#: 0xE9 of a latin-1 ``secr\xe9t.py``.
CLASS_PATTERN = "secr[\udce9]t.py"


class TestAClassHoldingAnUndecodableByte:
    def test_it_matches_no_ascii_name(self):
        """Compared in the record form the class holds the escape's six characters,
        ``\\``, ``u``, ``d``, ``c``, ``e`` and ``9``, so a name with one of them at
        that position matched a pattern written for a byte."""
        assert not _path_pattern_matches("secrdt.py", CLASS_PATTERN)
        assert not _path_pattern_matches("secrut.py", CLASS_PATTERN)
        assert not _path_pattern_matches("secr9t.py", CLASS_PATTERN)

    def test_it_still_matches_the_file_whose_byte_it_stands_for(self):
        assert _path_pattern_matches("secr\udce9t.py", CLASS_PATTERN)

    def test_it_matches_the_name_as_a_report_shows_it(self):
        assert _path_pattern_matches("secr\\udce9t.py", CLASS_PATTERN)

    def test_a_recursive_pattern_is_read_the_same_way(self):
        pattern = "**/secr[\udce9]t.py"
        assert not _path_pattern_matches("src/secrdt.py", pattern)
        assert _path_pattern_matches("src/secr\udce9t.py", pattern)

    def test_a_class_of_ordinary_characters_is_unchanged(self):
        assert _path_pattern_matches("secrat.py", "secr[abc]t.py")
        assert not _path_pattern_matches("secrdt.py", "secr[abc]t.py")


class TestAClassHoldingAnUndecodableByteAndOrdinaryOnes:
    """The class is matched against the name itself only, and that match has to be
    made for an ordinary name too: the record-form match it replaces is skipped, and
    the name-itself match was tried only for a name that holds a surrogate."""

    def test_a_negated_class_matches_a_name_without_the_byte(self):
        assert _path_pattern_matches("app.py", "[!\udce9]*.py")
        assert not _path_pattern_matches("\udce9app.py", "[!\udce9]*.py")

    def test_a_class_of_the_byte_and_an_ordinary_character_matches_both(self):
        pattern = "secr[\udce9e]t.py"
        assert _path_pattern_matches("secret.py", pattern)
        assert _path_pattern_matches("secr\udce9t.py", pattern)
        assert not _path_pattern_matches("secrdt.py", pattern)

    def test_a_recursive_pattern_with_such_a_class_matches_an_ordinary_name(self):
        assert _path_pattern_matches("src/app.py", "**/[!\udce9]*.py")
        assert _path_pattern_matches("src/secret.py", "**/secr[\udce9e]t.py")
        assert not _path_pattern_matches("src/secrdt.py", "**/secr[\udce9e]t.py")


class TestWhereTheBracketsAre:
    @pytest.mark.parametrize(
        "pattern, expected",
        [
            ("secr[\udce9]t.py", True),
            ("secr[!\udce9]t.py", True),
            ("secr[]\udce9]t.py", True),
            ("secr\udce9t.py", False),
            ("secr[abc]\udce9t.py", False),
            ("secr[\udce9t.py", False),
            ("secr[abc]t.py", False),
        ],
    )
    def test_a_surrogate_counts_only_inside_a_closed_class(self, pattern, expected):
        assert _class_holds_surrogate(pattern) is expected


class TestADirectoryThatIsOnlySeparators:
    @pytest.mark.parametrize("directory", ["", "/", "//", "\\", "/\\"])
    @pytest.mark.parametrize("ignore_path", [True, False])
    def test_it_has_no_spelling(self, directory, ignore_path):
        """``/`` as an ignore path matches nothing, and ``/**/*`` as a suppression
        path matches every file: advice that disagreed with itself."""
        assert directory_spelling(directory, ignore_path=ignore_path) == ""

    @pytest.mark.parametrize(
        "directory, ignore_path, spelling",
        [
            ("vendor", True, "vendor/"),
            ("vendor/", True, "vendor/"),
            ("docs", False, "docs/**/*"),
            ("docs\\", False, "docs/**/*"),
        ],
    )
    def test_a_named_directory_is_spelled_as_before(
        self, directory, ignore_path, spelling
    ):
        assert directory_spelling(directory, ignore_path=ignore_path) == spelling

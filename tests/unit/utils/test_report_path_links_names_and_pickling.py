# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Six readings of ``report_path_links``.

- ``ReportPathRefused`` and its subclasses survive a pickle or deepcopy round trip
  with ``found`` and the message intact; rebuilt from ``args`` they took the
  formatted message as ``found`` and appended the remedy a second time.
- A name Windows reserves for a device (``nul.json``) is not a report file name.
- ``ensure_reports_dir`` refuses a regular file at the reports path with the
  module's own error instead of a bare ``FileExistsError``.
- Two names that are nothing but dots and spaces are two files, not one.
- The collision key folds case one character at a time and normalizes Unicode, so
  the sharp s and ``ss`` stay apart and a form C and form D spelling come together.
- One writer naming two different texts that are one file is refused; the same text
  twice is not.

Every path here is under ``tmp_path``.
"""

from __future__ import annotations

import copy
import pickle
import unicodedata

import pytest

from automated_security_helper.utils.report_path_links import (
    FILE_REMEDY,
    ReportNameCollision,
    ReportPathLinkRefused,
    ReportPathRefused,
    ensure_reports_dir,
    is_report_file_name,
    refuse_colliding_report_names,
)

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    "make",
    [
        lambda: ReportPathRefused("the report file name 'x/y' is not a file in out"),
        lambda: ReportPathLinkRefused("the reports directory out is a symlink"),
        lambda: ReportNameCollision("a and b would both write 'ash.json' in out"),
    ],
    ids=["refused", "link", "collision"],
)
@pytest.mark.parametrize(
    "round_trip", [copy.deepcopy, lambda e: pickle.loads(pickle.dumps(e))]
)
def test_a_refusal_survives_a_round_trip(make, round_trip):
    original = make()

    rebuilt = round_trip(original)

    assert type(rebuilt) is type(original)
    assert rebuilt.found == original.found
    assert str(rebuilt) == str(original)


@pytest.mark.parametrize(
    "name", ["nul.json", "NUL", "con", "com1.txt", "lpt9", "aux.md"]
)
def test_a_windows_device_name_is_not_a_report_file_name(name):
    assert not is_report_file_name(name)


@pytest.mark.parametrize("name", ["null.json", "console.md", "com10.txt", "ash.sarif"])
def test_control_a_name_that_only_starts_like_a_device_is_a_file_name(name):
    assert is_report_file_name(name)


def test_a_file_at_the_reports_path_is_refused_with_the_modules_error(tmp_path):
    (tmp_path / "reports").write_text("not a directory\n", encoding="utf-8")

    with pytest.raises(ReportPathRefused) as refused:
        ensure_reports_dir(tmp_path / "reports")

    assert not isinstance(refused.value, FileExistsError)
    assert "is a file, not a directory" in str(refused.value)
    assert FILE_REMEDY in str(refused.value)


def test_control_a_missing_or_present_directory_is_created_or_kept(tmp_path):
    assert ensure_reports_dir(tmp_path / "reports").is_dir()
    assert ensure_reports_dir(tmp_path / "reports").is_dir()


def test_two_names_of_dots_and_spaces_are_two_files(tmp_path):
    refuse_colliding_report_names(
        tmp_path, [("the a reporter", ["..."]), ("the b reporter", [" "])]
    )


def test_the_sharp_s_and_ss_are_two_files(tmp_path):
    refuse_colliding_report_names(
        tmp_path,
        [("the a reporter", ["straße.md"]), ("the b reporter", ["strasse.md"])],
    )


def test_a_form_c_and_a_form_d_spelling_are_one_file(tmp_path):
    composed = unicodedata.normalize("NFC", "résumé.md")
    decomposed = unicodedata.normalize("NFD", composed)
    assert composed != decomposed

    with pytest.raises(ReportNameCollision):
        refuse_colliding_report_names(
            tmp_path, [("the a reporter", [composed]), ("the b reporter", [decomposed])]
        )


def test_one_writer_naming_two_case_variants_of_one_file_is_refused(tmp_path):
    with pytest.raises(ReportNameCollision) as refused:
        refuse_colliding_report_names(
            tmp_path, [("the a reporter", ["Ash.summary.md", "ash.summary.md"])]
        )

    assert "would write both" in str(refused.value)
    assert "'Ash.summary.md'" in str(refused.value)
    assert "'ash.summary.md'" in str(refused.value)


def test_control_one_writer_naming_one_file_twice_is_not_refused(tmp_path):
    refuse_colliding_report_names(
        tmp_path, [("the a reporter", ["ash.summary.md", "ash.summary.md"])]
    )


def test_control_two_writers_naming_case_variants_are_still_refused(tmp_path):
    with pytest.raises(ReportNameCollision):
        refuse_colliding_report_names(
            tmp_path,
            [("the a reporter", ["Ash.json"]), ("the b reporter", ["ash.json"])],
        )

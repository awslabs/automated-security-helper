# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The file names a reporter writes, and the formats that select it.

The helpers in ``base/reporter_plugin.py`` that name, check and write a reporter's
files hold small gaps of their own: a refused extension on a generic section named
the config class as if it were a config key; a colon in an extension or file name
(an NTFS stream of another file) passed; a NUL in a file name raised from
``resolve`` instead of being refused; a directory junction at a report's name, or
a reports directory that had become a link, was skipped with a warning where a
link at the name is raised; the write itself followed a reports directory swapped
for a link after the checks; a companion file declaration answering one string was
read one character at a time, and one answering None raised; and an iterator given
as the requested formats was read as an empty request or spent by the first
reporter.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import List

import pytest

from automated_security_helper.base import reporter_plugin
from automated_security_helper.base.options import reset_refused_tool_version_warnings
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginConfigBase,
    confined_report_path,
    is_filename_suffix,
    reporter_companion_file_names,
    reporter_matches_requested_formats,
    write_report_file,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.csv_reporter import (
    CSVReporterConfig,
)
from automated_security_helper.utils import report_path_links
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.output_dir_links import OutputDirLinkRefused
from automated_security_helper.utils.sandbox.fs_guard import OutputLinkRefused

pytestmark = pytest.mark.unit

needs_symlinks = pytest.mark.skipif(
    sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
)


@pytest.fixture
def warnings_logged():
    """ASH_LOGGER's warnings; it does not propagate, so caplog would see none."""
    records: List[str] = []

    class _Collect(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            if record.levelno >= logging.WARNING:
                records.append(record.getMessage())

    handler = _Collect(level=logging.WARNING)
    reset_refused_tool_version_warnings()
    ASH_LOGGER.addHandler(handler)
    try:
        yield records
    finally:
        ASH_LOGGER.removeHandler(handler)
        reset_refused_tool_version_warnings()


# --------------------------------------------------------------------------- #
# The extension
# --------------------------------------------------------------------------- #


def test_a_refused_extension_on_a_generic_section_does_not_name_the_class(
    warnings_logged,
):
    """The generic section has no name; its class name is no key of any config."""
    ReporterPluginConfigBase.model_validate({"extension": "a/b"})

    (message,) = warnings_logged
    assert "ReporterPluginConfigBase" not in message, message
    assert "Ignoring" in message and "filename suffix" in message, message


def test_a_refused_extension_on_a_named_section_still_names_its_key(warnings_logged):
    CSVReporterConfig.model_validate({"extension": "a/b"})

    (message,) = warnings_logged
    assert "reporters.csv.extension" in message, message


@pytest.mark.parametrize("value", ["csv:stream", ":", "C:csv"])
def test_an_extension_with_a_colon_is_replaced_by_the_default(value, warnings_logged):
    """On NTFS ``ash.csv:stream`` is a stream of the file ``ash.csv``."""
    config = CSVReporterConfig.model_validate({"extension": value})

    assert config.extension == "csv"
    (message,) = [text for text in warnings_logged if "reporters.csv.extension" in text]
    assert "':'" in message, message


def test_a_colon_is_not_part_of_a_filename_suffix():
    assert is_filename_suffix("json") is True
    assert is_filename_suffix("json:stream") is False


# --------------------------------------------------------------------------- #
# confined_report_path
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("name", ["ash.csv:stream", "C:ash.csv", "ash.a\x00b"])
def test_a_name_that_is_not_one_file_name_is_not_confined_to_the_directory(
    tmp_path, name
):
    assert confined_report_path(tmp_path, name) is None


def test_an_ordinary_name_is_still_confined_to_the_directory(tmp_path):
    assert confined_report_path(tmp_path, "ash.csv") == tmp_path / "ash.csv"


# --------------------------------------------------------------------------- #
# write_report_file
# --------------------------------------------------------------------------- #


def test_a_name_with_a_colon_is_not_written(tmp_path):
    assert write_report_file(tmp_path, "ash.csv:stream", "content") is None
    assert list(tmp_path.iterdir()) == []


def test_a_name_with_a_nul_is_not_written(tmp_path):
    # The link checks run before the name is confined; a NUL in the name must
    # be refused by the name rule first, not raise from the file-system probe.
    assert write_report_file(tmp_path, "ash.a\x00b", "content") is None
    assert list(tmp_path.iterdir()) == []


@needs_symlinks
def test_a_reports_directory_that_is_a_link_is_refused_not_skipped(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    reports = tmp_path / "reports"
    reports.symlink_to(real, target_is_directory=True)

    with pytest.raises(OutputLinkRefused):
        write_report_file(reports, "ash.x", "content")

    assert list(real.iterdir()) == []


def test_a_junction_at_the_name_is_refused_as_a_symlink_there_is(tmp_path, monkeypatch):
    """``link_kind`` answers a junction as it does on Windows; nothing is written."""
    reports = tmp_path / "reports"
    reports.mkdir()

    def kind(path):
        return "a directory junction" if Path(path).name == "ash.x" else None

    monkeypatch.setattr(report_path_links, "link_kind", kind)

    with pytest.raises(OutputDirLinkRefused) as refused:
        write_report_file(reports, "ash.x", "content")

    assert "ash.x is a directory junction" in str(refused.value)
    assert list(reports.iterdir()) == []


@needs_symlinks
def test_a_reports_directory_swapped_for_a_link_after_the_checks_is_not_written_through(
    tmp_path, monkeypatch
):
    reports = tmp_path / "reports"
    reports.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    checked = reporter_plugin.confined_report_path

    def checked_then_swapped(report_dir, filename):
        target = checked(report_dir, filename)
        reports.rename(tmp_path / "reports.moved")
        reports.symlink_to(outside, target_is_directory=True)
        return target

    monkeypatch.setattr(reporter_plugin, "confined_report_path", checked_then_swapped)

    with pytest.raises(OutputLinkRefused):
        write_report_file(reports, "ash.x", "content")

    assert list(outside.iterdir()) == []


def test_a_file_is_written_where_it_is_named(tmp_path):
    assert write_report_file(tmp_path, "ash.x", "content") == tmp_path / "ash.x"
    assert (tmp_path / "ash.x").read_text(encoding="utf-8") == "content"


# --------------------------------------------------------------------------- #
# reporter_companion_file_names
# --------------------------------------------------------------------------- #


class _Declares:
    def __init__(self, answer):
        self._answer = answer

    def companion_file_names(self):
        return self._answer


def test_a_declaration_that_answers_one_string_names_that_one_file():
    assert reporter_companion_file_names(_Declares("ash.extra.md")) == ("ash.extra.md",)


def test_a_declaration_that_answers_none_names_no_file():
    assert reporter_companion_file_names(_Declares(None)) == ()


def test_a_path_is_kept_as_its_string_and_another_object_is_not_a_name():
    declared = _Declares([Path("ash.extra.md"), 5, "ash.more.md"])

    assert reporter_companion_file_names(declared) == ("ash.extra.md", "ash.more.md")


def test_a_declaration_that_raises_is_not_swallowed():
    class _Raises:
        def companion_file_names(self):
            raise RuntimeError("declared badly")

    with pytest.raises(RuntimeError):
        reporter_companion_file_names(_Raises())


# --------------------------------------------------------------------------- #
# reporter_matches_requested_formats
# --------------------------------------------------------------------------- #


def _reporter_named(name):
    return SimpleNamespace(config=SimpleNamespace(name=name))


@pytest.mark.parametrize("formats", [iter([]), iter(["markdown"])])
def test_an_iterator_is_refused_as_the_requested_formats(formats):
    with pytest.raises(TypeError):
        reporter_matches_requested_formats(_reporter_named("markdown"), formats)


def test_a_collection_of_formats_selects_by_name():
    reporter = _reporter_named("markdown")

    assert reporter_matches_requested_formats(reporter, []) is True
    assert reporter_matches_requested_formats(reporter, ["markdown"]) is True
    assert reporter_matches_requested_formats(reporter, ("sarif",)) is False

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""The converters' record of what each converted file came from.

Why this exists
---------------
A converted file (a notebook's Python, an archive member) is scanned under a path
in the output directory that the scanned tree never had, so ``--changed-files-only``
could not tell whether the file it came from was in the diff. Each converter now
writes ``converted-sources.json`` beside its output, mapping every path it wrote
(relative to the work directory, the ``converted_path`` a finding carries) to the
source in the tree, and the engine reads every converter's file back for the
filter. These tests pin the writer and the reader: the key form, the directory
form for an extracted archive, and that a bad file costs its converter's entries
and never the scan.
"""

import json
import logging
import sys
from pathlib import Path
from typing import List

import pytest

from automated_security_helper.utils.scan_output_dirs import (
    CONVERTED_SOURCES_FILE_NAME,
    converted_sources_of,
    record_converted_sources,
)
from automated_security_helper.utils.undecodable_text import text_of_undecodable

pytestmark = pytest.mark.unit


class _Context:
    def __init__(self, work_dir=None, output_dir=None):
        self.work_dir = work_dir
        self.output_dir = output_dir
        self.source_dir = Path(".")


@pytest.fixture
def ash_warnings():
    """Every WARNING the 'ash' logger emits during the test; it does not propagate,
    so caplog never sees it."""
    records: List[logging.LogRecord] = []

    class _Collector(logging.Handler):
        def emit(self, record):
            records.append(record)

    handler = _Collector(level=logging.WARNING)
    logger = logging.getLogger("ash")
    logger.addHandler(handler)
    try:
        yield records
    finally:
        logger.removeHandler(handler)


class TestRecordConvertedSources:
    def test_a_converted_file_is_keyed_relative_to_the_work_directory(self, tmp_path):
        work = tmp_path / "out" / "converted"
        results_dir = work / "jupyter"
        converted = results_dir / "nb__ipynb-converted.py"
        converted.parent.mkdir(parents=True)
        converted.write_text("x = 1\n", encoding="utf-8")

        written = record_converted_sources(
            results_dir, work, {converted: "notebooks/nb.ipynb"}
        )

        assert written == results_dir / CONVERTED_SOURCES_FILE_NAME
        assert json.loads(written.read_text(encoding="utf-8")) == {
            "jupyter/nb__ipynb-converted.py": "notebooks/nb.ipynb"
        }

    def test_an_extraction_directory_is_keyed_with_a_trailing_slash(self, tmp_path):
        """Every member below it was converted from the one archive."""
        work = tmp_path / "out" / "converted"
        results_dir = work / "archive"
        extracted = results_dir / "lib__bundle__zip"
        extracted.mkdir(parents=True)
        (extracted / "m.js").write_text("", encoding="utf-8")

        written = record_converted_sources(
            results_dir, work, {extracted: "lib/bundle.zip"}
        )

        assert json.loads(written.read_text(encoding="utf-8")) == {
            "archive/lib__bundle__zip/": "lib/bundle.zip"
        }

    @pytest.mark.skipif(
        sys.platform == "win32", reason="a name that is not UTF-8 is a POSIX shape"
    )
    def test_a_name_that_is_not_utf8_is_keyed_in_the_record_form(self, tmp_path):
        """``mark_converted_results`` writes ``converted_path`` in the record form,
        each lone surrogate as six characters of text; a key that held the
        surrogate itself matched no finding, so the filter could not place the
        file."""
        work = tmp_path / "out" / "converted"
        results_dir = work / "jupyter"
        results_dir.mkdir(parents=True)
        lone_surrogate = chr(0xDCFF)
        name = f"nb{lone_surrogate}__ipynb-converted.py"
        converted = results_dir / name
        converted.write_text("x = 1\n", encoding="utf-8")

        written = record_converted_sources(results_dir, work, {converted: "nb.ipynb"})

        (key,) = json.loads(written.read_text(encoding="utf-8"))
        assert key == f"jupyter/{text_of_undecodable(name)}"
        assert lone_surrogate not in key
        assert "udcff" in key

    def test_nothing_is_written_for_an_empty_mapping(self, tmp_path):
        work = tmp_path / "out" / "converted"
        results_dir = work / "jupyter"
        results_dir.mkdir(parents=True)

        assert record_converted_sources(results_dir, work, {}) is None
        assert not (results_dir / CONVERTED_SOURCES_FILE_NAME).exists()

    def test_a_path_outside_the_work_directory_is_left_out(self, tmp_path):
        """No finding carries such a converted_path, so no entry can place one."""
        work = tmp_path / "out" / "converted"
        results_dir = work / "jupyter"
        results_dir.mkdir(parents=True)
        elsewhere = tmp_path / "elsewhere.py"
        elsewhere.write_text("", encoding="utf-8")

        assert (
            record_converted_sources(results_dir, work, {elsewhere: "a.ipynb"}) is None
        )


class TestConvertedSourcesOf:
    def test_every_converters_file_is_read_and_merged(self, tmp_path):
        work = tmp_path / "out" / "converted"
        for converter, mapping in (
            ("jupyter", {"jupyter/nb__ipynb-converted.py": "nb.ipynb"}),
            ("archive", {"archive/a__zip/": "a.zip"}),
        ):
            directory = work / converter
            directory.mkdir(parents=True)
            (directory / CONVERTED_SOURCES_FILE_NAME).write_text(
                json.dumps(mapping), encoding="utf-8"
            )

        assert converted_sources_of(_Context(work_dir=work)) == {
            "jupyter/nb__ipynb-converted.py": "nb.ipynb",
            "archive/a__zip/": "a.zip",
        }

    def test_the_work_directory_is_derived_from_the_output_directory(self, tmp_path):
        output = tmp_path / "out"
        directory = output / "converted" / "jupyter"
        directory.mkdir(parents=True)
        (directory / CONVERTED_SOURCES_FILE_NAME).write_text(
            json.dumps({"jupyter/x.py": "x.ipynb"}), encoding="utf-8"
        )

        assert converted_sources_of(_Context(output_dir=output)) == {
            "jupyter/x.py": "x.ipynb"
        }

    def test_a_missing_work_directory_is_an_empty_mapping(self, tmp_path):
        assert converted_sources_of(_Context(work_dir=tmp_path / "nowhere")) == {}
        assert converted_sources_of(_Context()) == {}

    def test_a_file_that_is_not_json_costs_its_converter_only(
        self, tmp_path, ash_warnings
    ):
        work = tmp_path / "out" / "converted"
        bad = work / "archive"
        bad.mkdir(parents=True)
        (bad / CONVERTED_SOURCES_FILE_NAME).write_text("{not json", encoding="utf-8")
        good = work / "jupyter"
        good.mkdir()
        (good / CONVERTED_SOURCES_FILE_NAME).write_text(
            json.dumps({"jupyter/x.py": "x.ipynb"}), encoding="utf-8"
        )

        assert converted_sources_of(_Context(work_dir=work)) == {
            "jupyter/x.py": "x.ipynb"
        }
        assert any(
            CONVERTED_SOURCES_FILE_NAME in record.getMessage()
            and "archive" in record.getMessage()
            for record in ash_warnings
        ), [record.getMessage() for record in ash_warnings]

    def test_a_file_that_is_not_an_object_of_strings_is_left_out(
        self, tmp_path, ash_warnings
    ):
        work = tmp_path / "out" / "converted"
        a_list = work / "archive"
        a_list.mkdir(parents=True)
        (a_list / CONVERTED_SOURCES_FILE_NAME).write_text("[1, 2]", encoding="utf-8")
        mixed = work / "jupyter"
        mixed.mkdir()
        (mixed / CONVERTED_SOURCES_FILE_NAME).write_text(
            json.dumps({"jupyter/x.py": "x.ipynb", "jupyter/y.py": 7, "": "z.ipynb"}),
            encoding="utf-8",
        )

        assert converted_sources_of(_Context(work_dir=work)) == {
            "jupyter/x.py": "x.ipynb"
        }
        assert len(ash_warnings) == 1, [r.getMessage() for r in ash_warnings]

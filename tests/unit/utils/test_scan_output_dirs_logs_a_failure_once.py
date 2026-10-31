# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""scan_output_dirs logs a caught failure's text once, through logging itself.

Three handlers in utils/scan_output_dirs.py put the exception they caught into a
log f-string (``{error}``, ``{type(error).__name__}``). The package's check that no
text is shown twice (``tests/unit/utils/test_no_text_is_shown_twice.py``) reads a
handler's variable as shown text when some site in the package raises that
exception type with text an escaper produced, and a log method shows its message
again, so the three sites were among its offenders. The handlers now log a plain
message and hand the exception to logging's own rendering (``exc_info=True``), so
the failure's text reaches the log once, with its traceback, at DEBUG.
"""

from __future__ import annotations

import logging
from pathlib import Path
from types import SimpleNamespace
from typing import List

import pytest

from automated_security_helper.utils import scan_output_dirs
from automated_security_helper.utils.scan_output_dirs import (
    CONVERTED_SOURCES_FILE_NAME,
    committed_output_files,
    converted_sources_of,
    drop_results_in_ash_output_dirs,
)

pytestmark = pytest.mark.unit

_FILE = "automated_security_helper/utils/scan_output_dirs.py"


@pytest.fixture
def records(caplog):
    """ASH_LOGGER's records at DEBUG, through pytest's capture handler.

    The logger's own handlers write to a console and leave nothing in
    ``caplog.records``, so they are swapped for the capture handler for the test
    (the shape of tests/unit/utils/test_get_scan_set_coverage.py).
    """
    logger = scan_output_dirs.ASH_LOGGER
    saved_handlers = logger.handlers
    saved_propagate = logger.propagate
    saved_level = logger.level
    logger.handlers = [caplog.handler]
    logger.propagate = False
    logger.setLevel(logging.DEBUG)
    caplog.set_level(logging.DEBUG, logger=logger.name)
    try:
        yield caplog
    finally:
        logger.handlers = saved_handlers
        logger.propagate = saved_propagate
        logger.setLevel(saved_level)


def _messages(records, needle: str) -> List[logging.LogRecord]:
    return [r for r in records.records if needle in r.getMessage()]


def test_the_shown_twice_check_names_no_site_in_scan_output_dirs():
    """The package-wide oracle, read for this module only.

    Red before the cut: the three handlers above were its offenders in this file.
    """
    from tests.unit.utils.test_no_text_is_shown_twice import (
        _Analysis,
        _package_sources,
    )

    sources = _package_sources()
    assert _FILE in sources, "the module under test is not in the package walk"

    sites = sorted(s for s in _Analysis(sources).offenders() if s[0] == _FILE)

    assert sites == [], "shown twice:\n" + "\n".join(map(repr, sites))


class TestNamingTheOutputDirectoriesFails:
    """The two readers of named_output_dirs_of, when it raises."""

    @pytest.fixture
    def failing(self, monkeypatch, tmp_path):
        def refuse(context):
            raise ValueError("the reason, shown once")

        monkeypatch.setattr(scan_output_dirs, "named_output_dirs_of", refuse)
        return SimpleNamespace(source_dir=tmp_path, output_dir=tmp_path / "out")

    def test_committed_output_files_logs_the_failure_once_with_its_traceback(
        self, failing, records
    ):
        assert committed_output_files(failing, scanned_files=[]) == set()

        found = _messages(records, "Could not name ASH's output directories")
        assert len(found) == 1
        (record,) = found
        assert record.levelno == logging.DEBUG
        assert record.exc_info is not None and record.exc_info[0] is ValueError
        # The exception's text is not in the message: logging renders it from
        # exc_info, so it is shown once, by the sink.
        assert "the reason" not in record.getMessage()

    def test_the_drop_logs_the_failure_once_with_its_traceback(self, failing, records):
        report = SimpleNamespace(runs=[SimpleNamespace(results=[])])

        assert drop_results_in_ash_output_dirs(report, failing) == 0

        found = _messages(records, "Could not name ASH's output directories")
        assert len(found) == 1
        (record,) = found
        assert record.levelno == logging.DEBUG
        assert record.exc_info is not None and record.exc_info[0] is ValueError
        assert "the reason" not in record.getMessage()


def test_an_unreadable_converted_sources_record_is_skipped_with_one_warning(
    tmp_path: Path, records
):
    """The warning names the file and the filter's answer; the failure's own text
    and type reach the log once, as DEBUG exception info."""
    work = tmp_path / "work"
    (work / "jupyter").mkdir(parents=True)
    (work / "jupyter" / CONVERTED_SOURCES_FILE_NAME).write_text(
        "{not json", encoding="utf-8"
    )
    context = SimpleNamespace(work_dir=work, output_dir=None)

    assert converted_sources_of(context) == {}

    warnings = [r for r in records.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert f"Skipped jupyter/{CONVERTED_SOURCES_FILE_NAME}" in warnings[0].getMessage()
    assert "JSONDecodeError" not in warnings[0].getMessage()
    assert warnings[0].exc_info is None

    why = _messages(records, f"Why jupyter/{CONVERTED_SOURCES_FILE_NAME} could not")
    assert len(why) == 1
    assert why[0].levelno == logging.DEBUG
    assert why[0].exc_info is not None
    assert issubclass(why[0].exc_info[0], ValueError)

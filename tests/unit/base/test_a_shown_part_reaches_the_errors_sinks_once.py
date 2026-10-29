# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A part a call site showed reaches a scanner's errors as written, and is shown once.

Why this exists
---------------
PluginBase._plugin_log appends what it is given to the plugin's ``errors``, and
every reader of ``errors`` takes the entries as written: the empty-results
warning and the failure detail quote them and show the whole once, and the SARIF
invocation's exitCodeDescription stores them as data. A part a call site has
shown already, a ShownText, is stored as the text it was made from; were it
joined in as the shown text, each of those would show it a second time, with
the backslash of each escape doubled. No caller passes one today; these cells
call it directly.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import ClassVar
from unittest.mock import MagicMock

import pytest

from automated_security_helper.base.scanner_plugin import ScannerPluginBase
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.utils.log import console_text
from automated_security_helper.utils.terminal_text import shown_not_obeyed

pytestmark = pytest.mark.unit

#: A tool's stderr line holding an ESC, as written.
TEXT = "a\x1bb"

#: TEXT shown once: its ESC as an escape.
SHOWN_ONCE = "a\\x1bb"

SARIF = '{"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "fake"}}}]}'


def _make_scanner(tmp_path, *, exit_code: int, writes_results: str | None):
    """A scanner over the real base whose tool reports TEXT, shown by the call
    site, through _plugin_log."""
    source_dir = tmp_path / "src"
    source_dir.mkdir(parents=True, exist_ok=True)
    (source_dir / "app.py").write_text("print('x')\n", encoding="utf-8")
    output_dir = tmp_path / "out"
    output_dir.mkdir(parents=True, exist_ok=True)
    results_file = output_dir / "scanners" / "fake" / "results.json"

    class _FakeScanner(ScannerPluginBase):
        fake_exit_code: ClassVar[int] = exit_code
        fake_writes_results: ClassVar[str | None] = writes_results
        fake_results_file: ClassVar[Path] = results_file

        def model_post_init(self, context) -> None:
            return None

        def validate_plugin_dependencies(self) -> bool:
            return True

        def _execute_scan(self, target, target_type, global_ignore_paths):
            return (["fake-tool", "--scan"], self.fake_results_file, None)

        def _run_subprocess(self, command, results_dir=None, **kwargs):
            self.exit_code = self.fake_exit_code
            self._plugin_log(shown_not_obeyed(TEXT), level=logging.ERROR)
            if self.fake_writes_results is not None:
                self.fake_results_file.parent.mkdir(parents=True, exist_ok=True)
                self.fake_results_file.write_text(
                    self.fake_writes_results, encoding="utf-8"
                )
            return {"returncode": self.fake_exit_code}

    context = MagicMock()
    context.source_dir = source_dir
    context.output_dir = output_dir
    context.work_dir = tmp_path / "work"

    scanner = _FakeScanner.model_construct()
    scanner.context = context
    scanner.config = MagicMock()
    scanner.config.name = "fake-tool"
    scanner.errors = []
    scanner.output = []
    scanner.exit_code = 0
    scanner.results_dir = output_dir / "scanners" / "fake"
    return scanner


def _run(scanner, tmp_path):
    return scanner.scan(target=tmp_path / "src", target_type="source")


def _assert_shown_once(shown: str) -> None:
    assert SHOWN_ONCE in shown, shown
    # Shown twice, the escape's backslash is doubled.
    assert "\\\\x1b" not in shown, shown


def test_errors_hold_the_part_as_written(tmp_path):
    scanner = _make_scanner(tmp_path, exit_code=0, writes_results=SARIF)

    scanner._run_subprocess(["fake-tool"])

    assert scanner.errors == [f"(fake-tool) {TEXT}"], scanner.errors


def test_the_failure_detail_shows_the_part_once(tmp_path):
    scanner = _make_scanner(tmp_path, exit_code=7, writes_results=None)

    with pytest.raises(ScannerError) as raised:
        _run(scanner, tmp_path)

    detail = str(raised.value)
    # The control: the detail quotes the tool's stderr.
    assert "Stderr:" in detail, detail
    _assert_shown_once(shown_not_obeyed(detail))


def test_the_empty_results_warning_shows_the_part_once(tmp_path):
    records: list = []

    class _Collector(logging.Handler):
        def emit(self, record):
            records.append(record)

    handler = _Collector(level=logging.WARNING)
    logger = logging.getLogger("ash")
    logger.addHandler(handler)
    try:
        # An empty results file after an accepted exit code is nothing to grade:
        # the warning is logged, then the scan is refused.
        with pytest.raises(ScannerError, match="nothing to grade"):
            _run(_make_scanner(tmp_path, exit_code=0, writes_results=""), tmp_path)
    finally:
        logger.removeHandler(handler)

    warnings = [r for r in records if "results file is empty" in r.getMessage()]
    # The control: the empty-results warning was logged.
    assert warnings, [r.getMessage() for r in records]
    for record in warnings:
        _assert_shown_once(console_text(record, record.getMessage()))


def test_the_sarif_exit_description_holds_the_part_as_written(tmp_path):
    report = _run(_make_scanner(tmp_path, exit_code=0, writes_results=SARIF), tmp_path)

    description = report.runs[0].invocations[0].exitCodeDescription
    assert description == f"(fake-tool) {TEXT}", description

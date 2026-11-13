# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The CSV report's fields and headers are what a consumer can read.

* A field holding a line break spans physical lines of the file, and a line
  starting with ``::`` or holding ``##name[`` was a CI workflow command when the
  file was printed to a runner's log. Each such form is broken, as the console
  shows it.
* ``sarif_field_mappings`` named title-case headers ("Rule ID") that no row of
  the report has carried since the header was derived from ``FlatVulnerability``.
* Rows ended in ``\\r\\n``, which a text-mode file handle turned into ``\\r\\r\\n``
  on Windows; the writer now ends a row in ``\\n`` and the handle supplies the
  platform's ending.
"""

import csv
from io import StringIO
from unittest.mock import MagicMock

import pytest

from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.plugin_modules.ash_builtin.reporters.csv_reporter import (
    CsvReporter,
    spreadsheet_safe,
)

pytestmark = pytest.mark.unit


@pytest.fixture
def csv_reporter(test_plugin_context):
    return CsvReporter(context=test_plugin_context)


def _report(csv_reporter, **fields) -> str:
    model = MagicMock()
    vuln = MagicMock()
    vuln.model_dump.return_value = fields
    model.to_flat_vulnerabilities.return_value = [vuln]
    return csv_reporter.report(model)


def _command_lines(text: str) -> list[str]:
    """The lines that start, after whitespace, with "::" or "##"."""
    return [
        line for line in text.splitlines() if line.lstrip().startswith(("::", "##"))
    ]


class TestCommandFormsInFields:
    def test_a_line_start_command_inside_a_field_is_broken(self, csv_reporter):
        text = _report(
            csv_reporter,
            id="V1",
            code_snippet="x\n::add-mask::secret-a\n##[group]secret-b",
            description="y\n  ::warning::secret-c",
        )

        assert _command_lines(text) == [], text
        rows = list(csv.reader(StringIO(text)))
        assert rows[1][1] == "x\n\\x3a:add-mask::secret-a\n\\x23#[group]secret-b"
        assert rows[1][2] == "y\n  \\x3a:warning::secret-c"

    def test_a_named_hash_form_mid_line_is_broken_too(self):
        assert (
            spreadsheet_safe("a ##vso[task.complete]b") == "a \\x23#vso[task.complete]b"
        )

    def test_a_tag_and_a_heading_are_written_as_they_are(self):
        assert spreadsheet_safe("tool_name::bandit") == "tool_name::bandit"
        assert (
            spreadsheet_safe("## Summary\n\nno findings") == "## Summary\n\nno findings"
        )

    def test_a_broken_form_is_still_made_text_for_a_spreadsheet(self):
        assert spreadsheet_safe("=1\n::x") == "'=1\n\\x3a:x"


class TestHeadersAndRowEndings:
    def test_every_mapped_header_is_a_field_the_report_emits(self):
        for header in CsvReporter.sarif_field_mappings().values():
            assert header in FlatVulnerability.model_fields, header

    def test_rows_end_in_a_bare_newline(self, csv_reporter):
        text = _report(csv_reporter, id="V1", title="t")

        assert "\r" not in text
        assert text.endswith("\n")

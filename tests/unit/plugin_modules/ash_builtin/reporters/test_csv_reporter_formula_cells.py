# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A CSV cell that begins with a formula character is written as text.

Every text cell of the CSV report is repository- or scanner-derived: a code
snippet, a finding's message, a file path, a rule title. The report wrote them
verbatim, so a cell beginning with ``=``, ``+``, ``-`` or ``@`` was evaluated
as a formula by the spreadsheet the format targets. A single quote in front
makes the cell text in every spreadsheet.
"""

import csv
from io import StringIO
from unittest.mock import MagicMock

import pytest

from automated_security_helper.plugin_modules.ash_builtin.reporters.csv_reporter import (
    CsvReporter,
    spreadsheet_safe,
)

pytestmark = pytest.mark.unit


@pytest.fixture
def csv_reporter(test_plugin_context):
    return CsvReporter(context=test_plugin_context)


def _rows(csv_reporter, **cells):
    model = MagicMock()
    vuln = MagicMock()
    vuln.model_dump.return_value = cells
    model.to_flat_vulnerabilities.return_value = [vuln]
    return list(csv.reader(StringIO(csv_reporter.report(model))))


def test_a_formula_leading_cell_is_prefixed_with_a_quote(csv_reporter):
    rows = _rows(
        csv_reporter,
        id="V1",
        title='=HYPERLINK("https://example.invalid","click")',
        description="+1+1",
        code_snippet="@SUM(A1:A9)",
        scanner="-bandit",
    )

    assert rows[1] == [
        "V1",
        '\'=HYPERLINK("https://example.invalid","click")',
        "'+1+1",
        "'@SUM(A1:A9)",
        "'-bandit",
    ]


def test_an_ordinary_cell_is_unchanged(csv_reporter):
    rows = _rows(csv_reporter, id="V1", title="Test Finding", severity="high")

    assert rows[1] == ["V1", "Test Finding", "high"]


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("=cmd", "'=cmd"),
        ("+1", "'+1"),
        ("-x", "'-x"),
        ("@a", "'@a"),
        ("\tx", "'\tx"),
        ("\rx", "'\rx"),
        ("plain", "plain"),
        ("", ""),
        (7, 7),
        (-1, -1),
        (None, None),
    ],
)
def test_spreadsheet_safe(value, expected):
    assert spreadsheet_safe(value) == expected

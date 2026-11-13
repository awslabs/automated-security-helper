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


def test_the_workspace_project_cell_of_a_skipped_project_row_is_escaped(
    csv_reporter,
):
    """The project column and the skipped-project row are written by code of
    their own, outside the flattened-finding path; a project directory named
    with a leading ``@`` reaches the sheet as text. The row's other text values
    begin with the fixed words the reporter puts first ("Project ...",
    "ash-workspace-skipped-project:"), so a skip detail that starts with a
    formula character never leads a value."""
    from automated_security_helper.models.asharp_model import AshAggregatedResults
    from automated_security_helper.models.workspace import (
        ProjectRunStatus,
        SkippedProjectReason,
        WorkspaceProjectResult,
        WorkspaceResults,
    )
    from automated_security_helper.plugin_modules.ash_builtin.reporters.csv_reporter import (
        PROJECT_COLUMN,
        SKIPPED_PROJECT_ROW_TYPE,
    )

    model = AshAggregatedResults()
    model.workspace = WorkspaceResults(
        workspace_file="/w/.ash-workspace.yaml",
        workspace_root="/w",
        exit_code=2,
        projects=[
            WorkspaceProjectResult(
                project="@scope",
                relative_path="@scope",
                display_label="@scope",
                status=ProjectRunStatus.SKIPPED,
                skip_reason=SkippedProjectReason.ERROR,
                skip_detail='=HYPERLINK("https://example.invalid","x")',
                output_path="projects/@scope",
            )
        ],
    )

    header, row = list(csv.reader(StringIO(csv_reporter.report(model))))[:2]

    assert row[header.index(PROJECT_COLUMN)] == "'@scope"
    assert row[header.index("workspace_row_type")] == SKIPPED_PROJECT_ROW_TYPE
    assert row[header.index("title")] == "Project '@scope' was not scanned"
    assert row[header.index("description")].startswith("Project '@scope' was not")
    assert (
        '=HYPERLINK("https://example.invalid","x")' in row[header.index("description")]
    )
    for value in row:
        assert not value.startswith(("=", "+", "-", "@", "\t", "\r")), value


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

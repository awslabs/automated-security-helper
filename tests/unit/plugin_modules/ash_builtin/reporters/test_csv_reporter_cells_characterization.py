# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What the CSV writes for each kind of cell, pinned cell by cell.

The expected rows are written out by hand, from the format's rules rather than
from a run: a text cell has each CI command form broken and a leading formula
character quoted; an integer or a boolean is written as Python prints it and is
never quoted (``-3`` stays a number); a missing or null value is an empty cell;
a text with a lone surrogate comes back as it went in; the workspace columns lead
in workspace mode. These were run against the loop that built the rows one cell at
a time before they were run against the frame projection that replaced it.
"""

import csv
from io import StringIO
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.plugin_modules.ash_builtin.reporters.csv_reporter import (
    CsvReporter,
)

pytestmark = pytest.mark.unit


@pytest.fixture
def csv_reporter(test_plugin_context):
    return CsvReporter(context=test_plugin_context)


def _model(*dumps):
    model = MagicMock()
    findings = []
    for dump in dumps:
        finding = MagicMock()
        finding.model_dump.return_value = dump
        findings.append(finding)
    model.to_flat_vulnerabilities.return_value = findings
    return model


FIRST = {
    "id": "V1",
    "title": "=1+1",
    "description": "x\n::add-mask::s",
    "severity": "HIGH",
    "scanner": "bandit",
    "line_start": 12,
    "line_end": 2**70,
    "is_suppressed": False,
    "code_snippet": "\ud800tail",
    "package_version": None,
    "tags": ["a", "b"],
    "ratio": 1.5,
}

SECOND = {
    "id": "V2",
    "title": "-5",
    "description": "##[error]x",
    "severity": "LOW",
    "line_start": -3,
    "is_suppressed": True,
    "code_snippet": "\t=tab",
    "extra_key_not_in_the_header": "dropped",
}


def test_every_kind_of_cell_is_written_as_the_format_says(csv_reporter):
    text = csv_reporter.report(_model(FIRST, SECOND))

    assert "\r" not in text
    assert text.endswith("\n")
    rows = list(csv.reader(StringIO(text)))
    assert rows[0] == list(FIRST)
    assert rows[1] == [
        "V1",
        "'=1+1",
        "x\n\\x3a:add-mask::s",
        "HIGH",
        "bandit",
        "12",
        str(2**70),
        "False",
        "\ud800tail",
        "",
        "['a', 'b']",
        "1.5",
    ]
    assert rows[2] == [
        "V2",
        "'-5",
        "\\x23#[error]x",
        "LOW",
        "",
        "-3",
        "",
        "True",
        "'\t=tab",
        "",
        "",
        "",
    ]
    assert len(rows) == 3


def test_a_workspace_scan_leads_with_the_project_and_the_row_type(csv_reporter):
    dump = {
        "id": "V1",
        "workspace_project": "@proj",
        "title": "t",
        "line_start": 7,
    }
    with (
        patch(
            "automated_security_helper.plugin_modules.ash_builtin.reporters.csv_reporter.is_workspace_scan",
            return_value=True,
        ),
        patch(
            "automated_security_helper.plugin_modules.ash_builtin.reporters.csv_reporter.skipped_projects",
            return_value=[],
        ),
    ):
        rows = list(csv.reader(StringIO(csv_reporter.report(_model(dump)))))

    assert rows == [
        ["workspace_project", "workspace_row_type", "id", "title", "line_start"],
        ["'@proj", "finding", "V1", "t", "7"],
    ]


def test_a_cell_is_written_from_the_text_it_was_given_not_its_wire_form(
    csv_reporter,
):
    """A non-ASCII cell has the command check made on the text it is, and comes
    back unchanged: it goes through a frame column as UTF-8 bytes, and the check
    is made on the text before that."""
    dump = {"id": "V1", "description": "\u00e9\n\u00a0::x", "title": "\u00a0=a"}
    rows = list(csv.reader(StringIO(csv_reporter.report(_model(dump)))))

    # U+00A0 is whitespace to the check, so the "::" after it is a line start; a
    # title that begins with it does not begin with a formula character.
    assert rows[1] == ["V1", "\u00e9\n\u00a0\\x3a:x", "\u00a0=a"]

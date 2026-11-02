# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The HTML report's reporter columns look a path up the way the presence check does.

The reporter mappings key every array index as ``[]`` (``runs[].results[].x``).
The presence check was fixed to look a path up that way, and the HTML columns
still looked up the raw path, so a path written with an index
(``runs[0].results[0].message.text``) showed an empty entry in every reporter
column, and the mapping the presence check had already found was ignored.
"""

import html as html_module

import pytest

from automated_security_helper.utils.meta_analysis.reporting import (
    generate_html_report,
    get_reporter_mappings,
)

pytestmark = pytest.mark.unit

MAPPED = "runs[].results[].message.text"


def _validation():
    return {
        "missing_fields": {},
        "match_statistics": {},
        "summary": {
            "total_findings": 1,
            "matched_findings": 1,
            "critical_missing_fields": 0,
            "important_missing_fields": 0,
            "informational_missing_fields": 0,
        },
    }


def _page(tmp_path, presence):
    report = tmp_path / "report.html"
    generate_html_report(_validation(), str(report), presence)
    return html_module.unescape(report.read_text(encoding="utf-8"))


def _cell(name):
    return f"<td class='field-path'>{name}</td>"


def test_an_indexed_path_shows_the_mapped_name_in_the_reporter_column(tmp_path):
    mapped = get_reporter_mappings()["ocsf"][MAPPED]

    page = _page(
        tmp_path,
        {
            "runs[0].results[0].message.text": {
                "type": ["str"],
                "scanners": ["bandit"],
                "in_aggregate": True,
            }
        },
    )

    assert _cell(mapped) in page


def test_the_unindexed_form_still_shows_it(tmp_path):
    """The control: the form the mappings use was never blank."""
    mapped = get_reporter_mappings()["ocsf"][MAPPED]

    page = _page(
        tmp_path,
        {MAPPED: {"type": ["str"], "scanners": ["bandit"], "in_aggregate": True}},
    )

    assert _cell(mapped) in page


def test_a_mapping_the_presence_check_found_is_shown(tmp_path):
    page = _page(
        tmp_path,
        {
            "runs[0].results[0].x": {
                "type": ["str"],
                "scanners": ["bandit"],
                "in_aggregate": True,
                "reporter_mappings": {"ocsf": "found.by.the.presence.check"},
            }
        },
    )

    assert _cell("found.by.the.presence.check") in page

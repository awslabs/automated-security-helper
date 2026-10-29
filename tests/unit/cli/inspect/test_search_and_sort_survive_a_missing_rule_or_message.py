# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Search and the rule and message sorts work on a result with no rule id or no
message text.

extract_findings gives such a result a None rule_id or message, which the dict
default in the search and sort did not replace: ``.lower()`` on None ended the
explorer with an AttributeError, and sorting None against str with a TypeError.
"""

import pytest

from automated_security_helper.cli.inspect.inspect_findings_app import (
    FindingsExplorerApp,
)

pytestmark = pytest.mark.unit


def _findings() -> list[dict]:
    return [
        {
            "rule_id": None,
            "severity": "high",
            "scanner": "bandit",
            "message": None,
            "file": "src/app.py",
            "line": 10,
            "suppressed": False,
        },
        {
            "rule_id": "B102",
            "severity": "medium",
            "scanner": "bandit",
            "message": "Hardcoded password",
            "file": "src/db.py",
            "line": 20,
            "suppressed": False,
        },
    ]


def _app() -> FindingsExplorerApp:
    findings = _findings()
    app = FindingsExplorerApp(findings)
    app.filtered_findings = findings
    return app


def test_a_search_matches_the_other_fields_and_raises_nothing():
    app = _app()
    app.search_query = "password"

    app._apply_search()

    assert [f["rule_id"] for f in app.filtered_findings] == ["B102"]


def test_a_search_for_a_file_name_still_finds_the_finding_with_no_rule():
    app = _app()
    app.search_query = "app.py"

    app._apply_search()

    assert [f["file"] for f in app.filtered_findings] == ["src/app.py"]


@pytest.mark.parametrize("column", ["rule_id", "message"])
def test_sorting_by_a_text_column_orders_the_missing_value_first(column):
    app = _app()
    app.current_sort = column
    app.sort_reverse = False

    app._apply_sorting()

    assert [f.get(column) for f in app.filtered_findings][0] is None

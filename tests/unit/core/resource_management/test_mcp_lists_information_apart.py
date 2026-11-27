# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The MCP results tools list a result that states no finding and count it nowhere.

A SARIF result whose ``kind`` is ``pass``, ``notApplicable`` or ``informational``
states no finding (SARIF 3.27.9). The note ASH writes when nothing scanned a
container image is one. At the ``ALL`` threshold the tools counted it as an
actionable finding, in the findings list, in the total and in the INFO bucket.

The findings list is the actionable view's, so the note never reaches it, and each
entry names its kind in ``result_kind``
(tests/unit/cli/mcp/test_actionable_findings_reach_the_client.py drives it through
the server). ``findings_count``, the total, the buckets and the actionable view leave
the note out. ``explain_finding`` names the kind of the finding it explains.
"""

from unittest.mock import patch

import pytest

from automated_security_helper.cli.mcp_tools import mcp_explain_finding
from automated_security_helper.core.resource_management.result_filters import (
    _counts_toward_exit_2,
    _stats_of_sarif,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.schemas.sarif_schema_model import SarifReport

pytestmark = pytest.mark.unit

NOTE = "ASH-container-image-not-scanned"


def _bandit() -> dict:
    return {
        "ruleId": "B602",
        "level": "error",
        "message": {"text": "subprocess call with shell=True"},
        "properties": {"scanner_name": "bandit"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "src/app.py"},
                    "region": {"startLine": 3},
                }
            }
        ],
    }


def _note() -> dict:
    return {
        "ruleId": NOTE,
        "kind": "informational",
        "level": "none",
        "message": {"text": "container image example:1 was not scanned"},
    }


def _sarif(*results: dict) -> dict:
    return {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "ASH"}}, "results": list(results)}],
    }


def test_a_result_that_states_no_finding_never_counts_toward_exit_2():
    """The gate's per-result test: B602 counts at ALL, the note does not."""
    assert _counts_toward_exit_2(_bandit(), "ALL") is True
    assert _counts_toward_exit_2(_note(), "ALL") is False


def test_the_recount_puts_the_note_in_no_bucket_and_no_total():
    stats = _stats_of_sarif(_sarif(_bandit(), _note()), {"": "ALL"}, {})

    assert stats["total"] == 1
    assert stats["actionable"] == 1
    assert stats["severity_counts"]["info"] == 0


def test_explain_finding_names_the_kind_of_the_result(tmp_path):
    model = AshAggregatedResults()
    model.sarif = SarifReport.model_validate(_sarif(_bandit(), _note()))
    flat = model.to_flat_vulnerabilities()
    note = next(row for row in flat if row.rule_id == NOTE)

    with patch(
        "automated_security_helper.cli.mcp_tools._load_flat_vulns_for_explain",
        return_value=flat,
    ):
        result = mcp_explain_finding(finding_id=note.id, results_path=str(tmp_path))

    assert result["success"] is True
    assert result["finding"].get("result_kind") == "informational"

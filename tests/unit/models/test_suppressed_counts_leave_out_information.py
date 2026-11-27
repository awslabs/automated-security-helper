# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A suppressed result that states no finding is in no suppressed total.

A SARIF result whose ``kind`` is ``pass``, ``notApplicable`` or ``informational``
states no finding (SARIF 3.27.9), so there is nothing for a suppression to hide:
the reports list the row under Information, and no total counts it, the suppressed
total included. Flattening the results writes each scanner's suppressed count from
the flat rows, and wrote the count of this row too.
"""

import pytest

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.schemas.sarif_schema_model import SarifReport

pytestmark = pytest.mark.unit

NOTE = "ASH-container-image-not-scanned"


def _suppressed(rule_id: str, **extra) -> dict:
    return {
        "ruleId": rule_id,
        "level": "error",
        "message": {"text": f"result of {rule_id}"},
        "properties": {"scanner_name": "bandit"},
        "suppressions": [{"kind": "inSource", "justification": "accepted"}],
        **extra,
    }


def _model() -> AshAggregatedResults:
    """Two results of one scanner, both suppressed; the second states no finding."""
    model = AshAggregatedResults()
    model.sarif = SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "bandit"}},
                    "results": [
                        _suppressed("B602"),
                        _suppressed(NOTE, kind="informational", level="none"),
                    ],
                }
            ],
        }
    )
    return model


def test_the_suppressed_count_of_a_scanner_leaves_the_note_out():
    model = _model()
    flat = model.to_flat_vulnerabilities()

    assert [row.is_suppressed for row in flat] == [True, True]
    assert model._suppressed_by_scanner(flat) == {"bandit": 1}


def test_the_suppressed_total_of_the_summary_leaves_the_note_out():
    model = _model()

    model.to_flat_vulnerabilities()

    assert model.metadata.summary_stats.suppressed == 1

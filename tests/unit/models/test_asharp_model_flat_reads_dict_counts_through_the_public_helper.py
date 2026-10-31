# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Flattening counts a dict result's suppressed findings through a public helper.

``to_flat_vulnerabilities`` is called by every reporter, and it counted a scanner's
suppressed findings with ``ScannerStatisticsCalculator._dict_result_counts``, a
private helper of another class, called with the model as its first argument. A
change to that helper's signature or to the way it reads odd ``additional_reports``
values then broke every reporter. The calculator now has ``dict_result_counts``,
which the flatten calls; it answers what the private helper answers.

The controls say the public helper answers the same counts, and that the summary and
the row still carry the dict result's suppressed findings after the flatten.
"""

from __future__ import annotations

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.scanner_statistics_calculator import (
    ScannerStatisticsCalculator,
)
from automated_security_helper.core.unified_metrics import (
    populate_metrics_from_unified_source,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()

SCANNER = "dict-tool"


def _dict_report(suppressed: int) -> dict:
    """The per-target report the processor writes for a graded dict result."""
    counts = {
        "suppressed": suppressed,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }
    return {
        "scanner_name": SCANNER,
        "target_type": "source",
        "status": "PASSED",
        "finding_count": suppressed,
        "severity_counts": counts,
        "raw_results": {"severity_counts": counts},
    }


def _model(suppressed: int) -> AshAggregatedResults:
    model = AshAggregatedResults()
    model.ash_config = get_default_config()
    model.additional_reports = {SCANNER: {"source": _dict_report(suppressed)}}
    return model


def test_the_flatten_reads_the_counts_through_the_public_helper(monkeypatch):
    model = _model(3)
    seen = []
    real = ScannerStatisticsCalculator.dict_result_counts

    def spy(asharp_model, scanner_name):
        seen.append((asharp_model, scanner_name))
        return real(asharp_model, scanner_name)

    monkeypatch.setattr(
        ScannerStatisticsCalculator, "dict_result_counts", staticmethod(spy)
    )

    model.to_flat_vulnerabilities()

    assert any(held is model and name == SCANNER for held, name in seen)


def test_the_public_helper_answers_what_the_private_helper_answers():
    model = _model(3)

    public = ScannerStatisticsCalculator.dict_result_counts(model, SCANNER)
    private = ScannerStatisticsCalculator._dict_result_counts(model, SCANNER)

    assert public.model_dump() == private.model_dump()
    assert public.suppressed == 3


def test_the_summary_and_the_row_keep_the_dict_results_suppressed_findings():
    model = _model(3)
    populate_metrics_from_unified_source(model)

    model.to_flat_vulnerabilities()

    assert model.metadata.summary_stats.suppressed == 3
    assert model.scanner_results[SCANNER].suppressed_finding_count == 3

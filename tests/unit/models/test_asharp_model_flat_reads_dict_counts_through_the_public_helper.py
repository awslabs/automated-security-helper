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

from automated_security_helper.core.scanner_statistics_calculator import (
    ScannerStatisticsCalculator,
)
from automated_security_helper.core.unified_metrics import (
    populate_metrics_from_unified_source,
)
from tests.unit.models._suppressed_count_helpers import (
    SCANNER,
    build_model,
    dict_report,
)

pytestmark = pytest.mark.unit


def test_the_flatten_reads_the_counts_through_the_public_helper(monkeypatch):
    model = build_model(reports={SCANNER: dict_report(3)})
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
    model = build_model(reports={SCANNER: dict_report(3)})

    public = ScannerStatisticsCalculator.dict_result_counts(model, SCANNER)
    private = ScannerStatisticsCalculator._dict_result_counts(model, SCANNER)

    assert public.model_dump() == private.model_dump()
    assert public.suppressed == 3


def test_the_summary_and_the_row_keep_the_dict_results_suppressed_findings():
    model = build_model(reports={SCANNER: dict_report(3)})
    populate_metrics_from_unified_source(model)

    model.to_flat_vulnerabilities()

    assert model.metadata.summary_stats.suppressed == 3
    assert model.scanner_results[SCANNER].suppressed_finding_count == 3

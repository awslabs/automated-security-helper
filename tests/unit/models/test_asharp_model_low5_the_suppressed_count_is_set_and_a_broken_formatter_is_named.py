# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Flattening sets the suppressed counts, and a broken error formatter is named.

``to_flat_vulnerabilities`` sets ``summary_stats.suppressed`` from the flattened
findings and passes each scanner's whole count to the row, which sets it too, so
flattening again (after the cache is dropped, as ``save_model`` does) gives the
same count and not a doubled one. The method's docstring said the counts were
bumped; it now says they are set. The metrics handler's fallback line names the
type of the first error alone, and the error that stopped the description is now
named the same way on the line before it.
"""

from __future__ import annotations

import logging

import pytest

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.utils.log import ASH_LOGGER
from tests.unit.models.test_asharp_model_low4_the_flat_cache_is_dropped_on_request import (
    _model,
    _result,
)

pytestmark = pytest.mark.unit


@pytest.fixture
def logged():
    lines = []

    class _Collect(logging.Handler):
        def emit(self, record):
            lines.append(logging.Formatter("%(message)s").format(record))

    handler = _Collect(level=logging.DEBUG)
    level = ASH_LOGGER.level
    ASH_LOGGER.setLevel(logging.DEBUG)
    ASH_LOGGER.addHandler(handler)
    try:
        yield lines
    finally:
        ASH_LOGGER.removeHandler(handler)
        ASH_LOGGER.setLevel(level)


def _three_findings_two_suppressed() -> AshAggregatedResults:
    return _model(
        _result("B101", suppressed=True),
        _result("B102", suppressed=True),
        _result("B103"),
    )


def test_flattening_counts_each_suppressed_finding_once():
    model = _three_findings_two_suppressed()

    model.to_flat_vulnerabilities()

    assert model.metadata.summary_stats.suppressed == 2


def test_flattening_again_after_the_cache_is_dropped_sets_the_same_count():
    model = _three_findings_two_suppressed()
    model.to_flat_vulnerabilities()

    model._invalidate_flat_cache()
    model.to_flat_vulnerabilities()

    assert model.metadata.summary_stats.suppressed == 2


def test_a_flatten_after_the_save_reads_the_same_count(tmp_path):
    model = _three_findings_two_suppressed()
    model.to_flat_vulnerabilities()

    model.save_model(tmp_path)
    again = model.to_flat_vulnerabilities()

    assert model.metadata.summary_stats.suppressed == 2
    assert [vuln.is_suppressed for vuln in again].count(True) == 2


def test_the_docstring_says_the_counts_are_set_not_bumped():
    doc = AshAggregatedResults.to_flat_vulnerabilities.__doc__ or ""

    assert "setting summary_stats.suppressed" in doc
    assert "bumping" not in doc


def test_the_error_that_stopped_the_description_is_named_before_the_fallback(
    monkeypatch, logged
):
    model = AshAggregatedResults()

    def refuse(_results):
        raise RuntimeError("could not compute the metrics")

    def broken(_error, _values=()):
        raise ValueError("the text of the error could not be built")

    monkeypatch.setattr(
        "automated_security_helper.core.unified_metrics.get_unified_scanner_metrics",
        refuse,
    )
    monkeypatch.setattr("automated_security_helper.utils.error_text.error_text", broken)

    model._populate_final_metrics()

    assert logged[-1] == "Error populating final metrics: RuntimeError", logged
    assert "Describing the final-metrics error raised ValueError" in logged[-2], logged
    assert "could not be built" not in "\n".join(logged), logged

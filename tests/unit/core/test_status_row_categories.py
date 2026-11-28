"""A scanner's status row carries the scan categories the scanner can serve.

``ScannerTargetStatusInfo.categories`` holds the category values the scanner can
serve, in canonical order. It defaults to an empty list, so a row built without it,
and a row read from a results file written before the field existed, both read
``[]`` without the field counting as set.

The metrics rebuild builds every scanner row from the fields it collected, and
``AshAggregatedResults.to_simple_dict`` (the payload the CloudWatch Logs and S3
reporters send) dumps each row with ``exclude_unset``, so a field left at its
default never reaches the payload. The rebuild therefore sets ``categories`` on
every row it writes: a shipped scanner's row carries its categories, replacing any
value an earlier row held, and a row for a name nothing knows keeps the categories
its earlier row recorded (``ash merge`` rebuilds rows read back from a results
file) or else carries an empty list that is still set.
"""

from typing import Any

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.unified_metrics import (
    ScannerMetrics,
    _populate_scanner_results_from_unified_metrics,
)
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerTargetStatusInfo,
)

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()

#: What trivy can serve, in canonical order.
TRIVY_CATEGORIES = ["secrets", "sca", "container", "iac", "license"]


def _the_field_exists() -> None:
    assert "categories" in ScannerTargetStatusInfo.model_fields, (
        "ScannerTargetStatusInfo has no categories field"
    )


def _rebuilt(model: AshAggregatedResults, name: str) -> ScannerTargetStatusInfo:
    """The row the metrics rebuild writes for *name* after a clean run."""
    _populate_scanner_results_from_unified_metrics(
        model, [ScannerMetrics(scanner_name=name, status="PASSED")]
    )
    return model.scanner_results[name]


def test_a_status_row_and_an_older_row_both_have_no_categories() -> None:
    """The field is described and comes after ``skipped_reason``; a row built
    without it and a row from an older results file both read ``[]``, unset."""
    _the_field_exists()
    names = list(ScannerTargetStatusInfo.model_fields)
    assert names.index("categories") > names.index("skipped_reason"), names
    assert ScannerTargetStatusInfo.model_fields["categories"].description

    built = ScannerTargetStatusInfo()
    older = ScannerTargetStatusInfo.model_validate({"status": "PASSED"})

    for row in (built, older):
        assert row.categories == [], row.categories
        assert "categories" not in row.model_fields_set, row.model_fields_set


@pytest.mark.parametrize(
    "earlier",
    [
        pytest.param(None, id="no-earlier-row"),
        pytest.param({"status": "PASSED", "excluded": False}, id="an-older-row"),
        pytest.param({"status": "PASSED", "categories": ["sast"]}, id="a-stale-value"),
    ],
)
def test_the_rebuilt_row_of_a_shipped_scanner_carries_its_categories_into_the_payload(
    earlier: dict[str, Any] | None,
) -> None:
    """The rebuild sets trivy's categories on its row whatever row was there
    before (none, one from an older file, one holding another value), and the
    payload the reporters send carries them."""
    _the_field_exists()
    model = AshAggregatedResults()
    if earlier is not None:
        model.scanner_results["trivy"] = ScannerTargetStatusInfo.model_validate(earlier)

    row = _rebuilt(model, "trivy")

    assert row.categories == TRIVY_CATEGORIES, row.categories
    assert "categories" in row.model_fields_set, row.model_fields_set
    payload = model.to_simple_dict()["scanner_results"]["trivy"]
    assert payload.get("categories") == TRIVY_CATEGORIES, payload


def test_a_rebuilt_row_for_a_name_nothing_knows_carries_an_empty_list_set() -> None:
    """A scanner name that no table, row or record knows: the rebuilt row carries
    ``[]`` as a set value, so the payload states that the scanner serves no known
    category instead of leaving the field out."""
    _the_field_exists()
    name = "category-fixture-status-unknown-scanner"
    model = AshAggregatedResults()

    row = _rebuilt(model, name)

    assert row.categories == [], row.categories
    assert "categories" in row.model_fields_set, row.model_fields_set
    payload = model.to_simple_dict()["scanner_results"][name]
    assert payload.get("categories") == [], payload


def test_a_rebuilt_row_for_an_unknown_name_keeps_its_recorded_categories() -> None:
    """``ash merge`` rebuilds rows read back from a results file, in a process that
    may not load the plugin that wrote them. There the lookup names no category, and
    the rebuild keeps the categories the original run recorded instead of wiping
    them; the payload carries them."""
    _the_field_exists()
    name = "category-fixture-status-merged-plugin-scanner"
    recorded = ["sast", "secrets"]
    model = AshAggregatedResults()
    model.scanner_results[name] = ScannerTargetStatusInfo.model_validate(
        {"status": "PASSED", "categories": recorded}
    )

    row = _rebuilt(model, name)

    assert row.categories == recorded, row.categories
    assert "categories" in row.model_fields_set, row.model_fields_set
    payload = model.to_simple_dict()["scanner_results"][name]
    assert payload.get("categories") == recorded, payload

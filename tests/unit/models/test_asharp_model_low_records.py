# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The converter records and the report metadata keep what a results file gave.

A refused-input record and a failed-input record hold the path, member and reason
as the converter gave them: the names of a tree can begin or end in whitespace,
and a record that strips it names another file. Both drop the keys they do not
define and count them for the one warning a read of a results file logs, and
``AshAggregatedResults.load_model`` reads with that count as ``ash report`` and
``ash merge`` do. ``generated_at`` takes a trailing ``Z`` and any number of
fraction digits whichever Python reads it: before 3.11 ``fromisoformat`` refuses
both, which the stand-in below reproduces on any version.
"""

import json
import logging
import re
from datetime import datetime

import pytest

from automated_security_helper.models import asharp_model
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ConverterStatusInfo,
    FailedInputInfo,
    RefusedInputInfo,
    ReportMetadata,
    warning_of_dropped_keys,
)
from automated_security_helper.utils.log import ASH_LOGGER

pytestmark = pytest.mark.unit

PLANTED = "x_planted_key"


@pytest.fixture
def warnings(caplog):
    """ASH's warnings, through pytest's capture handler (ASH's own handler renders
    to a console and leaves nothing in ``caplog.records``)."""
    saved_handlers = ASH_LOGGER.handlers
    saved_propagate = ASH_LOGGER.propagate
    ASH_LOGGER.handlers = [caplog.handler]
    ASH_LOGGER.propagate = False
    caplog.set_level(logging.WARNING, logger=ASH_LOGGER.name)
    try:
        yield caplog
    finally:
        ASH_LOGGER.handlers = saved_handlers
        ASH_LOGGER.propagate = saved_propagate


def _dropped_warnings(warnings) -> list:
    return [
        record.getMessage()
        for record in warnings.records
        if "Dropped" in record.getMessage()
    ]


def test_a_refused_record_keeps_the_whitespace_of_its_names():
    record = RefusedInputInfo(path=" lib/a.tar ", member=" b.js ", reason=" a link ")

    assert (record.path, record.member, record.reason) == (
        " lib/a.tar ",
        " b.js ",
        " a link ",
    )
    again = RefusedInputInfo.model_validate_json(record.model_dump_json())
    assert again == record


def test_a_failed_record_keeps_the_whitespace_of_its_names():
    record = FailedInputInfo(path=" nb/a.ipynb ", reason=" it did not convert ")

    assert (record.path, record.reason) == (" nb/a.ipynb ", " it did not convert ")
    again = FailedInputInfo.model_validate_json(record.model_dump_json())
    assert again == record


def test_a_failed_record_counts_the_keys_it_drops(warnings):
    with warning_of_dropped_keys("results.json") as context:
        record = FailedInputInfo.model_validate(
            {"path": "nb/a.ipynb", "reason": "r", PLANTED: "v"}, context=context
        )

    assert PLANTED not in record.model_dump()
    dropped = _dropped_warnings(warnings)
    assert len(dropped) == 1, dropped
    assert "Dropped 1 key" in dropped[0], dropped[0]
    assert "results.json" in dropped[0], dropped[0]
    assert PLANTED not in dropped[0], dropped[0]


def test_a_refused_record_is_counted_beside_a_failed_one(warnings):
    with warning_of_dropped_keys("results.json") as context:
        RefusedInputInfo.model_validate(
            {"path": "lib/b.tar", "reason": "r", PLANTED: "v"}, context=context
        )
        FailedInputInfo.model_validate(
            {"path": "nb/a.ipynb", "reason": "r", PLANTED: "v"}, context=context
        )

    dropped = _dropped_warnings(warnings)
    assert len(dropped) == 1, dropped
    assert "Dropped 2 keys" in dropped[0], dropped[0]


def test_load_model_says_how_many_keys_its_records_dropped(tmp_path, warnings):
    model = AshAggregatedResults()
    model.converter_results = {
        "archive": ConverterStatusInfo(
            refused_inputs=[
                RefusedInputInfo(path="lib/b.tar", member="l.js", reason="a link")
            ]
        )
    }
    data = json.loads(model.model_dump_json(by_alias=True))
    data["converter_results"]["archive"]["refused_inputs"][0][PLANTED] = "v"
    results_file = tmp_path / "ash_aggregated_results.json"
    results_file.write_text(json.dumps(data), encoding="utf-8")

    loaded = AshAggregatedResults.load_model(results_file)

    assert loaded is not None
    assert PLANTED not in loaded.model_dump_json(by_alias=True)
    dropped = _dropped_warnings(warnings)
    assert len(dropped) == 1, dropped
    assert "Dropped 1 key" in dropped[0], dropped[0]
    assert str(results_file) in dropped[0], dropped[0]


@pytest.mark.parametrize(
    "stamp",
    ["2026-01-01T00:00:00Z", "2026-01-01T00:00:00.5Z", "2026-01-01T00:00:00.1234Z"],
)
def test_generated_at_takes_a_trailing_z_and_any_fraction_digits(stamp):
    assert ReportMetadata(generated_at=stamp).generated_at == (
        "2026-01-01T00:00:00+00:00"
    )


def test_generated_at_reads_the_same_where_fromisoformat_is_the_older_one(
    monkeypatch,
):
    class _BeforeThreeEleven(datetime):
        """fromisoformat as Python 3.10 has it: no trailing Z, and a fraction of
        3 or 6 digits only."""

        @classmethod
        def fromisoformat(cls, text):
            fraction = re.search(r"\.(\d+)", text)
            if text.endswith("Z") or (
                fraction and len(fraction.group(1)) not in (3, 6)
            ):
                raise ValueError("Invalid isoformat string")
            return datetime.fromisoformat(text)

    monkeypatch.setattr(asharp_model, "datetime", _BeforeThreeEleven)

    for stamp in ("2026-01-01T00:00:00Z", "2026-01-01T00:00:00.5Z"):
        assert ReportMetadata(generated_at=stamp).generated_at == (
            "2026-01-01T00:00:00+00:00"
        )


def test_a_generated_at_that_is_not_a_date_is_still_refused():
    with pytest.raises(ValueError, match="ISO 8601"):
        ReportMetadata(generated_at="not-a-date")

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Refusals and failed inputs read back from ash_aggregated_results.json intact.

``ash report`` and ``ash merge`` rebuild their reports from the stored results
file. ``ConverterStatusInfo`` allows extra fields, so with ``failed_inputs``
undeclared the records still rode along as plain dicts, the gate still counted
them, and the reports named them with no path and no reason. Every other test
built its model in memory, so none saw it. This one saves the model and loads it
back, as ``ash report`` does.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ConverterStatusInfo,
    FailedInputInfo,
    RefusedInputInfo,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.flatjson_reporter import (
    FlatJSONReporter,
)
from automated_security_helper.utils.converter_refusals import converter_refusals

pytestmark = pytest.mark.unit


def stored_and_loaded(tmp_path: Path) -> AshAggregatedResults:
    model = AshAggregatedResults(ash_config=get_default_config())
    model.converter_results["archive"] = ConverterStatusInfo(
        converted_paths=[],
        refused_inputs=[
            RefusedInputInfo(path="big.zip", reason="over", limit="max_total_bytes")
        ],
        failed_inputs=[FailedInputInfo(path="crc.zip", reason="Bad CRC-32")],
    )
    model.save_model(tmp_path)
    loaded = AshAggregatedResults.load_model(tmp_path / "ash_aggregated_results.json")
    assert loaded is not None
    return loaded


def test_failed_inputs_load_back_as_records(tmp_path):
    row = stored_and_loaded(tmp_path).converter_results["archive"]

    (failed,) = row.failed_inputs
    assert isinstance(failed, FailedInputInfo)
    (refused,) = row.refused_inputs
    assert isinstance(refused, RefusedInputInfo)


def test_the_loaded_refusals_keep_their_paths_and_reasons(tmp_path):
    refusals = converter_refusals(stored_and_loaded(tmp_path))

    assert sorted((r.path, r.reason, r.scan_incomplete) for r in refusals) == [
        ("big.zip", "over", True),
        ("crc.zip", "Bad CRC-32", True),
    ]


def test_the_flat_json_report_of_a_loaded_model_names_both(tmp_path):
    context = PluginContext(
        source_dir=Path("."), output_dir=Path("."), config=get_default_config()
    )

    data = json.loads(
        FlatJSONReporter(context=context).report(stored_and_loaded(tmp_path))
    )

    rows = sorted(
        (row["path"], row["reason"], row["scan_incomplete"])
        for row in data["converter_refusals"]
    )
    assert rows == [("big.zip", "over", True), ("crc.zip", "Bad CRC-32", True)]

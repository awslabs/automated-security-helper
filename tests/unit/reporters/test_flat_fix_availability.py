# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Preserve npm audit fix availability through aggregation and flat reports."""

import csv
import json
from io import StringIO
from pathlib import Path

import pytest

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_builtin.reporters.csv_reporter import (
    CsvReporter,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.flatjson_reporter import (
    FlatJSONReporter,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.npm_audit_scanner import (
    NpmAuditScanner,
    NpmAuditScannerConfig,
)

pytestmark = pytest.mark.unit


def test_npm_fixture_fix_availability_reaches_flat_json_and_csv(
    test_plugin_context, tmp_path
):
    fixture = (
        Path(__file__).parents[2] / "test_data" / "scanners" / "npmaudit" / "npm.json"
    )
    audit = json.loads(fixture.read_text())
    scanner = NpmAuditScanner(
        context=test_plugin_context, config=NpmAuditScannerConfig()
    )
    scanner.exit_code = 0
    sarif = scanner._convert_npm_audit_to_sarif(audit, tmp_path)
    source = sarif.model_dump(mode="json")
    model = AshAggregatedResults(sarif=sarif)

    flattened = model.to_flat_vulnerabilities()
    findings = json.loads(FlatJSONReporter(context=test_plugin_context).report(model))[
        "findings"
    ]
    rows = list(
        csv.DictReader(StringIO(CsvReporter(context=test_plugin_context).report(model)))
    )

    assert len(flattened) == len(sarif.runs[0].results) == len(findings) == len(rows)
    observed = set()
    for result, flat, finding, row in zip(
        sarif.runs[0].results, flattened, findings, rows, strict=True
    ):
        original = result.properties.fix_available
        expected = True if isinstance(original, dict) else original
        observed.add((type(original).__name__, expected))
        assert flat.fix_available is expected
        assert finding["fix_available"] is expected
        assert row["fix_available"] == str(expected)
        assert json.loads(flat.properties)["fix_available"] == original
        assert json.loads(flat.raw_data)["properties"]["fix_available"] == original

    assert observed == {("bool", True), ("bool", False), ("dict", True)}
    assert sarif.model_dump(mode="json") == source

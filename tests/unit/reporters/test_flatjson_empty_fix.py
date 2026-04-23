# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Regression test: FlatJSON reporter must not inject phantom findings on clean scans."""

import json

from automated_security_helper.plugin_modules.ash_builtin.reporters.flatjson_reporter import (
    FlatJSONReporter,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults


class TestFlatJSONEmptyFindings:
    """FlatJSON reporter should return an empty findings array when no vulnerabilities exist."""

    def test_empty_scan_produces_no_findings(
        self, sample_ash_model: AshAggregatedResults, test_plugin_context
    ):
        reporter = FlatJSONReporter(context=test_plugin_context)
        raw = reporter.report(sample_ash_model)
        data = json.loads(raw)

        assert data["findings"] == [], (
            f"Expected empty findings array, got {len(data['findings'])} item(s)"
        )

    def test_no_phantom_test_id(
        self, sample_ash_model: AshAggregatedResults, test_plugin_context
    ):
        reporter = FlatJSONReporter(context=test_plugin_context)
        raw = reporter.report(sample_ash_model)

        assert "test-id" not in raw, "Phantom 'test-id' finding leaked into output"

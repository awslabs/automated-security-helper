# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for the unused suppressions reporter."""

import json
import pytest
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.core import AshSuppression
from automated_security_helper.plugin_modules.ash_builtin.reporters.unused_suppressions_reporter import (
    UnusedSuppressionsReporter,
)


@pytest.fixture
def test_plugin_context(tmp_path):
    """Create a test plugin context."""
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.config.ash_config import AshConfig

    config = AshConfig()
    config.global_settings.suppressions = [
        AshSuppression(
            path="src/app.py",
            rule_id="B201",
            line_start=42,
            reason="Test suppression 1",
        ),
        AshSuppression(
            path="src/utils.py",
            rule_id="B603",
            reason="Test suppression 2",
        ),
        AshSuppression(
            path="tests/**/*.py",
            rule_id="B101",
            reason="Test suppression 3",
        ),
    ]

    context = PluginContext(
        source_dir=tmp_path / "source",
        output_dir=tmp_path / "output",
        work_dir=tmp_path / "work",
        config=config,
    )
    return context


def test_unused_suppressions_reporter_all_unused(test_plugin_context):
    """Test reporter when all suppressions are unused."""
    model = AshAggregatedResults()
    model.used_suppressions = set()  # No suppressions used

    reporter = UnusedSuppressionsReporter(context=test_plugin_context)
    result = reporter.report(model)

    # Parse the JSON result
    report_data = json.loads(result)

    # Verify summary
    assert report_data["summary"]["total_suppressions"] == 3
    assert report_data["summary"]["used_suppressions"] == 0
    assert report_data["summary"]["unused_suppressions"] == 3

    # Verify all suppressions are listed as unused
    assert len(report_data["unused_suppressions"]) == 3


def test_unused_suppressions_reporter_some_used(test_plugin_context):
    """Test reporter when some suppressions are used."""
    model = AshAggregatedResults()
    # Mark one suppression as used
    model.used_suppressions = {"src/app.py|B201|42|42"}

    reporter = UnusedSuppressionsReporter(context=test_plugin_context)
    result = reporter.report(model)

    # Parse the JSON result
    report_data = json.loads(result)

    # Verify summary
    assert report_data["summary"]["total_suppressions"] == 3
    assert report_data["summary"]["used_suppressions"] == 1
    assert report_data["summary"]["unused_suppressions"] == 2

    # Verify only unused suppressions are listed
    assert len(report_data["unused_suppressions"]) == 2

    # Verify the used suppression is not in the unused list
    unused_paths = [s["path"] for s in report_data["unused_suppressions"]]
    assert "src/app.py" not in unused_paths or any(
        s["path"] == "src/app.py" and s["line_start"] != 42
        for s in report_data["unused_suppressions"]
    )


def test_unused_suppressions_reporter_all_used(test_plugin_context):
    """Test reporter when all suppressions are used."""
    model = AshAggregatedResults()
    # Mark all suppressions as used
    model.used_suppressions = {
        "src/app.py|B201|42|42",
        "src/utils.py|B603|*|*",
        "tests/**/*.py|B101|*|*",
    }

    reporter = UnusedSuppressionsReporter(context=test_plugin_context)
    result = reporter.report(model)

    # Parse the JSON result
    report_data = json.loads(result)

    # Verify summary
    assert report_data["summary"]["total_suppressions"] == 3
    assert report_data["summary"]["used_suppressions"] == 3
    assert report_data["summary"]["unused_suppressions"] == 0

    # Verify no suppressions are listed as unused
    assert len(report_data["unused_suppressions"]) == 0


def test_unused_suppressions_reporter_no_suppressions(test_plugin_context):
    """Test reporter when no suppressions are configured."""
    # Create context with no suppressions
    test_plugin_context.config.global_settings.suppressions = []

    model = AshAggregatedResults()
    model.used_suppressions = set()

    reporter = UnusedSuppressionsReporter(context=test_plugin_context)
    result = reporter.report(model)

    # Parse the JSON result
    report_data = json.loads(result)

    # Verify summary
    assert report_data["summary"]["total_suppressions"] == 0
    assert report_data["summary"]["used_suppressions"] == 0
    assert report_data["summary"]["unused_suppressions"] == 0

    # Verify no suppressions are listed
    assert len(report_data["unused_suppressions"]) == 0

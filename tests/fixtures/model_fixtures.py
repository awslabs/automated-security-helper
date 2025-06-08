# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Model fixtures for ASH tests."""

import pytest
import json

from automated_security_helper.models.core import Suppression, IgnorePathWithReason
from automated_security_helper.models.asharp_model import AshAggregatedResults


@pytest.fixture
def sample_suppression():
    """Create a sample suppression for testing."""
    return Suppression(
        rule_id="TEST-001",
        path="src/example.py",
        reason="Test suppression",
    )


@pytest.fixture
def sample_suppression_with_lines():
    """Create a sample suppression with line numbers for testing."""
    return Suppression(
        rule_id="TEST-001",
        path="src/example.py",
        line_start=10,
        line_end=15,
        reason="Test suppression with lines",
    )


@pytest.fixture
def sample_ignore_path():
    """Create a sample ignore path for testing."""
    return IgnorePathWithReason(
        path="src/ignored.py",
        reason="Test ignore path",
    )


@pytest.fixture
def sample_ash_model(test_data_dir):
    """Load a sample ASH aggregated results model from test data."""
    sample_aggregated_results = (
        test_data_dir / "outputs" / "ash_aggregated_results.json"
    )

    with open(sample_aggregated_results, mode="r", encoding="utf-8") as f:
        sample_aggregated_results = json.loads(f.read())

    # Fix the converters section to use proper config objects instead of boolean values
    if (
        "ash_config" in sample_aggregated_results
        and "converters" in sample_aggregated_results["ash_config"]
    ):
        converters = sample_aggregated_results["ash_config"]["converters"]
        if "archive" in converters and converters["archive"] is True:
            converters["archive"] = {"name": "archive", "enabled": True}
        if "jupyter" in converters and converters["jupyter"] is True:
            converters["jupyter"] = {"name": "jupyter", "enabled": True}

    model = AshAggregatedResults(**sample_aggregated_results)
    return model

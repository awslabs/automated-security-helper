"""Utility functions for run_ash_scan tests."""

from unittest.mock import MagicMock


def create_mock_aggregated_results(actionable_findings=0):
    """Create a mock AshAggregatedResults object with specified actionable findings."""
    mock_results = MagicMock()
    mock_results.metadata.summary_stats.actionable = actionable_findings
    return mock_results

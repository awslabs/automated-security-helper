"""Tests for core/metrics_table.py — covers metrics table generation functions."""

from unittest.mock import MagicMock, patch
import pytest


class TestMetricsTableModule:
    """Tests for metrics_table module."""

    def test_module_imports(self):
        from automated_security_helper.core import metrics_table

        assert hasattr(metrics_table, "generate_metrics_table_from_unified_data")
        assert hasattr(metrics_table, "display_metrics_table")

    def test_generate_function_callable(self):
        from automated_security_helper.core.metrics_table import (
            generate_metrics_table_from_unified_data,
        )

        assert callable(generate_metrics_table_from_unified_data)

    def test_display_function_callable(self):
        from automated_security_helper.core.metrics_table import display_metrics_table

        assert callable(display_metrics_table)

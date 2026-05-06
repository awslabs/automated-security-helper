"""Extended tests for models/asharp_model.py — covers model methods and serialization."""

from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch
import json
import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerStatusInfo,
    ConverterStatusInfo,
)
from automated_security_helper.core.enums import ScannerStatus

AshAggregatedResults.model_rebuild()


class TestAshAggregatedResultsConstruction:
    """Tests for AshAggregatedResults construction and basic methods."""

    def test_default_construction(self):
        results = AshAggregatedResults()
        assert results.scanner_results == {}
        assert results.converter_results == {}
        assert results.additional_reports == {}

    def test_with_scanner_results(self):
        results = AshAggregatedResults()
        results.scanner_results["bandit"] = ScannerStatusInfo(
            status=ScannerStatus.PASSED
        )
        assert results.scanner_results["bandit"].status == ScannerStatus.PASSED

    def test_with_converter_results(self):
        results = AshAggregatedResults()
        results.converter_results["jupyter"] = ConverterStatusInfo()
        assert "jupyter" in results.converter_results

    def test_additional_reports(self):
        results = AshAggregatedResults()
        results.additional_reports["html"] = {"status": "completed"}
        assert "html" in results.additional_reports


class TestScannerStatusInfo:
    """Tests for ScannerStatusInfo model."""

    def test_default_values(self):
        info = ScannerStatusInfo()
        assert info.dependencies_satisfied is True
        assert info.excluded is False

    def test_with_status(self):
        info = ScannerStatusInfo(status=ScannerStatus.MISSING)
        assert info.status == ScannerStatus.MISSING

    def test_with_excluded(self):
        info = ScannerStatusInfo(excluded=True, status=ScannerStatus.SKIPPED)
        assert info.excluded is True
        assert info.status == ScannerStatus.SKIPPED

    def test_with_missing_deps(self):
        info = ScannerStatusInfo(
            dependencies_satisfied=False, status=ScannerStatus.MISSING
        )
        assert info.dependencies_satisfied is False

    def test_serialization(self):
        info = ScannerStatusInfo(status=ScannerStatus.ERROR)
        data = info.model_dump()
        assert data["status"] == ScannerStatus.ERROR


class TestConverterStatusInfo:
    """Tests for ConverterStatusInfo model."""

    def test_default_construction(self):
        info = ConverterStatusInfo()
        assert info is not None


class TestAdditionalReports:
    """Tests for additional_reports in AshAggregatedResults."""

    def test_default_empty(self):
        results = AshAggregatedResults()
        assert results.additional_reports == {}


class TestAshAggregatedResultsSerialization:
    """Tests for model serialization methods."""

    def test_model_dump(self):
        results = AshAggregatedResults()
        results.scanner_results["bandit"] = ScannerStatusInfo(
            status=ScannerStatus.PASSED
        )
        data = results.model_dump()
        assert isinstance(data, dict)

    def test_model_dump_json(self):
        results = AshAggregatedResults()
        json_str = results.model_dump_json()
        parsed = json.loads(json_str)
        assert isinstance(parsed, dict)

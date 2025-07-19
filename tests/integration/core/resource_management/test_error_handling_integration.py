#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Integration tests for error handling in the scan workflow.

This module tests various error scenarios in the scan workflow to ensure
they are handled gracefully and provide meaningful error messages.
"""

import json
from datetime import datetime
from unittest import mock

import pytest

from automated_security_helper.core.resource_management.exceptions import (
    MCPResourceError,
)
from automated_security_helper.core.resource_management.scan_registry import (
    ScanStatus,
    get_scan_registry,
)
from automated_security_helper.core.resource_management.scan_management import (
    cleanup_scan_resources,
    check_scan_progress,
)
from automated_security_helper.core.resource_management.scan_tracking import (
    get_scan_results,
    get_scan_results_with_error_handling,
)
from automated_security_helper.core.resource_management.error_handling import (
    ErrorCategory,
    create_error_response,
)


@pytest.fixture
def test_directory(tmp_path):
    """Create a test directory with sample code files."""
    test_dir = tmp_path / "test_project"
    test_dir.mkdir()
    (test_dir / "app.py").write_text("print('Hello, world!')")
    return test_dir


@pytest.fixture
def output_directory(tmp_path):
    """Create an output directory for scan results."""
    output_dir = tmp_path / "ash_output"
    output_dir.mkdir()
    return output_dir


class TestErrorHandlingIntegration:
    """Integration tests for error handling in the scan workflow."""

    @pytest.mark.asyncio
    async def test_invalid_scan_id_format(self):
        """Test handling of invalid scan ID format."""
        # Try to check progress with an invalid scan ID
        with pytest.raises(MCPResourceError) as excinfo:
            await check_scan_progress("")

        error = excinfo.value
        assert "Invalid scan ID" in str(error)
        assert (
            error.context.get("error_category") == ErrorCategory.INVALID_PARAMETER.value
        )

        # Try with a non-string scan ID
        with pytest.raises(MCPResourceError) as excinfo:
            # We can't directly pass None to check_scan_progress due to type hints,
            # so we'll mock validate_scan_id to simulate the error
            with mock.patch(
                "automated_security_helper.core.resource_management.error_handling.validate_scan_id"
            ) as mock_validate:
                mock_validate.return_value = MCPResourceError(
                    "Invalid scan ID: None. Must be a non-empty string.",
                    context={"error_category": ErrorCategory.INVALID_PARAMETER.value},
                )
                await check_scan_progress("dummy")

        error = excinfo.value
        assert "Invalid scan ID" in str(error)
        assert (
            error.context.get("error_category") == ErrorCategory.INVALID_PARAMETER.value
        )

    @pytest.mark.asyncio
    async def test_invalid_directory_path(self, test_directory):
        """Test handling of invalid directory path."""
        registry = get_scan_registry()

        # Try to register a scan with a non-existent directory
        with pytest.raises(MCPResourceError) as excinfo:
            registry.register_scan(
                directory_path="/non/existent/directory",
                output_directory=str(test_directory),
                severity_threshold="MEDIUM",
            )

        error = excinfo.value
        assert "not found" in str(error) or "does not exist" in str(error)
        assert error.context.get("error_category") == ErrorCategory.FILE_NOT_FOUND.value

    @pytest.mark.asyncio
    async def test_invalid_severity_threshold(self, test_directory, output_directory):
        """Test handling of invalid severity threshold."""
        registry = get_scan_registry()

        # Try to register a scan with an invalid severity threshold
        with pytest.raises(MCPResourceError) as excinfo:
            registry.register_scan(
                directory_path=str(test_directory),
                output_directory=str(output_directory),
                severity_threshold="INVALID",
            )

        error = excinfo.value
        assert "Invalid severity threshold" in str(error)
        assert (
            error.context.get("error_category") == ErrorCategory.INVALID_PARAMETER.value
        )

    @pytest.mark.asyncio
    async def test_invalid_config_path(self, test_directory, output_directory):
        """Test handling of invalid config path."""
        registry = get_scan_registry()

        # Try to register a scan with a non-existent config file
        with pytest.raises(MCPResourceError) as excinfo:
            registry.register_scan(
                directory_path=str(test_directory),
                output_directory=str(output_directory),
                severity_threshold="MEDIUM",
                config_path="/non/existent/config.yaml",
            )

        error = excinfo.value
        assert "not found" in str(error) or "does not exist" in str(error)
        assert error.context.get("error_category") == ErrorCategory.FILE_NOT_FOUND.value

    @pytest.mark.asyncio
    async def test_duplicate_scan_id(self, test_directory, output_directory):
        """Test handling of duplicate scan ID."""
        registry = get_scan_registry()

        # Register a scan with a custom ID
        scan_id = "custom_scan_id"
        registry.register_scan(
            directory_path=str(test_directory),
            output_directory=str(output_directory),
            severity_threshold="MEDIUM",
            scan_id=scan_id,
        )

        # Try to register another scan with the same ID
        with pytest.raises(MCPResourceError) as excinfo:
            registry.register_scan(
                directory_path=str(test_directory / "other"),
                output_directory=str(output_directory / "other"),
                severity_threshold="MEDIUM",
                scan_id=scan_id,
            )

        error = excinfo.value
        assert "already exists" in str(error)
        assert (
            error.context.get("error_category") == ErrorCategory.INVALID_PARAMETER.value
        )

        # Clean up
        await cleanup_scan_resources(scan_id)

    @pytest.mark.asyncio
    async def test_duplicate_directory_scan(self, test_directory, output_directory):
        """Test handling of duplicate directory scan."""
        registry = get_scan_registry()

        # Register a scan
        scan_id = registry.register_scan(
            directory_path=str(test_directory),
            output_directory=str(output_directory),
            severity_threshold="MEDIUM",
        )

        # Try to register another scan for the same directory
        with pytest.raises(MCPResourceError) as excinfo:
            registry.register_scan(
                directory_path=str(test_directory),
                output_directory=str(output_directory / "other"),
                severity_threshold="MEDIUM",
            )

        error = excinfo.value
        assert "already has an active scan" in str(error)
        assert (
            error.context.get("error_category")
            == ErrorCategory.RESOURCE_EXHAUSTED.value
        )

        # Clean up
        await cleanup_scan_resources(scan_id)

    @pytest.mark.asyncio
    async def test_invalid_result_file_format(self, test_directory, output_directory):
        """Test handling of invalid result file format."""
        registry = get_scan_registry()

        # Register a scan
        scan_id = registry.register_scan(
            directory_path=str(test_directory),
            output_directory=str(output_directory),
            severity_threshold="MEDIUM",
        )

        # Mark the scan as running
        registry.update_scan_status(scan_id, ScanStatus.RUNNING)

        # Create scanners directory
        scanners_dir = output_directory / "scanners"
        scanners_dir.mkdir(exist_ok=True)

        # Create scanner directory
        scanner_dir = scanners_dir / "scanner1"
        scanner_dir.mkdir()
        source_dir = scanner_dir / "source"
        source_dir.mkdir()

        # Create invalid JSON file
        with open(source_dir / "ASH.ScanResults.json", "w") as f:
            f.write("{invalid json")

        # Create aggregated results file with invalid format
        with open(output_directory / "ash_aggregated_results.json", "w") as f:
            f.write("{invalid json")

        # Try to get scan results
        with pytest.raises(MCPResourceError) as excinfo:
            get_scan_results(scan_id, output_directory)

        error = excinfo.value
        assert "Invalid JSON" in str(error) or "JSON decode error" in str(error)
        assert error.context.get("error_category") == ErrorCategory.INVALID_FORMAT.value

        # Clean up
        await cleanup_scan_resources(scan_id)

    @pytest.mark.asyncio
    async def test_missing_required_fields_in_results(
        self, test_directory, output_directory
    ):
        """Test handling of missing required fields in results."""
        registry = get_scan_registry()

        # Register a scan
        scan_id = registry.register_scan(
            directory_path=str(test_directory),
            output_directory=str(output_directory),
            severity_threshold="MEDIUM",
        )

        # Mark the scan as running
        registry.update_scan_status(scan_id, ScanStatus.RUNNING)

        # Create aggregated results file with missing required fields
        with open(output_directory / "ash_aggregated_results.json", "w") as f:
            json.dump(
                {
                    # Missing "findings" field
                    "scanners_completed": ["scanner1"],
                    "completion_time": datetime.now().isoformat(),
                },
                f,
            )

        # Try to get scan results
        with pytest.raises(MCPResourceError) as excinfo:
            get_scan_results(scan_id, output_directory)

        error = excinfo.value
        assert "Invalid result structure" in str(
            error
        ) or "Missing required field" in str(error)
        assert error.context.get("error_category") == ErrorCategory.INVALID_FORMAT.value

        # Clean up
        await cleanup_scan_resources(scan_id)

    @pytest.mark.asyncio
    async def test_permission_denied_for_output_directory(
        self, test_directory, output_directory
    ):
        """Test handling of permission denied for output directory."""
        registry = get_scan_registry()

        # Register a scan
        scan_id = registry.register_scan(
            directory_path=str(test_directory),
            output_directory=str(output_directory),
            severity_threshold="MEDIUM",
        )

        # Mock permission denied error
        with mock.patch(
            "automated_security_helper.core.resource_management.error_handling.validate_directory_path"
        ) as mock_validate:
            mock_validate.return_value = MCPResourceError(
                f"Permission denied: Cannot access directory {output_directory}",
                context={"error_category": ErrorCategory.PERMISSION_DENIED.value},
            )

            # Try to check scan progress
            with pytest.raises(MCPResourceError) as excinfo:
                await check_scan_progress(scan_id)

        error = excinfo.value
        assert "Permission denied" in str(error)
        assert (
            error.context.get("error_category") == ErrorCategory.PERMISSION_DENIED.value
        )

        # Clean up
        await cleanup_scan_resources(scan_id)

    @pytest.mark.asyncio
    async def test_error_response_format(self):
        """Test the format of error responses."""
        # Create an error
        error = MCPResourceError(
            "Test error message",
            context={
                "scan_id": "test_scan_id",
                "error_category": ErrorCategory.INVALID_PARAMETER.value,
            },
        )

        # Create error response
        response = create_error_response(
            error=error,
            operation="test_operation",
            suggestions=["Suggestion 1", "Suggestion 2"],
        )

        # Verify response format
        assert response["success"] is False
        assert response["operation"] == "test_operation"
        assert response["error"] == "Test error message"
        assert response["error_category"] == ErrorCategory.INVALID_PARAMETER.value
        assert "scan_id" in response["context"]
        assert response["context"]["scan_id"] == "test_scan_id"
        assert len(response["suggestions"]) == 2
        assert "timestamp" in response

    @pytest.mark.asyncio
    async def test_get_scan_results_with_error_handling(
        self, test_directory, output_directory
    ):
        """Test the get_scan_results_with_error_handling function."""
        registry = get_scan_registry()

        # Register a scan
        scan_id = registry.register_scan(
            directory_path=str(test_directory),
            output_directory=str(output_directory),
            severity_threshold="MEDIUM",
        )

        # Try to get results for incomplete scan
        result = get_scan_results_with_error_handling(scan_id, output_directory)

        # Verify error response format
        assert result["success"] is False
        assert "error" in result
        assert "not complete" in result["error"]
        assert "operation" in result
        assert result["operation"] == "get_scan_results"
        assert "suggestions" in result
        assert len(result["suggestions"]) > 0
        assert "timestamp" in result

        # Clean up
        await cleanup_scan_resources(scan_id)

    @pytest.mark.asyncio
    async def test_unexpected_error_handling(self, test_directory, output_directory):
        """Test handling of unexpected errors."""
        registry = get_scan_registry()

        # Register a scan
        scan_id = registry.register_scan(
            directory_path=str(test_directory),
            output_directory=str(output_directory),
            severity_threshold="MEDIUM",
        )

        # Mock an unexpected error
        with mock.patch(
            "automated_security_helper.core.resource_management.scan_tracking.check_scan_completion"
        ) as mock_check:
            mock_check.side_effect = Exception("Unexpected test error")

            # Try to check scan progress
            with pytest.raises(MCPResourceError) as excinfo:
                await check_scan_progress(scan_id)

        error = excinfo.value
        assert "Unexpected" in str(error)
        assert (
            error.context.get("error_category") == ErrorCategory.UNEXPECTED_ERROR.value
        )
        assert "error_type" in error.context
        assert error.context["error_type"] == "Exception"

        # Clean up
        await cleanup_scan_resources(scan_id)

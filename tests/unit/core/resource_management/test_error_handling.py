#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Unit tests for the error handling module.

This module tests the error handling utilities for ASH MCP server.
"""

import json
from pathlib import Path
from unittest import mock


from automated_security_helper.core.resource_management.exceptions import (
    MCPResourceError,
)
from automated_security_helper.core.resource_management.error_handling import (
    ErrorCategory,
    safe_read_json_file,
    safe_write_json_file,
    validate_directory_path,
    validate_scan_id,
    validate_severity_threshold,
    validate_config_path,
    validate_scan_parameters,
    check_file_exists,
    check_directory_exists,
    create_error_response,
)


class TestErrorCategories:
    """Tests for the ErrorCategory enum."""

    def test_error_categories(self):
        """Test that all expected error categories are defined."""
        assert ErrorCategory.FILE_NOT_FOUND.value == "file_not_found"
        assert ErrorCategory.PERMISSION_DENIED.value == "permission_denied"
        assert ErrorCategory.INVALID_FORMAT.value == "invalid_format"
        assert ErrorCategory.INVALID_PARAMETER.value == "invalid_parameter"
        assert ErrorCategory.INVALID_PATH.value == "invalid_path"
        assert ErrorCategory.RESOURCE_EXHAUSTED.value == "resource_exhausted"
        assert ErrorCategory.OPERATION_TIMEOUT.value == "operation_timeout"
        assert ErrorCategory.SCAN_NOT_FOUND.value == "scan_not_found"
        assert ErrorCategory.SCAN_INCOMPLETE.value == "scan_incomplete"
        assert ErrorCategory.UNEXPECTED_ERROR.value == "unexpected_error"


class TestSafeFileOperations:
    """Tests for safe file operations."""

    def test_safe_read_json_file_success(self, tmp_path):
        """Test reading a valid JSON file."""
        # Create a test JSON file
        test_file = tmp_path / "test.json"
        test_data = {"test": "data", "nested": {"value": 123}}
        with open(test_file, "w") as f:
            json.dump(test_data, f)

        # Read the file
        data, error = safe_read_json_file(test_file)

        assert error is None
        assert data == test_data

    def test_safe_read_json_file_not_found(self):
        """Test reading a non-existent file."""
        # Try to read a non-existent file
        data, error = safe_read_json_file(
            Path("/non/existent/file.json"), required=False
        )

        assert data is None
        assert error is None  # Not required, so no error

    def test_safe_read_json_file_not_found_required(self):
        """Test reading a required non-existent file."""
        # Try to read a non-existent file that is required
        data, error = safe_read_json_file(
            Path("/non/existent/file.json"), required=True
        )

        assert data is None
        assert error is not None
        assert isinstance(error, MCPResourceError)
        assert "not found" in str(error)
        assert error.context["error_category"] == ErrorCategory.FILE_NOT_FOUND.value

    def test_safe_read_json_file_invalid_json(self, tmp_path):
        """Test reading an invalid JSON file."""
        # Create an invalid JSON file
        test_file = tmp_path / "invalid.json"
        with open(test_file, "w") as f:
            f.write("{invalid json")

        # Try to read the file
        data, error = safe_read_json_file(test_file)

        assert data is None
        assert error is not None
        assert isinstance(error, MCPResourceError)
        assert "Invalid JSON format" in str(error)
        assert error.context["error_category"] == ErrorCategory.INVALID_FORMAT.value

    def test_safe_read_json_file_permission_error(self, tmp_path):
        """Test reading a file with permission error."""
        # Create a test file
        test_file = tmp_path / "noperm.json"
        with open(test_file, "w") as f:
            json.dump({"test": "data"}, f)

        # Mock os.access to simulate permission error
        with mock.patch("os.access", return_value=False):
            data, error = safe_read_json_file(test_file)

            assert data is None
            assert error is not None
            assert isinstance(error, MCPResourceError)
            assert "Permission denied" in str(error)
            assert (
                error.context["error_category"] == ErrorCategory.PERMISSION_DENIED.value
            )

    def test_safe_write_json_file_success(self, tmp_path):
        """Test writing a JSON file successfully."""
        test_file = tmp_path / "write.json"
        test_data = {"test": "write", "array": [1, 2, 3]}

        error = safe_write_json_file(test_file, test_data)

        assert error is None
        assert test_file.exists()

        # Verify the file content
        with open(test_file, "r") as f:
            read_data = json.load(f)

        assert read_data == test_data

    def test_safe_write_json_file_create_directories(self, tmp_path):
        """Test writing a JSON file with directory creation."""
        test_file = tmp_path / "subdir" / "nested" / "write.json"
        test_data = {"test": "write"}

        error = safe_write_json_file(test_file, test_data)

        assert error is None
        assert test_file.exists()

        # Verify the file content
        with open(test_file, "r") as f:
            read_data = json.load(f)

        assert read_data == test_data


class TestValidationFunctions:
    """Tests for validation functions."""

    def test_validate_directory_path_valid(self, tmp_path):
        """Test validating a valid directory path."""
        error = validate_directory_path(tmp_path)
        assert error is None

    def test_validate_directory_path_not_exists(self):
        """Test validating a non-existent directory path."""
        error = validate_directory_path(Path("/non/existent/dir"))

        assert error is not None
        assert isinstance(error, MCPResourceError)
        assert "not found" in str(error)
        assert error.context["error_category"] == ErrorCategory.FILE_NOT_FOUND.value

    def test_validate_directory_path_not_exists_optional(self):
        """Test validating a non-existent directory path when existence is optional."""
        error = validate_directory_path(Path("/non/existent/dir"))
        assert error is not None
        assert "Directory not found or not a directory" in str(error)

    def test_validate_directory_path_not_directory(self, tmp_path):
        """Test validating a path that is not a directory."""
        # Create a file
        test_file = tmp_path / "file.txt"
        with open(test_file, "w") as f:
            f.write("test")

        error = validate_directory_path(test_file)

        assert error is not None
        assert isinstance(error, MCPResourceError)
        assert "Directory not found or not a directory" in str(error)
        assert error.context["error_category"] == ErrorCategory.FILE_NOT_FOUND.value

    def test_validate_directory_path_permission_error(self, tmp_path):
        """Test validating a directory with permission error."""
        # Our new implementation doesn't check permissions directly
        # So we need to mock Path.exists to simulate permission error
        with mock.patch.object(
            Path, "exists", side_effect=PermissionError("Permission denied")
        ):
            error = validate_directory_path(tmp_path)

            assert error is not None
            assert isinstance(error, MCPResourceError)
            assert "Unexpected error validating directory path" in str(error)
            assert (
                error.context["error_category"] == ErrorCategory.UNEXPECTED_ERROR.value
            )

    def test_validate_scan_id_valid(self):
        """Test validating a valid scan ID."""
        error = validate_scan_id("valid-scan-id")
        assert error is None

    def test_validate_scan_id_empty(self):
        """Test validating an empty scan ID."""
        error = validate_scan_id("")

        assert error is not None
        assert isinstance(error, MCPResourceError)
        assert "empty" in str(error)
        assert error.context["error_category"] == ErrorCategory.INVALID_PARAMETER.value

    def test_validate_scan_id_not_string(self):
        """Test validating a non-string scan ID."""
        error = validate_scan_id(123)

        assert error is not None
        assert isinstance(error, MCPResourceError)
        assert "must be a string" in str(error)
        assert error.context["error_category"] == ErrorCategory.INVALID_PARAMETER.value

    def test_validate_severity_threshold_valid(self):
        """Test validating a valid severity threshold."""
        for threshold in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
            error = validate_severity_threshold(threshold)
            assert error is None

    def test_validate_severity_threshold_invalid(self):
        """Test validating an invalid severity threshold."""
        error = validate_severity_threshold("INVALID")

        assert error is not None
        assert isinstance(error, MCPResourceError)
        assert "Invalid severity threshold" in str(error)
        assert error.context["error_category"] == ErrorCategory.INVALID_PARAMETER.value

    def test_validate_severity_threshold_empty(self):
        """Test validating an empty severity threshold."""
        error = validate_severity_threshold("")

        assert error is not None
        assert isinstance(error, MCPResourceError)
        assert "empty" in str(error)
        assert error.context["error_category"] == ErrorCategory.INVALID_PARAMETER.value

    def test_validate_severity_threshold_not_string(self):
        """Test validating a non-string severity threshold."""
        error = validate_severity_threshold(123)

        assert error is not None
        assert isinstance(error, MCPResourceError)
        assert "must be a string" in str(error)
        assert error.context["error_category"] == ErrorCategory.INVALID_PARAMETER.value

    def test_validate_config_path_valid(self, tmp_path):
        """Test validating a valid config path."""
        # Create a config file
        config_file = tmp_path / "config.yaml"
        with open(config_file, "w") as f:
            f.write("test: config")

        error = validate_config_path(str(config_file))
        assert error is None

    def test_validate_config_path_not_exists(self):
        """Test validating a non-existent config path."""
        error = validate_config_path("/non/existent/config.yaml")

        assert error is not None
        assert isinstance(error, MCPResourceError)
        assert "not found" in str(error)
        assert error.context["error_category"] == ErrorCategory.FILE_NOT_FOUND.value

    def test_validate_config_path_not_file(self, tmp_path):
        """Test validating a config path that is not a file."""
        error = validate_config_path(str(tmp_path))

        assert error is not None
        assert isinstance(error, MCPResourceError)
        assert "not a file" in str(error)
        assert error.context["error_category"] == ErrorCategory.INVALID_PATH.value

    def test_validate_config_path_permission_error(self, tmp_path):
        """Test validating a config path with permission error."""
        # Create a config file
        config_file = tmp_path / "config.yaml"
        with open(config_file, "w") as f:
            f.write("test: config")

        with mock.patch("os.access", return_value=False):
            error = validate_config_path(str(config_file))

            assert error is not None
            assert isinstance(error, MCPResourceError)
            assert "Permission denied" in str(error)
            assert (
                error.context["error_category"] == ErrorCategory.PERMISSION_DENIED.value
            )

    def test_validate_scan_parameters_valid(self, tmp_path):
        """Test validating valid scan parameters."""
        # Create a config file
        config_file = tmp_path / "config.yaml"
        with open(config_file, "w") as f:
            f.write("test: config")

        is_valid, errors = validate_scan_parameters(
            directory_path=str(tmp_path),
            severity_threshold="MEDIUM",
            config_path=str(config_file),
        )

        assert is_valid is True
        assert errors == []

    def test_validate_scan_parameters_invalid_directory(self):
        """Test validating scan parameters with invalid directory."""
        is_valid, errors = validate_scan_parameters(
            directory_path="/non/existent/dir",
            severity_threshold="MEDIUM",
            config_path=None,
        )

        assert is_valid is False
        assert len(errors) == 1
        assert isinstance(errors[0], MCPResourceError)
        assert "not found" in str(errors[0])

    def test_validate_scan_parameters_invalid_severity(self, tmp_path):
        """Test validating scan parameters with invalid severity threshold."""
        is_valid, errors = validate_scan_parameters(
            directory_path=str(tmp_path), severity_threshold="INVALID", config_path=None
        )

        assert is_valid is False
        assert len(errors) == 1
        assert isinstance(errors[0], MCPResourceError)
        assert "Invalid severity threshold" in str(errors[0])

    def test_validate_scan_parameters_invalid_config(self, tmp_path):
        """Test validating scan parameters with invalid config path."""
        is_valid, errors = validate_scan_parameters(
            directory_path=str(tmp_path),
            severity_threshold="MEDIUM",
            config_path="/non/existent/config.yaml",
        )

        assert is_valid is False
        assert len(errors) == 1
        assert isinstance(errors[0], MCPResourceError)
        assert "not found" in str(errors[0])

    def test_validate_scan_parameters_multiple_errors(self):
        """Test validating scan parameters with multiple errors."""
        is_valid, errors = validate_scan_parameters(
            directory_path="/non/existent/dir",
            severity_threshold="INVALID",
            config_path="/non/existent/config.yaml",
        )

        assert is_valid is False
        assert len(errors) == 3
        assert all(isinstance(error, MCPResourceError) for error in errors)


class TestUtilityFunctions:
    """Tests for utility functions."""

    def test_check_file_exists_true(self, tmp_path):
        """Test checking if a file exists when it does."""
        # Create a file
        test_file = tmp_path / "file.txt"
        with open(test_file, "w") as f:
            f.write("test")

        assert check_file_exists(test_file) is True

    def test_check_file_exists_false(self):
        """Test checking if a file exists when it doesn't."""
        assert check_file_exists(Path("/non/existent/file.txt")) is False

    def test_check_directory_exists_true(self, tmp_path):
        """Test checking if a directory exists when it does."""
        assert check_directory_exists(tmp_path) is True

    def test_check_directory_exists_false(self):
        """Test checking if a directory exists when it doesn't."""
        assert check_directory_exists(Path("/non/existent/dir")) is False

    def test_create_error_response(self):
        """Test creating an error response."""
        error = MCPResourceError(
            "Test error",
            context={
                "test": "context",
                "error_category": ErrorCategory.INVALID_PARAMETER.value,
            },
        )

        response = create_error_response(
            error=error,
            operation="test_operation",
            suggestions=["Suggestion 1", "Suggestion 2"],
        )

        assert response["success"] is False
        assert response["error"] == "Test error"
        assert response["operation"] == "test_operation"
        assert response["error_type"] == "MCPResourceError"
        assert response["error_category"] == ErrorCategory.INVALID_PARAMETER.value
        assert response["context"]["test"] == "context"
        assert response["suggestions"] == ["Suggestion 1", "Suggestion 2"]
        assert "timestamp" in response

    def test_create_error_response_with_default_suggestions(self):
        """Test creating an error response with default suggestions."""
        error = MCPResourceError(
            "Test error",
            context={"error_category": ErrorCategory.INVALID_PARAMETER.value},
        )

        response = create_error_response(error=error, operation="test_operation")

        assert response["success"] is False
        assert "suggestions" in response
        assert len(response["suggestions"]) > 0

    def test_create_error_response_with_non_mcp_error(self):
        """Test creating an error response with a non-MCPResourceError."""
        error = ValueError("Test error")

        response = create_error_response(error=error, operation="test_operation")

        assert response["success"] is False
        assert response["error"] == "Test error"
        assert response["error_type"] == "ValueError"
        assert "error_category" in response
        assert response["error_category"] == ErrorCategory.UNEXPECTED_ERROR.value

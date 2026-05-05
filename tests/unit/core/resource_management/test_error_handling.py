#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Test script for error handling utilities.

This script demonstrates the usage of the error handling utilities and
can be used to verify that they work as expected.
"""

import json
from pathlib import Path

from automated_security_helper.core.resource_management.error_handling import (
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
    ErrorCategory,
)
from automated_security_helper.core.resource_management.exceptions import (
    MCPResourceError,
)
from automated_security_helper.utils.log import ASH_LOGGER

logger = ASH_LOGGER


def test_safe_read_json_file():
    """Test the safe_read_json_file function."""
    logger.info("Testing safe_read_json_file...")

    # Test with a valid JSON file
    test_file = Path("test_valid.json")
    test_data = {"test": "data", "nested": {"value": 123}}

    with open(test_file, "w") as f:
        json.dump(test_data, f)

    data, error = safe_read_json_file(test_file)
    if error:
        logger.error(f"Error reading valid JSON file: {error}")
    else:
        logger.info(f"Successfully read valid JSON file: {data}")

    # Test with a non-existent file
    non_existent_file = Path("non_existent.json")
    data, error = safe_read_json_file(non_existent_file, required=False)
    if error:
        logger.error(f"Error reading non-existent file (expected): {error}")
    else:
        logger.info("Successfully handled non-existent file as optional")

    # Test with a required non-existent file
    data, error = safe_read_json_file(non_existent_file, required=True)
    if error:
        logger.info(f"Successfully detected required non-existent file: {error}")
    else:
        logger.error("Failed to detect required non-existent file")

    # Test with an invalid JSON file
    invalid_file = Path("test_invalid.json")
    with open(invalid_file, "w") as f:
        f.write("{invalid json")

    data, error = safe_read_json_file(invalid_file)
    if error:
        logger.info(f"Successfully detected invalid JSON: {error}")
    else:
        logger.error("Failed to detect invalid JSON")

    # Clean up test files
    test_file.unlink(missing_ok=True)
    invalid_file.unlink(missing_ok=True)


def test_safe_write_json_file():
    """Test the safe_write_json_file function."""
    logger.info("Testing safe_write_json_file...")

    # Test writing to a file
    test_file = Path("test_write.json")
    test_data = {"test": "write", "array": [1, 2, 3]}

    error = safe_write_json_file(test_file, test_data)
    if error:
        logger.error(f"Error writing JSON file: {error}")
    else:
        logger.info(f"Successfully wrote JSON file to {test_file}")

    # Verify the file was written correctly
    with open(test_file, "r") as f:
        read_data = json.load(f)

    if read_data == test_data:
        logger.info("File content matches the written data")
    else:
        logger.error(f"File content does not match: {read_data} != {test_data}")

    # Test writing to a nested directory that doesn't exist
    nested_file = Path("test_dir/nested/test.json")
    error = safe_write_json_file(nested_file, test_data)
    if error:
        logger.error(f"Error writing to nested directory: {error}")
    else:
        logger.info(f"Successfully created directories and wrote file to {nested_file}")

    # Clean up test files
    test_file.unlink(missing_ok=True)
    if nested_file.exists():
        nested_file.unlink()

    # Clean up test directories
    if Path("test_dir").exists():
        import shutil

        shutil.rmtree("test_dir")


def test_validation_functions():
    """Test the validation functions."""
    logger.info("Testing validation functions...")

    # Test directory path validation
    current_dir = Path.cwd()
    error = validate_directory_path(current_dir)
    if error:
        logger.error(f"Error validating current directory: {error}")
    else:
        logger.info("Successfully validated current directory")

    # Test non-existent directory
    non_existent_dir = Path("non_existent_dir")
    error = validate_directory_path(non_existent_dir)
    if error:
        logger.info(f"Successfully detected non-existent directory: {error}")
    else:
        logger.error("Failed to detect non-existent directory")

    # Test scan ID validation
    error = validate_scan_id("valid-scan-id")
    if error:
        logger.error(f"Error validating valid scan ID: {error}")
    else:
        logger.info("Successfully validated scan ID")

    error = validate_scan_id("")
    if error:
        logger.info(f"Successfully detected empty scan ID: {error}")
    else:
        logger.error("Failed to detect empty scan ID")

    # Test severity threshold validation
    error = validate_severity_threshold("MEDIUM")
    if error:
        logger.error(f"Error validating valid severity threshold: {error}")
    else:
        logger.info("Successfully validated severity threshold")

    error = validate_severity_threshold("INVALID")
    if error:
        logger.info(f"Successfully detected invalid severity threshold: {error}")
    else:
        logger.error("Failed to detect invalid severity threshold")

    # Test config path validation
    if Path("test_config.yaml").exists():
        Path("test_config.yaml").unlink()

    with open("test_config.yaml", "w") as f:
        f.write("test: config")

    error = validate_config_path("test_config.yaml")
    if error:
        logger.error(f"Error validating valid config path: {error}")
    else:
        logger.info("Successfully validated config path")

    error = validate_config_path("non_existent_config.yaml")
    if error:
        logger.info(f"Successfully detected non-existent config path: {error}")
    else:
        logger.error("Failed to detect non-existent config path")

    # Test scan parameters validation
    is_valid, errors = validate_scan_parameters(
        current_dir, "MEDIUM", "test_config.yaml"
    )
    if is_valid:
        logger.info("Successfully validated scan parameters")
    else:
        logger.error(f"Error validating valid scan parameters: {errors}")

    is_valid, errors = validate_scan_parameters(
        non_existent_dir, "INVALID", "non_existent_config.yaml"
    )
    if not is_valid:
        logger.info(
            f"Successfully detected invalid scan parameters: {len(errors)} errors"
        )
        for i, error in enumerate(errors):
            logger.info(f"  Error {i + 1}: {error}")
    else:
        logger.error("Failed to detect invalid scan parameters")

    # Clean up test files
    Path("test_config.yaml").unlink(missing_ok=True)


def test_utility_functions():
    """Test the utility functions."""
    logger.info("Testing utility functions...")

    # Test check_file_exists
    test_file = Path("test_exists.txt")
    with open(test_file, "w") as f:
        f.write("test")

    if check_file_exists(test_file):
        logger.info("Successfully detected existing file")
    else:
        logger.error("Failed to detect existing file")

    if not check_file_exists("non_existent.txt"):
        logger.info("Successfully detected non-existent file")
    else:
        logger.error("Failed to detect non-existent file")

    # Test check_directory_exists
    current_dir = Path.cwd()
    if check_directory_exists(current_dir):
        logger.info("Successfully detected existing directory")
    else:
        logger.error("Failed to detect existing directory")

    if not check_directory_exists("non_existent_dir"):
        logger.info("Successfully detected non-existent directory")
    else:
        logger.error("Failed to detect non-existent directory")

    # Test create_error_response
    error = MCPResourceError(
        "Test error",
        context={
            "test": "context",
            "error_category": ErrorCategory.INVALID_PARAMETER.value,
        },
    )

    response = create_error_response(error, "test_operation")
    logger.info(f"Error response: {json.dumps(response, indent=2)}")

    # Clean up test files
    test_file.unlink(missing_ok=True)


def main():
    """Run all tests."""
    logger.info("Starting error handling tests...")

    test_safe_read_json_file()
    test_safe_write_json_file()
    test_validation_functions()
    test_utility_functions()

    logger.info("All tests completed.")


if __name__ == "__main__":
    main()

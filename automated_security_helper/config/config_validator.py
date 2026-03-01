# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Configuration validation utilities for ASH."""

import json
from pathlib import Path
from typing import List, Tuple

import yaml


class ConfigValidationError(Exception):
    """Raised when configuration validation fails."""

    pass


class ConfigValidator:
    """Validates ASH configuration files for common issues."""

    # Fields that should NOT appear in user configs (internal-only)
    INTERNAL_SCANNER_FIELDS = {
        "name",
        "extension",
        "tool_version",
        "install_timeout",
    }

    INTERNAL_REPORTER_FIELDS = {
        "name",
        "extension",
    }

    INTERNAL_CONVERTER_FIELDS = {
        "name",
        "tool_version",
        "install_timeout",
    }

    # Top-level fields that should NOT appear in user configs
    INVALID_TOP_LEVEL_FIELDS = {
        "build",
        "mcp-resource-management",
    }

    # Required top-level fields
    REQUIRED_TOP_LEVEL_FIELDS = {
        "project_name",
    }

    # Valid top-level fields
    VALID_TOP_LEVEL_FIELDS = {
        "project_name",
        "fail_on_findings",
        "ash_plugin_modules",
        "external_reports_to_include",
        "global_settings",
        "scanners",
        "reporters",
        "converters",
    }

    @classmethod
    def validate_config_file(cls, config_path: Path) -> Tuple[bool, List[str]]:
        """Validate a configuration file and return validation results.

        Args:
            config_path: Path to the configuration file

        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []

        try:
            # Load the config file
            with open(config_path, "r", encoding="utf-8") as f:
                if str(config_path).endswith(".json"):
                    config_data = json.load(f)
                else:
                    config_data = yaml.safe_load(f)

            if not isinstance(config_data, dict):
                errors.append(
                    f"Configuration must be a dictionary/object, got {type(config_data).__name__}"
                )
                return False, errors

            # Check for required fields
            for field in cls.REQUIRED_TOP_LEVEL_FIELDS:
                if field not in config_data:
                    errors.append(f"Missing required top-level field: '{field}'")

            # Check for invalid top-level fields
            for field in config_data.keys():
                if field in cls.INVALID_TOP_LEVEL_FIELDS:
                    errors.append(
                        f"Invalid top-level field '{field}' - this is an internal field and should not be in user configs"
                    )
                elif field not in cls.VALID_TOP_LEVEL_FIELDS:
                    errors.append(
                        f"Unknown top-level field '{field}' - may cause parsing issues"
                    )

            # Check for duplicate field definitions (YAML allows this but causes issues)
            raw_content = config_path.read_text()
            top_level_fields = {}
            for line in raw_content.split("\n"):
                stripped = line.strip()
                if stripped and not stripped.startswith("#") and ":" in stripped:
                    field_name = stripped.split(":")[0].strip()
                    if field_name in cls.VALID_TOP_LEVEL_FIELDS:
                        if field_name in top_level_fields:
                            errors.append(
                                f"Duplicate top-level field '{field_name}' found at multiple locations"
                            )
                        top_level_fields[field_name] = True

            # Validate scanners section
            if "scanners" in config_data and isinstance(config_data["scanners"], dict):
                for scanner_name, scanner_config in config_data["scanners"].items():
                    if isinstance(scanner_config, dict):
                        for field in scanner_config.keys():
                            if field in cls.INTERNAL_SCANNER_FIELDS:
                                errors.append(
                                    f"Scanner '{scanner_name}' contains internal-only field '{field}' - "
                                    f"this should not be in user configs"
                                )

            # Validate reporters section
            if "reporters" in config_data and isinstance(
                config_data["reporters"], dict
            ):
                for reporter_name, reporter_config in config_data["reporters"].items():
                    if isinstance(reporter_config, dict):
                        for field in reporter_config.keys():
                            if field in cls.INTERNAL_REPORTER_FIELDS:
                                errors.append(
                                    f"Reporter '{reporter_name}' contains internal-only field '{field}' - "
                                    f"this should not be in user configs"
                                )

            # Validate converters section
            if "converters" in config_data and isinstance(
                config_data["converters"], dict
            ):
                for converter_name, converter_config in config_data[
                    "converters"
                ].items():
                    if isinstance(converter_config, dict):
                        for field in converter_config.keys():
                            if field in cls.INTERNAL_CONVERTER_FIELDS:
                                errors.append(
                                    f"Converter '{converter_name}' contains internal-only field '{field}' - "
                                    f"this should not be in user configs"
                                )

            return len(errors) == 0, errors

        except yaml.YAMLError as e:
            errors.append(f"YAML parsing error: {str(e)}")
            return False, errors
        except json.JSONDecodeError as e:
            errors.append(f"JSON parsing error: {str(e)}")
            return False, errors
        except Exception as e:
            errors.append(f"Unexpected error during validation: {str(e)}")
            return False, errors

    @classmethod
    def validate_and_raise(cls, config_path: Path) -> None:
        """Validate a configuration file and raise an exception if invalid.

        Args:
            config_path: Path to the configuration file

        Raises:
            ConfigValidationError: If the configuration is invalid
        """
        is_valid, errors = cls.validate_config_file(config_path)

        if not is_valid:
            error_msg = f"Configuration validation failed for {config_path}:\n"
            for i, error in enumerate(errors, 1):
                error_msg += f"  {i}. {error}\n"
            error_msg += "\nPlease fix these issues and try again."
            error_msg += "\nTip: Run 'ash config validate' for detailed validation."
            raise ConfigValidationError(error_msg)

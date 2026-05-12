# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Configuration validation utilities for ASH."""

import json
from pathlib import Path
from typing import List, Optional, Tuple

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
        "mcp-resource-management",
    }

    @classmethod
    def validate_config_file(
        cls, config_path: Path, source_dir: Optional[Path] = None
    ) -> Tuple[bool, List[str]]:
        """Validate a configuration file and return validation results.

        Args:
            config_path: Path to the configuration file
            source_dir: Path to the source directory (for resolving ignore_path patterns).
                        If None, inferred from config_path location.

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
                # Only consider lines with no leading whitespace (true top-level fields)
                if (
                    stripped
                    and not stripped.startswith("#")
                    and ":" in stripped
                    and not line[0].isspace()
                ):
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

            # Validate ignore_paths and suppression paths for directory-without-glob issues
            warnings = cls._check_path_patterns(config_path, config_data, source_dir)
            errors.extend(warnings)

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
    def _check_path_patterns(
        cls,
        config_path: Path,
        config_data: dict,
        source_dir: Optional[Path] = None,
    ) -> List[str]:
        """Check ignore_paths and suppression paths for directory-without-glob issues.

        Returns a list of warning messages for paths that point to existing directories
        but lack a '**' glob suffix (meaning they won't match files inside).
        Only warns when the path actually exists as a directory in the repo.
        """
        warnings = []

        # Determine the project root for resolving relative paths
        if source_dir is not None:
            project_root = source_dir.resolve()
        else:
            config_parent = config_path.resolve().parent
            if config_parent.name == ".ash":
                project_root = config_parent.parent
            else:
                project_root = config_parent

        global_settings = config_data.get("global_settings", {})
        if not isinstance(global_settings, dict):
            return warnings

        # Check ignore_paths
        ignore_paths = global_settings.get("ignore_paths", [])
        if isinstance(ignore_paths, list):
            for entry in ignore_paths:
                if not isinstance(entry, dict):
                    continue
                path_pattern = entry.get("path", "")
                warning = cls._check_single_path(path_pattern, project_root)
                if warning:
                    warnings.append(warning)

        # Check suppression paths
        suppressions = global_settings.get("suppressions", [])
        if isinstance(suppressions, list):
            for entry in suppressions:
                if not isinstance(entry, dict):
                    continue
                path_pattern = entry.get("path", "")
                warning = cls._check_single_path(path_pattern, project_root)
                if warning:
                    warnings.append(warning)

        return warnings

    @classmethod
    def _check_single_path(cls, path_pattern: str, project_root: Path) -> Optional[str]:
        """Check a single path pattern for directory-without-glob issues.

        Returns a warning message if the path points to an existing directory
        without a '**' glob suffix, or None if the path is fine.
        """
        if not path_pattern:
            return None

        # Skip patterns that already contain ** (recursive glob)
        if "**" in path_pattern:
            return None

        # Strip trailing slash for directory check
        clean_path = path_pattern.rstrip("/")

        # Skip patterns with wildcards in the filename portion
        from pathlib import PurePosixPath

        basename = PurePosixPath(clean_path).name
        if "*" in basename or "?" in basename or "[" in basename:
            return None

        # Check if this path resolves to an existing directory
        candidate = project_root / clean_path
        if candidate.is_dir():
            return (
                f"Path '{path_pattern}' points to a directory but lacks a '**' glob suffix — "
                f"it will not match files inside the directory. "
                f"Use '{clean_path}/**' to ignore all files recursively."
            )

        return None

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

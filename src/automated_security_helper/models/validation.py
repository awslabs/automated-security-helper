"""Configuration validation framework for ASH."""

from typing import Any, Dict, List, Optional, Type, Union

from pydantic import BaseModel, ValidationError

from automated_security_helper.base.scanner import ParserConfig
from automated_security_helper.base.scanner_plugin import ScannerPlugin


class ConfigurationValidator:
    """Validates ASH configurations."""

    VALID_SCANNER_TYPES = ("SAST", "DAST", "SBOM", "CONTAINER", "IAC", "DEPENDENCY")

    @staticmethod
    def _normalize_scanner_type(scanner_type: str) -> str:
        """Convert legacy scanner types to their modern equivalents."""
        if not isinstance(scanner_type, str):
            return scanner_type
        scanner_type = str(scanner_type).upper().strip()
        # Handle legacy types
        if scanner_type == "STATIC":
            return "SAST"
        return scanner_type

    VALID_OUTPUT_FORMATS = [
        "json",
        "text",
        "html",
        "csv",
        "yaml",
        "junitxml",
        "sarif",
        "asff",
        "cyclonedx",
        "spdx",
    ]

    @staticmethod
    def _validate_output_formats(formats: List[str]) -> tuple[bool, Optional[str]]:
        """Validate output format list.

        Args:
            formats: List of output format strings to validate

        Returns:
            Tuple of (is_valid: bool, error_message: Optional[str])
        """
        if not isinstance(formats, list):
            return False, f"Expected list of formats, got {type(formats).__name__}"

        invalid_formats = [
            fmt
            for fmt in formats
            if fmt not in ConfigurationValidator.VALID_OUTPUT_FORMATS
        ]
        if invalid_formats:
            return False, f"Invalid output formats: {invalid_formats}"

        return True, None

    @staticmethod
    def _is_valid_scanner_type(scanner_type: str) -> bool:
        """Check if scanner type is valid after normalization."""
        try:
            if not scanner_type or not isinstance(scanner_type, str):
                return False
            normalized = ConfigurationValidator._normalize_scanner_type(scanner_type)
            return normalized in ConfigurationValidator.VALID_SCANNER_TYPES
        except Exception:
            return False

    @staticmethod
    def _validate_scanner_type(
        scanner_type: Any,
    ) -> tuple[bool, Optional[str], Optional[str]]:
        """Validate and normalize a scanner type.

        Returns:
            Tuple of (is_valid, error_message, normalized_type)
        """
        if not scanner_type:
            return False, "Scanner type is required", None

        if not isinstance(scanner_type, str):
            return False, f"Scanner type must be string, got {type(scanner_type)}", None

        # Normalize and validate type
        scanner_type = str(scanner_type).strip().upper()

        # Handle legacy STATIC -> SAST mapping
        if scanner_type == "STATIC":
            scanner_type = "SAST"

        if scanner_type not in ConfigurationValidator.VALID_SCANNER_TYPES:
            return (
                False,
                f"Scanner type must be one of: {', '.join(ConfigurationValidator.VALID_SCANNER_TYPES)}",
                None,
            )

        return True, None, scanner_type

    @staticmethod
    def validate_output_config(config: Dict[str, Any]) -> tuple[bool, Optional[str]]:
        """Validate output configuration.

        Args:
            config: Output configuration dictionary to validate

        Returns:
            Tuple of (is_valid: bool, error_message: Optional[str])
        """
        if not isinstance(config, dict):
            return False, f"Expected dict, got {type(config).__name__}"

        formats = config.get("formats", ["json"])
        if not formats:
            return True, None  # Empty list will use default json

        return ConfigurationValidator._validate_output_formats(formats)

    @staticmethod
    def validate_config(
        config: Union[Dict[str, Any], BaseModel], config_type: Type[BaseModel]
    ) -> tuple[bool, Optional[str]]:
        """Validate a configuration against its expected type.

        Args:
            config: Configuration to validate as dict or BaseModel
            config_type: Expected configuration type (e.g., ScannerConfig)

        Returns:
            Tuple of (is_valid: bool, error_message: Optional[str])
        """
        try:
            # Basic validation
            if config is None or (isinstance(config, dict) and not config):
                return False, "Empty configuration"

            if not isinstance(config, (dict, BaseModel)):
                return False, f"Expected dict or BaseModel, got {type(config).__name__}"

            # Handle already validated models
            if isinstance(config, BaseModel):
                if not isinstance(config, config_type):
                    return (
                        False,
                        f"Expected {config_type.__name__}, got {type(config).__name__}",
                    )
                return True, None

            # Dict validation
            if not isinstance(config, dict):
                return False, f"Expected dict, got {type(config).__name__}"

            # Check required name
            if not config.get("name"):
                return False, "Name is required"

            # Special handling for scanner configs
            if config_type is ScannerPlugin:
                return ConfigurationValidator.validate_scanner_config(config)

            # Regular validation
            try:
                config_type.model_validate(config)
                return True, None
            except ValidationError as e:
                return False, str(e)

        except Exception as e:
            return False, str(e)

    @staticmethod
    def _normalize_config(
        config: Union[Dict[str, Any], BaseModel], config_type: Type[BaseModel] = None
    ) -> Dict[str, Any]:
        """Convert config to dictionary format and normalize values.

        Args:
            config: Configuration to normalize
            config_type: Optional type information for special handling

        Returns:
            Normalized configuration dictionary
        """
        # Convert to dict
        config_dict = (
            config.model_dump() if isinstance(config, BaseModel) else dict(config)
        )

        # Special handling for scanner configs
        if config_type is ScannerPlugin and "type" in config_dict:
            scanner_type = config_dict.get("type")
            if isinstance(scanner_type, str):
                scanner_type = scanner_type.strip().upper()
                if scanner_type == "STATIC":
                    config_dict = dict(config_dict)  # Make a copy
                    config_dict["type"] = "SAST"
                elif scanner_type not in ConfigurationValidator.VALID_SCANNER_TYPES:
                    # Keep original for validation error
                    pass
                else:
                    config_dict = dict(config_dict)
                    config_dict["type"] = scanner_type

        return config_dict

    @staticmethod
    def validate_scanner_config(
        config: Union[Dict[str, Any], ScannerPlugin],
    ) -> tuple[bool, Optional[str]]:
        """Validate scanner configuration.

        Args:
            config: Scanner configuration to validate

        Returns:
            Tuple of (is_valid: bool, error_message: Optional[str])
        """
        try:
            # Basic validation
            if not config:
                return False, "Empty configuration"

            if isinstance(config, ScannerPlugin):
                return True, None

            if not isinstance(config, dict):
                return (
                    False,
                    f"Expected dict or ScannerConfig, got {type(config).__name__}",
                )

            # Check required fields
            if not config.get("name"):
                return False, "Name is required"

            # Handle type normalization
            if "type" in config:
                scanner_type = config.get("type")
                if scanner_type and isinstance(scanner_type, str):
                    scanner_type = str(scanner_type).strip().upper()
                    if scanner_type == "STATIC":
                        config = dict(config)
                        config["type"] = "SAST"

            # Validate config
            try:
                ScannerPlugin.model_validate(config)
                return True, None
            except ValidationError as e:
                return False, f"Invalid scanner config: {str(e)}"

        except Exception as e:
            return False, str(e)

    @staticmethod
    def validate_parser_config(
        config: Union[Dict[str, Any], ParserConfig],
    ) -> tuple[bool, Optional[str]]:
        """Validate parser configuration.

        Args:
            config: Parser configuration to validate

        Returns:
            Tuple of (is_valid: bool, error_message: Optional[str])
        """
        return ConfigurationValidator.validate_config(config, ParserConfig)

    @staticmethod
    @staticmethod
    def validate_configs(
        configs: List[Union[Dict[str, Any], BaseModel]], config_type: Type[BaseModel]
    ) -> List[tuple[bool, Optional[str]]]:
        """Validate multiple configurations against their expected type.

        Args:
            configs: List of configurations to validate
            config_type: Expected configuration type for all configs

        Returns:
            List of (is_valid: bool, error_message: Optional[str]) tuples
        """
        if not configs:
            return [(False, "Empty configuration list")]

        validator = ConfigurationValidator()
        results = []

        for config in configs:
            if config is None or (isinstance(config, dict) and not config):
                results.append((False, "Empty configuration"))
                continue

            # Validate config
            if config_type is ScannerPlugin:
                results.append(validator.validate_scanner_config(config))
            else:
                # Handle non-scanner configs
                try:
                    if isinstance(config, dict):
                        if not config.get("name"):
                            results.append((False, "Name is required"))
                            continue
                        config_type.model_validate(config)
                    elif not isinstance(config, config_type):
                        results.append(
                            (
                                False,
                                f"Invalid configuration type: {type(config).__name__}",
                            )
                        )
                        continue
                    results.append((True, None))
                except ValidationError as e:
                    results.append((False, str(e)))

        return results

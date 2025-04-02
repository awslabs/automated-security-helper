"""Configuration validation framework for ASH."""

from typing import Any, Dict, List, Optional, Type, Union
from pydantic import BaseModel, ValidationError
from .config import ScannerConfig, ParserConfig


class ConfigurationValidator:
    """Validates ASH configurations."""

    @staticmethod
    def validate_config(
        config: Union[Dict[str, Any], BaseModel], config_type: Type[BaseModel]
    ) -> tuple[bool, Optional[str]]:
        """
        Validate a configuration against its expected type.

        Args:
            config: Configuration to validate as dict or BaseModel
            config_type: Expected configuration type (e.g., ScannerConfig)

        Returns:
            Tuple of (is_valid: bool, error_message: Optional[str])
        """
        try:
            if isinstance(config, dict):
                config_type.model_validate(config)
            elif isinstance(config, BaseModel):
                if not isinstance(config, config_type):
                    raise ValidationError(
                        f"Expected config type {config_type.__name__}, got {type(config).__name__}"
                    )
            return True, None
        except ValidationError as e:
            return False, str(e)

    @staticmethod
    def validate_scanner_config(
        config: Union[Dict[str, Any], ScannerConfig],
    ) -> tuple[bool, Optional[str]]:
        """Validate scanner configuration."""
        return ConfigurationValidator.validate_config(config, ScannerConfig)

    @staticmethod
    def validate_parser_config(
        config: Union[Dict[str, Any], ParserConfig],
    ) -> tuple[bool, Optional[str]]:
        """Validate parser configuration."""
        return ConfigurationValidator.validate_config(config, ParserConfig)

    @staticmethod
    def validate_configs(
        configs: List[Union[Dict[str, Any], BaseModel]], config_type: Type[BaseModel]
    ) -> List[tuple[bool, Optional[str]]]:
        """
        Validate multiple configurations of the same type.

        Args:
            configs: List of configurations to validate
            config_type: Expected configuration type

        Returns:
            List of validation results as (is_valid, error_message) tuples
        """
        return [
            ConfigurationValidator.validate_config(config, config_type)
            for config in configs
        ]

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import os
import yaml
import copy
from typing import Dict, Type, Union

from automated_security_helper.models.config import ASHConfig


class ConfigurationManager:
    """Singleton class responsible for managing scanner configurations and parsers."""

    _instance = None

    @classmethod
    def _reset(cls):
        """Reset the singleton instance (for testing purposes)."""
        cls._instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(ConfigurationManager, cls).__new__(cls)
            # Define instance attributes
            cls._instance._registered_scanners = {}
            cls._instance._registered_parsers = {}
            cls._instance._config_pipeline = []
            cls._instance._override_rules = {}
        return cls._instance

    def register_scanner(self, scanner_name: str, scanner_class: Type):
        """Register a scanner with the configuration manager.

        Args:
            scanner_name: Unique identifier for the scanner
            scanner_class: The scanner class to register
        """
        self._registered_scanners[scanner_name] = scanner_class

    def register_parser(self, parser_name: str, parser_class: Type):
        """Register a parser with the configuration manager.

        Args:
            parser_name: Unique identifier for the parser
            parser_class: The parser class to register
        """
        self._registered_parsers[parser_name] = parser_class

    def add_config_pipeline_step(self, step_fn):
        """Add a step to the configuration resolution pipeline.

        Args:
            step_fn: Function that takes a config dict and returns modified config dict
        """
        self._config_pipeline.append(step_fn)

    def set_override_rule(self, property_path: str, rule: Dict):
        """Set an override rule for a specific property path.

        Args:
            property_path: Dot-notation path to the property
            rule: Dictionary containing override rules and validation hooks
        """
        self._override_rules[property_path] = rule

    def resolve_configuration(
        self, base_config: Union[Dict, "ASHConfig"]
    ) -> "ASHConfig":
        """Process a configuration through the resolution pipeline.

        Args:
            base_config: Initial configuration dictionary or ASHConfig object

        Returns:
            Processed and validated configuration dictionary
        """
        if hasattr(base_config, "model_dump"):
            current_config = base_config.model_dump()
        else:
            current_config = base_config.copy()
        # Apply pipeline steps
        for step in self._config_pipeline:
            current_config = step(current_config)

        # Apply override rules
        for prop_path, rule in self._override_rules.items():
            self._apply_override_rule(current_config, prop_path, rule)

        return current_config

    def load_config(self, file_path: str) -> Union[Dict, ASHConfig]:
        """Load configuration from a YAML file.

        Args:
            file_path: Path to the YAML configuration file

        Returns:
            Configuration as Dict or ASHConfig object

        Raises:
            FileNotFoundError: If the configuration file doesn't exist
            yaml.YAMLError: If the YAML file is invalid
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Configuration file not found: {file_path}")

        with open(file_path, "r") as f:
            config_data = yaml.safe_load(f)
            try:
                return ASHConfig.model_validate(config_data)
            except Exception:
                # If validation fails, return as regular dict
                return config_data

    def save_config(self, config: Union[Dict, ASHConfig], file_path: str) -> None:
        """Save configuration to a YAML file.

        Args:
            config: Configuration dictionary to save
            file_path: Path where to save the configuration file
        """
        with open(file_path, "w") as f:
            if hasattr(config, "model_dump"):
                yaml.dump(config.model_dump(), f)
            else:
                yaml.dump(config, f)

    def validate_config(self, config: Union[Dict, ASHConfig]) -> bool:
        """Validate the configuration structure.

        Args:
            config: Configuration dictionary to validate

        Returns:
            True if configuration is valid

        Raises:
            ValueError: If configuration is invalid
        """
        if not isinstance(config, dict):
            raise ValueError("Configuration must be a dictionary")

        if "scanners" not in config or not isinstance(config["scanners"], dict):
            raise ValueError("Configuration must contain 'scanners' dictionary")

        if "parsers" not in config or not isinstance(config["parsers"], dict):
            raise ValueError("Configuration must contain 'parsers' dictionary")

        return True

    def get_scanner_config(self, config: Union[Dict, ASHConfig]) -> Dict:
        """Get scanner-specific configuration.

        Args:
            config: Complete configuration dictionary or ASHConfig object

        Returns:
            Dictionary containing scanner configuration
        """
        if hasattr(config, "model_dump"):
            return config.model_dump().get("scanners", {})
        return config.get("scanners", {})

    def get_parser_config(self, config: Union[Dict, ASHConfig]) -> Dict:
        """Get parser-specific configuration.

        Args:
            config: Complete configuration dictionary or ASHConfig object

        Returns:
            Dictionary containing parser configuration
        """
        if hasattr(config, "model_dump"):
            return config.model_dump().get("parsers", {})
        return config.get("parsers", {})

    # Define and bind the deep update method
    def _deep_update(self, base_dict: Dict, update_dict: Dict) -> None:
        """Recursively update a dictionary with another dictionary.

        This performs a deep merge of two dictionaries, where nested dictionaries
        are merged rather than replaced.

        Args:
            base_dict: Base dictionary to update
            update_dict: Dictionary to update with
        """
        for key, value in update_dict.items():
            if (
                key in base_dict
                and isinstance(base_dict[key], dict)
                and isinstance(value, dict)
            ):
                self._deep_update(base_dict[key], value)
            else:
                base_dict[key] = copy.deepcopy(value)

    def merge_configs(
        self,
        base_config: Union[Dict, ASHConfig],
        override_config: Union[Dict, ASHConfig],
    ) -> Union[Dict, ASHConfig]:
        """Merge two configuration dictionaries.

        Args:
            base_config: Base configuration dictionary
            override_config: Override configuration dictionary

        Returns:
            Merged configuration dictionary
        """
        # Convert configs to dictionaries if they are ASHConfig objects
        if hasattr(base_config, "model_dump"):
            base_dict = base_config.model_dump()
        else:
            base_dict = base_config.copy()

        if hasattr(override_config, "model_dump"):
            override_dict = override_config.model_dump()
        else:
            override_dict = override_config.copy()

        # Deep merge the configurations
        self._deep_update(base_dict, override_dict)

        # Try to convert back to ASHConfig if possible
        try:
            return ASHConfig.model_validate(base_dict)
        except Exception:
            return base_dict

    def _apply_override_rule(self, config: Dict, property_path: str, rule: Dict):
        """Apply an override rule to a specific property in the configuration.

        Args:
            config: Configuration dictionary to modify
            property_path: Dot-notation path to the property
            rule: Dictionary containing override rules and validation hooks
        """
        # Implementation of override rule application
        pass

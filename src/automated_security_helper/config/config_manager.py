# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import os
import yaml
from typing import Dict, Type


class ConfigurationManager:
    """Singleton class responsible for managing scanner configurations and parsers."""

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(ConfigurationManager, cls).__new__(cls)
            cls._instance._initialize()
        return cls._instance

    def _initialize(self):
        """Initialize the configuration manager state."""
        self._registered_scanners = {}
        self._registered_parsers = {}
        self._config_pipeline = []
        self._override_rules = {}

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

    def resolve_configuration(self, base_config: Dict) -> Dict:
        """Process a configuration through the resolution pipeline.

        Args:
            base_config: Initial configuration dictionary

        Returns:
            Processed and validated configuration dictionary
        """
        current_config = base_config.copy()

        # Apply pipeline steps
        for step in self._config_pipeline:
            current_config = step(current_config)

        # Apply override rules
        for prop_path, rule in self._override_rules.items():
            self._apply_override_rule(current_config, prop_path, rule)

        return current_config

    def load_config(self, file_path: str) -> Dict:
        """Load configuration from a YAML file.

        Args:
            file_path: Path to the YAML configuration file

        Returns:
            Dictionary containing the configuration

        Raises:
            FileNotFoundError: If the configuration file doesn't exist
            yaml.YAMLError: If the YAML file is invalid
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Configuration file not found: {file_path}")

        with open(file_path, "r") as f:
            return yaml.safe_load(f)

    def save_config(self, config: Dict, file_path: str) -> None:
        """Save configuration to a YAML file.

        Args:
            config: Configuration dictionary to save
            file_path: Path where to save the configuration file
        """
        with open(file_path, "w") as f:
            yaml.dump(config, f)

    def validate_config(self, config: Dict) -> bool:
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

    def get_scanner_config(self, config: Dict) -> Dict:
        """Get scanner-specific configuration.

        Args:
            config: Complete configuration dictionary

        Returns:
            Dictionary containing scanner configuration
        """
        return config["scanners"]

    def get_parser_config(self, config: Dict) -> Dict:
        """Get parser-specific configuration.

        Args:
            config: Complete configuration dictionary

        Returns:
            Dictionary containing parser configuration
        """
        return config["parsers"]

    def merge_configs(self, base_config: Dict, override_config: Dict) -> Dict:
        """Merge two configuration dictionaries.

        Args:
            base_config: Base configuration dictionary
            override_config: Override configuration dictionary

        Returns:
            Merged configuration dictionary
        """
        merged = base_config.copy()

        # Merge scanners
        merged["scanners"] = {
            **base_config.get("scanners", {}),
            **override_config.get("scanners", {}),
        }

        # Merge parsers
        merged["parsers"] = {
            **base_config.get("parsers", {}),
            **override_config.get("parsers", {}),
        }

        return merged

    def _apply_override_rule(self, config: Dict, property_path: str, rule: Dict):
        """Apply an override rule to a specific property in the configuration.

        Args:
            config: Configuration dictionary to modify
            property_path: Dot-notation path to the property
            rule: Dictionary containing override rules and validation hooks
        """
        # Implementation of override rule application
        pass

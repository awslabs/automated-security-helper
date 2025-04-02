# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

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

    def _apply_override_rule(self, config: Dict, property_path: str, rule: Dict):
        """Apply an override rule to a specific property in the configuration.

        Args:
            config: Configuration dictionary to modify
            property_path: Dot-notation path to the property
            rule: Override rule to apply
        """
        # Split property path into parts
        parts = property_path.split(".")

        # Navigate to the property
        current = config
        for part in parts[:-1]:
            if part not in current:
                return
            current = current[part]

        last_part = parts[-1]
        if last_part in current:
            # Apply validation hooks if present
            if "validation" in rule:
                validation_result = rule["validation"](current[last_part])
                if not validation_result:
                    return

            # Apply override if conditions are met
            if "override" in rule:
                current[last_part] = rule["override"]

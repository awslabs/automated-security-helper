"""Test data factories for creating test objects and data.

This module provides factory classes and utilities for creating test objects
and generating test data for use in tests.
"""

import random
import string
import uuid
from typing import Dict, Any, List, Optional, Union, TypeVar, Generic, Type
from pathlib import Path
import json
import yaml
from datetime import datetime, timedelta

# Type variable for generic factory
T = TypeVar("T")


class TestDataFactory(Generic[T]):
    """Base factory class for creating test objects.

    This class provides a foundation for creating test objects with default values
    that can be overridden as needed.
    """

    def __init__(self, cls: Type[T]):
        """Initialize the factory with the class it creates.

        Args:
            cls: The class that this factory creates instances of
        """
        self.cls = cls
        self.default_values = {}

    def set_default(self, **kwargs) -> "TestDataFactory[T]":
        """Set default values for object attributes.

        Args:
            **kwargs: Default values for object attributes

        Returns:
            Self for method chaining
        """
        self.default_values.update(kwargs)
        return self

    def create(self, **kwargs) -> T:
        """Create an instance of the class with the specified attributes.

        Args:
            **kwargs: Values for object attributes that override defaults

        Returns:
            An instance of the class
        """
        # Combine default values with provided values
        values = {**self.default_values, **kwargs}
        return self.cls(**values)

    def create_batch(self, size: int, **kwargs) -> List[T]:
        """Create multiple instances of the class.

        Args:
            size: Number of instances to create
            **kwargs: Values for object attributes that override defaults

        Returns:
            List of instances
        """
        return [self.create(**kwargs) for _ in range(size)]


class Builder:
    """Builder pattern implementation for creating complex objects.

    This class provides a flexible way to build complex objects with many
    optional parameters.
    """

    def __init__(self):
        """Initialize the builder with empty attributes."""
        self._attributes = {}

    def with_attribute(self, name: str, value: Any) -> "Builder":
        """Set an attribute value.

        Args:
            name: Attribute name
            value: Attribute value

        Returns:
            Self for method chaining
        """
        self._attributes[name] = value
        return self

    def with_attributes(self, **kwargs) -> "Builder":
        """Set multiple attribute values.

        Args:
            **kwargs: Attribute name-value pairs

        Returns:
            Self for method chaining
        """
        self._attributes.update(kwargs)
        return self

    def build(self):
        """Build the object using the configured attributes.

        This method should be overridden by subclasses to create the specific object.

        Returns:
            The built object
        """
        raise NotImplementedError("Subclasses must implement build()")


class RandomDataGenerator:
    """Utility class for generating random test data."""

    @staticmethod
    def random_string(length: int = 10) -> str:
        """Generate a random string of specified length.

        Args:
            length: Length of the string to generate

        Returns:
            Random string
        """
        return "".join(random.choice(string.ascii_letters) for _ in range(length))

    @staticmethod
    def random_email() -> str:
        """Generate a random email address.

        Returns:
            Random email address
        """
        username = RandomDataGenerator.random_string(8).lower()
        domain = RandomDataGenerator.random_string(6).lower()
        return f"{username}@{domain}.com"

    @staticmethod
    def random_uuid() -> str:
        """Generate a random UUID.

        Returns:
            Random UUID as string
        """
        return str(uuid.uuid4())

    @staticmethod
    def random_int(min_val: int = 0, max_val: int = 100) -> int:
        """Generate a random integer in the specified range.

        Args:
            min_val: Minimum value (inclusive)
            max_val: Maximum value (inclusive)

        Returns:
            Random integer
        """
        return random.randint(min_val, max_val)

    @staticmethod
    def random_float(min_val: float = 0.0, max_val: float = 1.0) -> float:
        """Generate a random float in the specified range.

        Args:
            min_val: Minimum value (inclusive)
            max_val: Maximum value (inclusive)

        Returns:
            Random float
        """
        return random.uniform(min_val, max_val)

    @staticmethod
    def random_bool() -> bool:
        """Generate a random boolean value.

        Returns:
            Random boolean
        """
        return random.choice([True, False])

    @staticmethod
    def random_list(generator_func, size: int = 5, **kwargs) -> List[Any]:
        """Generate a list of random values using the provided generator function.

        Args:
            generator_func: Function to generate each item
            size: Number of items to generate
            **kwargs: Arguments to pass to the generator function

        Returns:
            List of random values
        """
        return [generator_func(**kwargs) for _ in range(size)]

    @staticmethod
    def random_dict(keys: List[str], value_generator_func, **kwargs) -> Dict[str, Any]:
        """Generate a dictionary with random values.

        Args:
            keys: List of keys to include in the dictionary
            value_generator_func: Function to generate values
            **kwargs: Arguments to pass to the value generator function

        Returns:
            Dictionary with random values
        """
        return {key: value_generator_func(**kwargs) for key in keys}

    @staticmethod
    def random_date(
        start_date: Optional[datetime] = None, end_date: Optional[datetime] = None
    ) -> datetime:
        """Generate a random date between start_date and end_date.

        Args:
            start_date: Start date (defaults to 30 days ago)
            end_date: End date (defaults to today)

        Returns:
            Random date
        """
        if start_date is None:
            start_date = datetime.now() - timedelta(days=30)
        if end_date is None:
            end_date = datetime.now()

        time_delta = end_date - start_date
        random_days = random.randint(0, time_delta.days)
        return start_date + timedelta(days=random_days)


class SarifReportBuilder(Builder):
    """Builder for creating SARIF report test data."""

    def __init__(self):
        """Initialize the SARIF report builder with default values."""
        super().__init__()
        # Initialize with minimal valid SARIF structure
        self._attributes = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {"name": "TestTool", "version": "1.0.0", "rules": []}
                    },
                    "results": [],
                }
            ],
        }

    def with_tool_name(self, name: str) -> "SarifReportBuilder":
        """Set the tool name.

        Args:
            name: Tool name

        Returns:
            Self for method chaining
        """
        self._attributes["runs"][0]["tool"]["driver"]["name"] = name
        return self

    def with_tool_version(self, version: str) -> "SarifReportBuilder":
        """Set the tool version.

        Args:
            version: Tool version

        Returns:
            Self for method chaining
        """
        self._attributes["runs"][0]["tool"]["driver"]["version"] = version
        return self

    def add_rule(
        self, rule_id: str, name: str, description: str
    ) -> "SarifReportBuilder":
        """Add a rule to the SARIF report.

        Args:
            rule_id: Rule ID
            name: Rule name
            description: Rule description

        Returns:
            Self for method chaining
        """
        rule = {"id": rule_id, "name": name, "shortDescription": {"text": description}}
        self._attributes["runs"][0]["tool"]["driver"]["rules"].append(rule)
        return self

    def add_result(
        self,
        rule_id: str,
        level: str,
        message: str,
        file_path: str,
        start_line: int,
        end_line: int,
    ) -> "SarifReportBuilder":
        """Add a result to the SARIF report.

        Args:
            rule_id: Rule ID
            level: Result level (e.g., "error", "warning")
            message: Result message
            file_path: Path to the file with the issue
            start_line: Start line of the issue
            end_line: End line of the issue

        Returns:
            Self for method chaining
        """
        result = {
            "ruleId": rule_id,
            "level": level,
            "message": {"text": message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": file_path},
                        "region": {"startLine": start_line, "endLine": end_line},
                    }
                }
            ],
        }
        self._attributes["runs"][0]["results"].append(result)
        return self

    def build(self) -> Dict[str, Any]:
        """Build the SARIF report.

        Returns:
            Dictionary representing the SARIF report
        """
        return self._attributes

    def build_json(self) -> str:
        """Build the SARIF report as a JSON string.

        Returns:
            JSON string representing the SARIF report
        """
        return json.dumps(self._attributes, indent=2)

    def build_file(self, file_path: Union[str, Path]) -> Path:
        """Build the SARIF report and write it to a file.

        Args:
            file_path: Path to write the SARIF report to

        Returns:
            Path to the created file
        """
        file_path = Path(file_path)
        file_path.write_text(self.build_json())
        return file_path


class ConfigBuilder(Builder):
    """Builder for creating configuration test data."""

    def __init__(self, format: str = "yaml"):
        """Initialize the configuration builder.

        Args:
            format: Format of the configuration ("yaml" or "json")
        """
        super().__init__()
        self._format = format.lower()
        # Initialize with basic configuration structure
        self._attributes = {
            "project_name": "test_project",
            "scanners": {},
            "output": {"directory": ".ash/ash_output"},
        }

    def with_project_name(self, name: str) -> "ConfigBuilder":
        """Set the project name.

        Args:
            name: Project name

        Returns:
            Self for method chaining
        """
        self._attributes["project_name"] = name
        return self

    def with_output_directory(self, directory: str) -> "ConfigBuilder":
        """Set the output directory.

        Args:
            directory: Output directory path

        Returns:
            Self for method chaining
        """
        self._attributes["output"]["directory"] = directory
        return self

    def enable_scanner(
        self, scanner_name: str, config: Optional[Dict[str, Any]] = None
    ) -> "ConfigBuilder":
        """Enable a scanner with optional configuration.

        Args:
            scanner_name: Scanner name
            config: Scanner configuration

        Returns:
            Self for method chaining
        """
        scanner_config = {"enabled": True}
        if config:
            scanner_config.update(config)

        self._attributes["scanners"][scanner_name] = scanner_config
        return self

    def disable_scanner(self, scanner_name: str) -> "ConfigBuilder":
        """Disable a scanner.

        Args:
            scanner_name: Scanner name

        Returns:
            Self for method chaining
        """
        self._attributes["scanners"][scanner_name] = {"enabled": False}
        return self

    def build(self) -> Dict[str, Any]:
        """Build the configuration.

        Returns:
            Dictionary representing the configuration
        """
        return self._attributes

    def build_string(self) -> str:
        """Build the configuration as a string.

        Returns:
            String representing the configuration in the specified format
        """
        if self._format == "yaml":
            return yaml.dump(self._attributes)
        else:
            return json.dumps(self._attributes, indent=2)

    def build_file(self, file_path: Union[str, Path]) -> Path:
        """Build the configuration and write it to a file.

        Args:
            file_path: Path to write the configuration to

        Returns:
            Path to the created file
        """
        file_path = Path(file_path)
        file_path.write_text(self.build_string())
        return file_path


class VulnerabilityFactory:
    """Factory for creating vulnerability test data."""

    @staticmethod
    def create_vulnerability(
        vuln_id: Optional[str] = None,
        name: Optional[str] = None,
        severity: Optional[str] = None,
        description: Optional[str] = None,
        file_path: Optional[str] = None,
        line_number: Optional[int] = None,
        **kwargs,
    ) -> Dict[str, Any]:
        """Create a vulnerability object.

        Args:
            vuln_id: Vulnerability ID
            name: Vulnerability name
            severity: Vulnerability severity
            description: Vulnerability description
            file_path: Path to the file with the vulnerability
            line_number: Line number of the vulnerability
            **kwargs: Additional vulnerability attributes

        Returns:
            Dictionary representing the vulnerability
        """
        vuln = {
            "id": vuln_id or RandomDataGenerator.random_string(8),
            "name": name
            or f"Test Vulnerability {RandomDataGenerator.random_string(4)}",
            "severity": severity
            or random.choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"]),
            "description": description
            or f"Test vulnerability description {RandomDataGenerator.random_string(20)}",
            "location": {
                "file": file_path
                or f"src/test_{RandomDataGenerator.random_string(5)}.py",
                "line": line_number or RandomDataGenerator.random_int(1, 100),
            },
        }

        # Add any additional attributes
        vuln.update(kwargs)

        return vuln

    @staticmethod
    def create_vulnerabilities(count: int = 5, **kwargs) -> List[Dict[str, Any]]:
        """Create multiple vulnerability objects.

        Args:
            count: Number of vulnerabilities to create
            **kwargs: Default vulnerability attributes

        Returns:
            List of dictionaries representing vulnerabilities
        """
        return [
            VulnerabilityFactory.create_vulnerability(**kwargs) for _ in range(count)
        ]


class ScanResultFactory:
    """Factory for creating scan result test data."""

    @staticmethod
    def create_scan_result(
        scanner_name: Optional[str] = None,
        status: Optional[str] = None,
        vulnerabilities: Optional[List[Dict[str, Any]]] = None,
        **kwargs,
    ) -> Dict[str, Any]:
        """Create a scan result object.

        Args:
            scanner_name: Scanner name
            status: Scan status
            vulnerabilities: List of vulnerabilities
            **kwargs: Additional scan result attributes

        Returns:
            Dictionary representing the scan result
        """
        result = {
            "scanner": scanner_name
            or f"test_scanner_{RandomDataGenerator.random_string(4)}",
            "status": status or random.choice(["SUCCESS", "FAILURE", "ERROR"]),
            "timestamp": datetime.now().isoformat(),
            "vulnerabilities": vulnerabilities
            or VulnerabilityFactory.create_vulnerabilities(
                count=RandomDataGenerator.random_int(0, 10)
            ),
        }

        # Add any additional attributes
        result.update(kwargs)

        return result

    @staticmethod
    def create_scan_results(count: int = 3, **kwargs) -> List[Dict[str, Any]]:
        """Create multiple scan result objects.

        Args:
            count: Number of scan results to create
            **kwargs: Default scan result attributes

        Returns:
            List of dictionaries representing scan results
        """
        return [ScanResultFactory.create_scan_result(**kwargs) for _ in range(count)]

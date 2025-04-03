"""Unit tests for abstract scanner module."""

import json
from typing import Any, Dict, Optional

import pytest

from automated_security_helper.models.config import ScannerConfig
from automated_security_helper.scanners.abstract_scanner import (
    AbstractScanner,
    ScannerError,
)


class ConcreteScanner(AbstractScanner):
    """Concrete implementation of Scanner for testing."""

    def validate(self):
        return True

    def scan(self, target: str, options: Optional[Dict[str, Any]] = None) -> None:
        """Execute the actual scan operation."""
        self._pre_scan(target, options)
        # Simulate a scan result
        self._output = [
            json.dumps(
                {
                    "findings": [],
                    "metadata": {
                        "scanner": self.name,
                        "type": self.type,
                        "target": target,
                    },
                }
            )
        ]


def test_scanner_initialization():
    """Test scanner initialization with config."""
    config = ScannerConfig(name="test-scanner", command="pwd")
    scanner = ConcreteScanner()
    scanner.configure(config)
    assert scanner.name == "test-scanner"
    assert scanner.config == config
    assert scanner.options == {}


def test_scanner_initialization_none():
    """Test scanner initialization with no config."""
    scanner = ConcreteScanner()
    assert scanner.name == "<unknown>"
    assert scanner.type == ""
    assert scanner.config is None
    assert scanner.options == {}


def test_scanner_initialization_with_options():
    """Test scanner initialization with custom options."""
    config = ScannerConfig(
        name="test-scanner", type="SAST", options={"severity": "high", "threshold": 5}
    )
    scanner = ConcreteScanner()
    scanner.configure(config)
    assert scanner.options == {"severity": "high", "threshold": 5}


def test_scanner_execution():
    """Test basic scanner execution."""
    config = ScannerConfig(name="test-scanner", type="SAST")
    scanner = ConcreteScanner()
    scanner.configure(config)

    # Execute scan
    scanner.scan("test/target")

    # Verify output was generated
    assert len(scanner.output) == 1
    result = json.loads(scanner.output[0])
    assert result["metadata"]["scanner"] == "test-scanner"
    assert result["metadata"]["type"] == "SAST"
    assert result["metadata"]["target"] == "test/target"
    assert "findings" in result


def test_scanner_execution_with_options():
    """Test scanner execution with options."""
    config = ScannerConfig(
        name="test-scanner", type="SAST", options={"severity": "high"}
    )
    scanner = ConcreteScanner()
    scanner.configure(config)

    # Execute scan with additional options
    scanner.scan("test/target", {"threshold": 5})

    # Verify options were merged correctly
    assert scanner.options["severity"] == "high"
    assert scanner.options["threshold"] == 5


def test_scanner_error_handling():
    """Test scanner error handling."""
    scanner = ConcreteScanner()
    scanner.configure(ScannerConfig(name="test-scanner", type="SAST"))

    # Test with empty target
    with pytest.raises(ScannerError, match="No target specified"):
        scanner.scan(None)


def test_scanner_result_processing():
    """Test scanner result handling."""
    scanner = ConcreteScanner()
    scanner.configure(ScannerConfig(name="test-scanner", type="SAST"))
    scanner.scan("test/target")
    assert len(scanner.output) == 1
    assert not scanner.errors


def test_scanner_metadata_handling():
    """Test scanner metadata access."""
    scanner = ConcreteScanner()
    scanner.configure(
        ScannerConfig(name="test-scanner", type="SAST", options={"key": "value"})
    )
    assert scanner.name == "test-scanner"
    assert scanner.type == "SAST"
    assert scanner.options == {"key": "value"}


def test_scanner_command_execution():
    """Test scanner subprocess execution."""
    scanner = ConcreteScanner()
    scanner.configure(ScannerConfig(name="test-scanner", type="SAST"))
    scanner._run_subprocess(["echo", "test"])
    assert len(scanner.output) == 1
    assert scanner.output[0] == "test"


def test_scanner_command_execution_error():
    """Test scanner subprocess error handling."""
    scanner = ConcreteScanner()
    scanner.configure(ScannerConfig(name="test-scanner", type="SAST"))
    with pytest.raises(ScannerError):
        scanner._run_subprocess(["nonexistent_command"])


def test_scanner_with_custom_config():
    """Test scanner with custom configuration."""
    config = ScannerConfig(
        name="custom-scanner",
        type="CUSTOM",
        options={"level": "high", "include": ["*.py"], "exclude": ["test/*"]},
    )
    scanner = ConcreteScanner()
    scanner.configure(config)
    assert scanner.name == "custom-scanner"
    assert scanner.type == "CUSTOM"
    assert scanner.options == {
        "level": "high",
        "include": ["*.py"],
        "exclude": ["test/*"],
    }


def test_scanner_validate_config():
    """Test scanner configuration validation."""
    config = {"name": "invalid", "command": "pwd"}
    scanner = ConcreteScanner()
    scanner.configure(config)
    assert scanner.name == "invalid"
    assert scanner.config.command == "pwd"
    assert scanner.options == {}

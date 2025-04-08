"""Unit tests for abstract scanner module."""

from pathlib import Path
from typing import Any, Dict, Optional

import pytest

from automated_security_helper.config.config import ScannerPluginConfig

import logging

from automated_security_helper.models.scanner_plugin import (
    ScannerPlugin,
)
from automated_security_helper.exceptions import ScannerError
from automated_security_helper.utils.log import get_logger
from tests.conftest import TEST_SOURCE_DIR, TEST_OUTPUT_DIR


class ConcreteScanner(ScannerPlugin):
    """Concrete implementation of Scanner for testing."""

    def __init__(self, source_dir: Path = None, output_dir: Path = None):
        logger = get_logger("test_logger", level=logging.DEBUG)
        source_dir = source_dir if source_dir else TEST_SOURCE_DIR
        output_dir = output_dir if output_dir else TEST_OUTPUT_DIR
        super().__init__(source_dir, output_dir, logger)

    @property
    def default_config(self):
        """Get default scanner configuration."""
        return ScannerPluginConfig(
            name="test_scanner",
            type="CUSTOM",
            command="test_command",
            source_dir=self.source_dir,
            output_dir=self.output_dir,
        )

    def validate(self):
        return True

    def scan(self, target: str, options: Optional[Dict[str, Any]] = None) -> None:
        """Execute the actual scan operation."""
        self._pre_scan(target, options)
        # Simulate a scan result
        self._run_subprocess(["python", "--version"])


def test_scanner_initialization(test_source_dir, test_output_dir):
    """Test scanner initialization with config."""
    config = ScannerPluginConfig(
        name="test_scanner",
        command="pwd",
        source_dir=test_source_dir,
        output_dir=test_output_dir,
    )
    scanner = ConcreteScanner(source_dir=test_source_dir, output_dir=test_output_dir)
    scanner.configure(config)
    assert scanner.name == "test_scanner"
    assert scanner.config == config
    assert scanner.options == {}


def test_scanner_initialization_none(test_source_dir, test_output_dir):
    """Test scanner initialization with no config."""
    scanner = ConcreteScanner(source_dir=test_source_dir, output_dir=test_output_dir)
    assert scanner.name == "test_scanner"
    assert scanner.type == ""
    assert scanner.config is not None
    assert scanner.options == {}


def test_scanner_initialization_with_options(test_source_dir, test_output_dir):
    """Test scanner initialization with custom options."""
    config = ScannerPluginConfig(
        name="test_scanner",
        type="SAST",
        options={"severity": "high", "threshold": 5},
        source_dir=test_source_dir,
        output_dir=test_output_dir,
    )
    scanner = ConcreteScanner(source_dir=test_source_dir, output_dir=test_output_dir)
    scanner.configure(config)
    assert scanner.options == {"severity": "high", "threshold": 5}


def test_scanner_execution(test_source_dir, test_output_dir):
    """Test basic scanner execution."""
    config = ScannerPluginConfig(
        name="test_scanner",
        type="SAST",
    )
    scanner = ConcreteScanner(source_dir=test_source_dir, output_dir=test_output_dir)
    scanner.configure(config)

    # Execute scan
    scanner.scan("test/target")

    # Verify output was generated
    assert (
        len([item for item in scanner.output if item is not None and item != ""]) == 1
    )
    assert "Python 3" in scanner.output[0]


def test_scanner_execution_with_options(test_source_dir, test_output_dir):
    """Test scanner execution with options."""
    config = ScannerPluginConfig(
        name="test_scanner",
        type="SAST",
        options={"severity": "high"},
        source_dir=test_source_dir,
        output_dir=test_output_dir,
    )
    scanner = ConcreteScanner(source_dir=test_source_dir, output_dir=test_output_dir)
    scanner.configure(config)

    # Execute scan with additional options
    scanner.scan("test/target", {"threshold": 5})

    # Verify options were merged correctly
    assert scanner.options["severity"] == "high"
    assert scanner.options["threshold"] == 5


def test_scanner_error_handling(test_source_dir, test_output_dir):
    """Test scanner error handling."""
    scanner = ConcreteScanner(source_dir=test_source_dir, output_dir=test_output_dir)
    scanner.configure(
        ScannerPluginConfig(
            name="test_scanner",
            type="SAST",
            source_dir=test_source_dir,
            output_dir=test_output_dir,
        )
    )

    # Test with empty target
    with pytest.raises(ScannerError, match="No target specified"):
        scanner.scan(None)


def test_scanner_result_processing(test_source_dir, test_output_dir):
    """Test scanner result handling."""
    scanner = ConcreteScanner(source_dir=test_source_dir, output_dir=test_output_dir)
    scanner.configure(scanner.default_config)
    scanner.scan("test/target")
    assert (
        len([item for item in scanner.output if item is not None and item != ""]) == 1
    )
    assert not scanner.errors


def test_scanner_metadata_handling(test_source_dir, test_output_dir):
    """Test scanner metadata access."""
    scanner = ConcreteScanner(source_dir=test_source_dir, output_dir=test_output_dir)
    scanner.configure(
        ScannerPluginConfig(name="test_scanner", type="SAST", options={"key": "value"})
    )
    assert scanner.name == "test_scanner"
    assert scanner.type == "SAST"
    assert scanner.options == {
        "severity": "high",
        "threshold": 5,
        "key": "value",
    }


def test_scanner_command_execution(test_source_dir, test_output_dir):
    """Test scanner subprocess execution."""
    scanner = ConcreteScanner(source_dir=test_source_dir, output_dir=test_output_dir)
    scanner.configure(
        ScannerPluginConfig(
            name="test_scanner",
            type="SAST",
        )
    )
    scanner._run_subprocess(["echo", "test"])
    assert (
        len([item for item in scanner.output if item is not None and item != ""]) == 1
    )
    assert scanner.output[0] == "test\n"


def test_scanner_command_execution_error(test_source_dir, test_output_dir):
    """Test scanner subprocess error handling."""
    scanner = ConcreteScanner(source_dir=test_source_dir, output_dir=test_output_dir)
    scanner.configure(
        ScannerPluginConfig(
            name="test_scanner",
            type="SAST",
            source_dir=test_source_dir,
            output_dir=test_output_dir,
        )
    )
    with pytest.raises(ScannerError):
        scanner._run_subprocess(["nonexistent_command"])


def test_scanner_with_custom_config(test_source_dir, test_output_dir):
    """Test scanner with custom configuration."""
    scanner = ConcreteScanner(source_dir=test_source_dir, output_dir=test_output_dir)
    config = ScannerPluginConfig(
        name="custom_scanner",
        type="CUSTOM",
        options={"level": "high", "include": ["*.py"], "exclude": ["test/*"]},
        source_dir=test_source_dir,
        output_dir=test_output_dir,
    )
    scanner.configure(config)
    assert scanner.name == "custom_scanner"
    assert scanner.type == "CUSTOM"
    assert scanner.options == {
        "severity": "high",
        "threshold": 5,
        "key": "value",
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
    assert scanner.options == {
        "severity": "high",
        "threshold": 5,
        "key": "value",
        "level": "high",
        "include": ["*.py"],
        "exclude": ["test/*"],
    }

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for execution engine module."""

import pytest
from unittest.mock import Mock, patch

from automated_security_helper.execution_engine import (
    ScanExecutionEngine,
    ExecutionStrategy,
)
from automated_security_helper.scanners.abstract_scanner import AbstractScanner


class MockScanner(AbstractScanner):
    """Mock scanner for testing."""

    def __init__(self, name: str = "test-scanner"):
        """Initialize mock scanner.

        Args:
            name: Name to use for this scanner instance
        """
        # Initialize parent with name in config
        super().__init__()
        self._name = name
        self._description = f"Mock scanner {self.name}"  # Use property
        self.results = {"test": "results"}
        self.scan_called = False

    def configure(self, config):
        """Configure the scanner.

        Args:
            config: Configuration to apply

        Returns:
            Applied configuration
        """
        super()._set_config(config)
        if isinstance(config, dict) and "name" in config:
            self._description = f"Mock scanner {self.name}"
        return self.config

    def validate(self):
        return True

    def scan(self, config=None):
        """Mock scan method."""
        self.scan_called = True
        return self.results

    @property
    def description(self) -> str:
        """Get scanner description."""
        # Use configured name from parent
        return f"Mock scanner {self.name}"


def test_engine_initialization():
    """Test execution engine initialization."""
    engine = ScanExecutionEngine()
    assert engine.strategy == ExecutionStrategy.PARALLEL
    assert engine._max_workers == 4


def test_get_scanner():
    """Test getting registered scanner."""
    engine = ScanExecutionEngine()
    scanner = MockScanner()
    engine.register_scanner("test-scanner", lambda: scanner)

    created_scanner = engine.get_scanner("test-scanner")
    assert created_scanner is scanner
    assert created_scanner.description == "Mock scanner test-scanner"

    with pytest.raises(ValueError, match="Scanner unknown not registered"):
        engine.get_scanner("unknown")


def test_register_scanner():
    """Test scanner registration."""
    engine = ScanExecutionEngine()
    scanner = MockScanner()
    engine.register_scanner("test-scanner", lambda: scanner)

    created_scanner = engine._scanners["test-scanner"]()
    assert created_scanner is scanner


def test_execute_with_registered_scanner():
    """Test execution with registered scanner."""
    engine = ScanExecutionEngine()
    scanner = MockScanner()
    engine.register_scanner("test-scanner", lambda: scanner)

    assert not scanner.scan_called

    results = engine.execute(
        {"scanners": {"test-scanner": {"type": "static", "config_file": "test.yaml"}}}
    )

    assert scanner.scan_called
    assert results["test-scanner"] == {"test": "results"}


@patch("concurrent.futures.ThreadPoolExecutor")
def test_execute_with_parallel_mode(mock_executor):
    """Test parallel execution mode."""
    # Setup mock executor
    mock_executor_instance = Mock()
    mock_executor.return_value.__enter__.return_value = mock_executor_instance

    def mock_submit(fn, args):
        future = Mock()
        result = fn(args)
        future.result.return_value = result
        return future

    mock_executor_instance.submit.side_effect = mock_submit

    # Test execution
    engine = ScanExecutionEngine()
    scanner1 = MockScanner("test-scanner1")
    scanner2 = MockScanner("test-scanner2")

    engine.register_scanner("test-scanner1", lambda: scanner1)
    engine.register_scanner("test-scanner2", lambda: scanner2)

    results = engine.execute(
        {
            "scanners": {
                "test-scanner1": {"type": "static"},
                "test-scanner2": {"type": "static"},
            }
        }
    )

    assert len(results) == 2
    assert scanner1.scan_called
    assert scanner2.scan_called
    assert results["test-scanner1"] == {"test": "results"}
    assert results["test-scanner2"] == {"test": "results"}


def test_execute_with_sequential_mode():
    """Test sequential execution mode."""
    engine = ScanExecutionEngine(strategy=ExecutionStrategy.SEQUENTIAL)

    scanner1 = MockScanner("test-scanner1")
    scanner2 = MockScanner("test-scanner2")

    engine.register_scanner("test-scanner1", lambda: scanner1)
    engine.register_scanner("test-scanner2", lambda: scanner2)

    results = engine.execute(
        {
            "scanners": {
                "test-scanner1": {"type": "static"},
                "test-scanner2": {"type": "static"},
            }
        }
    )

    assert len(results) == 2
    assert scanner1.scan_called
    assert scanner2.scan_called
    assert results["test-scanner1"] == {"test": "results"}
    assert results["test-scanner2"] == {"test": "results"}


def test_execute_with_scanner_error():
    """Test error handling during scanner execution."""

    class ErrorScanner(MockScanner):
        def __init__(self):
            """Initialize error scanner."""
            # Initialize with error scanner config
            super().__init__("error-scanner")
            self.results = None

        def scan(self, config=None):
            """Mock scan that raises an error."""
            raise RuntimeError("Scan error")

    engine = ScanExecutionEngine()
    scanner = ErrorScanner()
    engine.register_scanner("error-scanner", lambda: scanner)

    with pytest.raises(RuntimeError) as exc:
        engine.execute({"scanners": {"error-scanner": {"type": "static"}}})
    # Error message should contain scanner's registered name
    assert "error-scanner failed: Scan error" in str(exc.value)


def test_execute_with_empty_config():
    """Test execution with empty config."""
    engine = ScanExecutionEngine()
    assert engine.execute(None) == {}
    assert engine.execute({}) == {}
    assert engine.execute({"scanners": {}}) == {}


def test_execute_with_invalid_mode():
    """Test execution with invalid mode."""
    engine = ScanExecutionEngine()

    with pytest.raises(ValueError, match="Invalid execution mode"):
        engine.execute({"scanners": {"test-scanner": {}}}, mode="invalid")

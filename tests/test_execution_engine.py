# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for execution engine module."""

import pytest
from unittest.mock import Mock, patch

from automated_security_helper.config.default_config import DEFAULT_ASH_CONFIG
from automated_security_helper.execution_engine import (
    ScanExecutionEngine,
    ExecutionStrategy,
)
from automated_security_helper.models.config import ASHConfig, ScannerConfig
from automated_security_helper.models.scanner_types import (
    CustomScannerConfig,
    ScannerOptions,
)
from automated_security_helper.scanners.abstract_scanner import AbstractScanner


class MockScanner(AbstractScanner):
    """Mock scanner for testing."""

    scan_called = False

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
    scanner.configure(
        ScannerConfig(
            command="pwd",
            name="test-scanner",
            type="CUSTOM",
            invocation_mode="directory",
        )
    )
    engine.register_scanner("test-scanner", lambda: scanner)

    created_scanner = engine._scanners["test-scanner"]()
    assert created_scanner is scanner


def test_execute_with_registered_scanner():
    """Test execution with registered scanner."""
    engine = ScanExecutionEngine()
    scanner = MockScanner()
    scanner.configure(
        ScannerConfig(
            command="pwd",
            name="test-scanner",
            type="CUSTOM",
            invocation_mode="directory",
        )
    )
    engine.register_scanner("test-scanner", lambda: scanner)

    assert not scanner.scan_called

    results = engine.execute(
        ASHConfig(
            project_name="ash-tests",
            sast={
                "testscanner": CustomScannerConfig(
                    name="test-scanner",
                    options=ScannerOptions(
                        enabled=True,
                    ),
                )
            },
        )
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
    scanner1 = MockScanner()
    scanner1.configure(
        ScannerConfig(
            command="pwd",
            name="test-scanner1",
            type="CUSTOM",
            invocation_mode="directory",
        )
    )
    scanner2 = MockScanner()
    scanner2.configure(
        ScannerConfig(
            command="pwd",
            name="test-scanner2",
            type="CUSTOM",
            invocation_mode="file",
        )
    )

    engine.register_scanner("test-scanner1", lambda: scanner1)
    engine.register_scanner("test-scanner2", lambda: scanner2)

    results = engine.execute(DEFAULT_ASH_CONFIG)

    assert len(results) == 2
    assert scanner1.scan_called is True
    assert scanner2.scan_called is True
    assert results["test-scanner1"] == {"test": "results"}
    assert results["test-scanner2"] == {"test": "results"}


def test_execute_with_sequential_mode():
    """Test sequential execution mode."""
    engine = ScanExecutionEngine(strategy=ExecutionStrategy.SEQUENTIAL)

    scanner1 = MockScanner()
    scanner1.configure(
        ScannerConfig(
            command="pwd",
            name="test-scanner1",
            type="CUSTOM",
            invocation_mode="directory",
        )
    )
    scanner2 = MockScanner()
    scanner2.configure(
        ScannerConfig(
            command="pwd",
            name="test-scanner2",
            type="CUSTOM",
            invocation_mode="file",
        )
    )

    engine.register_scanner("test-scanner1", lambda: scanner1)
    engine.register_scanner("test-scanner2", lambda: scanner2)

    results = engine.execute()

    assert len(results) == 2
    assert scanner1.scan_called
    assert scanner2.scan_called
    assert results["test-scanner1"] == {"test": "results"}
    assert results["test-scanner2"] == {"test": "results"}


def test_execute_with_scanner_error():
    """Test error handling during scanner execution."""

    class ErrorScanner(MockScanner):
        def validate(self):
            return True

        def scan(self, config=None):
            """Mock scan that raises an error."""
            raise RuntimeError("Scan error")

    engine = ScanExecutionEngine()
    scanner = ErrorScanner()
    engine.register_scanner("error-scanner", lambda: scanner)

    with pytest.raises(ValueError) as exc:
        engine.execute({"scanners": {"error-scanner": {"type": "static"}}})
    assert "Configuration must be an ASHConfig instance" in str(exc.value)


def test_execute_with_empty_config():
    """Test execution with empty config."""
    engine = ScanExecutionEngine()
    assert engine.execute(None) == {"scanners": {}}
    with pytest.raises(ValueError, match="Configuration must be an ASHConfig instance"):
        assert engine.execute({}) == {}
    with pytest.raises(ValueError, match="Configuration must be an ASHConfig instance"):
        assert engine.execute({"scanners": {}}) == {}


def test_execute_with_invalid_mode():
    """Test execution with invalid mode."""
    engine = ScanExecutionEngine()

    with pytest.raises(ValueError, match="Configuration must be an ASHConfig instance"):
        engine.execute({"scanners": {"test-scanner": {}}}, mode="invalid")

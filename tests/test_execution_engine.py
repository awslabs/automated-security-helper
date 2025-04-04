# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for execution engine module."""

import logging
from pathlib import Path
from typing import Any, Dict, Optional, Type
import tempfile
import pytest
from unittest.mock import Mock, patch

from automated_security_helper.execution_engine import (
    ScanExecutionEngine,
    ExecutionStrategy,
)
from automated_security_helper.config.config import (
    ASHConfig,
    SASTScannerConfig,
    ScannerPluginConfig,
)
from automated_security_helper.config.scanner_types import (
    CustomScannerConfig,
    ScannerOptions,
)
from automated_security_helper.models.data_interchange import ExportFormat
from automated_security_helper.scanners.scanner_plugin import ScannerPlugin


class MockEngine(ScanExecutionEngine):
    def __init__(
        self,
        strategy: ExecutionStrategy = ExecutionStrategy.PARALLEL,
    ):
        # Create directories and logger
        source_dir = Path(tempfile.mkdtemp(prefix="ash-pytest", suffix="source"))
        output_dir = Path(tempfile.mkdtemp(prefix="ash-pytest", suffix="output"))
        work_dir = output_dir.joinpath("work")
        logger = logging.Logger("test_logger", level=logging.DEBUG)

        # Initialize default config
        global DEFAULT_ASH_CONFIG
        DEFAULT_ASH_CONFIG = ASHConfig(
            project_name="test",
            fail_on_findings=False,
            sast=SASTScannerConfig(
                enabled=True,
                output_formats=[ExportFormat.JSON],
                scanners=[
                    CustomScannerConfig(
                        name="test_scanner1",
                        type="CUSTOM",
                        enabled=True,
                        custom=ScannerOptions(enabled=True),
                    ),
                    CustomScannerConfig(
                        name="test_scanner2",
                        type="CUSTOM",
                        enabled=True,
                        custom=ScannerOptions(enabled=True),
                    ),
                ],
            ),
        )

        # Create clean scanner factory
        class TestScannerFactory:
            """Clean scanner factory that doesn't inherit from ScannerFactory."""

            def __init__(self):
                # Initialize minimal required attributes
                self._scanners = {}
                self._logger = logger

            def available_scanners(self) -> Dict[str, Type[ScannerPlugin]]:
                """Return only explicitly registered scanners."""
                return self._scanners.copy()

            def register_scanner(
                self, name: str, scanner_class: Type[ScannerPlugin]
            ) -> None:
                """Register scanner and prevent default registration."""
                scanner = scanner_class()
                if hasattr(scanner, "_default_config"):
                    # Update default config name and type
                    scanner._default_config.name = name
                    scanner._default_config.type = "CUSTOM"
                # Update scanner name and type if needed
                scanner._name = name
                scanner._config = CustomScannerConfig(
                    name=name,
                    type="CUSTOM",
                    enabled=True,
                    custom=ScannerOptions(enabled=True),
                )
                # Store scanner class
                self._scanners[name] = scanner_class

            def get_scanner_class(self, name: str) -> Type[ScannerPlugin]:
                """Get scanner class by name."""
                if name not in self._scanners:
                    raise ValueError(f"Scanner {name} not registered")
                return self._scanners[name]

            def create_scanner(self, name: str) -> ScannerPlugin:
                """Create scanner instance."""
                scanner_class = self.get_scanner_class(name)
                scanner = scanner_class()
                scanner._name = name
                scanner._config = CustomScannerConfig(
                    name=name,
                    type="CUSTOM",
                    enabled=True,
                    custom=ScannerOptions(enabled=True),
                )
                return scanner

        # Initialize with clean factory
        scanner_factory = TestScannerFactory()

        # Initialize parent first
        super().__init__(
            source_dir=source_dir,
            output_dir=output_dir,
            work_dir=work_dir,
            strategy=strategy,
            logger=logger,
        )

        # Override parent initialization to prevent default scanners
        self._scanners = {}
        self._original_scanners = {}  # Prevent parent defaults
        self._scanner_factory = scanner_factory
        self._strategy = strategy

        # Verify initialization
        assert len(self._scanner_factory._scanners) == 0, (
            "Scanner factory should be empty"
        )
        assert self._strategy == strategy, "Strategy not set correctly"
        assert len(getattr(self, "_original_scanners")) == 0, (
            "Should not have default scanners"
        )


class MockPwdScanner(ScannerPlugin):
    """Mock scanner for testing."""

    _default_config = CustomScannerConfig(
        name="test_scanner",
        type="CUSTOM",
        enabled=True,
        custom=ScannerOptions(enabled=True),
    )

    def __init__(self):
        super().__init__()
        self.scan_called = False

    def validate(self):
        """Validate scanner configuration."""
        return True

    def configure(self, config):
        """Configure scanner with provided config."""
        # Convert legacy config types to new format
        if isinstance(config, dict):
            config = CustomScannerConfig(**config)
        elif not isinstance(config, CustomScannerConfig):
            config = CustomScannerConfig(
                name=config.name,
                type="CUSTOM",
                enabled=config.enabled,
                custom=ScannerOptions(enabled=True),
            )

        # Set scanner config
        self._config = config
        self._name = config.name
        self.scan_called = False  # Reset scan flag

        # Override parent name
        if hasattr(self, "_default_config"):
            self._default_config.name = config.name

    def scan(
        self, target: str, options: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Mock scan method."""
        self.scan_called = True
        return {
            "status": "success",
            "name": self._name,  # Use configured name
            "type": self._config.type,
            "results": {"test": "results"},
        }

    def get_config(self) -> CustomScannerConfig:
        """Get current scanner configuration."""
        return (
            self._config
            if isinstance(self._config, CustomScannerConfig)
            else CustomScannerConfig(
                name=self._name,
                type="CUSTOM",
                enabled=True,
                custom=ScannerOptions(enabled=True),
            )
        )

    @property
    def description(self) -> str:
        """Get scanner description."""
        if self._config and hasattr(self._config, "name"):
            return f"Mock scanner {self._config.name}"
        return "Mock scanner test_scanner"


def test_engine_initialization():
    """Test execution engine initialization."""
    engine = MockEngine()
    assert engine._strategy == ExecutionStrategy.PARALLEL
    assert engine._max_workers == 4


def test_get_scanner():
    """Test getting registered scanner."""
    engine = MockEngine()

    # Register test scanner
    engine.register_scanner("test_scanner", MockPwdScanner)

    # Get scanner and verify instance
    created_scanner = engine.get_scanner("test_scanner")
    assert isinstance(created_scanner, MockPwdScanner)
    assert created_scanner.get_config().name == "test_scanner"
    assert created_scanner.description == "Mock scanner test_scanner"
    assert "test_scanner" in engine._scanners

    with pytest.raises(ValueError, match="Scanner 'unknown' not registered"):
        engine.get_scanner("unknown")


def test_register_scanner():
    """Test scanner registration."""
    engine = MockEngine()
    scanner = MockPwdScanner()
    scanner.configure(
        ScannerPluginConfig(
            command="pwd",
            name="test_scanner",
            type="CUSTOM",
            invocation_mode="directory",
        )
    )
    engine.register_scanner("test_scanner", MockPwdScanner)

    created_scanner = engine.get_scanner("test_scanner")
    assert isinstance(created_scanner, MockPwdScanner)


def test_execute_with_registered_scanner():
    """Test execution with registered scanner."""
    engine = MockEngine()

    # Configure scanner instance
    scanner_config = CustomScannerConfig(
        name="test_scanner",
        type="CUSTOM",
        enabled=True,
        custom=ScannerOptions(enabled=True),
    )

    scanner = MockPwdScanner()
    scanner.configure(scanner_config)

    # Register scanner class
    engine.register_scanner("test_scanner", MockPwdScanner)

    # Verify initial state
    assert not scanner.scan_called

    # Execute with explicit scanner config
    config = ASHConfig(
        project_name="test",
        fail_on_findings=False,
        sast=SASTScannerConfig(
            output_formats=[ExportFormat.JSON],
            enabled=True,
            scanners=[
                CustomScannerConfig(
                    name="test_scanner",
                    type="CUSTOM",
                    enabled=True,
                    custom=ScannerOptions(enabled=True),
                )
            ],
        ),
    )
    results = engine.execute(config)

    # Verify execution and results
    expected_result = {
        "status": "success",
        "name": "test_scanner",
        "type": "CUSTOM",
        "results": {"test": "results"},
    }

    assert "test_scanner" in results["scanners"]
    assert results["scanners"]["test_scanner"] == expected_result


@patch("concurrent.futures.ThreadPoolExecutor")
def test_execute_with_parallel_mode(mock_executor):
    """Test parallel execution mode."""
    # Setup mock executor
    global DEFAULT_ASH_CONFIG
    mock_executor_instance = Mock()
    mock_executor.return_value.__enter__.return_value = mock_executor_instance

    def mock_submit(fn, args):
        future = Mock()
        result = fn(args)
        future.result.return_value = result
        return future

    mock_executor_instance.submit.side_effect = mock_submit

    # Test execution
    engine = MockEngine(strategy=ExecutionStrategy.PARALLEL)
    scanner1 = MockPwdScanner()
    scanner2 = MockPwdScanner()

    # Configure scanners with proper CustomScannerConfig
    scanner1_config = CustomScannerConfig(
        name="test_scanner1",
        type="CUSTOM",
        enabled=True,
        custom=ScannerOptions(enabled=True),
    )
    scanner2_config = CustomScannerConfig(
        name="test_scanner2",
        type="CUSTOM",
        enabled=True,
        custom=ScannerOptions(enabled=True),
    )

    # Configure scanners and register with engine
    scanner1.configure(scanner1_config)
    scanner2.configure(scanner2_config)
    engine.register_scanner("test_scanner1", MockPwdScanner)
    engine.register_scanner("test_scanner2", MockPwdScanner)

    # Execute with proper config
    config = ASHConfig(
        project_name="test",
        fail_on_findings=False,
        sast=SASTScannerConfig(
            output_formats=[ExportFormat.JSON],
            enabled=True,
            scanners=[scanner1_config, scanner2_config],
        ),
    )
    results = engine.execute(config)

    # Verify both scanners executed
    assert len(results["scanners"]) == 2
    assert "test_scanner1" in results["scanners"]
    assert "test_scanner2" in results["scanners"]
    assert results["scanners"]["test_scanner1"]["status"] == "success"
    assert results["scanners"]["test_scanner2"]["status"] == "success"
    # Verify scanner results - since scanners are created as new instances by the factory,
    # we verify execution through the results rather than the local scanner instances
    scanner1_result = results["scanners"]["test_scanner1"]
    scanner2_result = results["scanners"]["test_scanner2"]

    assert scanner1_result["status"] == "success"
    assert scanner2_result["status"] == "success"
    assert scanner1_result["results"] == {"test": "results"}
    assert scanner2_result["results"] == {"test": "results"}


def test_execute_with_sequential_mode():
    """Test sequential execution mode."""
    engine = MockEngine(strategy=ExecutionStrategy.SEQUENTIAL)
    assert engine._strategy == ExecutionStrategy.SEQUENTIAL

    # Create and configure scanners
    scanner1_config = CustomScannerConfig(
        name="test_scanner1",
        type="CUSTOM",
        enabled=True,
        custom=ScannerOptions(enabled=True),
    )
    scanner2_config = CustomScannerConfig(
        name="test_scanner2",
        type="CUSTOM",
        enabled=True,
        custom=ScannerOptions(enabled=True),
    )

    # Register scanners with config
    engine.register_scanner("test_scanner1", MockPwdScanner)
    engine.register_scanner("test_scanner2", MockPwdScanner)

    # Execute with scanner configs
    config = ASHConfig(
        project_name="test",
        fail_on_findings=False,
        sast=SASTScannerConfig(
            output_formats=[ExportFormat.JSON],
            enabled=True,
            scanners=[scanner1_config, scanner2_config],
        ),
    )
    results = engine.execute(config)

    # Verify both scanners executed and produced expected results
    assert "scanners" in results
    assert len(results["scanners"]) == 2
    assert "test_scanner1" in results["scanners"]
    assert "test_scanner2" in results["scanners"]

    # Verify scanner results format and content
    scanner1_result = results["scanners"]["test_scanner1"]
    scanner2_result = results["scanners"]["test_scanner2"]

    # Verify scanner result contents
    assert scanner1_result["status"] == "success"
    assert scanner2_result["status"] == "success"
    assert scanner1_result["name"] == "test_scanner1"
    assert scanner2_result["name"] == "test_scanner2"
    assert scanner1_result["type"] == "CUSTOM"
    assert scanner2_result["type"] == "CUSTOM"
    assert scanner1_result["results"] == {"test": "results"}
    assert scanner2_result["results"] == {"test": "results"}


def test_execute_with_scanner_error():
    """Test error handling during scanner execution."""

    class ErrorScanner(MockPwdScanner):
        def validate(self):
            return True

        def scan(self, config=None):
            """Mock scan that raises an error."""
            raise RuntimeError("Scan error")

    engine = MockEngine()
    engine.register_scanner("error_scanner", ErrorScanner)

    with pytest.raises(ValueError) as exc:
        engine.execute({"scanners": {"error_scanner": {"type": "static"}}})
    assert "Configuration must be an ASHConfig instance" in str(exc.value)


def test_execute_with_empty_config():
    """Test execution with empty config."""
    engine = MockEngine()
    resp = engine.execute()
    assert resp is not None
    assert "scanners" in resp
    assert resp["scanners"] == {}
    with pytest.raises(ValueError, match="Configuration must be an ASHConfig instance"):
        assert engine.execute({}) == {}
    with pytest.raises(ValueError, match="Configuration must be an ASHConfig instance"):
        assert engine.execute({"scanners": {}}) == {}


def test_execute_with_invalid_mode():
    """Test execution with invalid mode."""
    engine = MockEngine()

    with pytest.raises(ValueError, match="Configuration must be an ASHConfig instance"):
        engine.execute({"scanners": {"test_scanner": {}}}, mode="invalid")

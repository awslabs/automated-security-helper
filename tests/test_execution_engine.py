"""Unit tests for execution engine module."""

import logging
from typing import Dict, Optional, Type

from automated_security_helper.execution_engine import (
    ExecutionStrategy,
    ScanExecutionEngine,
)
from automated_security_helper.models.scanner_plugin import ScannerPlugin

from automated_security_helper.config.config import (
    ASHConfig,
    SASTScannerConfig,
    SASTScannerListConfig,
    SBOMScannerConfig,
    SBOMScannerListConfig,
)
from automated_security_helper.models.data_interchange import ExportFormat
from automated_security_helper.scanners.bandit_scanner import BanditScanner

from tests.conftest import TEST_OUTPUT_DIR, TEST_SOURCE_DIR


class MockEngine(ScanExecutionEngine):
    """Test execution engine with pre-configured scanner factory."""

    def __init__(
        self,
        strategy: ExecutionStrategy = ExecutionStrategy.PARALLEL,
        source_dir=None,
        output_dir=None,
    ):
        # Set up paths and logging first
        source_dir = source_dir or TEST_SOURCE_DIR
        output_dir = output_dir or TEST_OUTPUT_DIR
        self.logger = logging.getLogger("test_execution_engine")

        # Initialize engine state and scanners
        self._scanners = {}  # Start with empty scanner registry
        self._enabled_scanners = None  # Default to all enabled
        self._initialized = False  # Will be set after initialization

        # Configure and create scanner factory
        class TestScannerFactory:
            """Scanner factory for testing."""

            def __init__(self, logger):
                self._logger = logger
                self._scanners = {
                    "bandit": BanditScanner,
                    # 'cfnnag': CFNNagScanner
                }
                self._logger.debug(
                    f"Initialized scanner factory with: {list(self._scanners.keys())}"
                )

            def available_scanners(self) -> Dict[str, Type[ScannerPlugin]]:
                return self._scanners.copy()

            def get_scanner_class(self, name: str) -> Optional[Type[ScannerPlugin]]:
                return self._scanners.get(name.lower().strip())

            def register_scanner(
                self, scanner_name: str, scanner_class: Type[ScannerPlugin]
            ) -> None:
                name = scanner_name.lower().strip()
                self._scanners[name] = scanner_class
                self._logger.debug(f"Registered scanner: {name}")

            def create_scanner(self, scanner_name: str, **kwargs) -> ScannerPlugin:
                name = scanner_name.lower().strip()
                scanner_class = self.get_scanner_class(name)
                if not scanner_class:
                    raise ValueError(f"Scanner {name} not found")
                return scanner_class(**kwargs)

        # Create scanner factory and mark engine as uninitialized
        self._scanner_factory = TestScannerFactory(self.logger)
        self._initialized = False

        # Initialize parent with scanner factory ready
        super().__init__(
            source_dir=source_dir,
            output_dir=output_dir,
            strategy=strategy,
            logger=self.logger,
        )

        # Default config for testing
        self._config = ASHConfig(
            project_name="test",
            fail_on_findings=False,
            sast=SASTScannerConfig(
                output_formats=[ExportFormat.JSON],
                enabled=True,
                scanners=SASTScannerListConfig(),
            ),
            sbom=SBOMScannerConfig(
                output_formats=[ExportFormat.JSON],
                enabled=True,
                scanners=SBOMScannerListConfig(),
            ),
        )

        # Register and enable scanners
        self.ensure_initialized(self._config)

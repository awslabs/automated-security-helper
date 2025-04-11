#!/usr/bin/env python3
"""Main entry point for ASH multi-scanner execution."""

import json
import logging
import shutil
from pathlib import Path
from typing import Annotated, Any, Dict, List, Optional

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from automated_security_helper.config.default_config import DEFAULT_ASH_CONFIG

from automated_security_helper.core.execution_engine import (
    ExecutionStrategy,
    ScanExecutionEngine,
)
from automated_security_helper.core.result_processor import ResultProcessor

from automated_security_helper.config.config import ASHConfig
from automated_security_helper.core.exceptions import ASHValidationError
from automated_security_helper.utils.get_scan_set import scan_set
from automated_security_helper.utils.log import get_logger


class ASHScanOrchestrator(BaseModel):
    """Orchestrator class for ASH security scanning operations."""

    model_config = ConfigDict(arbitrary_types_allowed=True, extra="allow")

    source_dir: Annotated[Path, Field(..., description="Source directory to scan")]
    output_dir: Annotated[Path, Field(..., description="Output directory for results")]
    work_dir: Annotated[
        Path, Field(description="Working directory for scan operations")
    ] = None
    config: Annotated[
        ASHConfig | None, Field(description="The resolved ASH configuration")
    ] = None

    strategy: Annotated[
        ExecutionStrategy,
        Field(description="Whether to execute scanners in parallel or sequentially"),
    ] = ExecutionStrategy.PARALLEL
    scan_output_formats: Annotated[
        List[str],
        Field(description="List of output formats to generate"),
    ] = Field(default_factory=lambda: ["json"])
    config_path: Annotated[
        Optional[Path], Field(None, description="Path to configuration file")
    ]
    verbose: Annotated[bool, Field(False, description="Enable verbose logging")]
    debug: Annotated[bool, Field(False, description="Enable debug logging")]
    offline: Annotated[bool, Field(False, description="Run in offline mode")]
    no_run: Annotated[bool, Field(False, description="Only build container image")]
    build_target: Annotated[
        str, Field("default", description="Build target for container image")
    ]
    enabled_scanners: Annotated[
        List[str],
        Field(
            description="List of enabled scanners. Defaults to all registered.",
        ),
    ] = []
    oci_runner: Annotated[str, Field("docker", description="OCI runner to use")]
    no_cleanup: Annotated[
        bool, Field(False, description="Keep work directory after scan")
    ]
    metadata: Annotated[
        Dict[str, Any],
        Field(default_factory=dict, description="Additional metadata for the scan"),
    ]

    # Core components
    result_processor: Annotated[
        ResultProcessor | None, Field(description="Result processor")
    ] = None
    execution_engine: Annotated[ScanExecutionEngine | None, Field()] = None
    logger: Annotated[logging.Logger | None, Field()] = logging.Logger(name=__name__)

    def ensure_directories(self):
        """Ensure required directories exist in a thread-safe manner.

        Creates work_dir if it doesn't exist or if no_cleanup
        is True, and output_dir if it doesn't exist.
        """
        try:
            # Create work directory if it doesn't exist or if no_cleanup is True
            self.logger.debug(
                f"Creating work directory if it does not exist: {self.work_dir}"
            )
            if not self.work_dir.exists() or self.no_cleanup:
                # Remove existing work dir if no_cleanup is True to ensure clean state
                if self.work_dir.exists() and self.no_cleanup:
                    try:
                        shutil.rmtree(self.work_dir)
                    except PermissionError as e:
                        self.logger.error(
                            f"Permission error removing work directory: {str(e)}"
                        )
                        raise ASHValidationError(
                            f"Failed to clean work directory: {str(e)}"
                        )
                    except Exception as e:
                        self.logger.error(f"Error removing work directory: {str(e)}")
                        raise ASHValidationError(
                            f"Failed to clean work directory: {str(e)}"
                        )

                try:
                    self.work_dir.mkdir(parents=True, exist_ok=True)
                except Exception as e:
                    self.logger.error(f"Failed to create work directory: {str(e)}")
                    raise ASHValidationError(
                        f"Failed to create work directory: {str(e)}"
                    )

            # Create output directory if it doesn't exist
            self.logger.debug(
                f"Creating output directory if it does not exist: {self.output_dir}"
            )
            try:
                self.output_dir.mkdir(parents=True, exist_ok=True)
            except Exception as e:
                self.logger.error(f"Failed to create output directory: {str(e)}")
                raise ASHValidationError(f"Failed to create output directory: {str(e)}")
        except Exception as e:
            self.logger.error(f"Error ensuring directories: {str(e)}")
            raise ASHValidationError(f"Failed to ensure directories: {str(e)}")

    def model_post_init(self, context):
        """Post initialization configuration."""
        super().model_post_init(context)
        self.logger = self._get_logger()
        self.validate_output_formats()

    def validate_output_formats(self):
        """Validate output formats."""
        valid_formats = [
            "json",
            "text",
            "html",
            "csv",
            "yaml",
            "junitxml",
            "sarif",
            "asff",
            "cyclonedx",
            "spdx",
        ]
        invalid_formats = [
            fmt for fmt in self.scan_output_formats if fmt not in valid_formats
        ]
        if invalid_formats:
            self.logger.error(f"Invalid output formats specified: {invalid_formats}")
            raise ASHValidationError(f"Invalid output formats: {invalid_formats}")

        self.logger.debug(f"Using output formats: {self.scan_output_formats}")
        if self.work_dir is None:
            self.work_dir = self.output_dir.joinpath("work")
        self.result_processor = ResultProcessor(
            logger=self.logger,
        )
        self.scan_set = scan_set(
            source=self.source_dir,
            output=self.work_dir,
            debug=self.verbose,
        )
        self.config = self._load_config()

        self.execution_engine = ScanExecutionEngine(
            source_dir=self.source_dir,
            output_dir=self.output_dir,
            strategy=self.strategy,
            logger=self.logger,
            enabled_scanners=self.enabled_scanners,
            config=self.config,
        )

    def _get_logger(self) -> logging.Logger:
        """Configure and return a logger instance."""
        log_level = (
            logging.DEBUG
            if self.debug
            else (logging.INFO if not self.verbose else logging.DEBUG)
        )
        return get_logger(level=log_level)

    def _load_config(self) -> ASHConfig:
        """Load configuration from file or return default configuration."""
        try:
            if not self.config_path:
                self.logger.debug(
                    "No configuration file provided, using default configuration"
                )
                config = DEFAULT_ASH_CONFIG
            else:
                self.logger.debug(f"Loading configuration from {self.config_path}")
                try:
                    with open(self.config_path, "r") as f:
                        if str(self.config_path).endswith(".json"):
                            config_data = json.load(f)
                        else:
                            config_data = yaml.safe_load(f)

                    if not isinstance(config_data, dict):
                        raise ValueError("Configuration must be a dictionary")

                    self.logger.debug("Transforming file config")
                    config = ASHConfig(**config_data)
                except (IOError, yaml.YAMLError, json.JSONDecodeError) as e:
                    self.logger.error(f"Failed to load configuration file: {str(e)}")
                    raise ASHValidationError(f"Failed to load configuration: {str(e)}")
                except ValidationError as e:
                    self.logger.error(f"Configuration validation failed: {str(e)}")
                    raise ASHValidationError(
                        f"Configuration validation failed: {str(e)}"
                    )

            # Use CLI-specified formats if provided
            if self.scan_output_formats:
                config.output.formats = self.scan_output_formats
                self.logger.debug(
                    f"Using CLI-specified output formats: {self.scan_output_formats}"
                )

            return config
        except Exception as e:
            self.logger.error(f"Error during configuration loading: {str(e)}")
            raise ASHValidationError(f"Failed to load configuration: {str(e)}")

    def execute_scan(self) -> Dict:
        """Execute the security scan and return results."""
        self.logger.info("Starting ASH scan")
        self.logger.debug(f"Source directory: {self.source_dir}")
        self.logger.debug(f"Output directory: {self.output_dir}")
        self.logger.debug(f"Work directory: {self.work_dir}")
        self.logger.debug(f"Configuration path: {self.config_path}")
        self.logger.debug(f"Output formats: {self.scan_output_formats}")

        try:
            # Ensure required directories exist
            self.logger.debug("Ensuring required directories exist")
            self.ensure_directories()

            # Load and validate configuration
            self.logger.debug("Loading and validating configuration")
            config = self._load_config()

            # Setup execution engine if not already configured
            if self.execution_engine is None:
                self.logger.debug("Creating execution engine")
                self.execution_engine = ScanExecutionEngine(
                    source_dir=self.source_dir,
                    output_dir=self.output_dir,
                    work_dir=self.work_dir,
                    strategy=self.strategy,
                    logger=self.logger,
                    enabled_scanners=self.enabled_scanners,
                    config=self.config,
                )

            # Execute scanners with validated config
            self.logger.info("Starting ASH execution engine")
            try:
                results = self.execution_engine.execute(config)
                self.logger.debug("Scan execution completed successfully")
            except Exception as e:
                self.logger.error(f"Scan execution failed: {str(e)}")
                raise ASHValidationError(f"Scan execution failed: {str(e)}")

            # Process and validate results
            if not results:
                self.logger.debug("No results returned, using empty result set")
                results = {"scanners": {}}

            self.logger.info("ASH scan completed successfully")
            return results

        except ASHValidationError:
            raise
        except Exception as e:
            self.logger.error(f"Unexpected error during scan execution: {str(e)}")
            raise ASHValidationError(f"Scan execution failed: {str(e)}")

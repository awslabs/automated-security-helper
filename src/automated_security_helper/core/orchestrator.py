#!/usr/bin/env python3
"""Main entry point for ASH multi-scanner execution."""

import json
import shutil
from pathlib import Path
from typing import Annotated, Any, Dict, List, Optional

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from automated_security_helper.config.default_config import get_default_config

from automated_security_helper.core.execution_engine import (
    ExecutionStrategy,
    ScanExecutionEngine,
)

from automated_security_helper.config.ash_config import ASHConfig
from automated_security_helper.core.exceptions import ASHValidationError
from automated_security_helper.models.asharp_model import ASHARPModel
from automated_security_helper.models.core import ExportFormat
from automated_security_helper.utils.get_scan_set import scan_set
from automated_security_helper.utils.log import ASH_LOGGER


class ASHScanOrchestrator(BaseModel):
    """Orchestrator class for ASH security scanning operations."""

    model_config = ConfigDict(arbitrary_types_allowed=True, extra="allow")

    source_dir: Annotated[Path, Field(description="Source directory to scan")] = (
        Path.cwd()
    )
    output_dir: Annotated[Path, Field(description="Output directory for results")] = (
        Path.cwd().joinpath("ash_output")
    )
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
        List[ExportFormat],
        Field(description="List of output formats to generate"),
    ] = ["sarif", "cyclonedx", "json", "html", "junitxml"]
    config_path: Annotated[
        Optional[Path], Field(None, description="Path to configuration file")
    ]
    verbose: Annotated[bool, Field(False, description="Enable verbose logging")]
    debug: Annotated[bool, Field(False, description="Enable debug logging")]
    show_progress: Annotated[
        bool,
        Field(True, description="Enable graphical progress visibility in the console."),
    ]
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
    execution_engine: Annotated[ScanExecutionEngine | None, Field()] = None

    output_formats: List[ExportFormat] = [
        ExportFormat.HTML,
        ExportFormat.JSON,
        ExportFormat.JUNITXML,
        ExportFormat.SARIF,
        ExportFormat.CYCLONEDX,
    ]

    def model_post_init(self, context):
        """Post initialization configuration."""
        super().model_post_init(context)
        ASH_LOGGER.info("Initializing ASH Scanner")

        self.config = self._load_config()

        ASH_LOGGER.verbose(f"Using output formats: {self.config.output_formats}")
        ASH_LOGGER.verbose("Setting up working directories")
        if self.source_dir is None:
            ASH_LOGGER.warning(
                "No explicit source directory provided, using current working directory"
            )
            self.source_dir = Path.cwd()
        elif not isinstance(self.source_dir, Path):
            self.source_dir = Path(self.source_dir)

        if self.output_dir is None:
            ASH_LOGGER.verbose(
                "No explicit output directory provided, using 'ash_output' within the source directory."
            )
            self.output_dir = self.source_dir.joinpath("ash_output")
        elif not isinstance(self.output_dir, Path):
            self.output_dir = Path(self.output_dir)

        self.ensure_directories()

        for old_file in [
            file for file in self.output_dir.glob("*.*") if "ash.log" not in file.name
        ]:
            ASH_LOGGER.debug(f"Removing old file: {old_file}")
            old_file.unlink()

        self.execution_engine = ScanExecutionEngine(
            source_dir=self.source_dir,
            output_dir=self.output_dir,
            strategy=self.strategy,
            enabled_scanners=self.enabled_scanners,
            config=self.config,
            show_progress=self.show_progress,
        )

        ASH_LOGGER.info("Identifying non-ignored files to include in scans")
        self.scan_set = scan_set(
            source=self.source_dir,
            output=self.output_dir,
            debug=self.debug,
        )
        ASH_LOGGER.info(
            f"Found {len(self.scan_set)} files within the provided source directory to scan. Please see the 'ash-scan-set-files-list.txt' in the output folder for the full list of files identified to scan."
        )

        ASH_LOGGER.info(
            "ASH Orchestrator and ScanExecutionEngine initialized, ready to start next phase."
        )
        return super().model_post_init(context)

    def ensure_directories(self):
        """Ensure required directories exist in a thread-safe manner.

        Creates work_dir if it doesn't exist or if no_cleanup
        is True, and output_dir if it doesn't exist.
        """
        try:
            # Create output directory if it doesn't exist
            ASH_LOGGER.debug(
                f"Creating output directory if it does not exist: {self.output_dir}"
            )
            try:
                self.output_dir.mkdir(parents=True, exist_ok=True)
            except Exception as e:
                ASH_LOGGER.error(f"Failed to create output directory: {str(e)}")
                raise ASHValidationError(f"Failed to create output directory: {str(e)}")

            for working_dir in ["reports", "scanners"]:
                path_working_dir = self.output_dir.joinpath(working_dir)
                if path_working_dir.exists():
                    ASH_LOGGER.verbose(
                        f"Cleaning up working directory from previous run: {path_working_dir.as_posix()}"
                    )
                    shutil.rmtree(path_working_dir)

            # Create work directory if it doesn't exist or if no_cleanup is True
            ASH_LOGGER.debug(
                f"Creating work directory if it does not exist: {self.work_dir}"
            )
            if self.work_dir.exists():
                # Remove existing work dir if no_cleanup is True to ensure clean state
                if self.work_dir.exists() and self.no_cleanup:
                    try:
                        shutil.rmtree(self.work_dir)
                    except PermissionError as e:
                        ASH_LOGGER.error(
                            f"Permission error removing work directory: {str(e)}"
                        )
                        raise ASHValidationError(
                            f"Failed to clean work directory: {str(e)}"
                        )
                    except Exception as e:
                        ASH_LOGGER.error(f"Error removing work directory: {str(e)}")
                        raise ASHValidationError(
                            f"Failed to clean work directory: {str(e)}"
                        )
            try:
                self.work_dir.mkdir(parents=True, exist_ok=True)
            except Exception as e:
                ASH_LOGGER.error(f"Failed to create work directory: {str(e)}")
                raise ASHValidationError(f"Failed to create work directory: {str(e)}")
        except Exception as e:
            ASH_LOGGER.error(f"Error ensuring directories: {str(e)}")
            raise ASHValidationError(f"Failed to ensure directories: {str(e)}")

    def _load_config(self) -> ASHConfig:
        """Load configuration from file or return default configuration."""
        try:
            if not self.config_path:
                ASH_LOGGER.debug(
                    "No configuration file provided, using default configuration"
                )
                config = get_default_config()
            else:
                ASH_LOGGER.debug(f"Loading configuration from {self.config_path}")
                try:
                    with open(self.config_path, "r") as f:
                        if str(self.config_path).endswith(".json"):
                            config_data = json.load(f)
                        else:
                            config_data = yaml.safe_load(f)

                    if not isinstance(config_data, dict):
                        raise ValueError("Configuration must be a dictionary")

                    ASH_LOGGER.debug("Transforming file config")
                    config = ASHConfig(**config_data)
                except (IOError, yaml.YAMLError, json.JSONDecodeError) as e:
                    ASH_LOGGER.error(f"Failed to load configuration file: {str(e)}")
                    raise ASHValidationError(f"Failed to load configuration: {str(e)}")
                except ValidationError as e:
                    ASH_LOGGER.error(f"Configuration validation failed: {str(e)}")
                    raise ASHValidationError(
                        f"Configuration validation failed: {str(e)}"
                    )

            # Use CLI-specified formats if provided
            if self.scan_output_formats:
                config.output_formats = self.scan_output_formats
                ASH_LOGGER.debug(
                    f"Using CLI-specified output formats: {self.scan_output_formats}"
                )

            return config
        except Exception as e:
            ASH_LOGGER.error(f"Error during configuration loading: {str(e)}")
            raise ASHValidationError(f"Failed to load configuration: {str(e)}")

    def execute_scan(self) -> Dict:
        """Execute the security scan and return results."""
        ASH_LOGGER.debug(f"Source directory: {self.source_dir}")
        ASH_LOGGER.debug(f"Output directory: {self.output_dir}")
        ASH_LOGGER.debug(f"Work directory: {self.work_dir}")
        ASH_LOGGER.debug(f"Configuration path: {self.config_path}")
        ASH_LOGGER.debug(f"Output formats: {self.scan_output_formats}")

        try:
            # Ensure required directories exist
            ASH_LOGGER.debug("Ensuring required directories exist")
            self.ensure_directories()

            # Load and validate configuration
            ASH_LOGGER.debug("Loading and validating configuration")
            config = self._load_config()

            # Setup execution engine if not already configured
            if self.execution_engine is None:
                ASH_LOGGER.debug("Creating execution engine")
                self.execution_engine = ScanExecutionEngine(
                    source_dir=self.source_dir,
                    output_dir=self.output_dir,
                    work_dir=self.work_dir,
                    strategy=self.strategy,
                    enabled_scanners=self.enabled_scanners,
                    config=self.config,
                )

            # Execute scanners with validated config
            try:
                prepare_output = self.execution_engine.run_prepare_phase(config)
                ASH_LOGGER.verbose(f"Converted scannable paths: {prepare_output}")
                asharp_model_results = self.execution_engine.run_scan_phase(config)
                ASH_LOGGER.debug("Scan execution completed successfully")
            except Exception as e:
                ASH_LOGGER.error(f"Scan execution failed: {str(e)}")
                raise ASHValidationError(f"Scan execution failed: {str(e)}")

            # Process and validate results
            if not asharp_model_results:
                ASH_LOGGER.debug("No results returned, using empty result set")
                asharp_model_results = ASHARPModel(
                    description="ASH execution engine returned no results!"
                )
                # else:
                #     for fmt in self.config.output_formats:
                #         outfile = asharp_model_results.report(
                #             output_format=fmt,
                #             output_dir=self.output_dir,
                #         )
                #         if outfile is None:
                #             ASH_LOGGER.warning(
                #                 f"Failed to generate output for format {fmt}"
                #             )
                #         elif isinstance(outfile, Path) and not outfile.exists():
                #             ASH_LOGGER.warning(
                #                 f"Output file {outfile} does not exist for format {fmt}"
                #             )
                #         elif isinstance(outfile, Path) and outfile.exists():
                #             ASH_LOGGER.verbose(
                #                 f"Generated output for format {fmt} at {outfile}"
                #             )
                #         else:
                #             ASH_LOGGER.verbose(
                #                 f"Unexpected response when formatting {fmt}: {outfile}"
                #             )

                ASH_LOGGER.info("ASH scan completed successfully!")
            if not self.config.no_cleanup:
                ASH_LOGGER.verbose("Cleaning up working directory...")
                shutil.rmtree(self.work_dir)
                # ASH_LOGGER.info("Cleaning up scanners directory...")
                # shutil.rmtree(self.output_dir.joinpath("scanners"))

            return asharp_model_results

        except ASHValidationError:
            raise
        except Exception as e:
            ASH_LOGGER.error(f"Unexpected error during scan execution: {str(e)}")
            raise ASHValidationError(f"Scan execution failed: {str(e)}")

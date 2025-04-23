#!/usr/bin/env python3
"""Main entry point for ASH multi-scanner execution."""

import json
import shutil
from pathlib import Path
from typing import Annotated, Any, Dict, List, Optional

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from automated_security_helper.config.default_config import get_default_config

from automated_security_helper.core.progress import (
    ExecutionPhaseType,
    ExecutionStrategy,
)
from automated_security_helper.core.constants import ASH_CONFIG_FILE_NAMES
from automated_security_helper.core.execution_engine import (
    ScanExecutionEngine as ScanExecutionEngine,
)

from automated_security_helper.config.ash_config import ASHConfig
from automated_security_helper.core.exceptions import (
    ASHValidationError,
    ASHConfigValidationError,
)
from automated_security_helper.models.core import ExportFormat, IgnorePathWithReason
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
    color_system: Annotated[
        Optional[str], Field(None, description="Color system to use for console output")
    ] = None
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

    global_ignore_paths: Annotated[
        List[IgnorePathWithReason],
        Field(
            description="Global list of IgnorePaths. Each path requires a reason for ignoring, e.g. 'Folder contains test data only and is not committed'."
        ),
    ] = []

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
            global_ignore_paths=self.global_ignore_paths,
            color_system=self.color_system,
            verbose=self.verbose,
            debug=self.debug,
        )

        ASH_LOGGER.info("ASH Orchestrator and ScanExecutionEngine initialized")
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
            self.output_dir.mkdir(parents=True, exist_ok=True)
            for working_dir in ["reports", "scanners", "converted"]:
                path_working_dir = self.output_dir.joinpath(working_dir)
                if path_working_dir.exists():
                    ASH_LOGGER.verbose(
                        f"Cleaning up working directory from previous run: {path_working_dir.as_posix()}"
                    )
                    shutil.rmtree(path_working_dir)
                path_working_dir.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            ASH_LOGGER.error(f"Error ensuring directories: {str(e)}")
            raise ASHValidationError(f"Failed to ensure directories: {str(e)}")

    def _load_config(self) -> ASHConfig:
        """Load configuration from file or return default configuration."""
        try:
            if not self.config_path:
                ASH_LOGGER.verbose(
                    "No configuration file provided, checking for default paths"
                )
                for item in ASH_CONFIG_FILE_NAMES:
                    config_path = self.source_dir.joinpath(item)
                    if config_path.exists():
                        self.config_path = config_path
                        ASH_LOGGER.verbose(
                            f"Found configuration file at: {config_path.as_posix()}"
                        )
                        break
                ASH_LOGGER.verbose(
                    "Configuration file not found or provided, using default config"
                )
                config = get_default_config()

            # We *always* want to evaluate this after the inverse block above runs, in
            # case self.config_path is resolved from a default location.
            # Do not use `else:` here!
            if self.config_path:
                ASH_LOGGER.debug(
                    f"Loading configuration from {self.config_path.as_posix()}"
                )
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
                    raise ASHConfigValidationError(
                        f"Failed to load configuration: {str(e)}"
                    )
                except ValidationError as e:
                    ASH_LOGGER.error(f"Configuration validation failed: {str(e)}")
                    raise ASHConfigValidationError(
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
            raise e

    def execute_scan(
        self, phases: List[ExecutionPhaseType] = ["convert", "scan", "report"]
    ) -> Dict:
        """Execute the security scan and return results.

        Args:
            phases (List[ExecutionPhaseType], optional): The phases to execute.
                Defaults to ["convert", "scan", "report"].

        Returns:
            Dict: The results of the scan.
        """
        ASH_LOGGER.verbose(f"Source directory: {self.source_dir}")
        ASH_LOGGER.verbose(f"Output directory: {self.output_dir}")
        ASH_LOGGER.verbose(f"Work directory: {self.work_dir}")
        ASH_LOGGER.verbose(f"Configuration path: {self.config_path}")
        ASH_LOGGER.verbose(f"Output formats: {self.scan_output_formats}")
        ASH_LOGGER.verbose(f"Executing phases: {phases}")

        try:
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
                    show_progress=self.show_progress,
                    global_ignore_paths=self.global_ignore_paths,
                    color_system=self.color_system,
                    verbose=self.verbose,
                    debug=self.debug,
                )

            # Identify files to scan
            if "convert" in phases or "scan" in phases:
                ASH_LOGGER.info("Identifying non-ignored files to include in scans")
                self.source_scan_set = scan_set(
                    source=self.source_dir,
                    output=self.output_dir,
                    debug=self.debug,
                )
                ASH_LOGGER.info(
                    f"Found {len(self.source_scan_set)} files within the provided source directory to scan. Please see the 'ash-scan-set-files-list.txt' in the output folder for the full list of files identified to scan within the source directory identified."
                )

            try:
                # Execute all phases
                asharp_model_results = self.execution_engine.execute_phases(
                    phases=phases, config=config
                )

                # Update work scan set after conversion if convert phase was run
                if "convert" in phases:
                    self.work_scan_set = scan_set(
                        source=self.work_dir,
                        output=self.work_dir,
                        debug=self.debug,
                    )

                ASH_LOGGER.debug("Scan execution completed successfully")
            except Exception as e:
                ASH_LOGGER.error(f"Execution failed: {str(e)}")
                raise

                # Process and validate results
                # if not asharp_model_results:
                #     ASH_LOGGER.debug("No results returned, using empty result set")
                #     asharp_model_results = ASHARPModel(
                #         description="ASH execution engine returned no results!"
                #     )
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
                #             ASH_LOGGER.debug(
                #                 f"Generated output for format {fmt} at {outfile}"
                #             )
                #         else:
                #             ASH_LOGGER.verbose(
                #                 f"Unexpected response when formatting {fmt}: {outfile}"
                #             )

                ASH_LOGGER.info("ASH scan completed successfully!")
            if not self.no_cleanup:
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

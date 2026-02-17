#!/usr/bin/env python3
"""Main entry point for ASH multi-scanner execution."""

import json
import shutil
from pathlib import Path
from typing import Annotated, Any, Dict, List, Optional

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config

from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.core.enums import ExecutionStrategy
from automated_security_helper.core.progress import (
    ExecutionPhaseType,
)
from automated_security_helper.core.constants import (
    ASH_CONFIG_FILE_NAMES,
    ASH_WORK_DIR_NAME,
)
from automated_security_helper.core.execution_engine import (
    ScanExecutionEngine as ScanExecutionEngine,
)

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.exceptions import (
    ASHValidationError,
    ASHConfigValidationError,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.core.enums import ExportFormat
from automated_security_helper.utils.get_ash_version import get_ash_version
from automated_security_helper.utils.get_scan_set import scan_set
from automated_security_helper.utils.log import ASH_LOGGER


class ASHScanOrchestrator(BaseModel):
    """Orchestrator class for ASH security scanning operations."""

    model_config = ConfigDict(arbitrary_types_allowed=True, extra="allow")

    source_dir: Annotated[Path, Field(description="Source directory to scan")] = (
        Path.cwd()
    )
    output_dir: Annotated[Path, Field(description="Output directory for results")] = (
        Path.cwd().joinpath(".ash", "ash_output")
    )
    work_dir: Annotated[
        Path | None, Field(description="Working directory for scan operations")
    ] = None
    config: Annotated[
        AshConfig | None, Field(description="The resolved ASH configuration")
    ] = None

    strategy: Annotated[
        ExecutionStrategy,
        Field(description="Whether to execute scanners in parallel or sequentially"),
    ] = ExecutionStrategy.PARALLEL
    config_path: Annotated[
        Optional[Path | str], Field(None, description="Path to configuration file")
    ]
    config_overrides: Annotated[
        Optional[List[str]],
        Field(None, description="Configuration overrides as key-value pairs"),
    ]
    color_system: Annotated[
        Optional[str], Field(None, description="Color system to use for console output")
    ] = None
    verbose: Annotated[bool, Field(False, description="Enable verbose logging")] = False
    debug: Annotated[bool, Field(False, description="Enable debug logging")] = False
    show_progress: Annotated[
        bool,
        Field(True, description="Enable graphical progress visibility in the console."),
    ] = True
    simple_mode: Annotated[
        bool,
        Field(
            False,
            description="Enable simplified output mode for pre-commit hooks and CI.",
        ),
    ] = False
    offline: Annotated[bool, Field(False, description="Run in offline mode")] = False
    no_run: Annotated[bool, Field(False, description="Only build container image")] = (
        False
    )
    build_target: Annotated[
        str | None, Field("default", description="Build target for container image")
    ] = None
    enabled_scanners: Annotated[
        List[str],
        Field(
            description="List of enabled scanners. Defaults to all registered.",
        ),
    ] = []
    excluded_scanners: Annotated[
        List[str],
        Field(
            description="List of scanners to exclude. Takes precedence over enabled_scanners.",
        ),
    ] = []
    oci_runner: Annotated[str, Field("docker", description="OCI runner to use")] = (
        "docker"
    )
    no_cleanup: Annotated[
        bool, Field(False, description="Keep work directory after scan")
    ]
    ignore_suppressions: Annotated[
        bool,
        Field(
            False, description="Ignore all suppression rules and report all findings"
        ),
    ] = False

    metadata: Annotated[
        Dict[str, Any] | None,
        Field(default_factory=dict, description="Additional metadata for the scan"),
    ]

    # Core components
    execution_engine: Annotated[ScanExecutionEngine | None, Field()] = None

    output_formats: List[ExportFormat] = []

    existing_results_path: Annotated[
        Optional[Path],
        Field(description="Path to existing ash_aggregated_results.json file"),
    ] = None

    python_based_plugins_only: Annotated[
        bool,
        Field(
            False,
            description="Exclude execution of any plugins or tools that have dependencies external to Python",
        ),
    ] = False

    ash_plugin_modules: Annotated[
        List[str],
        Field(
            description="List of Python modules to import containing ASH plugins and/or event subscribers",
            default_factory=list,
        ),
    ]

    def model_post_init(self, context):
        """Post initialization configuration."""
        super().model_post_init(context)
        ASH_LOGGER.info(f"Initializing ASH v{get_ash_version()}")

        self.config = resolve_config(
            config_path=self.config_path,
            config_overrides=self.config_overrides
            if hasattr(self, "config_overrides")
            else [],
        )

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
                "No explicit output directory provided, using '.ash/ash_output' within the source directory."
            )
            self.output_dir = self.source_dir.joinpath(".ash", "ash_output")
        elif not isinstance(self.output_dir, Path):
            self.output_dir = Path(self.output_dir)

        self.ensure_directories()

        # Don't delete existing files if we're using existing results
        if self.existing_results_path is None:
            for old_file in [
                file
                for file in self.output_dir.glob("*.*")
                if file.name
                in [
                    "ash_aggregated_results.json",
                    "ash-ignore-report.txt",
                    "ash-scan-set-files-list.txt",
                    "ash.log",
                    "ash.log.jsonl",
                ]
            ]:
                ASH_LOGGER.debug(f"Removing old file: {old_file}")
                try:
                    old_file.unlink()
                except PermissionError as e:
                    ASH_LOGGER.debug(
                        f"Permission denied when trying to remove {old_file}: {str(e)}"
                    )
                    continue
            exec_engine_params = {}
        else:
            asharp_model = AshAggregatedResults.model_validate_json(
                Path(self.existing_results_path).read_text()
            )
            exec_engine_params = {"asharp_model": asharp_model}

        self.execution_engine = ScanExecutionEngine(
            context=PluginContext(
                source_dir=self.source_dir,
                output_dir=self.output_dir,
                work_dir=self.output_dir.joinpath(ASH_WORK_DIR_NAME),
                config=self.config,
                ignore_suppressions=self.ignore_suppressions,
            ),
            strategy=self.strategy,
            enabled_scanners=self.enabled_scanners,
            excluded_scanners=self.excluded_scanners,
            show_progress=self.show_progress,
            global_ignore_paths=self.config.global_settings.ignore_paths,
            color_system=self.color_system,
            verbose=self.verbose,
            debug=self.debug,
            python_based_plugins_only=self.python_based_plugins_only,
            ash_plugin_modules=self.ash_plugin_modules,  # Pass the ash_plugin_modules to the execution engine
            **exec_engine_params,
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

            # If we're using existing results, only ensure the reports directory exists
            if self.existing_results_path and self.existing_results_path.exists():
                path_reports_dir = self.output_dir.joinpath("reports")
                path_reports_dir.mkdir(parents=True, exist_ok=True)
            else:
                # Otherwise, set up all working directories
                for working_dir in ["analysis", "reports", "scanners", "converted"]:
                    path_working_dir = self.output_dir.joinpath(working_dir)
                    if path_working_dir.exists() and self.existing_results_path is None:
                        ASH_LOGGER.verbose(
                            f"Cleaning up working directory from previous run: {path_working_dir.as_posix()}"
                        )
                        shutil.rmtree(path_working_dir)
                    path_working_dir.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            ASH_LOGGER.error(f"Error ensuring directories: {str(e)}")
            raise ASHValidationError(f"Failed to ensure directories: {str(e)}")

    def _load_config(self) -> AshConfig:
        """Load configuration from file or return default configuration."""
        try:
            config = get_default_config()
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
                    config = AshConfig(**config_data)
                    ASH_LOGGER.debug(f"Loaded config from file: {config}")
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
            if self.output_formats:
                config.output_formats = self.output_formats
                ASH_LOGGER.debug(
                    f"Using CLI-specified output formats: {self.output_formats}"
                )

            return config
        except Exception as e:
            raise e

    def execute_scan(
        self, phases: List[ExecutionPhaseType] = ["convert", "scan", "report"]
    ) -> AshAggregatedResults:
        """Execute the security scan and return results.

        Args:
            phases (List[ExecutionPhaseType], optional): The phases to execute.
                Defaults to ["convert", "scan", "report"].

        Returns:
            AshAggregatedResults: The results of the scan.
        """
        ASH_LOGGER.verbose(f"Source directory: {self.source_dir}")
        ASH_LOGGER.verbose(f"Output directory: {self.output_dir}")
        ASH_LOGGER.verbose(f"Work directory: {self.work_dir}")
        ASH_LOGGER.verbose(f"Configuration path: {self.config_path}")
        ASH_LOGGER.verbose(f"Executing phases: {phases}")

        try:
            # Setup execution engine if not already configured
            if self.execution_engine is None:
                ASH_LOGGER.debug("Creating execution engine")
                self.execution_engine = ScanExecutionEngine(
                    context=PluginContext(
                        source_dir=self.source_dir,
                        output_dir=self.output_dir,
                        work_dir=self.output_dir.joinpath(ASH_WORK_DIR_NAME),
                        config=self.config,
                        ignore_suppressions=self.ignore_suppressions,
                    ),
                    strategy=self.strategy,
                    enabled_scanners=self.enabled_scanners,
                    show_progress=self.show_progress,
                    global_ignore_paths=self.config.global_settings.ignore_paths,
                    color_system=self.color_system,
                    verbose=self.verbose,
                    debug=self.debug,
                )

            # If existing results path is provided, load the model from it
            if self.existing_results_path and self.existing_results_path.exists():
                ASH_LOGGER.info(
                    f"Loading existing results from {self.existing_results_path}"
                )
                try:
                    from automated_security_helper.models.asharp_model import (
                        AshAggregatedResults,
                    )

                    with open(self.existing_results_path, "r") as f:
                        model_data = json.load(f)

                    # Load the model from the existing results
                    asharp_model = AshAggregatedResults.from_json(model_data)

                    # Update the execution engine's model
                    if hasattr(self.execution_engine, "_asharp_model"):
                        self.execution_engine._asharp_model = asharp_model

                    # When using existing results, only run the report phase
                    ASH_LOGGER.info(
                        "Using existing results - only running report phase"
                    )
                    phases = [
                        phase
                        for phase in [
                            "report",
                            "inspect" if "inspect" in phases else None,
                        ]
                        if phase is not None
                    ]

                    # Ensure the reports directory exists but don't clean up any other directories
                    reports_dir = self.output_dir.joinpath("reports")
                    reports_dir.mkdir(parents=True, exist_ok=True)

                except Exception as e:
                    ASH_LOGGER.error(f"Failed to load existing results: {str(e)}")
                    raise ASHValidationError(
                        f"Failed to load existing results: {str(e)}"
                    )
            # Only identify files to scan if we're not using existing results
            elif "convert" in phases or "scan" in phases:
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
                    phases=phases,
                )

                ASH_LOGGER.debug("Scan execution completed successfully")
            except Exception as e:
                ASH_LOGGER.error(f"Execution failed: {str(e)}")
                raise

                # Process and validate results
                # if not asharp_model_results:
                #     ASH_LOGGER.debug("No results returned, using empty result set")
                #     asharp_model_results = AshAggregatedResults(
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

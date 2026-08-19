#!/usr/bin/env python3
"""Main entry point for ASH multi-scanner execution."""

import json
import shutil
from pathlib import Path
from typing import Annotated, Any, Dict, List, Optional

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

    show_summary: Annotated[
        bool,
        Field(
            True,
            description="Show metrics table and results summary after scan completion",
        ),
    ] = True

    # Sentinel: True after initialize() has run successfully
    _initialized: bool = False

    def model_post_init(self, context):
        """Post initialization — data-only; no filesystem I/O."""
        super().model_post_init(context)
        # Coerce source_dir / output_dir to Path so callers never get str
        if self.source_dir is None:
            self.source_dir = Path.cwd()
        elif not isinstance(self.source_dir, Path):
            self.source_dir = Path(self.source_dir)

        if self.output_dir is None:
            self.output_dir = self.source_dir.joinpath(".ash", "ash_output")
        elif not isinstance(self.output_dir, Path):
            self.output_dir = Path(self.output_dir)

    def initialize(self) -> None:
        """Perform all filesystem I/O and engine setup.

        Idempotent: subsequent calls are no-ops once _initialized is True.
        Call this explicitly, or use the .create() factory which calls it for you.
        """
        if self._initialized:
            return

        ASH_LOGGER.info(f"Initializing ASH v{get_ash_version()}")

        self.config = resolve_config(
            config_path=self.config_path,
            source_dir=self.source_dir,
            config_overrides=self.config_overrides or [],
        )

        # Surface config resolution warnings prominently
        if self.config._resolution_warnings:
            for warning in self.config._resolution_warnings:
                ASH_LOGGER.warning(f"⚠️  CONFIG WARNING: {warning}")

        ASH_LOGGER.verbose("Setting up working directories")

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
                    # Don't delete log files here - they're managed by the logger
                    # which truncates them on initialization
                    # "ash.log",
                    # "ash.log.jsonl",
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
            exec_engine_params: Dict[str, Any] = {}
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
            show_summary=self.show_summary,
            global_ignore_paths=self.config.global_settings.ignore_paths,
            color_system=self.color_system,  # type: ignore[arg-type]
            verbose=self.verbose,
            debug=self.debug,
            python_based_plugins_only=self.python_based_plugins_only,
            ash_plugin_modules=self.ash_plugin_modules,
            output_formats=[f.value for f in self.output_formats] or None,
            asharp_model=exec_engine_params.get("asharp_model"),
        )

        self._initialized = True
        ASH_LOGGER.info("ASH Orchestrator and ScanExecutionEngine initialized")

    @classmethod
    def create(cls, **kwargs: Any) -> "ASHScanOrchestrator":
        """Construct and fully initialize an orchestrator.

        Equivalent to ASHScanOrchestrator(**kwargs) followed by .initialize().
        Use this in production code; use the bare constructor in tests that
        need an uninitialized instance.
        """
        instance = cls(**kwargs)
        instance.initialize()
        return instance

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

    def execute_scan(
        self, phases: List[ExecutionPhaseType] | None = None
    ) -> AshAggregatedResults:
        """Execute the security scan and return results.

        Args:
            phases (List[ExecutionPhaseType], optional): The phases to execute.
                Defaults to ["convert", "scan", "report"].

        Returns:
            AshAggregatedResults: The results of the scan.
        """
        if phases is None:
            phases = ["convert", "scan", "report"]
        ASH_LOGGER.verbose(f"Source directory: {self.source_dir}")
        ASH_LOGGER.verbose(f"Output directory: {self.output_dir}")
        ASH_LOGGER.verbose(f"Work directory: {self.work_dir}")
        ASH_LOGGER.verbose(f"Configuration path: {self.config_path}")
        ASH_LOGGER.verbose(f"Executing phases: {phases}")

        try:
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
                    if self.execution_engine is not None and hasattr(self.execution_engine, "_asharp_model"):
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
                    source=str(self.source_dir),
                    output=str(self.output_dir),
                    debug=self.debug,
                )
                ASH_LOGGER.info(
                    f"Found {len(self.source_scan_set)} files within the provided source directory to scan. Please see the 'ash-scan-set-files-list.txt' in the output folder for the full list of files identified to scan within the source directory identified."
                )

            try:
                # Execute all phases
                assert self.execution_engine is not None
                asharp_model_results = self.execution_engine.execute_phases(
                    phases=phases,
                )

                ASH_LOGGER.debug("Scan execution completed successfully")
            except Exception as e:
                ASH_LOGGER.error(f"Execution failed: {str(e)}")
                raise

            # Add config resolution warnings to validation checkpoints
            if self.config is not None and self.config._resolution_warnings:
                for warning in self.config._resolution_warnings:
                    asharp_model_results.validation_checkpoints.append(
                        {
                            "type": "config_warning",
                            "severity": "warning",
                            "message": warning,
                            "metadata": {
                                "source": "config_resolution",
                                "impact": "Suppressions and custom settings may not be active",
                            },
                        }
                    )

            if not self.no_cleanup:
                if self.work_dir and Path(self.work_dir).exists():
                    ASH_LOGGER.verbose("Cleaning up working directory...")
                    shutil.rmtree(self.work_dir)
            return asharp_model_results

        except ASHValidationError:
            raise
        except Exception as e:
            ASH_LOGGER.error(f"Unexpected error during scan execution: {str(e)}")
            raise ASHValidationError(f"Scan execution failed: {str(e)}")

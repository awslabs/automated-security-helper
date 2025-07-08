"""Implementation of the Scan phase."""

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Any, Tuple
from pathlib import Path

from automated_security_helper.base.engine_phase import EnginePhase
from automated_security_helper.core.enums import ExecutionPhase, ScannerStatus
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerStatusInfo,
)
from automated_security_helper.models.scan_results_container import ScanResultsContainer
from automated_security_helper.base.scanner_plugin import ScannerPluginBase
from automated_security_helper.models.core import IgnorePathWithReason
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.sarif_utils import (
    sanitize_sarif_paths,
    apply_suppressions_to_sarif,
)
from automated_security_helper.models.scanner_validation import ScannerValidationManager


"""Implementation of the Scan phase."""


class ScanPhase(EnginePhase):
    """Implementation of the Scan phase."""

    def __init__(
        self, plugin_context, plugins=None, progress_display=None, asharp_model=None
    ):
        """Initialize the ScanPhase with validation manager.

        Args:
            plugin_context: Plugin context with paths and configuration
            plugins: List of plugins to use
            progress_display: Progress display to use for reporting progress
            asharp_model: AshAggregatedResults to update with results
        """
        super().__init__(plugin_context, plugins or [], progress_display, asharp_model)
        self.validation_manager = ScannerValidationManager(plugin_context)

    @property
    def phase_name(self) -> str:
        """Return the name of this phase."""
        return "scan"

    def _execute_phase(
        self,
        aggregated_results: AshAggregatedResults,
        enabled_scanners: List[str] = [],
        excluded_scanners: List[str] = [],
        parallel: bool = True,
        max_workers: int = 4,
        global_ignore_paths: List[IgnorePathWithReason] = [],
        python_based_plugins_only: bool = False,
        **kwargs,
    ) -> AshAggregatedResults:
        """Execute the Scan phase.

        Args:
            enabled_scanners: List of scanner names to enable
            parallel: Whether to run scanners in parallel
            max_workers: Maximum number of worker threads for parallel execution
            global_ignore_paths: List of paths to ignore globally
            **kwargs: Additional arguments

        Returns:
            AshAggregatedResults: Results of the scan
        """
        ASH_LOGGER.debug("Entering: ScanPhase.execute()")

        # Initialize progress
        self.initialize_progress("Initializing scan phase...")

        # Reset state for new execution
        self._completed_scanners = []
        self._scan_results = {}
        self._global_ignore_paths = global_ignore_paths or []
        self._max_workers = max_workers
        work_dir_contents = [
            *self.plugin_context.work_dir.glob("*.*"),
            *self.plugin_context.work_dir.glob("**/*.*"),
        ]
        self._include_work_dir = len(work_dir_contents) > 0

        # Debug logging for scanner filtering parameters
        ASH_LOGGER.debug(f"Enabled scanners parameter: {enabled_scanners}")
        ASH_LOGGER.debug(f"Excluded scanners parameter: {excluded_scanners}")
        ASH_LOGGER.debug(f"Python-based plugins only: {python_based_plugins_only}")

        try:
            # Update progress to show we're starting
            self.update_progress(10, "Building scanner tasks...")

            # Print progress update
            ASH_LOGGER.info("Building scanner tasks...")

            # Build list of scanner tasks for execution (no queue needed)
            self._scanner_tasks: List[
                Tuple[str, ScannerPluginBase, List[Dict[str, Any]]]
            ] = []

            # Get all scanner plugins
            scanner_classes = self.plugins

            # Create scanner instances for validation and processing
            scanner_instances = []
            if scanner_classes:
                ASH_LOGGER.debug(
                    f"Creating instances for {len(scanner_classes)} scanner classes"
                )
                for plugin_class in scanner_classes:
                    try:
                        plugin_name = getattr(
                            plugin_class, "__name__", "Unknown"
                        ).lower()
                        ASH_LOGGER.debug(
                            f"Creating scanner instance for class: {plugin_name}"
                        )

                        # Create scanner instance
                        plugin_instance = plugin_class(
                            config=(
                                self.plugin_context.config.get_plugin_config(
                                    plugin_type="scanner",
                                    plugin_name=plugin_name,
                                )
                                if self.plugin_context.config is not None
                                else None
                            ),
                            context=self.plugin_context,
                        )
                        scanner_instances.append(plugin_instance)
                        ASH_LOGGER.debug(f"Created scanner instance for: {plugin_name}")
                    except Exception as e:
                        ASH_LOGGER.error(
                            f"Error creating scanner instance for {plugin_name}: {e}"
                        )

            # Validate registered scanners after creating instances
            if scanner_instances:
                self.validation_manager.validate_registered_scanners(scanner_instances)

                # CRITICAL: Initialize validation manager state for all registered scanners
                for plugin_instance in scanner_instances:
                    display_name = (
                        plugin_instance.config.name
                        if hasattr(plugin_instance, "config")
                        and hasattr(plugin_instance.config, "name")
                        else plugin_instance.__class__.__name__.lower()
                    )
                    self.validation_manager.update_scanner_state(
                        display_name,
                        registration_status="registered",
                        plugin_class=plugin_instance.__class__,
                    )
            else:
                ASH_LOGGER.warning(
                    "No scanner instances created during plugin discovery!"
                )

            # Filter enabled scanners
            enabled_scanner_classes = []
            enabled_scanner_names = []

            # Initialize lists to track scanner states for validation
            excluded_scanner_names = []
            dependency_error_scanners = {}

            # Process scanners
            if scanner_instances:
                ASH_LOGGER.debug(
                    f"Processing {len(scanner_instances)} scanner instances"
                )
                for plugin_instance in scanner_instances:
                    try:
                        plugin_name = getattr(
                            plugin_instance.__class__, "__name__", "Unknown"
                        ).lower()
                        ASH_LOGGER.debug(f"Processing scanner instance: {plugin_name}")

                        # Use the configured name if available
                        display_name = plugin_name
                        if hasattr(plugin_instance, "config") and hasattr(
                            plugin_instance.config, "name"
                        ):
                            display_name = plugin_instance.config.name
                        ASH_LOGGER.debug(f"Scanner display name: {display_name}")

                        # Check if scanner is in the excluded list
                        is_excluded = display_name.lower().strip() in [
                            s.lower().strip() for s in excluded_scanners
                        ]
                        if is_excluded:
                            ASH_LOGGER.info(
                                f"Scanner {display_name} is excluded from running"
                            )
                            # Track excluded scanner for validation
                            excluded_scanner_names.append(display_name)

                            # Create a ScanResultsContainer with excluded=True
                            results_container = ScanResultsContainer(
                                scanner_name=display_name,
                                excluded=True,
                                status=ScannerStatus.SKIPPED,
                                duration=None,  # Set duration to None for skipped scanners to show "N/A"
                            )

                            # Process the container through _process_results to store duration info
                            aggregated_results = self._process_results(
                                results=results_container,
                                aggregated_results=aggregated_results,
                            )

                            # Add to completed scanners for metrics display
                            self._completed_scanners.append(plugin_instance)

                            aggregated_results.scanner_results[display_name] = (
                                ScannerStatusInfo(
                                    status=ScannerStatus.SKIPPED,
                                    excluded=True,
                                    dependencies_satisfied=True,
                                )
                            )

                            continue

                        # Check dependencies early
                        ASH_LOGGER.debug(f"Validating dependencies for: {display_name}")
                        plugin_instance.dependencies_satisfied = (
                            plugin_instance.validate()
                        )
                        if not plugin_instance.dependencies_satisfied:
                            ASH_LOGGER.warning(
                                f"Scanner {display_name} dependencies are not satisfied, marking as MISSING"
                            )
                            # Track dependency error for validation
                            dependency_error_scanners[display_name] = [
                                "Dependencies not satisfied"
                            ]

                            # Create a ScanResultsContainer with dependencies_satisfied=False
                            results_container = ScanResultsContainer(
                                scanner_name=display_name,
                                dependencies_satisfied=False,
                                status=ScannerStatus.MISSING,
                                duration=None,  # Set duration to None for missing dependency scanners to show "N/A"
                            )

                            # Process the container through _process_results to store duration info
                            aggregated_results = self._process_results(
                                results=results_container,
                                aggregated_results=aggregated_results,
                            )

                            # Add to completed scanners for metrics display
                            self._completed_scanners.append(plugin_instance)

                            aggregated_results.scanner_results[display_name] = (
                                ScannerStatusInfo(
                                    status=ScannerStatus.MISSING,
                                    dependencies_satisfied=False,
                                    excluded=False,
                                )
                            )

                            continue

                        # Check if scanner is enabled and if python_based_plugins_only is set, check if it's a Python-only scanner
                        is_enabled = hasattr(
                            plugin_instance.config, "enabled"
                        ) and bool(plugin_instance.config.enabled)
                        is_in_enabled_scanners = (
                            not enabled_scanners
                            or display_name.lower().strip()
                            in [s.lower().strip() for s in enabled_scanners]
                        )

                        ASH_LOGGER.debug(
                            f"Scanner {display_name}: enabled={is_enabled}, in_enabled_list={is_in_enabled_scanners}"
                        )

                        # Add debug logging for python_based_plugins_only check
                        is_python_only_scanner = True  # Default to True to allow all scanners if not checking
                        if python_based_plugins_only:
                            is_python_only_scanner = plugin_instance.is_python_only()
                            ASH_LOGGER.info(
                                f"Scanner {display_name}: Python-only check result: {is_python_only_scanner}"
                            )

                        final_check = (
                            is_enabled
                            and is_in_enabled_scanners
                            and (
                                not python_based_plugins_only or is_python_only_scanner
                            )
                        )
                        ASH_LOGGER.debug(
                            f"Scanner {display_name}: final check result: {final_check}"
                        )

                        # Add detailed logging for debugging scanner filtering issues
                        ASH_LOGGER.debug(
                            f"Scanner {display_name} filtering details: "
                            f"is_enabled={is_enabled}, "
                            f"is_in_enabled_scanners={is_in_enabled_scanners}, "
                            f"python_based_plugins_only={python_based_plugins_only}, "
                            f"is_python_only_scanner={is_python_only_scanner}"
                        )

                        if final_check:
                            # Add a single task per scanner that will handle both source and converted directories
                            task_list = [
                                {
                                    "path": self.plugin_context.source_dir,
                                    "type": "source",
                                },
                            ]
                            if self._include_work_dir:
                                task_list.append(
                                    {
                                        "path": self.plugin_context.work_dir,
                                        "type": "converted",
                                    }
                                )
                            self._scanner_tasks.append(
                                (
                                    display_name,
                                    plugin_instance,
                                    task_list,
                                )
                            )
                            enabled_scanner_classes.append(plugin_instance.__class__)
                            enabled_scanner_names.append(display_name)
                            ASH_LOGGER.debug(
                                f"Added scanner {display_name} to execution tasks"
                            )

                            # CRITICAL: Update validation manager state for queued scanners
                            self.validation_manager.update_scanner_state(
                                display_name,
                                registration_status="registered",
                                enablement_status="enabled",
                                enablement_reason="Scanner passed all checks and was queued for execution",
                                queued_for_execution=True,
                                execution_completed=False,
                            )
                        else:
                            # Determine why scanner failed final check and track appropriately
                            exclusion_reason = []
                            if not is_enabled:
                                exclusion_reason.append("scanner config disabled")
                            if not is_in_enabled_scanners:
                                exclusion_reason.append("not in enabled scanners list")
                            if python_based_plugins_only and not is_python_only_scanner:
                                exclusion_reason.append("not Python-only compatible")

                            reason_str = (
                                ", ".join(exclusion_reason)
                                if exclusion_reason
                                else "unknown reason"
                            )
                            ASH_LOGGER.info(
                                f"Scanner {display_name} excluded from execution: {reason_str}"
                            )

                            # Track as excluded scanner for validation
                            excluded_scanner_names.append(display_name)

                            # CRITICAL: Update validation manager state immediately
                            self.validation_manager.update_scanner_state(
                                display_name,
                                registration_status="registered",
                                enablement_status="excluded",
                                enablement_reason=f"Scanner excluded during filtering: {reason_str}",
                                queued_for_execution=False,
                                execution_completed=False,
                            )

                            # Create a ScanResultsContainer with excluded=True
                            results_container = ScanResultsContainer(
                                scanner_name=display_name,
                                excluded=True,
                                status=ScannerStatus.SKIPPED,
                                duration=None,
                            )

                            # Process the container through _process_results to store duration info
                            aggregated_results = self._process_results(
                                results=results_container,
                                aggregated_results=aggregated_results,
                            )

                            # Add to completed scanners for metrics display
                            self._completed_scanners.append(plugin_instance)

                            aggregated_results.scanner_results[display_name] = (
                                ScannerStatusInfo(
                                    status=ScannerStatus.SKIPPED,
                                    excluded=True,
                                    dependencies_satisfied=True,
                                )
                            )
                    except Exception as e:
                        ASH_LOGGER.error(
                            f"Error checking scanner {getattr(plugin_instance.__class__, '__name__', 'Unknown')}: {e}"
                        )
                        # Add stack trace for debugging
                        import traceback

                        ASH_LOGGER.debug(f"Stack trace: {traceback.format_exc()}")
            else:
                ASH_LOGGER.warning("No scanner classes found!")

            # Validate scanner enablement after filtering
            self.validation_manager.validate_scanner_enablement(
                enabled_scanners=enabled_scanner_names,
                excluded_scanners=excluded_scanner_names,
                dependency_errors=dependency_error_scanners,
            )

            # Validate scanner tasks after population
            self._validate_scanner_tasks(aggregated_results)

            # Add comprehensive debugging for scanner filtering
            ASH_LOGGER.info("🔍 Scanner Filtering Summary:")
            ASH_LOGGER.info(
                f"   Total scanner classes found: {len(scanner_classes) if scanner_classes else 0}"
            )
            ASH_LOGGER.info(
                f"   Enabled scanners after filtering: {len(enabled_scanner_names)}"
            )
            ASH_LOGGER.info(f"   Enabled scanner names: {enabled_scanner_names}")

            # Count scanners in different states from additional_reports
            excluded_scanners_count = 0
            missing_deps_count = 0
            for (
                scanner_name,
                report_data,
            ) in aggregated_results.additional_reports.items():
                if "source" in report_data:
                    source_data = report_data["source"]
                    if isinstance(source_data, dict):
                        if source_data.get("excluded", False):
                            excluded_scanners_count += 1
                            ASH_LOGGER.debug(f"   Scanner {scanner_name}: EXCLUDED")
                        elif not source_data.get("dependencies_satisfied", True):
                            missing_deps_count += 1
                            ASH_LOGGER.debug(
                                f"   Scanner {scanner_name}: MISSING DEPENDENCIES"
                            )

            ASH_LOGGER.info(f"   Excluded scanners: {excluded_scanners_count}")
            ASH_LOGGER.info(f"   Missing dependencies: {missing_deps_count}")
            ASH_LOGGER.info(
                f"   Total accounted for: {len(enabled_scanner_names) + excluded_scanners_count + missing_deps_count}"
            )

            ASH_LOGGER.verbose(
                f"Prepared {len(enabled_scanner_names)} enabled scanners: {enabled_scanner_names}"
            )

            # Create the main scan task with initial progress
            scan_task = self.progress_display.add_task(
                phase=ExecutionPhase.SCAN,
                description=f"Preparing {len(enabled_scanner_names)} scanners...",
                total=100,
            )

            # Update the main task to show it's started
            self.progress_display.update_task(
                phase=ExecutionPhase.SCAN,
                task_id=scan_task,
                completed=30,
                description=f"Prepared {len(enabled_scanner_names)} scanners for execution",
            )

            # Update progress
            self.update_progress(
                30, f"Prepared {len(enabled_scanner_names)} scanners for execution"
            )

            # Execute scanners based on mode
            results = None
            if parallel:
                # Update the main task to show we're executing scanners
                self.progress_display.update_task(
                    phase=ExecutionPhase.SCAN,
                    task_id=scan_task,
                    completed=40,
                    description=f"Executing {len(enabled_scanner_names)} scanners in parallel...",
                )
                self.update_progress(40, "Executing scanners in parallel...")
                results = self._execute_scanners_parallel(
                    aggregated_results=aggregated_results
                )
            else:
                # Update the main task to show we're executing scanners
                self.progress_display.update_task(
                    phase=ExecutionPhase.SCAN,
                    task_id=scan_task,
                    completed=40,
                    description=f"Executing {len(enabled_scanner_names)} scanners sequentially...",
                )
                self.update_progress(40, "Executing scanners sequentially...")
                results = self._execute_scanners_sequential(
                    aggregated_results=aggregated_results
                )
            if isinstance(results, AshAggregatedResults):
                aggregated_results = results

            # Validate execution completion after scanner execution
            self._validate_execution_completion(aggregated_results)

            # Update progress
            self.update_progress(90, "Finalizing scan results...")

            # Update the main task to show we're finalizing
            self.progress_display.update_task(
                phase=ExecutionPhase.SCAN,
                task_id=scan_task,
                completed=90,
                description="Finalizing scan results...",
            )

            # Validate result completeness before finalizing scan results
            self._validate_result_completeness(aggregated_results)

            # Save AshAggregatedResults as JSON alongside results if output_dir is configured
            if self.plugin_context.output_dir:
                ASH_LOGGER.debug(
                    f"Saving AshAggregatedResults to {self.plugin_context.output_dir}"
                )
                # NOTE: save_model() now handles final metrics population automatically
                aggregated_results.save_model(self.plugin_context.output_dir)

            # NOTE: We no longer need _finalize_scanner_metrics here since
            # final metrics are populated automatically in save_model()

            # Validate metrics consistency (optional - logs warnings if inconsistent)
            self._validate_metrics_consistency(aggregated_results)

            # Update progress to 100%
            self.update_progress(
                100, f"Scan complete: {len(self._completed_scanners)} scanners executed"
            )

            # Update the main task to show completion
            self.progress_display.update_task(
                phase=ExecutionPhase.SCAN,
                task_id=scan_task,
                completed=100,
                description=f"Scanners complete: {len(self._completed_scanners)} scanners executed",
            )

            # Add summary row
            self.add_summary(
                "Complete", f"Executed {len(self._completed_scanners)} scanners"
            )

            return aggregated_results

        except Exception as e:
            # Update progress to show error
            self.update_progress(100, f"Scan failed: {str(e)}")

            # Add error to summary
            self.add_summary("Failed", f"Error: {str(e)}")

            ASH_LOGGER.error(f"Execution failed: {str(e)}")
            raise
        finally:
            # Clean up scanner tasks
            if hasattr(self, "_scanner_tasks"):
                self._scanner_tasks = []

    def _extract_metrics_from_sarif(self, sarif_report: SarifReport):
        """Extract severity metrics from a SARIF report.

        Args:
            sarif_report: SARIF report to extract metrics from

        Returns:
            Tuple[Dict[str, int], int]: Severity counts and total finding count

        Note:
            This method is kept for backward compatibility. For new code, use
            ScannerStatisticsCalculator.extract_sarif_counts_for_scanner instead.
        """
        from automated_security_helper.models.asharp_model import AshAggregatedResults
        from automated_security_helper.core.scanner_statistics_calculator import (
            ScannerStatisticsCalculator,
        )

        # Create a temporary AshAggregatedResults with the SARIF report
        temp_model = AshAggregatedResults()
        temp_model.sarif = sarif_report

        # Use the centralized calculator to extract counts for a generic scanner
        suppressed, critical, high, medium, low, info = (
            ScannerStatisticsCalculator.extract_sarif_counts_for_scanner(
                temp_model, "generic"
            )
        )

        # Format the results to match the expected return format
        severity_counts = {
            "suppressed": suppressed,
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "info": info,
        }
        total_findings = critical + high + medium + low + info + suppressed

        return severity_counts, total_findings

    def _execute_scanner(
        self,
        scanner_name: str,
        scanner_plugin: ScannerPluginBase,
        scan_targets: List[Dict[str, Any]],
    ) -> List[ScanResultsContainer]:
        """Execute a single scanner on multiple targets and process its results.

        Args:
            scanner_name: Name of the scanner
            scanner_plugin: Scanner plugin instance
            scan_targets: List of targets to scan, each with path and type

        Returns:
            List[ScanResultsContainer]: List of scan results containers
        """
        results = []

        try:
            ASH_LOGGER.debug("EVALUATING CONFIGURED SCANNERS")
            scanner_config = scanner_plugin.config
            ASH_LOGGER.debug(f"scanner_plugin.config: {scanner_plugin.config}")

            # Process each target sequentially
            for target_info in scan_targets:
                scan_target = target_info["path"]
                target_type = target_info["type"]

                # Skip empty or non-existent directories
                if not scan_target or not Path(scan_target).exists():
                    ASH_LOGGER.debug(
                        f"Skipping {target_type} directory {scan_target} - does not exist"
                    )
                    continue

                # Create a container for this target
                container = ScanResultsContainer(
                    scanner_name=scanner_config.name,
                    target=scan_target,
                    target_type=target_type,
                    scanner_severity_threshold=scanner_config.options.severity_threshold,
                )

                # Execute scan for this target
                raw_results = None
                scanner_config_name = (
                    scanner_config and scanner_config.name
                ) or scanner_plugin.__class__.__name__
                try:
                    if scanner_config and scanner_config.enabled:
                        ASH_LOGGER.debug(
                            f"Executing {scanner_config_name}.scan() on {target_type}"
                        )
                        # Ensure scanner has proper context
                        if (
                            not hasattr(scanner_plugin, "context")
                            or scanner_plugin.context is None
                        ):
                            scanner_plugin.context = self.plugin_context

                        # Ensure scanner output paths are set correctly
                        scanner_plugin.results_dir = (
                            self.plugin_context.output_dir.joinpath(
                                "scanners"
                            ).joinpath(scanner_config_name)
                        )

                        raw_results = scanner_plugin.scan(
                            target=scan_target,
                            config=scanner_config,
                            target_type=target_type,
                            global_ignore_paths=self._global_ignore_paths,
                        )
                    else:
                        ASH_LOGGER.warning(f"{scanner_config_name} is not enabled!")
                except Exception as e:
                    # Include stack trace for debugging
                    import traceback

                    stack_trace = traceback.format_exc()
                    ASH_LOGGER.debug(
                        f"Stack trace for scanner {scanner_name} failure:\n{stack_trace}"
                    )

                    err_str = f"Failed to execute {scanner_config_name} scanner on {target_type}: {e}"
                    ASH_LOGGER.error(err_str)
                    raw_results = {
                        "errors": [
                            err_str,
                            *scanner_plugin.errors,
                        ],
                        "output": scanner_plugin.output,
                        "status": "failed",
                        "exception": str(e),
                        "stack_trace": stack_trace,
                    }

                    # Notify about the error through the event system if available
                    try:
                        from automated_security_helper.plugins.events import (
                            AshEventType,
                        )

                        self.notify_event(
                            AshEventType.ERROR,
                            message=err_str,
                            scanner=scanner_name,
                            exception=e,
                        )
                    except Exception as event_error:
                        ASH_LOGGER.error(
                            f"Failed to notify error event: {str(event_error)}"
                        )
                finally:
                    ASH_LOGGER.trace(
                        f"{scanner_plugin.__class__.__name__} raw_results for {target_type}: {raw_results}"
                    )
                    if raw_results is None:
                        raw_results = {
                            "errors": scanner_plugin.errors or [],
                            "output": scanner_plugin.output or [],
                            "status": "failed",
                            "exception": "Scanner returned None",
                        }
                    elif not raw_results:
                        ASH_LOGGER.debug(
                            f"Scanner {scanner_plugin.__class__.__name__} returned False for {target_type} -- plugin is missing dependencies"
                        )
                        container.status = ScannerStatus.MISSING

                    # Set raw results
                    container.start_time = scanner_plugin.start_time
                    container.end_time = scanner_plugin.end_time
                    try:
                        container.duration = (
                            scanner_plugin.end_time - scanner_plugin.start_time
                        ).total_seconds()
                    except Exception as e:
                        ASH_LOGGER.debug(
                            f"Error calculating duration for scanner {scanner_plugin.config.name}: {e}"
                        )
                        container.duration = None
                    container.raw_results = raw_results

                    # Extract metrics based on result type
                    from automated_security_helper.schemas.sarif_schema_model import (
                        SarifReport,
                    )

                    if isinstance(raw_results, SarifReport):
                        # Sanitize paths in SARIF report to be relative to source directory
                        raw_results = sanitize_sarif_paths(
                            raw_results, self.plugin_context.source_dir
                        )

                        if not self.plugin_context.ignore_suppressions:
                            # Apply suppressions based on global ignore paths
                            ASH_LOGGER.trace(
                                f"Ignoring paths: {self.plugin_context.config.global_settings.ignore_paths}"
                            )
                            raw_results = apply_suppressions_to_sarif(
                                sarif_report=raw_results,
                                plugin_context=self.plugin_context,
                            )
                        else:
                            ASH_LOGGER.debug(
                                "Skipping suppression application due to --ignore-suppressions flag"
                            )

                        severity_counts, finding_count = (
                            self._extract_metrics_from_sarif(raw_results)
                        )
                        container.severity_counts = severity_counts
                        container.finding_count = finding_count
                    elif isinstance(raw_results, dict):
                        # Try to extract severity counts from dictionary
                        if "severity_counts" in raw_results:
                            container.severity_counts = raw_results["severity_counts"]
                            container.finding_count = sum(
                                raw_results["severity_counts"].values()
                            )
                        elif "findings" in raw_results and isinstance(
                            raw_results["findings"], list
                        ):
                            # Count findings by severity
                            for finding in raw_results["findings"]:
                                if "severity" in finding:
                                    severity = finding["severity"].lower()
                                    if severity in container.severity_counts:
                                        container.severity_counts[severity] += 1
                                    else:
                                        container.severity_counts["info"] += 1
                            container.finding_count = len(raw_results["findings"])

                    # Get exit code from scanner
                    container.exit_code = getattr(scanner_plugin, "exit_code", 0)

                    # Determine status based on severity counts
                    if container.severity_counts.get("critical", 0) > 0:
                        container.status = ScannerStatus.FAILED
                    elif container.severity_counts.get(
                        "high", 0
                    ) > 0 and scanner_config.options.severity_threshold in [
                        "ALL",
                        "LOW",
                        "MEDIUM",
                        "HIGH",
                    ]:
                        container.status = ScannerStatus.FAILED
                    elif container.severity_counts.get(
                        "medium", 0
                    ) > 0 and scanner_config.options.severity_threshold in [
                        "ALL",
                        "LOW",
                        "MEDIUM",
                    ]:
                        container.status = ScannerStatus.FAILED
                    elif container.severity_counts.get(
                        "low", 0
                    ) > 0 and scanner_config.options.severity_threshold in [
                        "ALL",
                        "LOW",
                    ]:
                        container.status = ScannerStatus.FAILED
                    elif container.severity_counts.get(
                        "info", 0
                    ) > 0 and scanner_config.options.severity_threshold in [
                        "ALL",
                    ]:
                        container.status = ScannerStatus.FAILED
                    else:
                        container.status = ScannerStatus.PASSED

                    # Extract and add metadata if present
                    if isinstance(raw_results, dict) and "metadata" in raw_results:
                        for key, value in raw_results["metadata"].items():
                            container.add_metadata(key, value)

                    # Add this container to our results
                    ASH_LOGGER.trace(
                        f"Appending {scanner_plugin.__class__.__name__} container to results: {container.model_dump_json(by_alias=True, exclude_unset=True)}"
                    )
                    results.append(container)

            # Mark scanner as completed
            ASH_LOGGER.debug(
                f"Appending {scanner_plugin.__class__.__name__} to completed_scanners"
            )
            self._completed_scanners.append(scanner_plugin)

            return results

        except Exception as e:
            ASH_LOGGER.error(
                f"Failed to execute {scanner_plugin.__class__.__name__} scanner: {e}"
            )
            raise

    def _execute_scanners_sequential(
        self, aggregated_results: AshAggregatedResults
    ) -> AshAggregatedResults | None:
        """Execute scanners sequentially and update AshAggregatedResults."""
        total_scanners = len(self._scanner_tasks)
        completed = 0

        # Create a list of all scanner names for tracking remaining scanners
        all_scanner_names = [scanner_tuple[0] for scanner_tuple in self._scanner_tasks]
        remaining_scanners = all_scanner_names.copy()

        # Process each scanner
        for scanner_tuple in self._scanner_tasks:
            scanner_name = scanner_tuple[0]
            scanner_plugin = scanner_tuple[1]
            scan_targets = scanner_tuple[2]

            # Create task for this scanner
            task_description = f"[cyan]({scanner_name}) Scanning directories..."
            scanner_task = self.progress_display.add_task(
                phase=ExecutionPhase.SCAN, description=task_description, total=100
            )

            # Update main scan task progress
            progress_percent = 40 + (completed / total_scanners * 50)
            self.update_progress(
                int(progress_percent),
                f"Running scanner {completed + 1}/{total_scanners}: {scanner_name}",
            )

            try:
                # Update scanner task to 50%
                self.progress_display.update_task(
                    phase=ExecutionPhase.SCAN,
                    task_id=scanner_task,
                    completed=50,
                )

                # Log progress
                ASH_LOGGER.info(f"Running scanner: {scanner_name}")

                # Notify scanner start
                try:
                    from automated_security_helper.plugins.events import AshEventType

                    self.notify_event(
                        AshEventType.SCAN_START,
                        scanner=scanner_name,
                        scanner_class=scanner_plugin.__class__.__name__,
                        scan_targets=scan_targets,
                        message=f"Starting scanner: {scanner_name}",
                    )
                except Exception as event_error:
                    ASH_LOGGER.error(
                        f"Failed to notify scanner start event: {str(event_error)}"
                    )

                # Use the safe wrapper to execute the scanner
                results_list = self._safe_execute_scanner(
                    scanner_name=scanner_name,
                    scanner_plugin=scanner_plugin,
                    scan_targets=scan_targets,
                )

                if results_list is None:
                    # Handle case where scanner completely failed and returned None
                    ASH_LOGGER.error(f"Scanner {scanner_name} returned None results")

                    # Create a failure container
                    failure_container = ScanResultsContainer(
                        scanner_name=scanner_name,
                        status=ScannerStatus.FAILED,
                        raw_results={
                            "errors": [
                                f"Scanner {scanner_name} failed with no results"
                            ],
                            "status": "failed",
                            "exception": "Scanner returned None results",
                        },
                    )

                    # Process the failure container
                    processed = self._process_results(
                        results=failure_container, aggregated_results=aggregated_results
                    )
                    if isinstance(processed, AshAggregatedResults):
                        aggregated_results = processed

                    # Update task to show failure
                    self.progress_display.update_task(
                        phase=ExecutionPhase.SCAN,
                        task_id=scanner_task,
                        completed=100,
                        description=f"[red]({scanner_name}) Failed: returned None results",
                    )
                else:
                    # Process each result
                    for results in results_list:
                        processed = self._process_results(
                            results=results, aggregated_results=aggregated_results
                        )
                        if isinstance(processed, AshAggregatedResults):
                            aggregated_results = processed

                    # Update scanner task to 100%
                    self.progress_display.update_task(
                        phase=ExecutionPhase.SCAN,
                        task_id=scanner_task,
                        completed=100,
                        description=f"[green]({scanner_name}) Completed scan",
                    )

                    # Log completion
                    # ASH_LOGGER.info(f"Completed scanner: {scanner_name}")

                    # Remove from remaining scanners and notify about completion
                    if scanner_name in remaining_scanners:
                        remaining_scanners.remove(scanner_name)

                    # Notify about scan completion with remaining scanners info
                    try:
                        from automated_security_helper.plugins.events import (
                            AshEventType,
                        )

                        remaining_count = len(remaining_scanners)
                        remaining_list = (
                            ", ".join(remaining_scanners)
                            if remaining_scanners
                            else "None"
                        )

                        self.notify_event(
                            AshEventType.SCAN_COMPLETE,
                            scanner=scanner_name,
                            completed_count=completed + 1,
                            total_count=total_scanners,
                            remaining_count=remaining_count,
                            remaining_scanners=remaining_scanners,
                            message=f"Scanner {scanner_name} completed. {remaining_count} remaining: {remaining_list}",
                        )

                    except Exception as event_error:
                        ASH_LOGGER.error(
                            f"Failed to notify scan completion event: {str(event_error)}"
                        )

            except Exception as e:
                # Include stack trace for debugging
                import traceback

                stack_trace = traceback.format_exc()
                ASH_LOGGER.debug(
                    f"Stack trace for scanner {scanner_name} failure:\n{stack_trace}"
                )

                # Update scanner task to show error
                self.progress_display.update_task(
                    phase=ExecutionPhase.SCAN,
                    task_id=scanner_task,
                    completed=100,
                    description=f"[red]({scanner_name}) Failed: {str(e)}",
                )

                # Log error but continue with other scanners
                ASH_LOGGER.error(f"Scanner failed: {scanner_name} - {str(e)}")

                # Create a failure container
                failure_container = ScanResultsContainer(
                    scanner_name=scanner_name,
                    status=ScannerStatus.FAILED,
                    raw_results={
                        "errors": [f"Scanner {scanner_name} failed: {str(e)}"],
                        "status": "failed",
                        "exception": str(e),
                        "stack_trace": stack_trace,
                    },
                )

                # Process the failure container
                try:
                    processed = self._process_results(
                        results=failure_container, aggregated_results=aggregated_results
                    )
                    if isinstance(processed, AshAggregatedResults):
                        aggregated_results = processed
                except Exception as process_error:
                    ASH_LOGGER.error(
                        f"Failed to process error results for {scanner_name}: {str(process_error)}"
                    )

            finally:
                completed += 1

        return aggregated_results

    def _execute_scanners_parallel(
        self, aggregated_results: AshAggregatedResults
    ) -> AshAggregatedResults | None:
        """Execute scanners in parallel and update AshAggregatedResults."""
        total_scanners = len(self._scanner_tasks)
        ASH_LOGGER.debug(f"Total scanners: {total_scanners}")
        scanner_tasks = {}

        # Create a list of all scanner names for tracking remaining scanners
        all_scanner_names = [scanner_tuple[0] for scanner_tuple in self._scanner_tasks]
        remaining_scanners = all_scanner_names.copy()
        # Use a lock to protect the remaining_scanners list in parallel execution
        import threading

        remaining_scanners_lock = threading.Lock()

        # Determine execution strategy based on parallel flag and number of scanners
        if total_scanners <= 1:
            # For single scanner, execute directly without thread pool overhead
            ASH_LOGGER.debug("Single scanner detected, executing directly")
            return self._execute_scanners_sequential(aggregated_results)

        with ThreadPoolExecutor(max_workers=self._max_workers) as executor:
            futures = []

            # Submit all scanners to the thread pool
            for scanner_tuple in self._scanner_tasks:
                ASH_LOGGER.debug("Processing scanner from queue")

                scanner_name = scanner_tuple[0]
                scanner_plugin = scanner_tuple[1]
                scan_targets = scanner_tuple[2]

                # Create task for this scanner
                task_key = f"{scanner_name}_task"
                task_description = f"[magenta]({scanner_name}) Scanning directories..."
                scanner_task = self.progress_display.add_task(
                    phase=ExecutionPhase.SCAN, description=task_description, total=100
                )
                scanner_tasks[task_key] = scanner_task

                # Update scanner task to show it's queued
                self.progress_display.update_task(
                    phase=ExecutionPhase.SCAN,
                    task_id=scanner_task,
                    completed=10,
                    description=f"[blue]({scanner_name}) Queued scan...",
                )

                ASH_LOGGER.debug(
                    f"Submitting {scanner_name} to thread pool to scan targets"
                )
                future = executor.submit(
                    self._safe_execute_scanner,  # Use our safe wrapper instead of direct call
                    scanner_name,
                    scanner_plugin,
                    scan_targets,
                )
                # Store scanner info with future for later reference
                future.scanner_info = {
                    "name": scanner_name,
                    "task_key": task_key,
                }
                ASH_LOGGER.debug(f"Submitted {scanner_name} to thread pool")
                futures.append(future)
                ASH_LOGGER.debug(f"Appended {scanner_name} to futures")

            # Update main scan task progress
            self.update_progress(
                50, f"Running {len(futures)} scanner tasks in parallel..."
            )

            # Wait for all futures to complete and handle any exceptions
            completed_count = 0
            for future in as_completed(futures):
                scanner_name = future.scanner_info["name"]
                task_key = future.scanner_info["task_key"]
                task_id = scanner_tasks.get(task_key)

                try:
                    ASH_LOGGER.debug(
                        f"Getting results from completed future for {scanner_name}"
                    )
                    results_list = future.result()

                    if results_list is None:
                        # Handle case where scanner completely failed and returned None
                        ASH_LOGGER.error(
                            f"Scanner {scanner_name} returned None results"
                        )

                        # Create a failure container
                        failure_container = ScanResultsContainer(
                            scanner_name=scanner_name,
                            status=ScannerStatus.FAILED,
                            raw_results={
                                "errors": [
                                    f"Scanner {scanner_name} failed with no results"
                                ],
                                "status": "failed",
                                "exception": "Scanner returned None results",
                            },
                        )

                        # Process the failure container
                        processed = self._process_results(
                            results=failure_container,
                            aggregated_results=aggregated_results,
                        )
                        if isinstance(processed, AshAggregatedResults):
                            aggregated_results = processed

                        # Update task to show failure
                        if task_id is not None:
                            self.progress_display.update_task(
                                phase=ExecutionPhase.SCAN,
                                task_id=task_id,
                                completed=100,
                                description=f"[red]({scanner_name}) Failed: returned None results",
                            )
                    else:
                        ASH_LOGGER.debug(f"Got results from {scanner_name}, processing")

                        # Process each result in the list
                        for results in results_list:
                            processed = self._process_results(
                                results=results, aggregated_results=aggregated_results
                            )
                            if isinstance(processed, AshAggregatedResults):
                                aggregated_results = processed

                        # Add scanner to completed list - CRITICAL FIX for parallel execution tracking
                        # Find the scanner plugin instance from the original scanner tuple
                        scanner_plugin = None
                        for scanner_tuple in self._scanner_tasks:
                            if scanner_tuple[0] == scanner_name:
                                scanner_plugin = scanner_tuple[1]
                                break

                        if scanner_plugin is not None:
                            self._completed_scanners.append(scanner_plugin)
                            ASH_LOGGER.debug(
                                f"Added {scanner_name} to completed scanners list"
                            )
                        else:
                            ASH_LOGGER.warning(
                                f"Could not find scanner plugin instance for {scanner_name}"
                            )

                        # Update scanner task to show completion
                        if task_id is not None:
                            self.progress_display.update_task(
                                phase=ExecutionPhase.SCAN,
                                task_id=task_id,
                                completed=100,
                                description=f"[green]({scanner_name}) Completed scan",
                            )

                        # Log completion
                        # ASH_LOGGER.info(f"Completed scanner: {scanner_name}")

                        # Remove from remaining scanners and notify about completion
                        with remaining_scanners_lock:
                            if scanner_name in remaining_scanners:
                                remaining_scanners.remove(scanner_name)

                            # Notify about scan completion with remaining scanners info
                            try:
                                from automated_security_helper.plugins.events import (
                                    AshEventType,
                                )

                                remaining_count = len(remaining_scanners)
                                remaining_list = (
                                    ", ".join(remaining_scanners)
                                    if remaining_scanners
                                    else "None"
                                )

                                self.notify_event(
                                    AshEventType.SCAN_COMPLETE,
                                    scanner=scanner_name,
                                    completed_count=completed_count + 1,
                                    total_count=total_scanners,
                                    remaining_count=remaining_count,
                                    remaining_scanners=remaining_scanners.copy(),  # Copy to avoid race conditions
                                    message=f"Scanner {scanner_name} completed. {remaining_count} remaining: {remaining_list}",
                                )

                            except Exception as event_error:
                                ASH_LOGGER.error(
                                    f"Failed to notify scan completion event: {str(event_error)}"
                                )

                except Exception as e:
                    # Include stack trace for debugging
                    import traceback

                    stack_trace = traceback.format_exc()
                    ASH_LOGGER.debug(
                        f"Stack trace for scanner {scanner_name} thread failure:\n{stack_trace}"
                    )

                    # Update scanner task to show error
                    if task_id is not None:
                        self.progress_display.update_task(
                            phase=ExecutionPhase.SCAN,
                            task_id=task_id,
                            completed=100,
                            description=f"[red]({scanner_name}) Failed: {str(e)}",
                        )

                    # Log error but continue with other scanners
                    ASH_LOGGER.error(
                        f"Scanner execution failed in thread pool: {scanner_name} - {str(e)}"
                    )

                    # Create a failure container
                    failure_container = ScanResultsContainer(
                        scanner_name=scanner_name,
                        status=ScannerStatus.FAILED,
                        raw_results={
                            "errors": [
                                f"Scanner {scanner_name} failed in thread pool: {str(e)}"
                            ],
                            "status": "failed",
                            "exception": str(e),
                            "stack_trace": stack_trace,
                        },
                    )

                    # Process the failure container
                    try:
                        processed = self._process_results(
                            results=failure_container,
                            aggregated_results=aggregated_results,
                        )
                        if isinstance(processed, AshAggregatedResults):
                            aggregated_results = processed
                    except Exception as process_error:
                        ASH_LOGGER.error(
                            f"Failed to process error results for {scanner_name}: {str(process_error)}"
                        )

                finally:
                    # Always count as completed for progress tracking
                    completed_count += 1
                    if len(futures) > 0:  # Avoid division by zero
                        progress_percent = 50 + (completed_count / len(futures) * 40)
                        self.update_progress(
                            int(progress_percent),
                            f"Completed {completed_count}/{len(futures)} scanner tasks",
                        )
        return aggregated_results

    def _process_results(
        self, results: ScanResultsContainer, aggregated_results: AshAggregatedResults
    ) -> AshAggregatedResults:
        """Process scanner results and update AshAggregatedResults.

        Args:
            results: Container with scanner results

        Note:
            This method no longer populates scanner_results or summary_stats.
            Those will be populated from the final SARIF data right before saving
            to ensure all metrics are aligned and based on the final processed data.
        """
        from automated_security_helper.schemas.sarif_schema_model import SarifReport
        from automated_security_helper.schemas.cyclonedx_bom_1_6_schema import (
            CycloneDXReport,
        )

        # Store metrics in additional_reports for later use
        scanner_name = results.scanner_name
        if scanner_name not in aggregated_results.additional_reports:
            aggregated_results.additional_reports[scanner_name] = {}

        # Store the full container information for duration and other metadata access
        # This preserves duration, start_time, end_time, and other container metadata
        aggregated_results.additional_reports[scanner_name]["source"] = (
            results.model_dump()
        )

        # NOTE: We no longer populate scanner_results or summary_stats here during scan phase.
        # Instead, both will be populated from the final SARIF data right before saving
        # using get_unified_scanner_metrics() after all processing is complete.
        # This ensures perfect alignment between summary_stats, scanner_results, and SARIF data.

        # Process the raw results based on type
        ASH_LOGGER.debug(
            f"🔍 Processing results for {scanner_name}: type={type(results.raw_results)}, value={results.raw_results if not isinstance(results.raw_results, SarifReport) else 'SarifReport'}"
        )

        if isinstance(results.raw_results, SarifReport):
            ASH_LOGGER.debug(
                f"✅ {scanner_name}: Processing as SARIF report with {len(results.raw_results.runs[0].results) if results.raw_results.runs and results.raw_results.runs[0].results else 0} results"
            )
            # Sanitize paths in SARIF report to be relative to source directory
            sanitized_sarif = sanitize_sarif_paths(
                results.raw_results, self.plugin_context.source_dir
            )

            if not self.plugin_context.ignore_suppressions:
                # Apply suppressions based on global ignore paths
                sanitized_sarif = apply_suppressions_to_sarif(
                    sarif_report=sanitized_sarif,
                    plugin_context=self.plugin_context,
                )
            else:
                ASH_LOGGER.debug(
                    "Skipping suppression application due to --ignore-suppressions flag"
                )

            # Attach scanner details to the SARIF report
            scanner_version = None

            # Try to get scanner version from different sources
            if (
                hasattr(results, "metadata")
                and results.metadata
                and "scanner_version" in results.metadata
            ):
                scanner_version = results.metadata["scanner_version"]
            elif hasattr(results.raw_results, "tool_version"):
                scanner_version = results.raw_results.tool_version

            # Build invocation details from metadata
            invocation_details = {}

            # If there's command execution info available, add it to invocation details
            if hasattr(results, "metadata") and results.metadata:
                if "command_line" in results.metadata:
                    invocation_details["command_line"] = results.metadata[
                        "command_line"
                    ]
                if "working_directory" in results.metadata:
                    invocation_details["working_directory"] = results.metadata[
                        "working_directory"
                    ]
                if "arguments" in results.metadata:
                    invocation_details["arguments"] = results.metadata["arguments"]
                if "exit_code" in results.metadata or hasattr(results, "exit_code"):
                    invocation_details["exit_code"] = results.metadata.get(
                        "exit_code", results.exit_code
                    )
                if "duration" in results.metadata or hasattr(results, "duration"):
                    invocation_details["duration"] = results.metadata.get(
                        "duration", results.duration
                    )

            # Add scanner execution details if available
            if hasattr(results, "start_time") and results.start_time:
                invocation_details["start_time"] = (
                    results.start_time.isoformat()
                    if hasattr(results.start_time, "isoformat")
                    else str(results.start_time)
                )
            if hasattr(results, "end_time") and results.end_time:
                invocation_details["end_time"] = (
                    results.end_time.isoformat()
                    if hasattr(results.end_time, "isoformat")
                    else str(results.end_time)
                )

            # Attach scanner details before merging
            sanitized_sarif.attach_scanner_details(
                scanner_name=results.scanner_name,
                scanner_version=scanner_version,
                invocation_details=invocation_details if invocation_details else None,
            )

            # Log the scanner details for debugging
            ASH_LOGGER.trace(
                f"Attached scanner details for {results.scanner_name} v{scanner_version} with invocation details: {invocation_details}"
            )

            aggregated_results.sarif.merge_sarif_report(sanitized_sarif)
        elif isinstance(results.raw_results, CycloneDXReport):
            ASH_LOGGER.debug(f"📊 {scanner_name}: Processing as CycloneDX report")
            aggregated_results.cyclonedx = results.raw_results
        elif isinstance(results.raw_results, AshAggregatedResults):
            ASH_LOGGER.debug(f"🔗 {scanner_name}: Processing as AshAggregatedResults")
            aggregated_results.merge_model(results.raw_results)
        else:
            ASH_LOGGER.debug(
                f"📁 {scanner_name}: Processing as additional report (type: {type(results.raw_results)})"
            )
            if scanner_name not in aggregated_results.additional_reports:
                aggregated_results.additional_reports[scanner_name] = {}

            if (
                results.target_type
                not in aggregated_results.additional_reports[scanner_name]
            ):
                aggregated_results.additional_reports[scanner_name][
                    results.target_type
                ] = {}

            aggregated_results.additional_reports[scanner_name][results.target_type][
                "raw_results"
            ] = results.raw_results

        return aggregated_results

    def _safe_execute_scanner(
        self,
        scanner_name: str,
        scanner_plugin: ScannerPluginBase,
        scan_targets: List[Dict[str, Any]],
    ) -> List[ScanResultsContainer]:
        """
        Safely execute a scanner with comprehensive error handling.
        This wrapper ensures that scanner failures are properly captured and don't crash the thread pool.

        Args:
            scanner_name: Name of the scanner
            scanner_plugin: Scanner plugin instance
            scan_targets: List of targets to scan, each with path and type

        Returns:
            List[ScanResultsContainer]: List of scan results containers, or empty list on failure
        """
        try:
            # Call the actual scanner execution method
            return self._execute_scanner(scanner_name, scanner_plugin, scan_targets)
        except Exception as e:
            # Capture any unexpected exceptions that might occur
            import traceback

            stack_trace = traceback.format_exc()

            error_msg = f"Unexpected error in scanner {scanner_name}: {str(e)}"
            ASH_LOGGER.error(error_msg)
            ASH_LOGGER.debug(
                f"Stack trace for scanner {scanner_name} failure:\n{stack_trace}"
            )

            # Create a failure container to report the error
            failure_container = ScanResultsContainer(
                scanner_name=scanner_name,
                status=ScannerStatus.FAILED,
                raw_results={
                    "errors": [error_msg],
                    "status": "failed",
                    "exception": str(e),
                    "stack_trace": stack_trace,
                },
            )

            # Try to notify about the error through the event system
            try:
                from automated_security_helper.plugins.events import AshEventType

                self.notify_event(
                    AshEventType.ERROR,
                    message=error_msg,
                    scanner=scanner_name,
                    exception=e,
                )
            except Exception as event_error:
                ASH_LOGGER.error(f"Failed to notify error event: {str(event_error)}")

            # Return a list with the failure container
            return [failure_container]

    def _validate_metrics_consistency(self, aggregated_results: AshAggregatedResults):
        """Validate that scanner_results totals match summary_stats.

        This method performs a consistency check to ensure that the individual
        scanner metrics add up to the summary stats totals. It logs warnings
        if any discrepancies are found.

        Args:
            aggregated_results: The AshAggregatedResults to validate
        """
        try:
            # Calculate totals from individual scanner results
            scanner_totals = {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
                "suppressed": 0,
                "total": 0,
                "actionable": 0,
            }

            for (
                scanner_name,
                scanner_info,
            ) in aggregated_results.scanner_results.items():
                # Handle both old ScannerStatusInfo and new ScannerMetrics structures
                if hasattr(scanner_info, "source") and hasattr(
                    scanner_info, "converted"
                ):
                    # Old ScannerStatusInfo structure
                    for target_info in [scanner_info.source, scanner_info.converted]:
                        if target_info and target_info.severity_counts:
                            scanner_totals["critical"] += (
                                target_info.severity_counts.critical
                            )
                            scanner_totals["high"] += target_info.severity_counts.high
                            scanner_totals["medium"] += (
                                target_info.severity_counts.medium
                            )
                            scanner_totals["low"] += target_info.severity_counts.low
                            scanner_totals["info"] += target_info.severity_counts.info
                            scanner_totals["suppressed"] += (
                                target_info.severity_counts.suppressed
                            )
                            scanner_totals["total"] += target_info.finding_count or 0
                            scanner_totals["actionable"] += (
                                target_info.actionable_finding_count or 0
                            )
                elif hasattr(scanner_info, "critical") and hasattr(
                    scanner_info, "scanner_name"
                ):
                    # New ScannerMetrics structure
                    scanner_totals["critical"] += scanner_info.critical
                    scanner_totals["high"] += scanner_info.high
                    scanner_totals["medium"] += scanner_info.medium
                    scanner_totals["low"] += scanner_info.low
                    scanner_totals["info"] += scanner_info.info
                    scanner_totals["suppressed"] += scanner_info.suppressed
                    scanner_totals["total"] += scanner_info.total
                    scanner_totals["actionable"] += scanner_info.actionable
                else:
                    ASH_LOGGER.debug(
                        f"Unknown scanner_info structure for {scanner_name}: {type(scanner_info)}"
                    )

            # Compare with summary stats
            summary_stats = aggregated_results.metadata.summary_stats
            actual_totals = {
                "critical": summary_stats.critical,
                "high": summary_stats.high,
                "medium": summary_stats.medium,
                "low": summary_stats.low,
                "info": summary_stats.info,
                "suppressed": summary_stats.suppressed,
                "total": summary_stats.total,
                "actionable": summary_stats.actionable,
            }

            # Check for discrepancies
            discrepancies_found = False
            for metric, expected in scanner_totals.items():
                actual = actual_totals[metric]
                if expected != actual:
                    ASH_LOGGER.warning(
                        f"Metrics consistency check failed for {metric}: "
                        f"scanner_results total={expected}, summary_stats={actual}"
                    )
                    discrepancies_found = True

            if not discrepancies_found:
                ASH_LOGGER.debug("Metrics consistency check passed - all totals match")

        except Exception as e:
            ASH_LOGGER.error(f"Error validating metrics consistency: {str(e)}")
            import traceback

            ASH_LOGGER.debug(f"Stack trace: {traceback.format_exc()}")

    def _validate_scanner_tasks(self, aggregated_results: AshAggregatedResults) -> None:
        """Validate scanner tasks after population and handle missing scanners.

        This method validates that all expected scanners have tasks in the list,
        attempts to retry registration for missing scanners, and handles validation
        errors gracefully to ensure scan continuity.

        Args:
            aggregated_results: The aggregated results object to add validation errors to
        """
        try:
            ASH_LOGGER.info("Starting scanner tasks validation")

            ASH_LOGGER.debug(f"Validating {len(self._scanner_tasks)} scanner tasks")

            # Validate the scanner tasks
            validation_checkpoint = self.validation_manager.validate_task_queue(
                self._scanner_tasks
            )

            # Check for missing scanners and attempt retry
            missing_scanners = validation_checkpoint.get_missing_scanners()
            if missing_scanners:
                ASH_LOGGER.info(
                    f"Found {len(missing_scanners)} missing scanners, attempting retry registration"
                )

                # Notify about missing scanners via event system
                try:
                    from automated_security_helper.plugins.events import AshEventType

                    self.notify_event(
                        AshEventType.WARNING,
                        message=f"Scanner tasks validation found {len(missing_scanners)} missing scanners",
                        missing_scanners=missing_scanners,
                        phase="scan",
                        validation_checkpoint="scanner_tasks_validation",
                    )
                except Exception as event_error:
                    ASH_LOGGER.debug(
                        f"Failed to notify validation warning event: {str(event_error)}"
                    )

                # Attempt to retry registration for missing scanners
                successfully_retried = (
                    self.validation_manager.retry_scanner_registration(missing_scanners)
                )

                if successfully_retried:
                    ASH_LOGGER.info(
                        f"Successfully retried {len(successfully_retried)} scanners: {', '.join(successfully_retried)}"
                    )

                    # Notify about successful retries
                    try:
                        from automated_security_helper.plugins.events import (
                            AshEventType,
                        )

                        self.notify_event(
                            AshEventType.INFO,
                            message=f"Successfully retried registration for {len(successfully_retried)} scanners",
                            retried_scanners=successfully_retried,
                            phase="scan",
                            validation_checkpoint="scanner_tasks_validation",
                        )
                    except Exception as event_error:
                        ASH_LOGGER.debug(
                            f"Failed to notify validation info event: {str(event_error)}"
                        )

                    # For successfully retried scanners, we would need to re-add them to the task list
                    # However, since the retry logic in ScannerValidationManager is mainly for state tracking
                    # and doesn't actually re-enable scanners in the current implementation,
                    # we'll log this as a limitation
                    ASH_LOGGER.warning(
                        "Note: Retried scanners are marked as enabled but not re-added to task list in current implementation"
                    )
                else:
                    ASH_LOGGER.warning("No scanners were successfully retried")

            # Handle validation errors gracefully
            self.validation_manager.handle_queue_validation_errors(
                validation_checkpoint=validation_checkpoint,
                scan_results=aggregated_results,
            )

            # Add validation results to aggregated results for debugging
            checkpoint_dict = {
                "checkpoint_name": validation_checkpoint.checkpoint_name,
                "timestamp": validation_checkpoint.timestamp.isoformat(),
                "expected_scanners": validation_checkpoint.expected_scanners,
                "actual_scanners": validation_checkpoint.actual_scanners,
                "discrepancies": validation_checkpoint.discrepancies,
                "errors": validation_checkpoint.errors,
                "metadata": validation_checkpoint.metadata,
            }
            aggregated_results.validation_checkpoints.append(checkpoint_dict)

            # Add validation summary to metadata for easy access
            if not hasattr(aggregated_results.metadata, "validation_summary"):
                aggregated_results.metadata.validation_summary = {}

            aggregated_results.metadata.validation_summary[
                "scanner_tasks_validation"
            ] = {
                "timestamp": validation_checkpoint.timestamp.isoformat(),
                "expected_count": len(validation_checkpoint.expected_scanners),
                "actual_count": len(validation_checkpoint.actual_scanners),
                "missing_count": len(missing_scanners),
                "has_issues": validation_checkpoint.has_issues(),
                "successfully_retried": (
                    len(successfully_retried)
                    if "successfully_retried" in locals()
                    else 0
                ),
            }

            # Log validation summary and notify via events
            if validation_checkpoint.has_issues():
                total_issues = len(validation_checkpoint.discrepancies) + len(
                    validation_checkpoint.errors
                )
                ASH_LOGGER.warning(
                    f"Scanner tasks validation completed with {total_issues} issues"
                )

                # Notify about validation issues
                try:
                    from automated_security_helper.plugins.events import AshEventType

                    self.notify_event(
                        AshEventType.WARNING,
                        message=f"Scanner tasks validation completed with {total_issues} issues",
                        total_issues=total_issues,
                        discrepancies=validation_checkpoint.discrepancies,
                        errors=validation_checkpoint.errors,
                        phase="scan",
                        validation_checkpoint="scanner_tasks_validation",
                    )
                except Exception as event_error:
                    ASH_LOGGER.debug(
                        f"Failed to notify validation warning event: {str(event_error)}"
                    )
            else:
                ASH_LOGGER.info("✅ Scanner tasks validation completed successfully")

                # Notify about successful validation
                try:
                    from automated_security_helper.plugins.events import AshEventType

                    self.notify_event(
                        AshEventType.INFO,
                        message="Scanner tasks validation completed successfully",
                        expected_count=len(validation_checkpoint.expected_scanners),
                        actual_count=len(validation_checkpoint.actual_scanners),
                        phase="scan",
                        validation_checkpoint="scanner_tasks_validation",
                    )
                except Exception as event_error:
                    ASH_LOGGER.debug(
                        f"Failed to notify validation info event: {str(event_error)}"
                    )

        except Exception as e:
            error_msg = f"Error during scanner tasks validation: {str(e)}"
            ASH_LOGGER.error(error_msg)

            # Notify about validation error via event system
            try:
                from automated_security_helper.plugins.events import AshEventType

                self.notify_event(
                    AshEventType.ERROR,
                    message=error_msg,
                    exception=str(e),
                    phase="scan",
                    validation_checkpoint="scanner_tasks_validation",
                )
            except Exception as event_error:
                ASH_LOGGER.debug(
                    f"Failed to notify validation error event: {str(event_error)}"
                )

            # Add error to validation manager for tracking
            self.validation_manager.add_queue_validation_error(error_msg)

            # Ensure scan continues despite validation error
            ASH_LOGGER.info("🔄 Scanner tasks validation failed but scan will continue")

            # Add stack trace for debugging
            import traceback

            ASH_LOGGER.debug(
                f"Scanner tasks validation error stack trace: {traceback.format_exc()}"
            )

    def _validate_execution_completion(
        self, aggregated_results: AshAggregatedResults
    ) -> None:
        """Validate execution completion after scanner execution.

        This method validates that all expected scanners completed execution,
        logs execution discrepancies, and handles validation errors gracefully
        to ensure scan continuity.

        Args:
            aggregated_results: The aggregated results object to add validation errors to
        """
        try:
            ASH_LOGGER.info("Starting execution completion validation")

            # Extract completed scanner names from self._completed_scanners
            completed_scanner_names = []
            if hasattr(self, "_completed_scanners") and self._completed_scanners:
                for scanner_plugin in self._completed_scanners:
                    # Get scanner name from plugin instance
                    if hasattr(scanner_plugin, "config") and hasattr(
                        scanner_plugin.config, "name"
                    ):
                        scanner_name = scanner_plugin.config.name
                    elif hasattr(scanner_plugin, "__class__"):
                        scanner_name = scanner_plugin.__class__.__name__.lower()
                    else:
                        scanner_name = str(scanner_plugin).lower()

                    completed_scanner_names.append(scanner_name)

            # Remove duplicates and sort for consistent output
            completed_scanner_names = sorted(list(set(completed_scanner_names)))

            ASH_LOGGER.debug(
                f"Extracted {len(completed_scanner_names)} completed scanner names: {completed_scanner_names}"
            )

            # Validate execution completion
            validation_checkpoint = (
                self.validation_manager.validate_execution_completion(
                    completed_scanner_names
                )
            )

            # Check for execution discrepancies
            missing_scanners = validation_checkpoint.get_missing_scanners()
            unexpected_scanners = validation_checkpoint.get_unexpected_scanners()

            if missing_scanners or unexpected_scanners:
                total_discrepancies = len(missing_scanners) + len(unexpected_scanners)
                ASH_LOGGER.warning(
                    f"Found {total_discrepancies} execution completion discrepancies"
                )

                # Notify about execution discrepancies via event system
                try:
                    from automated_security_helper.plugins.events import AshEventType

                    self.notify_event(
                        AshEventType.WARNING,
                        message=f"Execution completion validation found {total_discrepancies} discrepancies",
                        missing_scanners=missing_scanners,
                        unexpected_scanners=unexpected_scanners,
                        phase="scan",
                        validation_checkpoint="execution_completion_validation",
                    )
                except Exception as event_error:
                    ASH_LOGGER.debug(
                        f"Failed to notify execution completion warning event: {str(event_error)}"
                    )

                # Generate detailed execution discrepancy report
                discrepancy_report = (
                    self.validation_manager.report_execution_discrepancies(
                        validation_checkpoint
                    )
                )

                # Log detailed discrepancy information
                if missing_scanners:
                    ASH_LOGGER.warning(
                        f"Missing scanner completions ({len(missing_scanners)}): {', '.join(missing_scanners)}"
                    )
                    for scanner_name in missing_scanners:
                        scanner_state = self.validation_manager.get_scanner_state(
                            scanner_name
                        )
                        if scanner_state and scanner_state.failure_reason:
                            ASH_LOGGER.warning(
                                f"  - {scanner_name}: {scanner_state.failure_reason}"
                            )

                if unexpected_scanners:
                    ASH_LOGGER.info(
                        f"Unexpected scanner completions ({len(unexpected_scanners)}): {', '.join(unexpected_scanners)}"
                    )

                # Add discrepancy report to aggregated results for debugging
                if not hasattr(
                    aggregated_results.metadata, "execution_discrepancy_report"
                ):
                    aggregated_results.metadata.execution_discrepancy_report = (
                        discrepancy_report
                    )

            # Add validation results to aggregated results for debugging
            checkpoint_dict = {
                "checkpoint_name": validation_checkpoint.checkpoint_name,
                "timestamp": validation_checkpoint.timestamp.isoformat(),
                "expected_scanners": validation_checkpoint.expected_scanners,
                "actual_scanners": validation_checkpoint.actual_scanners,
                "discrepancies": validation_checkpoint.discrepancies,
                "errors": validation_checkpoint.errors,
                "metadata": validation_checkpoint.metadata,
            }
            aggregated_results.validation_checkpoints.append(checkpoint_dict)

            # Add validation summary to metadata for easy access
            if not hasattr(aggregated_results.metadata, "validation_summary"):
                aggregated_results.metadata.validation_summary = {}

            aggregated_results.metadata.validation_summary[
                "execution_completion_validation"
            ] = {
                "timestamp": validation_checkpoint.timestamp.isoformat(),
                "expected_count": len(validation_checkpoint.expected_scanners),
                "completed_count": len(validation_checkpoint.actual_scanners),
                "missing_count": len(missing_scanners),
                "unexpected_count": len(unexpected_scanners),
                "completion_rate": validation_checkpoint.metadata.get(
                    "completion_rate", 0.0
                ),
                "has_issues": validation_checkpoint.has_issues(),
            }

            # Log validation summary and notify via events
            if validation_checkpoint.has_issues():
                total_issues = len(validation_checkpoint.discrepancies) + len(
                    validation_checkpoint.errors
                )
                ASH_LOGGER.warning(
                    f"Execution completion validation completed with {total_issues} issues"
                )

                # Notify about validation issues
                try:
                    from automated_security_helper.plugins.events import AshEventType

                    self.notify_event(
                        AshEventType.WARNING,
                        message=f"Execution completion validation completed with {total_issues} issues",
                        total_issues=total_issues,
                        discrepancies=validation_checkpoint.discrepancies,
                        errors=validation_checkpoint.errors,
                        completion_rate=validation_checkpoint.metadata.get(
                            "completion_rate", 0.0
                        ),
                        phase="scan",
                        validation_checkpoint="execution_completion_validation",
                    )
                except Exception as event_error:
                    ASH_LOGGER.debug(
                        f"Failed to notify execution completion warning event: {str(event_error)}"
                    )
            else:
                completion_rate = validation_checkpoint.metadata.get(
                    "completion_rate", 0.0
                )
                ASH_LOGGER.info(
                    f"✅ Execution completion validation passed - completion rate: {completion_rate:.1%}"
                )

                # Notify about successful validation
                try:
                    from automated_security_helper.plugins.events import AshEventType

                    self.notify_event(
                        AshEventType.INFO,
                        message=f"Execution completion validation passed with {completion_rate:.1%} completion rate",
                        expected_count=len(validation_checkpoint.expected_scanners),
                        completed_count=len(validation_checkpoint.actual_scanners),
                        completion_rate=completion_rate,
                        phase="scan",
                        validation_checkpoint="execution_completion_validation",
                    )
                except Exception as event_error:
                    ASH_LOGGER.debug(
                        f"Failed to notify execution completion info event: {str(event_error)}"
                    )

        except Exception as e:
            error_msg = f"Error during execution completion validation: {str(e)}"
            ASH_LOGGER.error(error_msg)

            # Notify about validation error via event system
            try:
                from automated_security_helper.plugins.events import AshEventType

                self.notify_event(
                    AshEventType.ERROR,
                    message=error_msg,
                    exception=str(e),
                    phase="scan",
                    validation_checkpoint="execution_completion_validation",
                )
            except Exception as event_error:
                ASH_LOGGER.debug(
                    f"Failed to notify execution completion error event: {str(event_error)}"
                )

            # Ensure scan continues despite validation error
            ASH_LOGGER.info(
                "🔄 Execution completion validation failed but scan will continue"
            )

            # Add stack trace for debugging
            import traceback

            ASH_LOGGER.debug(
                f"Execution completion validation error stack trace: {traceback.format_exc()}"
            )

    def _validate_result_completeness(
        self, aggregated_results: AshAggregatedResults
    ) -> None:
        """Validate result completeness before finalizing scan results.

        This method ensures all originally registered scanners appear in the final
        aggregated results. Missing scanners are added with appropriate status and
        failure reasons to provide complete visibility into scan coverage.

        Args:
            aggregated_results: The aggregated scan results to validate and potentially modify
        """
        try:
            ASH_LOGGER.info("🔍 Validating result completeness...")

            # Call the validation manager to ensure complete results
            validation_checkpoint = self.validation_manager.ensure_complete_results(
                aggregated_results
            )

            # Extract validation results for reporting
            missing_scanners = validation_checkpoint.get_missing_scanners()
            unexpected_scanners = validation_checkpoint.get_unexpected_scanners()

            # Report validation results
            if missing_scanners or unexpected_scanners:
                total_adjustments = len(missing_scanners) + len(unexpected_scanners)
                ASH_LOGGER.info(
                    f"Result completeness validation made {total_adjustments} adjustments"
                )

                # Notify about result completeness adjustments via event system
                try:
                    from automated_security_helper.plugins.events import AshEventType

                    self.notify_event(
                        AshEventType.INFO,
                        message=f"Result completeness validation made {total_adjustments} adjustments",
                        missing_scanners=missing_scanners,
                        unexpected_scanners=unexpected_scanners,
                        total_adjustments=total_adjustments,
                        phase="scan",
                        validation_checkpoint="result_completeness_validation",
                    )
                except Exception as event_error:
                    ASH_LOGGER.debug(
                        f"Failed to notify result completeness info event: {str(event_error)}"
                    )

                # Generate detailed result completeness report
                completeness_report = (
                    self.validation_manager.report_result_completeness(
                        validation_checkpoint
                    )
                )

                # Log detailed adjustment information
                if missing_scanners:
                    ASH_LOGGER.info(
                        f"Added missing scanners ({len(missing_scanners)}): {', '.join(missing_scanners)}"
                    )
                    for scanner_name in missing_scanners:
                        scanner_state = self.validation_manager.get_scanner_state(
                            scanner_name
                        )
                        if scanner_state and scanner_state.failure_reason:
                            ASH_LOGGER.info(
                                f"  - {scanner_name}: {scanner_state.failure_reason}"
                            )

                if unexpected_scanners:
                    ASH_LOGGER.info(
                        f"Found unexpected scanners ({len(unexpected_scanners)}): {', '.join(unexpected_scanners)}"
                    )

                # Add completeness report to aggregated results for debugging
                if not hasattr(
                    aggregated_results.metadata, "result_completeness_report"
                ):
                    aggregated_results.metadata.result_completeness_report = (
                        completeness_report
                    )

            # Add validation results to aggregated results for debugging
            checkpoint_dict = {
                "checkpoint_name": validation_checkpoint.checkpoint_name,
                "timestamp": validation_checkpoint.timestamp.isoformat(),
                "expected_scanners": validation_checkpoint.expected_scanners,
                "actual_scanners": validation_checkpoint.actual_scanners,
                "discrepancies": validation_checkpoint.discrepancies,
                "errors": validation_checkpoint.errors,
                "metadata": validation_checkpoint.metadata,
            }
            aggregated_results.validation_checkpoints.append(checkpoint_dict)

            # Add validation summary to metadata for easy access
            if not hasattr(aggregated_results.metadata, "validation_summary"):
                aggregated_results.metadata.validation_summary = {}

            aggregated_results.metadata.validation_summary[
                "result_completeness_validation"
            ] = {
                "timestamp": validation_checkpoint.timestamp.isoformat(),
                "expected_count": len(validation_checkpoint.expected_scanners),
                "final_count": len(validation_checkpoint.actual_scanners),
                "missing_count": len(missing_scanners),
                "unexpected_count": len(unexpected_scanners),
                "completeness_rate": validation_checkpoint.metadata.get(
                    "completeness_rate", 0.0
                ),
                "has_issues": validation_checkpoint.has_issues(),
            }

            # Log validation summary and notify via events
            if validation_checkpoint.has_issues():
                total_issues = len(validation_checkpoint.discrepancies) + len(
                    validation_checkpoint.errors
                )
                ASH_LOGGER.warning(
                    f"Result completeness validation completed with {total_issues} issues"
                )

                # Notify about validation issues
                try:
                    from automated_security_helper.plugins.events import AshEventType

                    self.notify_event(
                        AshEventType.WARNING,
                        message=f"Result completeness validation completed with {total_issues} issues",
                        total_issues=total_issues,
                        discrepancies=validation_checkpoint.discrepancies,
                        errors=validation_checkpoint.errors,
                        completeness_rate=validation_checkpoint.metadata.get(
                            "completeness_rate", 0.0
                        ),
                        phase="scan",
                        validation_checkpoint="result_completeness_validation",
                    )
                except Exception as event_error:
                    ASH_LOGGER.debug(
                        f"Failed to notify result completeness warning event: {str(event_error)}"
                    )
            else:
                completeness_rate = validation_checkpoint.metadata.get(
                    "completeness_rate", 0.0
                )
                ASH_LOGGER.info(
                    f"✅ Result completeness validation passed - completeness rate: {completeness_rate:.1%}"
                )

                # Notify about successful validation
                try:
                    from automated_security_helper.plugins.events import AshEventType

                    self.notify_event(
                        AshEventType.INFO,
                        message=f"Result completeness validation passed with {completeness_rate:.1%} completeness rate",
                        expected_count=len(validation_checkpoint.expected_scanners),
                        final_count=len(validation_checkpoint.actual_scanners),
                        completeness_rate=completeness_rate,
                        phase="scan",
                        validation_checkpoint="result_completeness_validation",
                    )
                except Exception as event_error:
                    ASH_LOGGER.debug(
                        f"Failed to notify result completeness info event: {str(event_error)}"
                    )

        except Exception as e:
            error_msg = f"Error during result completeness validation: {str(e)}"
            ASH_LOGGER.error(error_msg)

            # Notify about validation error via event system
            try:
                from automated_security_helper.plugins.events import AshEventType

                self.notify_event(
                    AshEventType.ERROR,
                    message=error_msg,
                    exception=str(e),
                    phase="scan",
                    validation_checkpoint="result_completeness_validation",
                )
            except Exception as event_error:
                ASH_LOGGER.debug(
                    f"Failed to notify result completeness error event: {str(event_error)}"
                )

            # Ensure scan continues despite validation error
            ASH_LOGGER.info(
                "🔄 Result completeness validation failed but scan will continue"
            )

            # Add stack trace for debugging
            import traceback

            ASH_LOGGER.debug(
                f"Result completeness validation error stack trace: {traceback.format_exc()}"
            )

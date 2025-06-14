"""Implementation of the Scan phase."""

import multiprocessing
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Any
from pathlib import Path

from automated_security_helper.base.engine_phase import EnginePhase
from automated_security_helper.core.constants import ASH_DEFAULT_SEVERITY_LEVEL
from automated_security_helper.core.enums import ExecutionPhase, ScannerStatus
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerSeverityCount,
    ScannerStatusInfo,
    ScannerTargetStatusInfo,
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


"""Implementation of the Scan phase."""


class ScanPhase(EnginePhase):
    """Implementation of the Scan phase."""

    @property
    def phase_name(self) -> str:
        """Return the name of this phase."""
        return "scan"

    def _execute_phase(
        self,
        aggregated_results: AshAggregatedResults,
        enabled_scanners: List[str] = None,
        excluded_scanners: List[str] = None,
        parallel: bool = True,
        max_workers: int = 4,
        global_ignore_paths: List[IgnorePathWithReason] = None,
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
            self.update_progress(10, "Building scanner queue...")

            # Print progress update
            ASH_LOGGER.info("Building scanner queue...")

            # Build queue of scanner tuples for execution
            self._queue = multiprocessing.Queue()

            # Register queue for automatic cleanup to prevent hangs
            from automated_security_helper.utils.multiprocessing_cleanup import (
                register_multiprocessing_queue,
            )

            register_multiprocessing_queue(self._queue)

            # Get all scanner plugins
            scanner_classes = self.plugins

            # Filter enabled scanners
            enabled_scanner_classes = []
            enabled_scanner_names = []

            # Process scanners
            if scanner_classes:
                ASH_LOGGER.debug(f"Processing {len(scanner_classes)} scanner classes")
                for plugin_class in scanner_classes:
                    try:
                        plugin_name = getattr(
                            plugin_class, "__name__", "Unknown"
                        ).lower()
                        ASH_LOGGER.debug(f"Processing scanner class: {plugin_name}")

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
                        ASH_LOGGER.debug(f"Created scanner instance for: {plugin_name}")

                        # Use the configured name if available
                        display_name = plugin_name
                        if hasattr(plugin_instance, "config") and hasattr(
                            plugin_instance.config, "name"
                        ):
                            display_name = plugin_instance.config.name
                        ASH_LOGGER.debug(f"Scanner display name: {display_name}")

                        # Check if scanner is in the excluded list
                        is_excluded = (
                            excluded_scanners
                            and display_name.lower().strip()
                            in [s.lower().strip() for s in excluded_scanners]
                        )
                        if is_excluded:
                            ASH_LOGGER.info(
                                f"Scanner {display_name} is excluded from running"
                            )

                            # Create a ScanResultsContainer with excluded=True
                            results_container = ScanResultsContainer(
                                scanner_name=display_name,
                                excluded=True,
                                status=ScannerStatus.SKIPPED,
                            )

                            # Add to results
                            aggregated_results.additional_reports[display_name] = {
                                "source": results_container.model_dump()
                            }

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

                            # Create a ScanResultsContainer with dependencies_satisfied=False
                            results_container = ScanResultsContainer(
                                scanner_name=display_name,
                                dependencies_satisfied=False,
                                status=ScannerStatus.MISSING,
                            )

                            # Add to results
                            aggregated_results.additional_reports[display_name] = {
                                "source": results_container.model_dump()
                            }

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
                            self._queue.put(
                                (
                                    display_name,
                                    plugin_instance,
                                    task_list,
                                )
                            )
                            enabled_scanner_classes.append(plugin_class)
                            enabled_scanner_names.append(display_name)
                            ASH_LOGGER.debug(
                                f"Added scanner {display_name} to execution queue"
                            )
                        else:
                            ASH_LOGGER.debug(
                                f"Scanner {display_name} did not pass final checks, skipping"
                            )
                    except Exception as e:
                        ASH_LOGGER.error(
                            f"Error checking scanner {getattr(plugin_class, '__name__', 'Unknown')}: {e}"
                        )
                        # Add stack trace for debugging
                        import traceback

                        ASH_LOGGER.debug(f"Stack trace: {traceback.format_exc()}")
            else:
                ASH_LOGGER.warning("No scanner classes found!")

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
                results = self._execute_parallel(aggregated_results=aggregated_results)
            else:
                # Update the main task to show we're executing scanners
                self.progress_display.update_task(
                    phase=ExecutionPhase.SCAN,
                    task_id=scan_task,
                    completed=40,
                    description=f"Executing {len(enabled_scanner_names)} scanners sequentially...",
                )
                self.update_progress(40, "Executing scanners sequentially...")
                results = self._execute_sequential(
                    aggregated_results=aggregated_results
                )
            if isinstance(results, AshAggregatedResults):
                aggregated_results = results

            # Update progress
            self.update_progress(90, "Finalizing scan results...")

            # Update the main task to show we're finalizing
            self.progress_display.update_task(
                phase=ExecutionPhase.SCAN,
                task_id=scan_task,
                completed=90,
                description="Finalizing scan results...",
            )

            # Save AshAggregatedResults as JSON alongside results if output_dir is configured
            if self.plugin_context.output_dir:
                ASH_LOGGER.debug(
                    f"Saving AshAggregatedResults to {self.plugin_context.output_dir}"
                )
                aggregated_results.save_model(self.plugin_context.output_dir)

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
            # Clean up multiprocessing resources
            if hasattr(self, "_queue") and self._queue is not None:
                from automated_security_helper.utils.multiprocessing_cleanup import (
                    cleanup_multiprocessing_queue,
                )

                cleanup_multiprocessing_queue(self._queue)
                self._queue = None

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
                try:
                    if scanner_config.enabled:
                        ASH_LOGGER.debug(
                            f"Executing {scanner_config.name or scanner_plugin.__class__.__name__}.scan() on {target_type}"
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
                            ).joinpath(scanner_config.name)
                        )

                        raw_results = scanner_plugin.scan(
                            target=scan_target,
                            config=scanner_config,
                            target_type=target_type,
                            global_ignore_paths=self._global_ignore_paths,
                        )
                    else:
                        ASH_LOGGER.warning(f"{scanner_config.name} is not enabled!")
                except Exception as e:
                    # Include stack trace for debugging
                    import traceback

                    stack_trace = traceback.format_exc()
                    ASH_LOGGER.debug(
                        f"Stack trace for scanner {scanner_name} failure:\n{stack_trace}"
                    )

                    err_str = f"Failed to execute {scanner_config.name or scanner_plugin.__class__.__name__} scanner on {target_type}: {e}"
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

                        # Apply suppressions based on global ignore paths
                        ASH_LOGGER.trace(
                            f"Ignoring paths: {self.plugin_context.config.global_settings.ignore_paths}"
                        )
                        raw_results = apply_suppressions_to_sarif(
                            sarif_report=raw_results,
                            plugin_context=self.plugin_context,
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

    def _execute_sequential(self, aggregated_results: AshAggregatedResults) -> None:
        """Execute scanners sequentially and update AshAggregatedResults."""
        # On MacOS, qsize() raises NotImplementedError, so we need to count items differently
        # First, get all items from the queue into a list
        scanner_tuples = []
        while not self._queue.empty():
            scanner_tuples.append(self._queue.get())

        # Now we know the total count
        total_scanners = len(scanner_tuples)
        completed = 0

        # Create a list of all scanner names for tracking remaining scanners
        all_scanner_names = [scanner_tuple[0] for scanner_tuple in scanner_tuples]
        remaining_scanners = all_scanner_names.copy()

        # Process each scanner
        for scanner_tuple in scanner_tuples:
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
                    ASH_LOGGER.info(f"Completed scanner: {scanner_name}")

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

    def _execute_parallel(self, aggregated_results: AshAggregatedResults) -> None:
        """Execute scanners in parallel and update AshAggregatedResults."""
        # Get all scanner tasks from the queue first to avoid qsize() which is not implemented on macOS
        scanner_tuples = []
        while True:
            try:
                scanner_tuple = self._queue.get(block=False)
                scanner_tuples.append(scanner_tuple)
            except Exception:
                break

        total_scanners = len(scanner_tuples)
        ASH_LOGGER.debug(f"Total scanners: {total_scanners}")
        scanner_tasks = {}

        # Create a list of all scanner names for tracking remaining scanners
        all_scanner_names = [scanner_tuple[0] for scanner_tuple in scanner_tuples]
        remaining_scanners = all_scanner_names.copy()
        # Use a lock to protect the remaining_scanners list in parallel execution
        import threading

        remaining_scanners_lock = threading.Lock()

        with ThreadPoolExecutor(max_workers=self._max_workers) as executor:
            futures = []

            # Submit all scanners to the thread pool
            for scanner_tuple in scanner_tuples:
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

                        # Update scanner task to show completion
                        if task_id is not None:
                            self.progress_display.update_task(
                                phase=ExecutionPhase.SCAN,
                                task_id=task_id,
                                completed=100,
                                description=f"[green]({scanner_name}) Completed scan",
                            )

                        # Log completion
                        ASH_LOGGER.info(f"Completed scanner: {scanner_name}")

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
        """
        from automated_security_helper.schemas.sarif_schema_model import SarifReport
        from automated_security_helper.schemas.cyclonedx_bom_1_6_schema import (
            CycloneDXReport,
        )

        # Store metrics in additional_reports for later use
        scanner_name = results.scanner_name
        if scanner_name not in aggregated_results.additional_reports:
            aggregated_results.additional_reports[scanner_name] = {}

        # Determine which is set first:
        # 1. results.scanner_severity_threshold
        # 2. aggregated_results.ash_config.global_settings.severity_threshold
        # 3. ASH_DEFAULT_SEVERITY_LEVEL
        evaluation_threshold = (
            results.scanner_severity_threshold
            if results.scanner_severity_threshold is not None
            else (
                aggregated_results.ash_config.global_settings.severity_threshold
                if aggregated_results.ash_config.global_settings.severity_threshold
                is not None
                else ASH_DEFAULT_SEVERITY_LEVEL
            )
        )

        for sev in [
            "suppressed",
            "critical",
            "high",
            "medium",
            "low",
            "info",
        ]:
            aggregated_results.metadata.summary_stats.bump(
                sev, results.severity_counts.get(sev, 0)
            )
            aggregated_results.metadata.summary_stats.bump(
                "total", results.severity_counts.get(sev, 0)
            )

        actionable = 0
        if evaluation_threshold == "ALL":
            actionable = results.severity_counts["total"]
        elif evaluation_threshold == "LOW":
            actionable = (
                results.severity_counts["critical"]
                + results.severity_counts["high"]
                + results.severity_counts["medium"]
                + results.severity_counts["low"]
            )
        elif evaluation_threshold == "MEDIUM":
            actionable = (
                results.severity_counts["critical"]
                + results.severity_counts["high"]
                + results.severity_counts["medium"]
            )
        elif evaluation_threshold == "HIGH":
            actionable = (
                results.severity_counts["critical"] + results.severity_counts["high"]
            )
        elif evaluation_threshold == "CRITICAL":
            actionable = results.severity_counts["critical"]

        aggregated_results.metadata.summary_stats.bump("actionable", actionable)

        # Only update if not already set (to maintain precedence)
        status = results.status
        if scanner_name not in aggregated_results.scanner_results:
            # Determine status based on actionable findings
            if (
                results.dependencies_satisfied
                and not results.excluded
                and actionable > 0
            ):
                status = ScannerStatus.FAILED
            elif results.excluded:
                status = ScannerStatus.SKIPPED
            elif not results.dependencies_satisfied:
                status = ScannerStatus.MISSING
            else:
                status = ScannerStatus.PASSED

            aggregated_results.scanner_results[scanner_name] = ScannerStatusInfo(
                status=status,
                dependencies_satisfied=results.dependencies_satisfied,
                excluded=results.excluded,
                severity_threshold=evaluation_threshold,
            )
        if (
            status != ScannerStatus.PASSED
            and aggregated_results.scanner_results[scanner_name].status
            == ScannerStatus.PASSED
        ):
            aggregated_results.scanner_results[scanner_name].status = status
        res = ScannerTargetStatusInfo(
            status=status,
            dependencies_satisfied=results.dependencies_satisfied,
            excluded=results.excluded,
            severity_counts=ScannerSeverityCount(**results.severity_counts),
            finding_count=results.finding_count,
            actionable_finding_count=actionable,
            suppressed_finding_count=results.severity_counts.get("suppressed", 0),
            exit_code=results.exit_code,
            duration=results.duration,
        )
        if results.target_type == "source":
            aggregated_results.scanner_results[scanner_name].source = res
        else:
            aggregated_results.scanner_results[scanner_name].converted = res
        ASH_LOGGER.verbose(
            aggregated_results.scanner_results[scanner_name].model_dump_json(
                exclude_unset=True, by_alias=True
            )
        )

        # Process the raw results based on type
        if isinstance(results.raw_results, SarifReport):
            # Sanitize paths in SARIF report to be relative to source directory
            sanitized_sarif = sanitize_sarif_paths(
                results.raw_results, self.plugin_context.source_dir
            )

            # Apply suppressions based on global ignore paths
            sanitized_sarif = apply_suppressions_to_sarif(
                sarif_report=sanitized_sarif,
                plugin_context=self.plugin_context,
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
            aggregated_results.cyclonedx = results.raw_results
        elif isinstance(results.raw_results, AshAggregatedResults):
            aggregated_results.merge_model(results.raw_results)
        else:
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

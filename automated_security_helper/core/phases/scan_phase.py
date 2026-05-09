"""Implementation of the Scan phase."""

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import json
from typing import Dict, List, Any, Tuple
from pathlib import Path

from automated_security_helper.base.engine_phase import EnginePhase
from automated_security_helper.core.enums import ExecutionPhase, ScannerStatus
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerSeverityCount,
    ScannerStatusInfo,
)
from automated_security_helper.models.scan_results_container import ScanResultsContainer
from automated_security_helper.base.scanner_plugin import ScannerPluginBase
from automated_security_helper.models.core import IgnorePathWithReason
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.get_ash_version import get_ash_version
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.sarif_utils import (
    get_severity_metrics_from_sarif,
    sanitize_sarif_paths,
    apply_suppressions_to_sarif,
)
from automated_security_helper.models.scanner_validation import ScannerValidationManager
from automated_security_helper.core.phases.scanner_executor import ScannerExecutor
from automated_security_helper.core.phases.scan_result_processor import ScanResultProcessor


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
        enabled_scanners: List[str] | None = None,
        excluded_scanners: List[str] | None = None,
        parallel: bool = True,
        max_workers: int = 4,
        global_ignore_paths: List[IgnorePathWithReason] | None = None,
        python_based_plugins_only: bool = False,
        **kwargs,
    ) -> AshAggregatedResults:
        """Coordinate the Scan phase: filter plugins, run executor, process results.

        Args:
            enabled_scanners: List of scanner names to enable
            parallel: Whether to run scanners in parallel
            max_workers: Maximum number of worker threads for parallel execution
            global_ignore_paths: List of paths to ignore globally
            **kwargs: Additional arguments

        Returns:
            AshAggregatedResults: Results of the scan
        """
        if enabled_scanners is None:
            enabled_scanners = []
        if excluded_scanners is None:
            excluded_scanners = []
        if global_ignore_paths is None:
            global_ignore_paths = []
        ASH_LOGGER.debug("Entering: ScanPhase.execute()")

        # Initialize progress
        self.initialize_progress("Initializing scan phase...")

        # Reset state for new execution
        self._completed_scanners = []
        self._scan_results = {}
        self._global_ignore_paths = global_ignore_paths or []
        self._max_workers = max_workers
        self._include_work_dir = any(self.plugin_context.work_dir.rglob("*.*"))

        # Build the result processor (owns _process_results and validation metrics)
        self._result_processor = ScanResultProcessor(
            plugin_context=self.plugin_context,
            validation_manager=self.validation_manager,
        )

        # Compute the source file list once so scanners don't each re-glob
        source_files = [
            str(p)
            for p in self.plugin_context.source_dir.rglob("*")
            if p.is_file()
        ]
        if self._include_work_dir:
            source_files.extend(
                str(p)
                for p in self.plugin_context.work_dir.rglob("*")
                if p.is_file()
            )
        # Store on the context so individual scanners can access it
        self.plugin_context.cached_source_files = source_files
        ASH_LOGGER.debug(
            f"Cached {len(source_files)} source files for scanner use"
        )

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
                            results_container = ScanResultsContainer.for_excluded(
                                display_name
                            )

                            # Process the container through _process_results to store duration info
                            aggregated_results = self._process_results(
                                results=results_container,
                                aggregated_results=aggregated_results,
                            )

                            # Do NOT add to completed scanners - this scanner was excluded and didn't run
                            # self._completed_scanners.append(plugin_instance)

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
                            plugin_instance.validate_plugin_dependencies()
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
                            results_container = ScanResultsContainer.for_missing_deps(
                                display_name
                            )

                            # Process the container through _process_results to store duration info
                            aggregated_results = self._process_results(
                                results=results_container,
                                aggregated_results=aggregated_results,
                            )

                            # Do NOT add to completed scanners - this scanner didn't actually run due to missing dependencies
                            # self._completed_scanners.append(plugin_instance)

                            aggregated_results.scanner_results[display_name] = (
                                ScannerStatusInfo(
                                    status=ScannerStatus.MISSING,
                                    dependencies_satisfied=False,
                                    excluded=False,
                                )
                            )

                            continue

                        # Use the shared helper for the enabled + python_only check.
                        # validate_plugin_dependencies is already checked above with full tracking.
                        # The helper also calls validate_plugin_dependencies internally; since
                        # we already know deps are satisfied at this point, the second call is
                        # a no-op that always returns True and does not change state.
                        is_in_enabled_scanners = (
                            not enabled_scanners
                            or display_name.lower().strip()
                            in [s.lower().strip() for s in enabled_scanners]
                        )

                        passes_enabled_and_python = bool(
                            self.filter_enabled_plugins(
                                plugin_instances=[plugin_instance],
                                plugin_context=self.plugin_context,
                                python_only=python_based_plugins_only,
                            )
                        )

                        is_enabled = hasattr(
                            plugin_instance.config, "enabled"
                        ) and bool(plugin_instance.config.enabled)
                        is_python_only_scanner = (
                            plugin_instance.is_python_only()
                            if python_based_plugins_only
                            else True
                        )

                        ASH_LOGGER.debug(
                            f"Scanner {display_name}: enabled={is_enabled}, in_enabled_list={is_in_enabled_scanners}"
                        )
                        if python_based_plugins_only:
                            ASH_LOGGER.info(
                                f"Scanner {display_name}: Python-only check result: {is_python_only_scanner}"
                            )

                        final_check = passes_enabled_and_python and is_in_enabled_scanners
                        ASH_LOGGER.debug(
                            f"Scanner {display_name}: final check result: {final_check}"
                        )

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
                            results_container = ScanResultsContainer.for_excluded(
                                display_name
                            )

                            # Process the container through _process_results to store duration info
                            aggregated_results = self._process_results(
                                results=results_container,
                                aggregated_results=aggregated_results,
                            )

                            # Do NOT add to completed scanners - this scanner was excluded and didn't run
                            # self._completed_scanners.append(plugin_instance)

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
            ASH_LOGGER.info("Scanner Filtering Summary:")
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

            # Build the executor, wiring it to our result processor
            executor = ScannerExecutor(
                plugin_context=self.plugin_context,
                progress_display=self.progress_display,
                scanner_tasks=self._scanner_tasks,
                max_workers=max_workers,
                notify_fn=self.notify_event,
                process_results_fn=self._result_processor.process_container,
            )
            # Propagate global_ignore_paths so _execute_scanner can use it
            executor._global_ignore_paths = self._global_ignore_paths

            # Execute scanners based on mode
            if parallel:
                self.progress_display.update_task(
                    phase=ExecutionPhase.SCAN,
                    task_id=scan_task,
                    completed=40,
                    description=f"Executing {len(enabled_scanner_names)} scanners in parallel...",
                )
                self.update_progress(40, "Executing scanners in parallel...")
                results = executor.run_parallel(aggregated_results)
            else:
                self.progress_display.update_task(
                    phase=ExecutionPhase.SCAN,
                    task_id=scan_task,
                    completed=40,
                    description=f"Executing {len(enabled_scanner_names)} scanners sequentially...",
                )
                self.update_progress(40, "Executing scanners sequentially...")
                results = executor.run_sequential(aggregated_results)

            if isinstance(results, AshAggregatedResults):
                aggregated_results = results

            # Sync completed_scanners back from executor for validation methods
            self._completed_scanners = executor.completed_scanners

            # Expose executor on self so delegation stubs (_execute_scanner etc.) work
            self._executor = executor

            # Validate execution completion after scanner execution
            self._validate_execution_completion(aggregated_results)

            # Update progress
            self.update_progress(90, "Finalizing scan results...")

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
                aggregated_results.save_model(self.plugin_context.output_dir)

            # Validate metrics consistency (optional - logs warnings if inconsistent)
            self._validate_metrics_consistency(aggregated_results)

            # Update progress to 100%
            self.update_progress(
                100, f"Scan complete: {len(self._completed_scanners)} scanners executed"
            )

            self.progress_display.update_task(
                phase=ExecutionPhase.SCAN,
                task_id=scan_task,
                completed=100,
                description=f"Scanners complete: {len(self._completed_scanners)} scanners executed",
            )

            self.add_summary(
                "Complete", f"Executed {len(self._completed_scanners)} scanners"
            )

            return aggregated_results

        except Exception as e:
            self.update_progress(100, f"Scan failed: {str(e)}")
            self.add_summary("Failed", f"Error: {str(e)}")
            ASH_LOGGER.error(f"Execution failed: {str(e)}")
            raise
        finally:
            if hasattr(self, "_scanner_tasks"):
                self._scanner_tasks = []

    def _extract_metrics_from_sarif(self, sarif_report: SarifReport):
        """Extract severity metrics from a SARIF report.

        Args:
            sarif_report: SARIF report to extract metrics from

        Returns:
            Tuple[ScannerSeverityCount, int]: Severity counts and total finding count

        Note:
            This method is kept for backward compatibility. For new code, use
            ScannerStatisticsCalculator.extract_sarif_counts_for_scanner instead.
        """
        from automated_security_helper.models.asharp_model import AshAggregatedResults

        # Create a temporary AshAggregatedResults with the SARIF report
        temp_model = AshAggregatedResults()
        temp_model.sarif = sarif_report

        sev_count = get_severity_metrics_from_sarif(
            sarif_report=sarif_report, plugin_context=self.plugin_context
        )

        total_findings = sev_count.total + sev_count.suppressed

        return sev_count, total_findings

    def _make_executor_for_delegation(self) -> "ScannerExecutor":
        """Return a ScannerExecutor suitable for direct method delegation in tests."""
        executor = ScannerExecutor(
            plugin_context=self.plugin_context,
            progress_display=self.progress_display,
            scanner_tasks=getattr(self, "_scanner_tasks", []),
            max_workers=getattr(self, "_max_workers", 4),
            notify_fn=self.notify_event,
            process_results_fn=getattr(
                getattr(self, "_result_processor", None),
                "process_container",
                lambda c, a: a,
            ),
        )
        executor._global_ignore_paths = getattr(self, "_global_ignore_paths", [])
        return executor

    def _execute_scanner(
        self,
        scanner_name: str,
        scanner_plugin: ScannerPluginBase,
        scan_targets: List[Dict[str, Any]],
    ) -> List[ScanResultsContainer]:
        """Delegate to ScannerExecutor._execute_scanner."""
        executor = self._make_executor_for_delegation()
        result = executor._execute_scanner(scanner_name, scanner_plugin, scan_targets)
        # Sync completed_scanners back
        self._completed_scanners = list(
            set(getattr(self, "_completed_scanners", []) + executor.completed_scanners)
        )
        return result

    def _execute_scanners_sequential(
        self, aggregated_results: AshAggregatedResults
    ) -> AshAggregatedResults | None:
        """Execute scanner_tasks one at a time, routing through self._safe_execute_scanner."""
        import traceback as _traceback

        total = len(self._scanner_tasks)
        completed = 0
        all_scanner_names = [t[0] for t in self._scanner_tasks]
        remaining_scanners = all_scanner_names.copy()

        for scanner_name, scanner_plugin, scan_targets in self._scanner_tasks:
            scanner_task = self.progress_display.add_task(
                phase=ExecutionPhase.SCAN,
                description=f"[cyan]({scanner_name}) Scanning directories...",
                total=100,
            )
            progress_percent = 40 + (completed / max(total, 1) * 50)
            self.update_progress(
                int(progress_percent),
                f"Running scanner {completed + 1}/{total}: {scanner_name}",
            )

            try:
                self.progress_display.update_task(
                    phase=ExecutionPhase.SCAN, task_id=scanner_task, completed=50
                )
                ASH_LOGGER.info(f"Running scanner: {scanner_name}")

                try:
                    from automated_security_helper.plugins.events import AshEventType

                    self.notify_event(
                        AshEventType.SCAN_START,
                        scanner=scanner_name,
                        scanner_class=scanner_plugin.__class__.__name__,
                        scan_targets=scan_targets,
                        message=f"Starting scanner: {scanner_name}",
                    )
                except Exception:
                    pass

                results_list = self._safe_execute_scanner(scanner_name, scanner_plugin, scan_targets)

                if results_list is None:
                    ASH_LOGGER.error(f"Scanner {scanner_name} returned None results")
                    failure_container = ScanResultsContainer.for_failure(
                        scanner_name, errors=[f"Scanner {scanner_name} failed with no results"]
                    )
                    failure_container.raw_results = {
                        "errors": [f"Scanner {scanner_name} failed with no results"],
                        "status": "failed",
                        "exception": "Scanner returned None results",
                    }
                    processed = self._process_results(failure_container, aggregated_results)
                    if isinstance(processed, AshAggregatedResults):
                        aggregated_results = processed
                    self.progress_display.update_task(
                        phase=ExecutionPhase.SCAN,
                        task_id=scanner_task,
                        completed=100,
                        description=f"[red]({scanner_name}) Failed: returned None results",
                    )
                else:
                    for results in results_list:
                        processed = self._process_results(results, aggregated_results)
                        if isinstance(processed, AshAggregatedResults):
                            aggregated_results = processed

                    self.progress_display.update_task(
                        phase=ExecutionPhase.SCAN,
                        task_id=scanner_task,
                        completed=100,
                        description=f"[green]({scanner_name}) Completed scan",
                    )
                    if scanner_name in remaining_scanners:
                        remaining_scanners.remove(scanner_name)

                    try:
                        from automated_security_helper.plugins.events import AshEventType

                        remaining_count = len(remaining_scanners)
                        remaining_list = ", ".join(remaining_scanners) if remaining_scanners else "None"
                        self.notify_event(
                            AshEventType.SCAN_COMPLETE,
                            scanner=scanner_name,
                            completed_count=completed + 1,
                            total_count=total,
                            remaining_count=remaining_count,
                            remaining_scanners=remaining_scanners,
                            message=f"Scanner {scanner_name} completed. {remaining_count} remaining: {remaining_list}",
                        )
                    except Exception:
                        pass

            except Exception as e:
                stack_trace = _traceback.format_exc()
                ASH_LOGGER.debug(f"Stack trace for scanner {scanner_name} failure:\n{stack_trace}")
                self.progress_display.update_task(
                    phase=ExecutionPhase.SCAN,
                    task_id=scanner_task,
                    completed=100,
                    description=f"[red]({scanner_name}) Failed: {str(e)}",
                )
                ASH_LOGGER.error(f"Scanner failed: {scanner_name} - {str(e)}")
                failure_container = ScanResultsContainer.for_failure(
                    scanner_name,
                    errors=[f"Scanner {scanner_name} failed: {str(e)}"],
                    exception=e,
                )
                failure_container.raw_results = {
                    "errors": [f"Scanner {scanner_name} failed: {str(e)}"],
                    "status": "failed",
                    "exception": str(e),
                    "stack_trace": stack_trace,
                }
                try:
                    processed = self._process_results(failure_container, aggregated_results)
                    if isinstance(processed, AshAggregatedResults):
                        aggregated_results = processed
                except Exception as process_error:
                    ASH_LOGGER.error(f"Failed to process error results for {scanner_name}: {str(process_error)}")
            finally:
                completed += 1

        return aggregated_results

    def _execute_scanners_parallel(
        self, aggregated_results: AshAggregatedResults
    ) -> AshAggregatedResults | None:
        """Execute scanner_tasks via ThreadPoolExecutor; falls back to sequential for single scanner."""
        import threading
        import traceback as _traceback

        total = len(self._scanner_tasks)
        if total <= 1:
            ASH_LOGGER.debug("Single scanner detected, executing directly")
            return self._execute_scanners_sequential(aggregated_results)

        scanner_tasks_map: Dict[str, Any] = {}
        all_scanner_names = [t[0] for t in self._scanner_tasks]
        remaining_scanners = all_scanner_names.copy()
        remaining_scanners_lock = threading.Lock()

        with ThreadPoolExecutor(max_workers=self._max_workers) as executor:
            futures = []
            for scanner_name, scanner_plugin, scan_targets in self._scanner_tasks:
                task_key = f"{scanner_name}_task"
                scanner_task = self.progress_display.add_task(
                    phase=ExecutionPhase.SCAN,
                    description=f"[magenta]({scanner_name}) Scanning directories...",
                    total=100,
                )
                scanner_tasks_map[task_key] = scanner_task
                self.progress_display.update_task(
                    phase=ExecutionPhase.SCAN,
                    task_id=scanner_task,
                    completed=10,
                    description=f"[blue]({scanner_name}) Queued scan...",
                )
                future = executor.submit(self._safe_execute_scanner, scanner_name, scanner_plugin, scan_targets)
                future.scanner_info = {"name": scanner_name, "task_key": task_key}
                futures.append(future)

            self.update_progress(50, f"Running {len(futures)} scanner tasks in parallel...")

            completed_count = 0
            for future in as_completed(futures):
                scanner_name = future.scanner_info["name"]
                task_key = future.scanner_info["task_key"]
                task_id = scanner_tasks_map.get(task_key)

                try:
                    results_list = future.result()

                    if results_list is None:
                        ASH_LOGGER.error(f"Scanner {scanner_name} returned None results")
                        failure_container = ScanResultsContainer.for_failure(
                            scanner_name, errors=[f"Scanner {scanner_name} failed with no results"]
                        )
                        failure_container.raw_results = {
                            "errors": [f"Scanner {scanner_name} failed with no results"],
                            "status": "failed",
                            "exception": "Scanner returned None results",
                        }
                        processed = self._process_results(failure_container, aggregated_results)
                        if isinstance(processed, AshAggregatedResults):
                            aggregated_results = processed
                        if task_id is not None:
                            self.progress_display.update_task(
                                phase=ExecutionPhase.SCAN,
                                task_id=task_id,
                                completed=100,
                                description=f"[red]({scanner_name}) Failed: returned None results",
                            )
                    else:
                        for results in results_list:
                            processed = self._process_results(results, aggregated_results)
                            if isinstance(processed, AshAggregatedResults):
                                aggregated_results = processed

                        scanner_plugin = None
                        for t in self._scanner_tasks:
                            if t[0] == scanner_name:
                                scanner_plugin = t[1]
                                break
                        if scanner_plugin is not None:
                            self._completed_scanners.append(scanner_plugin)

                        if task_id is not None:
                            self.progress_display.update_task(
                                phase=ExecutionPhase.SCAN,
                                task_id=task_id,
                                completed=100,
                                description=f"[green]({scanner_name}) Completed scan",
                            )

                        with remaining_scanners_lock:
                            if scanner_name in remaining_scanners:
                                remaining_scanners.remove(scanner_name)
                            try:
                                from automated_security_helper.plugins.events import AshEventType

                                remaining_count = len(remaining_scanners)
                                remaining_list = ", ".join(remaining_scanners) if remaining_scanners else "None"
                                self.notify_event(
                                    AshEventType.SCAN_COMPLETE,
                                    scanner=scanner_name,
                                    completed_count=completed_count + 1,
                                    total_count=total,
                                    remaining_count=remaining_count,
                                    remaining_scanners=remaining_scanners.copy(),
                                    message=f"Scanner {scanner_name} completed. {remaining_count} remaining: {remaining_list}",
                                )
                            except Exception:
                                pass

                except Exception as e:
                    stack_trace = _traceback.format_exc()
                    ASH_LOGGER.debug(f"Stack trace for scanner {scanner_name} thread failure:\n{stack_trace}")
                    if task_id is not None:
                        self.progress_display.update_task(
                            phase=ExecutionPhase.SCAN,
                            task_id=task_id,
                            completed=100,
                            description=f"[red]({scanner_name}) Failed: {str(e)}",
                        )
                    ASH_LOGGER.error(f"Scanner execution failed in thread pool: {scanner_name} - {str(e)}")
                    failure_container = ScanResultsContainer.for_failure(
                        scanner_name,
                        errors=[f"Scanner {scanner_name} failed in thread pool: {str(e)}"],
                        exception=e,
                    )
                    failure_container.raw_results = {
                        "errors": [f"Scanner {scanner_name} failed in thread pool: {str(e)}"],
                        "status": "failed",
                        "exception": str(e),
                        "stack_trace": stack_trace,
                    }
                    try:
                        processed = self._process_results(failure_container, aggregated_results)
                        if isinstance(processed, AshAggregatedResults):
                            aggregated_results = processed
                    except Exception as process_error:
                        ASH_LOGGER.error(f"Failed to process error results for {scanner_name}: {str(process_error)}")
                finally:
                    completed_count += 1
                    if len(futures) > 0:
                        progress_percent = 50 + (completed_count / len(futures) * 40)
                        self.update_progress(
                            int(progress_percent),
                            f"Completed {completed_count}/{len(futures)} scanner tasks",
                        )

        return aggregated_results

    def _process_results(
        self, results: ScanResultsContainer, aggregated_results: AshAggregatedResults
    ) -> AshAggregatedResults:
        """Delegate to ScanResultProcessor.process_container."""
        processor = getattr(
            self,
            "_result_processor",
            ScanResultProcessor(plugin_context=self.plugin_context),
        )
        return processor.process_container(results, aggregated_results)

    def _safe_execute_scanner(
        self,
        scanner_name: str,
        scanner_plugin: ScannerPluginBase,
        scan_targets: List[Dict[str, Any]],
    ) -> List[ScanResultsContainer]:
        """Safely execute a scanner, wrapping exceptions into failure containers."""
        import traceback as _traceback

        try:
            return self._execute_scanner(scanner_name, scanner_plugin, scan_targets)
        except Exception as e:
            stack_trace = _traceback.format_exc()
            error_msg = f"Unexpected error in scanner {scanner_name}: {str(e)}"
            ASH_LOGGER.error(error_msg)
            ASH_LOGGER.debug(f"Stack trace for scanner {scanner_name} failure:\n{stack_trace}")
            failure_container = ScanResultsContainer.for_failure(
                scanner_name, errors=[error_msg], exception=e
            )
            failure_container.raw_results = {
                "errors": [error_msg],
                "status": "failed",
                "exception": str(e),
                "stack_trace": stack_trace,
            }
            try:
                from automated_security_helper.plugins.events import AshEventType

                self.notify_event(AshEventType.ERROR, message=error_msg, scanner=scanner_name, exception=e)
            except Exception:
                pass
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
                ASH_LOGGER.info("Scanner tasks validation completed successfully")

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
                    f"Execution completion validation passed - completion rate: {completion_rate:.1%}"
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
            ASH_LOGGER.info("Validating result completeness...")

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
                    setattr(
                        aggregated_results.metadata,
                        "result_completeness_report",
                        completeness_report,
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
                    f"Result completeness validation passed - completeness rate: {completeness_rate:.1%}"
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

"""Implementation of the Scan phase."""

import multiprocessing
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Any
from pathlib import Path

from automated_security_helper.base.engine_phase import EnginePhase
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.core.progress import ExecutionPhase
from automated_security_helper.core.scanner_factory import ScannerFactory
from automated_security_helper.core.plugin_registry import PluginRegistry, PluginType
from automated_security_helper.models.asharp_model import ASHARPModel
from automated_security_helper.models.scan_results_container import ScanResultsContainer
from automated_security_helper.base.scanner_plugin import ScannerPluginBase
from automated_security_helper.models.core import IgnorePathWithReason
from automated_security_helper.utils.log import ASH_LOGGER


class ScanPhase(EnginePhase):
    """Implementation of the Scan phase."""

    @property
    def phase_name(self) -> str:
        """Return the name of this phase."""
        return "scan"

    def execute(
        self,
        scanner_factory: ScannerFactory,
        plugin_registry: PluginRegistry,
        enabled_scanners: List[str] = None,
        parallel: bool = True,
        max_workers: int = 4,
        global_ignore_paths: List[IgnorePathWithReason] = None,
        **kwargs,
    ) -> ASHARPModel:
        """Execute the Scan phase.

        Args:
            scanner_factory: Factory for creating scanners
            plugin_registry: Registry of plugins to use
            enabled_scanners: List of scanner names to enable
            parallel: Whether to run scanners in parallel
            max_workers: Maximum number of worker threads for parallel execution
            global_ignore_paths: List of paths to ignore globally
            **kwargs: Additional arguments

        Returns:
            ASHARPModel: Results of the scan
        """
        ASH_LOGGER.debug("Entering: ScanPhase.execute()")

        # Initialize progress
        self.initialize_progress("Initializing scan phase...")

        # Reset state for new execution
        self._completed_scanners = []
        self._scan_results = {}
        self._global_ignore_paths = global_ignore_paths or []
        self._max_workers = max_workers

        try:
            # Update progress
            self.update_progress(10, "Building scanner queue...")

            # Print progress update
            ASH_LOGGER.info("Building scanner queue...")

            # Build queue of scanner tuples for execution
            self._queue = multiprocessing.Queue()

            # Get all enabled scanners
            scanner_configs = scanner_factory.available_scanners()
            ASH_LOGGER.debug(f"Scanner configs: {scanner_configs}")

            # Update progress
            self.update_progress(
                20, f"Found {len(scanner_configs)} scanner configurations"
            )

            final_enabled_scanners = set()

            # Process scanners
            if scanner_configs:
                for scanner_name, scanner_plugin_class in scanner_configs.items():
                    if scanner_plugin_class:
                        # Add scanner to execution queue with default target
                        scanner_plugin_class_instance = scanner_plugin_class(
                            config=(
                                self.config.get_plugin_config(
                                    plugin_type=PluginType.scanner,
                                    plugin_name=scanner_name,
                                )
                                if self.config is not None
                                else None
                            ),
                            context=PluginContext(
                                source_dir=self.source_dir,
                                output_dir=self.output_dir,
                                work_dir=self.work_dir,
                            ),
                            source_dir=self.source_dir,
                            output_dir=self.output_dir,
                        )
                        if (
                            hasattr(scanner_plugin_class_instance.config, "enabled")
                            and bool(scanner_plugin_class_instance.config.enabled)
                            and (
                                not enabled_scanners
                                or scanner_name.lower().strip() in enabled_scanners
                            )
                        ):
                            # Add a single task per scanner that will handle both source and converted directories
                            self._queue.put(
                                (
                                    scanner_name,
                                    scanner_plugin_class_instance,
                                    [
                                        {"path": self.source_dir, "type": "source"},
                                        {"path": self.work_dir, "type": "converted"},
                                    ],
                                )
                            )
                            final_enabled_scanners.add(scanner_name)

            # Update progress
            self.update_progress(
                30, f"Prepared {len(final_enabled_scanners)} scanners for execution"
            )

            # Execute scanners based on mode
            if parallel:
                self.update_progress(40, "Executing scanners in parallel...")
                self._execute_parallel()
            else:
                self.update_progress(40, "Executing scanners sequentially...")
                self._execute_sequential()

            # Update progress
            self.update_progress(90, "Finalizing scan results...")

            # Save ASHARPModel as JSON alongside results if output_dir is configured
            if self.output_dir:
                ASH_LOGGER.debug(f"Saving ASHARPModel to {self.output_dir}")
                self.asharp_model.save_model(self.output_dir)

            # Update progress to 100%
            self.update_progress(
                100, f"Scan complete: {len(self._completed_scanners)} scanners executed"
            )

            # Add summary row
            # self.add_summary(
            #     "Complete", f"Executed {len(self._completed_scanners)} scanners"
            # )

            return self.asharp_model

        except Exception as e:
            # Update progress to show error
            self.update_progress(100, f"Scan failed: {str(e)}")

            # Add error to summary
            # self.add_summary("Failed", f"Error: {str(e)}")

            ASH_LOGGER.error(f"Execution failed: {str(e)}")
            raise

    def _extract_metrics_from_sarif(self, sarif_report):
        """Extract severity metrics from a SARIF report.

        Args:
            sarif_report: SARIF report to extract metrics from

        Returns:
            Tuple[Dict[str, int], int]: Severity counts and total finding count
        """
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        total_findings = 0

        if hasattr(sarif_report, "runs") and sarif_report.runs:
            for run in sarif_report.runs:
                if hasattr(run, "results") and run.results:
                    for result in run.results:
                        total_findings += 1
                        # Map SARIF level to our severity levels
                        if hasattr(result, "level"):
                            if result.level == "error":
                                severity_counts["high"] += 1
                            elif result.level == "warning":
                                severity_counts["medium"] += 1
                            elif result.level == "note":
                                severity_counts["low"] += 1
                            else:
                                severity_counts["info"] += 1
                        else:
                            severity_counts["info"] += 1

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
                            scanner_plugin.context = PluginContext(
                                source_dir=self.source_dir,
                                output_dir=self.output_dir,
                                work_dir=self.work_dir,
                            )

                        # Ensure scanner output paths are set correctly
                        scanner_plugin.source_dir = self.source_dir
                        scanner_plugin.output_dir = self.output_dir
                        scanner_plugin.work_dir = self.work_dir
                        scanner_plugin.results_dir = self.output_dir.joinpath(
                            "scanners"
                        ).joinpath(scanner_config.name)

                        raw_results = scanner_plugin.scan(
                            target=scan_target,
                            config=scanner_config,
                            target_type=target_type,
                            global_ignore_paths=self._global_ignore_paths,
                        )
                    else:
                        ASH_LOGGER.warning(f"{scanner_config.name} is not enabled!")
                except Exception as e:
                    err_str = f"Failed to execute {scanner_config.name or scanner_plugin.__class__.__name__} scanner on {target_type}: {e}"
                    ASH_LOGGER.error(err_str)
                    raw_results = {
                        "errors": [
                            err_str,
                            *scanner_plugin.errors,
                        ],
                        "output": scanner_plugin.output,
                    }
                finally:
                    ASH_LOGGER.trace(
                        f"{scanner_plugin.__class__.__name__} raw_results for {target_type}: {raw_results}"
                    )
                    if raw_results is None:
                        raw_results = {
                            "errors": scanner_plugin.errors or [],
                            "output": scanner_plugin.output or [],
                        }

                    # Set raw results
                    container.raw_results = raw_results

                    # Extract metrics based on result type
                    from automated_security_helper.schemas.sarif_schema_model import (
                        SarifReport,
                    )

                    if isinstance(raw_results, SarifReport):
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
                    if (
                        container.severity_counts.get("critical", 0) > 0
                        or container.severity_counts.get("high", 0) > 0
                    ):
                        container.status = "failed"
                    elif container.severity_counts.get("medium", 0) > 0:
                        container.status = "warning"
                    else:
                        container.status = "passed"

                    # Extract and add metadata if present
                    if isinstance(raw_results, dict) and "metadata" in raw_results:
                        for key, value in raw_results["metadata"].items():
                            container.add_metadata(key, value)

                    # Add this container to our results
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

    def _execute_sequential(self) -> None:
        """Execute scanners sequentially and update ASHARPModel."""
        # On MacOS, qsize() raises NotImplementedError, so we need to count items differently
        # First, get all items from the queue into a list
        scanner_tuples = []
        while not self._queue.empty():
            scanner_tuples.append(self._queue.get())

        # Now we know the total count
        total_scanners = len(scanner_tuples)
        completed = 0

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

                results_list = self._execute_scanner(
                    scanner_name=scanner_name,
                    scanner_plugin=scanner_plugin,
                    scan_targets=scan_targets,
                )

                # Process each result
                for results in results_list:
                    self._process_results(results)

                # Update scanner task to 100%
                self.progress_display.update_task(
                    phase=ExecutionPhase.SCAN,
                    task_id=scanner_task,
                    completed=100,
                    description=f"[green]({scanner_name}) Completed scan",
                )

                # Log completion
                ASH_LOGGER.info(f"Completed scanner: {scanner_name}")

            except Exception as e:
                # Update scanner task to show error
                self.progress_display.update_task(
                    phase=ExecutionPhase.SCAN,
                    task_id=scanner_task,
                    completed=100,
                    description=f"[red]({scanner_name}) Failed: {str(e)}",
                )

                # Log error but continue with other scanners
                ASH_LOGGER.error(f"Scanner failed: {scanner_name} - {str(e)}")

                # Don't re-raise the exception so we can continue with other scanners
            finally:
                completed += 1

    def _execute_parallel(self) -> None:
        """Execute scanners in parallel and update ASHARPModel."""
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
                    self._execute_scanner,
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
                try:
                    ASH_LOGGER.debug("Getting results from completed future")
                    results_list = future.result()
                    ASH_LOGGER.debug("Got results from completed future, processing")

                    # Process each result in the list
                    for results in results_list:
                        self._process_results(results)

                    # Update scanner task to show completion
                    scanner_name = future.scanner_info["name"]
                    task_key = future.scanner_info["task_key"]
                    task_id = scanner_tasks.get(task_key)

                    if task_id is not None:
                        self.progress_display.update_task(
                            phase=ExecutionPhase.SCAN,
                            task_id=task_id,
                            completed=100,
                            description=f"[green]({scanner_name}) Completed scan",
                        )

                    # Log completion
                    ASH_LOGGER.info(f"Completed scanner: {scanner_name}")

                    # Update main scan task progress
                    completed_count += 1
                    if len(futures) > 0:  # Avoid division by zero
                        progress_percent = 50 + (completed_count / len(futures) * 40)
                        self.update_progress(
                            int(progress_percent),
                            f"Completed {completed_count}/{len(futures)} scanner tasks",
                        )

                except Exception as e:
                    # Update scanner task to show error
                    scanner_name = future.scanner_info["name"]
                    task_key = future.scanner_info["task_key"]
                    task_id = scanner_tasks.get(task_key)

                    if task_id is not None:
                        self.progress_display.update_task(
                            phase=ExecutionPhase.SCAN,
                            task_id=task_id,
                            completed=100,
                            description=f"[red]({scanner_name}) Failed: {str(e)}",
                        )

                    # Log error but continue with other scanners
                    ASH_LOGGER.error(
                        f"Scanner execution failed: {scanner_name} - {str(e)}"
                    )

                    # Still count this as completed for progress tracking
                    completed_count += 1
                    if len(futures) > 0:  # Avoid division by zero
                        progress_percent = 50 + (completed_count / len(futures) * 40)
                        self.update_progress(
                            int(progress_percent),
                            f"Completed {completed_count}/{len(futures)} scanner tasks (with errors)",
                        )

    def _process_results(self, results: ScanResultsContainer) -> None:
        """Process scanner results and update ASHARPModel.

        Args:
            results: Container with scanner results
        """
        from automated_security_helper.schemas.sarif_schema_model import SarifReport
        from automated_security_helper.schemas.cyclonedx_bom_1_6_schema import (
            CycloneDXReport,
        )

        # Store metrics in additional_reports for later use
        scanner_name = results.scanner_name
        if scanner_name not in self.asharp_model.additional_reports:
            self.asharp_model.additional_reports[scanner_name] = {}

        # Store metrics in the additional_reports
        self.asharp_model.additional_reports[scanner_name][results.target_type] = {
            "severity_counts": results.severity_counts,
            "finding_count": results.finding_count,
            "exit_code": results.exit_code,
            "status": results.status,
            "raw_results": results.raw_results,
        }

        # Process the raw results based on type
        if isinstance(results.raw_results, SarifReport):
            self.asharp_model.sarif.merge_sarif_report(results.raw_results)
        elif isinstance(results.raw_results, ASHARPModel):
            self.asharp_model.merge_model(results.raw_results)
        elif isinstance(results.raw_results, CycloneDXReport):
            self.asharp_model.cyclonedx = results.raw_results

"""ScannerExecutor — owns scanner task lifecycle for ScanPhase."""

import traceback
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from automated_security_helper.base.scanner_plugin import ScannerPluginBase
from automated_security_helper.core.enums import ExecutionPhase, ScannerStatus
from automated_security_helper.models.asharp_model import AshAggregatedResults, ScannerSeverityCount
from automated_security_helper.models.scan_results_container import ScanResultsContainer
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.sarif_utils import (
    apply_suppressions_to_sarif,
    sanitize_sarif_paths,
)

_ResultsFn = Callable[[ScanResultsContainer, AshAggregatedResults], AshAggregatedResults]


class ScannerExecutor:
    """Runs scanner tasks in parallel or sequential mode.

    Parameters
    ----------
    plugin_context:
        Shared plugin context (paths, config, …).
    progress_display:
        Progress display instance (may be a mock in tests).
    scanner_tasks:
        List of (scanner_name, plugin_instance, scan_targets) triples.
    max_workers:
        Thread-pool size for parallel execution.
    notify_fn:
        Optional callable(event_type, **kwargs) wired to the parent phase's
        notify_event.  When None, event notifications are silently skipped.
    process_results_fn:
        Callable(container, aggregated) → AshAggregatedResults.  Wired to
        ScanResultProcessor.process_container by ScanPhase.
    """

    def __init__(
        self,
        plugin_context: Any,
        progress_display: Any,
        scanner_tasks: List[Tuple[str, ScannerPluginBase, List[Dict[str, Any]]]],
        max_workers: int = 4,
        notify_fn: Optional[Callable[..., Any]] = None,
        process_results_fn: Optional[_ResultsFn] = None,
    ) -> None:
        self.plugin_context = plugin_context
        self.progress_display = progress_display
        self.scanner_tasks = scanner_tasks
        self.max_workers = max_workers
        self._notify_fn = notify_fn
        self._process_fn: _ResultsFn = process_results_fn or (lambda c, a: a)  # type: ignore[assignment]
        self.completed_scanners: List[ScannerPluginBase] = []
        # Populated by caller when scanner must respect ignored paths
        self._global_ignore_paths: List[Any] = []

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _notify(self, event_type: Any, **kwargs: Any) -> None:
        if self._notify_fn is not None:
            try:
                self._notify_fn(event_type, **kwargs)
            except Exception as e:
                ASH_LOGGER.error(f"Failed to notify event {event_type}: {e}")

    def _process_results_fn(
        self,
        results: ScanResultsContainer,
        aggregated_results: AshAggregatedResults,
    ) -> AshAggregatedResults:
        """Forward to the injected process function, or no-op if not wired."""
        return self._process_fn(results, aggregated_results)

    # ------------------------------------------------------------------
    # Single-scanner execution
    # ------------------------------------------------------------------

    def _execute_scanner(
        self,
        scanner_name: str,
        scanner_plugin: ScannerPluginBase,
        scan_targets: List[Dict[str, Any]],
    ) -> List[ScanResultsContainer]:
        """Execute a single scanner across all its targets."""
        results: List[ScanResultsContainer] = []

        try:
            ASH_LOGGER.debug("EVALUATING CONFIGURED SCANNERS")
            scanner_config = scanner_plugin.config
            if scanner_config is None:
                raise ValueError(f"Scanner {scanner_name} has no config")
            ASH_LOGGER.debug(f"scanner_plugin.config: {scanner_config}")

            for target_info in scan_targets:
                scan_target = target_info["path"]
                target_type = target_info["type"]

                if not scan_target or not Path(scan_target).exists():
                    ASH_LOGGER.debug(
                        f"Skipping {target_type} directory {scan_target} - does not exist"
                    )
                    continue

                container = ScanResultsContainer(
                    scanner_name=str(scanner_config.name),
                    target=scan_target,
                    target_type=target_type,
                    scanner_severity_threshold=scanner_config.options.severity_threshold,
                )

                raw_results: Any = None
                scanner_config_name: str = str(scanner_config.name) if scanner_config else scanner_plugin.__class__.__name__
                try:
                    if scanner_config and scanner_config.enabled:
                        ASH_LOGGER.debug(f"Executing {scanner_config_name}.scan() on {target_type}")
                        if not hasattr(scanner_plugin, "context") or scanner_plugin.context is None:
                            scanner_plugin.context = self.plugin_context
                        scanner_plugin.results_dir = (
                            self.plugin_context.output_dir.joinpath("scanners").joinpath(scanner_config_name)
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
                    stack_trace = traceback.format_exc()
                    ASH_LOGGER.debug(f"Stack trace for scanner {scanner_name} failure:\n{stack_trace}")
                    err_str = f"Failed to execute {scanner_config_name} scanner on {target_type}: {e}"
                    ASH_LOGGER.error(err_str)
                    raw_results = {
                        "errors": [err_str, *scanner_plugin.errors],
                        "output": scanner_plugin.output,
                        "status": "failed",
                        "exception": str(e),
                        "stack_trace": stack_trace,
                    }
                    try:
                        from automated_security_helper.plugins.events import AshEventType
                        self._notify(AshEventType.ERROR, message=err_str, scanner=scanner_name, exception=e)
                    except Exception:
                        pass
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
                            f"Scanner {scanner_plugin.__class__.__name__} returned False for {target_type} "
                            "-- plugin is missing dependencies"
                        )
                        container.status = ScannerStatus.MISSING

                    container.start_time = scanner_plugin.start_time
                    container.end_time = scanner_plugin.end_time
                    container.duration = None
                    try:
                        if isinstance(scanner_plugin.end_time, datetime) and isinstance(
                            scanner_plugin.start_time, datetime
                        ):
                            container.duration = (
                                scanner_plugin.end_time - scanner_plugin.start_time
                            ).total_seconds()
                    except Exception as dur_e:
                        ASH_LOGGER.debug(
                            f"Error calculating duration for scanner {scanner_config_name}: {dur_e}"
                        )
                    container.raw_results = raw_results

                    from automated_security_helper.schemas.sarif_schema_model import SarifReport

                    if isinstance(raw_results, SarifReport):
                        raw_results = sanitize_sarif_paths(raw_results, self.plugin_context.source_dir)
                        if not self.plugin_context.ignore_suppressions:
                            raw_results = apply_suppressions_to_sarif(
                                sarif_report=raw_results,
                                plugin_context=self.plugin_context,
                            )
                        severity_counts, finding_count = self._extract_metrics_from_sarif(raw_results)
                        container.severity_counts = severity_counts
                        container.finding_count = finding_count
                    elif isinstance(raw_results, dict):
                        if "status" in raw_results and raw_results["status"] == "failed":
                            container.status = ScannerStatus.ERROR
                        else:
                            if "severity_counts" in raw_results:
                                raw_counts = raw_results["severity_counts"]
                                if isinstance(raw_counts, ScannerSeverityCount):
                                    container.severity_counts = raw_counts
                                else:
                                    container.severity_counts = ScannerSeverityCount.model_validate(raw_counts)
                                container.finding_count = sum(
                                    int(v)
                                    for v in (
                                        raw_counts.values()
                                        if isinstance(raw_counts, dict)
                                        else raw_counts.model_dump().values()
                                    )
                                )
                            elif "findings" in raw_results and isinstance(raw_results["findings"], list):
                                for finding in raw_results["findings"]:
                                    if "severity" in finding:
                                        severity = finding["severity"].lower()
                                        try:
                                            container.severity_counts.increment(severity)
                                        except ValueError:
                                            container.severity_counts.increment("info")
                                container.finding_count = len(raw_results["findings"])

                    container.exit_code = getattr(scanner_plugin, "exit_code", 0)
                    if container.status != ScannerStatus.ERROR:
                        container.status = container.determine_status(
                            scanner_config.options.severity_threshold
                        )
                    if isinstance(raw_results, dict) and "metadata" in raw_results:
                        for key, value in raw_results["metadata"].items():
                            container.add_metadata(key, value)

                    results.append(container)

            return results

        except Exception as e:
            ASH_LOGGER.error(f"Failed to execute {scanner_plugin.__class__.__name__} scanner: {e}")
            raise

    def _extract_metrics_from_sarif(self, sarif_report: Any) -> Any:
        """Extract severity metrics from a SARIF report."""
        from automated_security_helper.utils.sarif_utils import get_severity_metrics_from_sarif
        return get_severity_metrics_from_sarif(sarif_report, self.plugin_context)

    def _safe_execute_scanner(
        self,
        scanner_name: str,
        scanner_plugin: ScannerPluginBase,
        scan_targets: List[Dict[str, Any]],
    ) -> Tuple[List[ScanResultsContainer], bool]:
        """Wrap _execute_scanner so unexpected exceptions become failure containers.

        Returns a tuple of (results, succeeded) where succeeded is False when
        _execute_scanner raised an unhandled exception.  Callers use the flag to
        decide whether to record the scanner in completed_scanners.
        """
        try:
            return self._execute_scanner(scanner_name, scanner_plugin, scan_targets), True
        except Exception as e:
            stack_trace = traceback.format_exc()
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
                self._notify(AshEventType.ERROR, message=error_msg, scanner=scanner_name, exception=e)
            except Exception:
                pass

            return [failure_container], False

    # ------------------------------------------------------------------
    # Sequential execution
    # ------------------------------------------------------------------

    def run_sequential(self, aggregated_results: AshAggregatedResults) -> AshAggregatedResults:
        """Execute scanner_tasks one at a time."""
        total = len(self.scanner_tasks)
        completed = 0
        all_scanner_names = [t[0] for t in self.scanner_tasks]
        remaining_scanners = all_scanner_names.copy()

        for scanner_name, scanner_plugin, scan_targets in self.scanner_tasks:
            scanner_task = self.progress_display.add_task(
                phase=ExecutionPhase.SCAN,
                description=f"[cyan]({scanner_name}) Scanning directories...",
                total=100,
            )
            progress_percent = 40 + (completed / max(total, 1) * 50)
            self._update_progress(
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
                    self._notify(
                        AshEventType.SCAN_START,
                        scanner=scanner_name,
                        scanner_class=scanner_plugin.__class__.__name__,
                        scan_targets=scan_targets,
                        message=f"Starting scanner: {scanner_name}",
                    )
                except Exception:
                    pass

                results_list, scanner_succeeded = self._safe_execute_scanner(
                    scanner_name, scanner_plugin, scan_targets
                )

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
                    processed = self._process_results_fn(failure_container, aggregated_results)
                    aggregated_results = processed
                    self.progress_display.update_task(
                        phase=ExecutionPhase.SCAN,
                        task_id=scanner_task,
                        completed=100,
                        description=f"[red]({scanner_name}) Failed: returned None results",
                    )
                else:
                    for r in results_list:
                        processed = self._process_results_fn(r, aggregated_results)
                        aggregated_results = processed

                    if scanner_succeeded:
                        ASH_LOGGER.debug(
                            f"Appending {scanner_plugin.__class__.__name__} to completed_scanners"
                        )
                        self.completed_scanners.append(scanner_plugin)

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
                        self._notify(
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
                stack_trace = traceback.format_exc()
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
                    processed = self._process_results_fn(failure_container, aggregated_results)
                    aggregated_results = processed
                except Exception as process_error:
                    ASH_LOGGER.error(f"Failed to process error results for {scanner_name}: {str(process_error)}")
            finally:
                completed += 1

        return aggregated_results

    # ------------------------------------------------------------------
    # Parallel execution
    # ------------------------------------------------------------------

    def run_parallel(self, aggregated_results: AshAggregatedResults) -> AshAggregatedResults:
        """Execute scanner_tasks via a ThreadPoolExecutor."""
        import threading

        total = len(self.scanner_tasks)
        ASH_LOGGER.debug(f"Total scanners: {total}")

        if total <= 1:
            ASH_LOGGER.debug("Single scanner detected, executing directly")
            return self.run_sequential(aggregated_results)

        scanner_tasks_map: Dict[str, Any] = {}
        all_scanner_names = [t[0] for t in self.scanner_tasks]
        remaining_scanners = all_scanner_names.copy()
        remaining_scanners_lock = threading.Lock()

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures: List[Future[Tuple[List[ScanResultsContainer], bool]]] = []

            for scanner_name, scanner_plugin, scan_targets in self.scanner_tasks:
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
                ASH_LOGGER.debug(f"Submitting {scanner_name} to thread pool")
                future = executor.submit(
                    self._safe_execute_scanner, scanner_name, scanner_plugin, scan_targets
                )
                future.scanner_name = scanner_name  # type: ignore[attr-defined]
                future.scanner_task_key = task_key  # type: ignore[attr-defined]
                futures.append(future)

            self._update_progress(50, f"Running {len(futures)} scanner tasks in parallel...")

            completed_count = 0
            for future in as_completed(futures):
                scanner_name = future.scanner_name  # type: ignore[attr-defined]
                task_key = future.scanner_task_key  # type: ignore[attr-defined]
                task_id = scanner_tasks_map.get(task_key)

                try:
                    results_list, scanner_succeeded = future.result()

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
                        processed = self._process_results_fn(failure_container, aggregated_results)
                        aggregated_results = processed
                        if task_id is not None:
                            self.progress_display.update_task(
                                phase=ExecutionPhase.SCAN,
                                task_id=task_id,
                                completed=100,
                                description=f"[red]({scanner_name}) Failed: returned None results",
                            )
                    else:
                        ASH_LOGGER.debug(f"Got results from {scanner_name}, processing")
                        for r in results_list:
                            processed = self._process_results_fn(r, aggregated_results)
                            aggregated_results = processed

                        if scanner_succeeded:
                            plugin_inst = next(
                                (t[1] for t in self.scanner_tasks if t[0] == scanner_name), None
                            )
                            if plugin_inst is not None:
                                ASH_LOGGER.debug(
                                    f"Appending {scanner_name} to completed_scanners"
                                )
                                self.completed_scanners.append(plugin_inst)

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
                                self._notify(
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
                    stack_trace = traceback.format_exc()
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
                        processed = self._process_results_fn(failure_container, aggregated_results)
                        aggregated_results = processed
                    except Exception as process_error:
                        ASH_LOGGER.error(f"Failed to process error results for {scanner_name}: {str(process_error)}")

                finally:
                    completed_count += 1
                    if futures:
                        progress_percent = 50 + (completed_count / len(futures) * 40)
                        self._update_progress(
                            int(progress_percent),
                            f"Completed {completed_count}/{len(futures)} scanner tasks",
                        )

        return aggregated_results

    # ------------------------------------------------------------------
    # Progress helper
    # ------------------------------------------------------------------

    def _update_progress(self, completed: int, description: str) -> None:
        """No-op when progress_display lacks phase_task."""
        try:
            phase_task = getattr(self.progress_display, "phase_task", None)
            if phase_task is not None:
                self.progress_display.update_task(
                    phase=ExecutionPhase.SCAN,
                    task_id=phase_task,
                    completed=completed,
                    description=description,
                )
        except Exception:
            pass

"""Implementation of the Report phase."""

from pathlib import Path
import traceback
from typing import Dict, Iterable, List, Sequence
from automated_security_helper.base.engine_phase import EnginePhase
from automated_security_helper.base.reporter_plugin import (
    reporter_format_name,
    reporter_matches_requested_formats,
)
from automated_security_helper.core.enums import ExecutionPhase
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.utils.log import ASH_LOGGER

#: A reporter for this format exists but was not selected -- it is disabled in
#: config, its dependencies are unsatisfied, or ``--python-based-plugins-only``
#: excluded it. Distinguished from :data:`FORMAT_NO_REPORTER` because the two send
#: the operator somewhere different: this one is a config or environment change,
#: and the other will not work however it is configured.
FORMAT_REPORTER_UNAVAILABLE = "reporter-unavailable"

#: No reporter produces this format at all. ``ExportFormat`` carries members that
#: name no reporter -- ``aggregated`` and ``dict`` are internal result shapes
#: rather than report formats, ``asff`` is the Security Hub reporter's payload but
#: that reporter is named ``aws-security-hub``, and ``custom`` is a placeholder --
#: so the CLI accepts all of them and only this check tells the operator that
#: asking for one produces nothing.
FORMAT_NO_REPORTER = "no-reporter"


def unsatisfied_output_formats(
    output_formats: Iterable[object],
    selected_instances: Sequence[object],
    all_instances: Sequence[object],
) -> Dict[str, str]:
    """Requested formats that will produce no report, and why.

    Why this exists
    ---------------
    ``--output-formats`` is validated against ``ExportFormat`` at the CLI, so a
    typo fails loudly. What did *not* fail loudly was naming a perfectly valid
    format that no reporter would answer: the run selected zero reporters, wrote
    nothing, and exited 0. An empty ``reports/`` directory was the operator's only
    signal, and the closing scan summary still pointed at report paths that were
    never written. Silence was the defect; the mismatched comparison in
    :func:`~automated_security_helper.base.reporter_plugin.reporter_matches_requested_formats`
    was merely its most common cause.

    The two reasons are reported separately on purpose. Collapsing them into one
    "no report for X" message would tell an operator who asked for ``yaml`` --
    which ships ``enabled: False`` -- that ASH cannot produce yaml, when in fact
    they need one line of config. Naming the cause is the difference between an
    actionable message and a misleading one.

    Args:
        output_formats: What the operator asked for. Empty yields an empty result:
            no explicit request means nothing was asked for and denied.
        selected_instances: Reporters that survived every filter and will run.
        all_instances: Every reporter that could be constructed, before the
            enabled/dependency/python-only filters. Supplies the evidence that a
            format's reporter exists but was excluded.

    Returns:
        Format name -> one of :data:`FORMAT_REPORTER_UNAVAILABLE` or
        :data:`FORMAT_NO_REPORTER`. Empty when every requested format will be
        produced, which is the normal case.
    """
    requested = [str(getattr(fmt, "value", fmt)) for fmt in output_formats or []]
    if not requested:
        return {}

    def names(instances: Sequence[object]) -> set:
        return {
            str(name)
            for name in (reporter_format_name(inst) for inst in instances)
            if name is not None
        }

    selected_names = names(selected_instances)
    known_names = names(all_instances)

    unsatisfied: Dict[str, str] = {}
    for fmt in requested:
        if fmt in selected_names:
            continue
        unsatisfied[fmt] = (
            FORMAT_REPORTER_UNAVAILABLE if fmt in known_names else FORMAT_NO_REPORTER
        )
    return unsatisfied


def _log_unsatisfied_output_formats(unsatisfied: Dict[str, str]) -> None:
    """Warn, once per format, that a requested format produces nothing.

    Warning rather than raising. A run that was asked for ``markdown,asff`` must
    still write the markdown report; failing the whole scan over one unproducible
    format would cost the operator every other report and, for ``ash scan``, the
    findings verdict along with it. The case where *nothing* was produced is
    additionally reported by the caller's existing "no enabled reporters" warning.
    """
    for fmt, reason in sorted(unsatisfied.items()):
        if reason == FORMAT_REPORTER_UNAVAILABLE:
            ASH_LOGGER.warning(
                f"No report will be written for requested format '{fmt}': its "
                f"reporter is present but not active. It is disabled in the "
                f"configuration, its dependencies are unsatisfied, or "
                f"--python-based-plugins-only excluded it. Enable it under "
                f"'reporters' in the ASH config to get this report."
            )
        else:
            ASH_LOGGER.warning(
                f"No report will be written for requested format '{fmt}': no "
                f"reporter produces it. The format is accepted by --output-formats "
                f"but has no reporter behind it."
            )


class ReportPhase(EnginePhase):
    """Implementation of the Report phase."""

    @property
    def phase_name(self) -> str:
        """Return the name of this phase."""
        return "report"

    def _execute_phase(
        self,
        report_dir: Path,
        aggregated_results: AshAggregatedResults,
        cli_output_formats=None,
        python_based_plugins_only: bool = False,
        **kwargs,
    ) -> AshAggregatedResults:
        """Execute the Report phase.

        Args:
            report_dir(Path): The directory to save reports to.
            cli_output_formats: Output formats specified via CLI, which override config
            **kwargs: Additional arguments
        """
        ASH_LOGGER.debug("Entering: ReportPhase._execute_phase()")
        report_dir.mkdir(parents=True, exist_ok=True)

        # Initialize progress
        self.initialize_progress("Starting report generation...")

        # Update progress
        self.update_progress(10, "Preparing report data...")

        # Print progress update
        ASH_LOGGER.info("Preparing report data...")

        # Get output formats from config
        output_formats = getattr(self.plugin_context.config, "output_formats", [])

        # If CLI output formats are provided, they override the config
        if cli_output_formats:
            output_formats = cli_output_formats
            ASH_LOGGER.info(f"Using CLI-specified output formats: {output_formats}")

        # Update progress
        self.update_progress(20, "Identifying reporters...")

        # Create a list of reporter classes
        reporter_classes = self.plugins

        # Create all reporter instances upfront, then filter via the shared helper.
        all_reporter_instances = []
        for plugin_class in reporter_classes:
            try:
                plugin_name = getattr(plugin_class, "__name__", "Unknown")
                plugin_config = (
                    self.plugin_context.config.get_plugin_config(
                        plugin_type="reporter",
                        plugin_name=plugin_name.lower(),
                    )
                    if self.plugin_context.config is not None
                    else None
                )
                plugin_instance = plugin_class(
                    context=self.plugin_context,
                    config=plugin_config,
                )
                all_reporter_instances.append(plugin_instance)
            except Exception as e:
                ASH_LOGGER.error(
                    f"Error creating reporter {getattr(plugin_class, '__name__', 'Unknown')}: {e}"
                )

        base_filtered = self.filter_enabled_plugins(
            plugin_instances=all_reporter_instances,
            plugin_context=self.plugin_context,
            python_only=python_based_plugins_only,
        )

        # Apply the format filter on top of the base enabled/deps/python check.
        #
        # Matched on the reporter's configured name, not on its extension. The
        # extension is a filename suffix and the requested formats are format
        # names; comparing them matched only the four reporters where the two
        # strings coincide and silently skipped the rest. See
        # reporter_matches_requested_formats for the full account and for why
        # renaming the extensions instead was rejected.
        enabled_reporters: List[object] = []
        enabled_reporter_names = []
        for plugin_instance in base_filtered:
            display_name = plugin_instance.__class__.__name__
            if hasattr(plugin_instance, "config") and hasattr(
                plugin_instance.config, "name"
            ):
                display_name = plugin_instance.config.name

            if not reporter_matches_requested_formats(plugin_instance, output_formats):
                ASH_LOGGER.debug(
                    f"Reporter {display_name} format "
                    f"'{reporter_format_name(plugin_instance)}' not in requested "
                    f"formats {output_formats}, skipping"
                )
                continue

            enabled_reporters.append(plugin_instance)
            enabled_reporter_names.append(display_name)

        ASH_LOGGER.verbose(
            f"Prepared {len(enabled_reporter_names)} enabled reporters: {enabled_reporter_names}"
        )

        # Account for every requested format that will produce nothing. Checked
        # against all_reporter_instances rather than base_filtered so that a
        # reporter which exists but is disabled is reported as disabled instead of
        # as nonexistent.
        _log_unsatisfied_output_formats(
            unsatisfied_output_formats(
                output_formats=output_formats,
                selected_instances=enabled_reporters,
                all_instances=all_reporter_instances,
            )
        )

        # Create the main report task with initial progress
        report_task = self.progress_display.add_task(
            phase=ExecutionPhase.REPORT,
            description=f"Preparing {len(enabled_reporter_names)} reporters...",
            total=100,
        )

        # Update the main task to show it's started
        self.progress_display.update_task(
            phase=ExecutionPhase.REPORT,
            task_id=report_task,
            completed=20,
            description=f"Generating reports with {len(enabled_reporter_names)} reporters...",
        )

        # Track progress for each reporter
        total_reporters = len(enabled_reporters)
        completed = 0

        # Directly invoke each reporter plugin
        results = []
        if enabled_reporters:
            ASH_LOGGER.debug(
                f"Processing {len(enabled_reporters)} enabled reporter classes"
            )
            for plugin_instance in enabled_reporters:
                try:
                    plugin_name = plugin_instance.__class__.__name__
                    ASH_LOGGER.debug(f"Initializing reporter: {plugin_name}")

                    # Create a task for this reporter
                    reporter_task = self.progress_display.add_task(
                        phase=ExecutionPhase.REPORT,
                        description=f"Starting reporter: {plugin_name}",
                        total=100,
                    )

                    # Use the configured name if available
                    display_name = plugin_name
                    if hasattr(plugin_instance, "config") and hasattr(
                        plugin_instance.config, "name"
                    ):
                        display_name = plugin_instance.config.name

                    # Update reporter task to 50%
                    self.progress_display.update_task(
                        phase=ExecutionPhase.REPORT,
                        task_id=reporter_task,
                        completed=50,
                        description=f"Running reporter: {display_name}",
                    )

                    # Update main progress
                    progress_percent = 20 + (completed / total_reporters * 70)
                    self.update_progress(
                        int(progress_percent),
                        f"Running reporter {completed + 1}/{total_reporters}: {display_name}",
                    )

                    # Call report method directly
                    ASH_LOGGER.debug(f"Calling report() on {display_name}")

                    # Notify reporter start
                    try:
                        from automated_security_helper.plugins.events import (
                            AshEventType,
                        )

                        self.notify_event(
                            AshEventType.REPORT_START,
                            reporter=display_name,
                            reporter_class=plugin_instance.__class__.__name__,
                            message=f"Starting reporter: {display_name}",
                        )
                    except Exception as event_error:
                        ASH_LOGGER.error(
                            f"Failed to notify reporter start event: {str(event_error)}"
                        )

                    report_result = plugin_instance.report(aggregated_results)

                    if report_result:
                        ASH_LOGGER.debug(f"Reporter {display_name} returned a report")

                        # Determine output filename based on reporter's extension if available
                        output_filename = "ash.txt"  # Default
                        if hasattr(plugin_instance, "config") and hasattr(
                            plugin_instance.config, "extension"
                        ):
                            extension = plugin_instance.config.extension
                            output_filename = f"ash.{extension}"

                        # Write the report to a file
                        output_file = report_dir.joinpath(output_filename)
                        ASH_LOGGER.info(
                            f"Writing {display_name} report to {output_file}"
                        )
                        with open(output_file, mode="w", encoding="utf-8") as f:
                            f.write(report_result)

                        results.append(report_result)

                        # Update reporter task to 100%
                        self.progress_display.update_task(
                            phase=ExecutionPhase.REPORT,
                            task_id=reporter_task,
                            completed=100,
                            description=f"[green]({display_name}) Generated report: {output_filename}",
                        )

                        # Notify reporter complete
                        try:
                            from automated_security_helper.plugins.events import (
                                AshEventType,
                            )

                            self.notify_event(
                                AshEventType.REPORT_COMPLETE,
                                reporter=display_name,
                                reporter_class=plugin_instance.__class__.__name__,
                                output_file=str(output_file),
                                output_filename=output_filename,
                                message=f"Reporter {display_name} completed: {output_filename}",
                            )
                        except Exception as event_error:
                            ASH_LOGGER.error(
                                f"Failed to notify reporter complete event: {str(event_error)}"
                            )
                    else:
                        ASH_LOGGER.debug(
                            f"Reporter {display_name} returned None or empty report"
                        )

                        # Update reporter task to 100%
                        self.progress_display.update_task(
                            phase=ExecutionPhase.REPORT,
                            task_id=reporter_task,
                            completed=100,
                            description=f"[yellow]({display_name}) No report generated",
                        )

                        # Notify reporter complete (no report)
                        try:
                            from automated_security_helper.plugins.events import (
                                AshEventType,
                            )

                            self.notify_event(
                                AshEventType.REPORT_COMPLETE,
                                reporter=display_name,
                                reporter_class=plugin_instance.__class__.__name__,
                                output_file=None,
                                output_filename=None,
                                message=f"Reporter {display_name} completed: no report generated",
                            )
                        except Exception as event_error:
                            ASH_LOGGER.error(
                                f"Failed to notify reporter complete event: {str(event_error)}"
                            )

                    # Increment completed count
                    completed += 1

                except Exception as e:
                    ASH_LOGGER.error(f"Error in reporter {plugin_name}: {e}")
                    ASH_LOGGER.debug(
                        f"Reporter exception traceback: {traceback.format_exc()}"
                    )

                    # Update reporter task to show error
                    self.progress_display.update_task(
                        phase=ExecutionPhase.REPORT,
                        task_id=reporter_task,
                        completed=100,
                        description=f"[red]({display_name}) Failed: {str(e)}",
                    )

                    # Increment completed count
                    completed += 1
        else:
            ASH_LOGGER.warning("No enabled reporters found matching requested formats")

        # Update main progress
        self.update_progress(
            100,
            f"Reporters complete: {len(results)} reports generated from {len(enabled_reporters)} reporters",
        )

        # Update progress
        self.progress_display.update_task(
            phase=ExecutionPhase.REPORT,
            task_id=report_task,
            completed=100,
            description=f"Reporters complete: {len(results)} reports generated from {len(enabled_reporters)} reporters",
        )

        # Add summary row
        self.add_summary("Complete", f"Generated {len(results)} reports")

        return aggregated_results

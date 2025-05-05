"""Implementation of the Report phase."""

from pathlib import Path
import traceback
from automated_security_helper.base.engine_phase import EnginePhase
from automated_security_helper.core.enums import ExecutionPhase
from automated_security_helper.utils.log import ASH_LOGGER


class ReportPhase(EnginePhase):
    """Implementation of the Report phase."""

    @property
    def phase_name(self) -> str:
        """Return the name of this phase."""
        return "report"

    def _execute_phase(
        self,
        report_dir: Path,
        cli_output_formats=None,
        python_based_plugins_only: bool = False,
        **kwargs,
    ) -> None:
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

        # Filter enabled reporters and those matching requested formats
        enabled_reporters = []
        enabled_reporter_names = []
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
                # Create temporary instance to check config
                plugin_instance = plugin_class(
                    context=self.plugin_context,
                    config=plugin_config,
                )
                # Use the configured name if available
                display_name = plugin_name
                if hasattr(plugin_instance, "config") and hasattr(
                    plugin_instance.config, "name"
                ):
                    display_name = plugin_instance.config.name

                # Check if enabled
                if hasattr(plugin_instance, "config") and hasattr(
                    plugin_instance.config, "enabled"
                ):
                    if not plugin_instance.config.enabled:
                        ASH_LOGGER.debug(
                            f"Reporter {display_name} is disabled, skipping"
                        )
                        continue

                # Check if python_based_plugins_only is set and if the reporter is Python-only
                if python_based_plugins_only and not plugin_instance.is_python_only():
                    ASH_LOGGER.debug(
                        f"Reporter {display_name} is not Python-only, skipping due to python_based_plugins_only flag"
                    )
                    continue

                # Check if format matches requested formats
                if (
                    output_formats
                    and hasattr(plugin_instance, "config")
                    and hasattr(plugin_instance.config, "extension")
                ):
                    extension = plugin_instance.config.extension
                    if extension not in output_formats:
                        ASH_LOGGER.debug(
                            f"Reporter {display_name} format '{extension}' not in requested formats {output_formats}, skipping"
                        )
                        continue

                # If we got here, the reporter is enabled and matches requested formats
                enabled_reporters.append(plugin_class)
                enabled_reporter_names.append(display_name)

            except Exception as e:
                ASH_LOGGER.error(
                    f"Error checking reporter {getattr(plugin_class, '__name__', 'Unknown')}: {e}"
                )

        ASH_LOGGER.verbose(
            f"Prepared {len(enabled_reporter_names)} enabled reporters: {enabled_reporter_names}"
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
            for plugin_class in enabled_reporters:
                try:
                    plugin_name = getattr(plugin_class, "__name__", "Unknown")
                    ASH_LOGGER.debug(f"Initializing reporter: {plugin_name}")

                    # Create a task for this reporter
                    reporter_task = self.progress_display.add_task(
                        phase=ExecutionPhase.REPORT,
                        description=f"Starting reporter: {plugin_name}",
                        total=100,
                    )

                    # Create reporter instance with context and config
                    plugin_instance = plugin_class(
                        context=self.plugin_context,
                        config=(
                            self.plugin_context.config.get_plugin_config(
                                plugin_type="reporter",
                                plugin_name=plugin_name.lower(),
                            )
                            if self.plugin_context.config is not None
                            else None
                        ),
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
                    report_result = plugin_instance.report(self.asharp_model)

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
                        with open(output_file, "w") as f:
                            f.write(report_result)

                        results.append(report_result)

                        # Update reporter task to 100%
                        self.progress_display.update_task(
                            phase=ExecutionPhase.REPORT,
                            task_id=reporter_task,
                            completed=100,
                            description=f"[green]({display_name}) Generated report: {output_filename}",
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

        return None

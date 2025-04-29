"""Implementation of the Report phase."""

from pathlib import Path
import traceback
from automated_security_helper.base.engine_phase import EnginePhase
from automated_security_helper.core.progress import ExecutionPhase
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

        ASH_LOGGER.verbose(f"Found {len(reporter_classes)} reporter classes")

        # Create a task for report generation
        report_task = self.progress_display.add_task(
            phase=ExecutionPhase.REPORT,
            description="Generating reports...",
            total=100,
        )

        # Directly invoke each reporter plugin
        results = []
        if reporter_classes:
            ASH_LOGGER.debug(f"Processing {len(reporter_classes)} reporter classes")
            for plugin_class in reporter_classes:
                try:
                    plugin_name = plugin_class.__name__
                    ASH_LOGGER.debug(f"Initializing reporter: {plugin_name}")

                    # Create reporter instance with context and default config
                    plugin_instance = plugin_class(
                        context=self.plugin_context,
                        config=(
                            self.plugin_context.config.get_plugin_config(
                                plugin_type="reporter",
                                plugin_name=plugin_name,
                            )
                            if self.plugin_context.config is not None
                            else None
                        ),
                    )

                    # Call report method directly
                    ASH_LOGGER.trace(f"Calling report() on {plugin_name}")
                    fmt = (
                        plugin_instance.config.extension
                        if hasattr(plugin_instance, "config")
                        and hasattr(plugin_instance.config, "extension")
                        else "txt"
                    )
                    formatted = plugin_instance.report(self.asharp_model)
                    if formatted is None:
                        ASH_LOGGER.error(
                            f"Failed to format report with {plugin_name} reporter, returned empty string"
                        )
                        raise ValueError(
                            f"Reporter returned empty result for {plugin_name}"
                        )

                    # Determine output filename based on reporter's extension if available
                    output_filename = f"ash.{fmt}"
                    if hasattr(plugin_instance, "config") and hasattr(
                        plugin_instance.config, "extension"
                    ):
                        output_filename = f"ash.{plugin_instance.config.extension}"

                    output_file = report_dir.joinpath(output_filename)
                    ASH_LOGGER.info(f"Writing {fmt} report to {output_file}")
                    output_file.write_text(formatted)

                except Exception as e:
                    ASH_LOGGER.error(f"Error in reporter {plugin_name}: {e}")
                    ASH_LOGGER.debug(
                        f"Reporter exception traceback: {traceback.format_exc()}"
                    )
        else:
            ASH_LOGGER.warning("No reporter classes found")

        # Update progress
        self.progress_display.update_task(
            phase=ExecutionPhase.REPORT,
            task_id=report_task,
            completed=100,
            description="Reports generated",
        )

        ASH_LOGGER.verbose(f"Generated {len(results) if results else 0} reports")

        # Update main progress
        self.update_progress(100, "Report generation complete")

        # Add summary row
        self.add_summary(
            "Complete", f"Generated {len(results) if results else 0} reports"
        )

        return None

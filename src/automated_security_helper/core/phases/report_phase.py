"""Implementation of the Report phase."""

from pathlib import Path
from automated_security_helper.base.engine_phase import EnginePhase
from automated_security_helper.core.progress import ExecutionPhase
from automated_security_helper.plugins.events import AshEventType
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
        ASH_LOGGER.debug("Entering: ReportPhase.execute()")
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
        self.update_progress(20, "Generating reports...")

        # Create a task for report generation
        report_task = self.progress_display.add_task(
            phase=ExecutionPhase.REPORT,
            description="Generating reports...",
            total=100,
        )

        # Notify plugins to generate reports
        results = self.notify_event(
            AshEventType.REPORT_GENERATE,
            model=self.asharp_model,
            plugin_context=self.plugin_context,
            output_formats=output_formats,
            report_dir=report_dir,
        )

        # Update progress
        self.progress_display.update_task(
            phase=ExecutionPhase.REPORT,
            task_id=report_task,
            completed=100,
            description="Reports generated",
        )

        # Update main progress
        self.update_progress(100, "Report generation complete")

        # Add summary row
        self.add_summary(
            "Complete", f"Generated {len(results) if results else 0} reports"
        )

        return None

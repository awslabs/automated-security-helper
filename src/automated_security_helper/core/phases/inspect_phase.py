"""Implementation of the Inspect phase."""

from automated_security_helper.base.engine_phase import EnginePhase
from automated_security_helper.utils.log import ASH_LOGGER


class InspectPhase(EnginePhase):
    """Implementation of the Inspect phase for analyzing SARIF fields."""

    @property
    def phase_name(self) -> str:
        """Return the name of this phase."""
        return "inspect"

    def _execute_phase(self, **kwargs) -> None:
        """Execute the Inspect phase.

        Args:
            **kwargs: Additional arguments
        """
        ASH_LOGGER.debug("Entering: InspectPhase.execute()")

        # Initialize progress
        self.initialize_progress("Starting SARIF field inspection...")

        # Update progress
        self.update_progress(10, "Preparing inspection...")

        # Print progress update
        ASH_LOGGER.info("Analyzing SARIF fields...")

        try:
            from automated_security_helper.cli.inspect import analyze_sarif_fields

            # Use the context to provide all necessary parameters
            sarif_dir = self.plugin_context.output_dir.joinpath("scanners")
            output_dir = self.plugin_context.output_dir.joinpath("analysis")
            aggregated_sarif = self.plugin_context.output_dir.joinpath(
                "reports"
            ).joinpath("ash.sarif")
            flat_reports_dir = self.plugin_context.output_dir.joinpath("reports")

            # Create the output directory if it doesn't exist
            output_dir.mkdir(parents=True, exist_ok=True)

            # Update progress
            self.update_progress(30, "Analyzing SARIF fields...")

            # Call the analyze_sarif_fields function directly
            analyze_sarif_fields(
                sarif_dir=str(sarif_dir),
                output_dir=str(output_dir),
                aggregated_sarif=str(aggregated_sarif),
                flat_reports_dir=str(flat_reports_dir),
            )

            # Update progress
            self.update_progress(90, "Inspection complete")

            ASH_LOGGER.info(f"Inspection results written to {output_dir}")

        except Exception as e:
            ASH_LOGGER.error(f"Error during inspection phase: {e}")
            ASH_LOGGER.debug("Exception details:", exc_info=True)
            # Continue execution even if inspection fails

        # Complete progress
        self.update_progress(100, "Inspection phase complete")

"""Implementation of the Inspect phase."""

from automated_security_helper.base.engine_phase import EnginePhase
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.utils.error_text import error_text
from automated_security_helper.utils.log import ASH_LOGGER


class InspectPhase(EnginePhase):
    """Implementation of the Inspect phase for analyzing SARIF fields."""

    @property
    def phase_name(self) -> str:
        """Return the name of this phase."""
        return "inspect"

    def _execute_phase(
        self,
        aggregated_results: AshAggregatedResults,
        **kwargs,
    ) -> AshAggregatedResults:
        """Execute the Inspect phase.

        Args:
            **kwargs: Additional arguments
        """
        ASH_LOGGER.debug("Entering: InspectPhase.execute()")
        ASH_LOGGER.info("Analyzing SARIF fields...")

        import typer

        try:
            from automated_security_helper.utils.sarif_field_analysis import (
                analyze_sarif_fields,
            )

            output_dir = self.plugin_context.output_dir.joinpath("analysis")

            # Create the output directory if it doesn't exist
            output_dir.mkdir(parents=True, exist_ok=True)

            # sarif_dir is this scan's output directory. Left unset, the function
            # reads .ash/ash_output under the working directory, which is an
            # earlier scan's output, or nothing, whenever --output-dir is elsewhere.
            analyze_sarif_fields(
                sarif_dir=str(self.plugin_context.output_dir),
                output_dir=str(output_dir),
            )

            ASH_LOGGER.info(f"Inspection results written to {output_dir}")

        except typer.Exit as e:
            # analyze_sarif_fields ends a command-line run with typer.Exit, for
            # instance when it finds no SARIF file, and has printed why. Exit is
            # a RuntimeError, so the handler below read it as a failure and
            # logged "Error during inspection phase: " with no cause.
            if e.exit_code:
                ASH_LOGGER.warning(
                    "Inspection stopped before it wrote results (analysis exit "
                    f"code {e.exit_code}); the reason is printed above. SARIF "
                    f"files are read from {self.plugin_context.output_dir}."
                )
            else:
                ASH_LOGGER.info(f"Inspection results written to {output_dir}")
        except Exception as e:
            ASH_LOGGER.error(f"Error during inspection phase: {error_text(e)}")
            ASH_LOGGER.debug("Exception details:", exc_info=True)
            # Continue execution even if inspection fails

        return aggregated_results

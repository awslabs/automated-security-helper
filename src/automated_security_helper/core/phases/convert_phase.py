"""Implementation of the Convert phase."""

from pathlib import Path
from typing import List

from automated_security_helper.base.engine_phase import EnginePhase
from automated_security_helper.core.progress import ExecutionPhase
from automated_security_helper.core.plugin_registry import PluginRegistry, PluginType
from automated_security_helper.utils.log import ASH_LOGGER


class ConvertPhase(EnginePhase):
    """Implementation of the Convert phase."""

    @property
    def phase_name(self) -> str:
        """Return the name of this phase."""
        return "convert"

    def execute(self, plugin_registry: PluginRegistry, **kwargs) -> List[Path]:
        """Execute the Convert phase.

        Args:
            plugin_registry: Registry of plugins to use
            **kwargs: Additional arguments

        Returns:
            List[Path]: List of converted paths
        """
        ASH_LOGGER.debug("Entering: ConvertPhase.execute()")

        # Initialize progress
        self.initialize_progress("Preparing for scan...")

        # Update progress to 10%
        self.update_progress(10, "Identifying converters...")

        converters = plugin_registry.get_plugin(plugin_type=PluginType.converter)
        converted_paths = []

        # Update progress to 20%
        self.update_progress(
            20, f"Found {len(converters) if converters else 0} converters"
        )

        # If no converters found, still update progress to 100%
        if not converters or not isinstance(converters, dict) or len(converters) == 0:
            self.update_progress(100, "No converters to run")
            # self.add_summary("Complete", "No converters to run")
            return converted_paths

        # We have converters to run
        total_converters = len(converters)
        completed_converters = 0

        for converter_name, converter_config in converters.items():
            # Create task for this converter
            converter_task = self.progress_display.add_task(
                phase=ExecutionPhase.CONVERT,
                description=f"Running converter: {converter_name}",
                total=100,
            )

            # Update main task progress
            progress_percent = 20 + (completed_converters / total_converters * 60)
            self.update_progress(
                int(progress_percent),
                f"Running converter {completed_converters + 1}/{total_converters}: {converter_name}",
            )

            ASH_LOGGER.debug(
                f"Running converter {converter_name} with config {converter_config}"
            )

            # Update converter task to 50%
            self.progress_display.update_task(
                phase=ExecutionPhase.CONVERT,
                task_id=converter_task,
                completed=50,
                description=f"Running converter: {converter_name}",
            )

            converter = converter_config.plugin_class(
                context=self.plugin_context,
            )
            out = converter.convert()

            # Update converter task to 100%
            self.progress_display.update_task(
                phase=ExecutionPhase.CONVERT,
                task_id=converter_task,
                completed=100,
                description=f"Completed converter: {converter_name}",
            )

            if out:
                ASH_LOGGER.debug(f"Converter {converter_name} returned: {out}")
                if isinstance(out, list):
                    converted_paths.extend(out)
                else:
                    converted_paths.append(out)

            completed_converters += 1

            # Update main task progress after each converter completes
            progress_percent = 20 + (completed_converters / total_converters * 60)
            self.update_progress(
                int(progress_percent),
                f"Completed {completed_converters}/{total_converters} converters",
            )

        # Update main task to 100%
        self.update_progress(
            100, f"Preparation complete: {len(converted_paths)} paths converted"
        )

        # Add summary row
        # self.add_summary("Complete", f"Converted {len(converted_paths)} paths")

        return converted_paths

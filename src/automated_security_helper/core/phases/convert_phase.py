"""Implementation of the Convert phase."""

from pathlib import Path
from typing import List

from automated_security_helper.base.engine_phase import EnginePhase
from automated_security_helper.core.progress import ExecutionPhase
from automated_security_helper.utils.log import ASH_LOGGER


class ConvertPhase(EnginePhase):
    """Implementation of the Convert phase."""

    @property
    def phase_name(self) -> str:
        """Return the name of this phase."""
        return "convert"

    def _execute_phase(self, **kwargs) -> List[Path]:
        """Execute the Convert phase with observer pattern.

        Args:
            **kwargs: Additional arguments

        Returns:
            List[Path]: List of converted paths
        """
        ASH_LOGGER.debug("Entering: ConvertPhase._execute_phase()")

        # Update progress to 10%
        self.update_progress(10, "Identifying converters...")

        # Get all converter plugins directly from the converters module
        ash_converters = self.plugins
        ASH_LOGGER.debug(
            f"Found {len(ash_converters)} converter plugins in ash_converters"
        )
        converted_paths = []

        # Update progress to 20%
        self.update_progress(
            20, f"Found {len(ash_converters) if ash_converters else 0} converters"
        )

        # If no converters found, still update progress to 100%
        if not ash_converters or len(ash_converters) == 0:
            ASH_LOGGER.debug("No converters found, skipping conversion phase")
            self.update_progress(100, "No converters to run")
            return converted_paths

        # Create task for conversion
        convert_task = self.progress_display.add_task(
            phase=ExecutionPhase.CONVERT,
            description="Running converters...",
            total=100,
        )

        # Directly invoke each converter plugin
        if ash_converters:
            ASH_LOGGER.debug(f"Processing {len(ash_converters)} converter plugins")
            for plugin_class in ash_converters:
                try:
                    plugin_name = getattr(plugin_class, "__name__", "Unknown")
                    ASH_LOGGER.debug(f"Initializing converter: {plugin_name}")

                    # Create converter instance with context
                    plugin_instance = plugin_class(
                        context=self.plugin_context,
                        config=(
                            self.plugin_context.config.get_plugin_config(
                                plugin_type="converter",
                                plugin_name=plugin_name,
                            )
                            if self.plugin_context.config is not None
                            else None
                        ),
                    )
                    if (
                        hasattr(plugin_instance, "config")
                        and hasattr(plugin_instance.config, "name")
                        and plugin_name != plugin_instance.config.name
                    ):
                        # Prefer the configured short name for the plugin
                        plugin_name = plugin_instance.config.name

                    # Validate the converter
                    if plugin_instance.validate():
                        # Call convert method directly - converters should handle finding their own targets
                        ASH_LOGGER.debug(f"Calling convert() on {plugin_name}")
                        # Pass the source directory as the target
                        convert_result = plugin_instance.convert(
                            self.plugin_context.source_dir
                        )
                        if convert_result:
                            if isinstance(convert_result, list):
                                ASH_LOGGER.debug(
                                    f"Converter {plugin_name} returned {len(convert_result)} paths"
                                )
                                converted_paths.extend(convert_result)
                            else:
                                ASH_LOGGER.debug(
                                    f"Converter {plugin_name} returned a single path: {convert_result}"
                                )
                                converted_paths.append(convert_result)
                        else:
                            ASH_LOGGER.debug(
                                f"Converter {plugin_name} returned None or empty result"
                            )
                    else:
                        ASH_LOGGER.debug(
                            f"Converter {plugin_name} validation failed, skipping"
                        )
                except Exception as e:
                    ASH_LOGGER.error(f"Error in converter {plugin_name}: {e}")
                    import traceback

                    ASH_LOGGER.debug(
                        f"Converter exception traceback: {traceback.format_exc()}"
                    )
        else:
            ASH_LOGGER.warning("No converter plugins found in ash_converters")

        # Update progress
        self.progress_display.update_task(
            phase=ExecutionPhase.CONVERT,
            task_id=convert_task,
            completed=100,
            description="Converters complete",
        )

        # Update main task to 100%
        self.update_progress(
            100, f"Preparation complete: {len(converted_paths)} paths converted"
        )

        # Add summary row
        self.add_summary("Complete", f"Converted {len(converted_paths)} paths")

        return converted_paths

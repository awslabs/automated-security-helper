"""Implementation of the Convert phase."""

from pathlib import Path
from automated_security_helper.base.engine_phase import EnginePhase
from automated_security_helper.core.enums import ExecutionPhase
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ConverterStatusInfo,
)
from automated_security_helper.utils.log import ASH_LOGGER


class ConvertPhase(EnginePhase):
    """Implementation of the Convert phase."""

    @property
    def phase_name(self) -> str:
        """Return the name of this phase."""
        return "convert"

    def _execute_phase(
        self,
        aggregated_results: AshAggregatedResults,
        python_based_plugins_only: bool = False,
        **kwargs,
    ) -> AshAggregatedResults:
        """Execute the Convert phase with observer pattern.

        Args:
            **kwargs: Additional arguments

        Returns:
            List[Path]: List of converted paths
        """
        ASH_LOGGER.debug("Entering: ConvertPhase._execute_phase()")

        # Update progress to 10%
        self.update_progress(10, "Identifying converters...")

        # Get all converter plugins
        converter_classes = self.plugins

        # Filter enabled converters
        enabled_converters = []
        enabled_converter_names = []
        for plugin_class in converter_classes:
            try:
                plugin_name = getattr(plugin_class, "__name__", "Unknown")

                # Create temporary instance to check config
                plugin_instance = plugin_class(
                    context=self.plugin_context,
                    config=(
                        self.plugin_context.config.get_plugin_config(
                            plugin_type="converter",
                            plugin_name=plugin_name.lower(),
                        )
                        if self.plugin_context.config is not None
                        else None
                    ),
                )

                # Check if enabled
                if hasattr(plugin_instance, "config") and hasattr(
                    plugin_instance.config, "enabled"
                ):
                    if not plugin_instance.config.enabled:
                        ASH_LOGGER.debug(
                            f"Converter {plugin_name} is disabled, skipping"
                        )
                        continue

                # Check if python_based_plugins_only is set and if the converter is Python-only
                if python_based_plugins_only and not plugin_instance.is_python_only():
                    ASH_LOGGER.debug(
                        f"Converter {plugin_name} is not Python-only, skipping due to python_based_plugins_only flag"
                    )
                    continue

                # Check if the converter validates
                if not plugin_instance.validate():
                    ASH_LOGGER.debug(
                        f"Converter {plugin_name} validation failed, skipping"
                    )
                    continue

                # If we got here, the converter is enabled and validates
                enabled_converters.append(plugin_class)

                # Use the configured name if available
                display_name = plugin_name
                if hasattr(plugin_instance, "config") and hasattr(
                    plugin_instance.config, "name"
                ):
                    display_name = plugin_instance.config.name

                enabled_converter_names.append(display_name)

            except Exception as e:
                ASH_LOGGER.error(
                    f"Error checking converter {getattr(plugin_class, '__name__', 'Unknown')}: {e}"
                )

        ASH_LOGGER.verbose(
            f"Prepared {len(enabled_converter_names)} enabled converters: {enabled_converter_names}"
        )
        converted_paths = []

        # Update progress to 20%
        self.update_progress(
            20, f"Prepared {len(enabled_converter_names)} enabled converters"
        )

        # If no converters found, still update progress to 100%
        if not enabled_converters:
            ASH_LOGGER.warning(
                "No enabled converter plugins found, skipping conversion phase"
            )
            self.update_progress(100, "No converters to run")
            return converted_paths

        # Create task for conversion - this is the main phase task
        convert_task = self.progress_display.add_task(
            phase=ExecutionPhase.CONVERT,
            description=f"Preparing {len(enabled_converters)} converters...",
            total=100,
        )

        # Update the main task to show it's started
        self.progress_display.update_task(
            phase=ExecutionPhase.CONVERT,
            task_id=convert_task,
            completed=20,
            description=f"Running {len(enabled_converters)} converters...",
        )

        # Track converters that found no convertible files
        converters_with_no_files = []

        # Track progress for each converter
        total_converters = len(enabled_converters)
        completed = 0

        # Directly invoke each converter plugin
        ASH_LOGGER.debug(
            f"Processing {len(enabled_converters)} enabled converter plugins"
        )
        for plugin_class in enabled_converters:
            plugin_converted_paths = []
            try:
                plugin_name = getattr(plugin_class, "__name__", "Unknown")
                ASH_LOGGER.debug(f"Initializing converter: {plugin_name}")

                # Create a task for this converter
                converter_task = self.progress_display.add_task(
                    phase=ExecutionPhase.CONVERT,
                    description=f"Starting converter: {plugin_name}",
                    total=100,
                )

                # Create converter instance with context
                plugin_instance = plugin_class(
                    context=self.plugin_context,
                    config=(
                        self.plugin_context.config.get_plugin_config(
                            plugin_type="converter",
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

                # Update converter task to 50%
                self.progress_display.update_task(
                    phase=ExecutionPhase.CONVERT,
                    task_id=converter_task,
                    completed=50,
                    description=f"Running converter: {display_name}",
                )

                # Update main progress
                progress_percent = 20 + (completed / total_converters * 70)
                self.update_progress(
                    int(progress_percent),
                    f"Running converter {completed + 1}/{total_converters}: {display_name}",
                )

                # Call convert method directly - converters should handle finding their own targets
                ASH_LOGGER.debug(f"Calling convert() on {display_name}")

                # Notify converter start
                try:
                    from automated_security_helper.plugins.events import AshEventType

                    self.notify_event(
                        AshEventType.CONVERT_START,
                        converter=display_name,
                        converter_class=plugin_class.__name__,
                        message=f"Starting converter: {display_name}",
                    )
                except Exception as event_error:
                    ASH_LOGGER.error(
                        f"Failed to notify converter start event: {str(event_error)}"
                    )

                # Pass the source directory as the target
                convert_result_initial = plugin_instance.convert()
                # Ensure all convert_result are strings in case some are Paths
                convert_result = []
                if convert_result_initial is not None:
                    convert_result = [
                        Path(item).as_posix()
                        for item in (
                            convert_result_initial
                            if isinstance(convert_result_initial, list)
                            else [convert_result_initial]
                        )
                    ]

                if isinstance(convert_result, list) and len(convert_result) > 0:
                    ASH_LOGGER.debug(
                        f"Converter {display_name} returned {len(convert_result)} paths"
                    )
                    plugin_converted_paths.extend(convert_result)
                    converted_paths.extend(convert_result)

                    # Update converter task to 100%
                    self.progress_display.update_task(
                        phase=ExecutionPhase.CONVERT,
                        task_id=converter_task,
                        completed=100,
                        description=f"[green]({display_name}) Converted {len(convert_result)} files",
                    )

                    # Notify converter complete
                    try:
                        from automated_security_helper.plugins.events import (
                            AshEventType,
                        )

                        self.notify_event(
                            AshEventType.CONVERT_COMPLETE,
                            converter=display_name,
                            converter_class=plugin_class.__name__,
                            converted_files=convert_result,
                            file_count=len(convert_result),
                            message=f"Converter {display_name} completed: {len(convert_result)} files converted",
                        )
                    except Exception as event_error:
                        ASH_LOGGER.error(
                            f"Failed to notify converter complete event: {str(event_error)}"
                        )
                else:
                    ASH_LOGGER.debug(
                        f"Converter {display_name} returned None or empty result"
                    )
                    converters_with_no_files.append(display_name)

                    # Update converter task to 100%
                    self.progress_display.update_task(
                        phase=ExecutionPhase.CONVERT,
                        task_id=converter_task,
                        completed=100,
                        description=f"[yellow]({display_name}) No files to convert",
                    )

                    # Notify converter complete (no files)
                    try:
                        from automated_security_helper.plugins.events import (
                            AshEventType,
                        )

                        self.notify_event(
                            AshEventType.CONVERT_COMPLETE,
                            converter=display_name,
                            converter_class=plugin_class.__name__,
                            converted_files=[],
                            file_count=0,
                            message=f"Converter {display_name} completed: no files to convert",
                        )
                    except Exception as event_error:
                        ASH_LOGGER.error(
                            f"Failed to notify converter complete event: {str(event_error)}"
                        )

                aggregated_results.converter_results[display_name] = (
                    ConverterStatusInfo(
                        dependencies_satisfied=plugin_instance.dependencies_satisfied,
                        excluded=not plugin_instance.config.enabled or False,
                        converted_paths=plugin_converted_paths,
                    )
                )

                # Increment completed count
                completed += 1

            except Exception as e:
                ASH_LOGGER.error(f"Error in converter {plugin_name}: {e}")
                import traceback

                ASH_LOGGER.debug(
                    f"Converter exception traceback: {traceback.format_exc()}"
                )

                # Update converter task to show error
                self.progress_display.update_task(
                    phase=ExecutionPhase.CONVERT,
                    task_id=converter_task,
                    completed=100,
                    description=f"[red]({display_name}) Failed: {str(e)}",
                )

                # Increment completed count
                completed += 1
                import traceback

                ASH_LOGGER.debug(
                    f"Converter exception traceback: {traceback.format_exc()}"
                )

        # Log a summary warning if no files were converted
        if not converted_paths:
            ASH_LOGGER.warning("No files were converted by any converter plugins")
        elif converters_with_no_files:
            ASH_LOGGER.info(
                f"The following converters found no files to convert: {', '.join(converters_with_no_files)}"
            )

        # Update progress
        self.progress_display.update_task(
            phase=ExecutionPhase.CONVERT,
            task_id=convert_task,
            completed=100,
            description="Convert phase complete",
        )

        # Update main task to 100%
        self.update_progress(
            100,
            f"Converters complete: {len(converted_paths)} paths converted from {len(enabled_converters)} converters",
        )

        # Add summary row
        self.add_summary("Complete", f"Converted {len(converted_paths)} paths")

        return aggregated_results

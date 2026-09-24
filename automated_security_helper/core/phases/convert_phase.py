"""Implementation of the Convert phase."""

from pathlib import Path
from typing import Any, List

from automated_security_helper.base.engine_phase import EnginePhase
from automated_security_helper.core.enums import ExecutionPhase
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ConverterStatusInfo,
)
from automated_security_helper.utils.log import ASH_LOGGER


def _converter_display_name(plugin_instance: Any) -> str:
    """The key a converter's ``converter_results`` row is written under.

    One helper rather than the two inline copies this was, because the key is now
    needed in more places than it was -- the conversion loop, its exception handler,
    and the pass that records converters the filter dropped -- and a key computed two
    ways would file the same converter under two names.
    """
    config = getattr(plugin_instance, "config", None)
    name = getattr(config, "name", None)
    return name or plugin_instance.__class__.__name__


class ConvertPhase(EnginePhase):
    """Implementation of the Convert phase."""

    @property
    def phase_name(self) -> str:
        """Return the name of this phase."""
        return "convert"

    def _record_filtered_out_converters(
        self,
        aggregated_results: AshAggregatedResults,
        all_converter_instances: List[Any],
        filtered_instances: List[Any],
        python_based_plugins_only: bool,
    ) -> None:
        """Write a ``converter_results`` row for each converter the filter dropped.

        ``excluded`` and ``dependencies_satisfied`` carry different facts and are
        kept apart deliberately, matching ``ScannerStatusInfo`` where ``excluded``
        is the authoritative signal for SKIPPED and ``dependencies_satisfied`` for
        MISSING. "Turned off" must not send an operator looking for a tool to
        install, and "tool absent" must not read as a deliberate exclusion.
        """
        # Identity, not membership. A converter instance is a pydantic model, whose
        # __eq__ compares field values, so `instance in filtered_instances` would
        # report a dropped converter as surviving whenever another instance of the
        # same class carries the same configuration.
        surviving = {id(instance) for instance in filtered_instances}

        for plugin_instance in all_converter_instances:
            if id(plugin_instance) in surviving:
                continue

            display_name = _converter_display_name(plugin_instance)
            enabled = bool(
                getattr(getattr(plugin_instance, "config", None), "enabled", True)
            )
            declined_by_python_only = False
            if python_based_plugins_only:
                try:
                    declined_by_python_only = not plugin_instance.is_python_only()
                except Exception:
                    # is_python_only is plugin-supplied, so the exception set is
                    # open. An unanswerable question is not an exclusion; the
                    # unexplained-drop arm below is what such an instance lands in.
                    declined_by_python_only = False
            dependencies_satisfied = bool(
                getattr(plugin_instance, "dependencies_satisfied", False)
            )

            drop_is_explained = (
                not enabled or declined_by_python_only or not dependencies_satisfied
            )
            failure = None
            if not drop_is_explained:
                # Dropped although every predicate this method can evaluate says it
                # should have survived, which leaves one cause: the instance's own
                # enabled or dependency check raised inside filter_enabled_plugins,
                # which logs at debug and drops it. Recorded as a failure rather
                # than left as a row that reads "ran and found nothing to convert",
                # because the whole point of these rows is that a converter which
                # did not run says so.
                failure = (
                    "dropped by the enabled/dependency filter, although its own "
                    "dependency check reported satisfied"
                )

            aggregated_results.converter_results[display_name] = ConverterStatusInfo(
                dependencies_satisfied=dependencies_satisfied,
                excluded=not enabled or declined_by_python_only,
                failure=failure,
                converted_paths=[],
            )

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

        # Create all converter instances upfront, then filter via the shared helper.
        all_converter_instances = []
        for plugin_class in converter_classes:
            try:
                plugin_name = getattr(plugin_class, "__name__", "Unknown")
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
                all_converter_instances.append(plugin_instance)
            except Exception as e:
                failed_name = getattr(plugin_class, "__name__", "Unknown")
                ASH_LOGGER.error(f"Error creating converter {failed_name}: {e}")
                # The third way a converter can produce nothing without saying so,
                # and the only one where there is no instance to ask for a name, so
                # the row is keyed on the class. Recorded for the same reason as the
                # other two: a converter whose constructor raised contributed no
                # targets, and without a row the run reports the same "no files
                # converted" as a repository with nothing to convert.
                #
                # dependencies_satisfied is left at its default rather than set
                # either way: the check never ran, so neither value would be a
                # measurement. failure is the signal here.
                aggregated_results.converter_results[failed_name] = ConverterStatusInfo(
                    excluded=False,
                    failure=f"{type(e).__name__}: {e}",
                    converted_paths=[],
                )

        # Assigned before filtering, and on the instance rather than in a local,
        # because filter_enabled_plugins returns only the survivors: a converter
        # dropped for unsatisfied dependencies never reaches the loop below, which
        # is the only site that writes converter_results. Recording the answer here
        # is what lets a row be written for a converter that is about to disappear.
        #
        # ConverterStatusInfo.dependencies_satisfied existed for exactly this and
        # was unreachable -- nothing in the tree assigned a converter's
        # dependencies_satisfied, so the field could not be False.
        #
        # Mirrors ScannerPluginBase._pre_scan, which assigns the same field from the
        # same call after the same filter has run; the check is therefore made twice
        # per converter here too. That is deliberate rather than overlooked: making
        # filter_enabled_plugins read the stored value instead of calling would
        # change the scan and report phases, which share it.
        for plugin_instance in all_converter_instances:
            try:
                plugin_instance.dependencies_satisfied = (
                    plugin_instance.validate_plugin_dependencies()
                )
            except Exception as e:
                # Fail closed. A dependency check that raised has not shown the
                # dependency to be present, and filter_enabled_plugins drops the
                # instance on the same exception, so False is what actually happens.
                ASH_LOGGER.debug(
                    f"Dependency check for converter "
                    f"{_converter_display_name(plugin_instance)} raised {e!r}; "
                    f"recording its dependencies as unsatisfied"
                )
                plugin_instance.dependencies_satisfied = False

        filtered_instances = self.filter_enabled_plugins(
            plugin_instances=all_converter_instances,
            plugin_context=self.plugin_context,
            python_only=python_based_plugins_only,
        )

        # A row for every converter the filter dropped, so a converter that did not
        # run is present in the machine-readable output instead of being absent from
        # it. Without this the only trace was a debug log, and the phase's summary
        # warning was the one a repository with nothing to convert gets.
        self._record_filtered_out_converters(
            aggregated_results=aggregated_results,
            all_converter_instances=all_converter_instances,
            filtered_instances=filtered_instances,
            python_based_plugins_only=python_based_plugins_only,
        )

        enabled_converters = [inst.__class__ for inst in filtered_instances]
        enabled_converter_names = [
            _converter_display_name(inst) for inst in filtered_instances
        ]

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
            return aggregated_results  # Return aggregated_results, not converted_paths!

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
            f"Processing {len(filtered_instances)} enabled converter plugins"
        )
        for plugin_instance in filtered_instances:
            plugin_converted_paths = []
            # Resolved ahead of the try, not inside it. The handler below needs both
            # to key its row and to paint its progress row, and every statement that
            # used to produce them was inside the try: add_task raising on the first
            # converter left converter_task unbound, so the handler died with a
            # NameError and took the whole phase with it.
            plugin_name = plugin_instance.__class__.__name__
            display_name = _converter_display_name(plugin_instance)
            converter_task = None
            try:
                ASH_LOGGER.debug(f"Initializing converter: {plugin_name}")

                # Create a task for this converter
                converter_task = self.progress_display.add_task(
                    phase=ExecutionPhase.CONVERT,
                    description=f"Starting converter: {plugin_name}",
                    total=100,
                )

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
                        converter_class=plugin_instance.__class__.__name__,
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
                            converter_class=plugin_instance.__class__.__name__,
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
                            converter_class=plugin_instance.__class__.__name__,
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

                # The failure is recorded where the success is recorded, and this is
                # the whole point of the handler. Every statement that wrote a row
                # was in the try above, so a converter that raised left no key at
                # all: converted_paths stayed empty, and the phase emitted the same
                # "No files were converted by any converter plugins" warning that a
                # repository with nothing to convert gets. A crash was
                # indistinguishable from an empty repository in every output ASH
                # produces.
                #
                # plugin_converted_paths rather than a literal empty list: the
                # exception is almost always out of convert() itself, in which case
                # it is empty, but a failure after extraction has already extended
                # the phase's converted_paths with those entries and the row should
                # agree with what the phase actually collected.
                #
                # excluded is False because reaching this loop means the converter
                # survived filter_enabled_plugins, and dependencies_satisfied is read
                # with getattr so that recording a failure cannot itself raise.
                aggregated_results.converter_results[display_name] = (
                    ConverterStatusInfo(
                        dependencies_satisfied=bool(
                            getattr(plugin_instance, "dependencies_satisfied", False)
                        ),
                        excluded=False,
                        failure=f"{type(e).__name__}: {e}",
                        converted_paths=plugin_converted_paths,
                    )
                )

                # Update converter task to show error. Skipped when add_task itself
                # is what raised, because there is no task id to update.
                if converter_task is not None:
                    self.progress_display.update_task(
                        phase=ExecutionPhase.CONVERT,
                        task_id=converter_task,
                        completed=100,
                        description=f"[red]({display_name}) Failed: {str(e)}",
                    )

                # Increment completed count
                completed += 1

        # Log a summary warning if no files were converted.
        #
        # The bare form of this warning is what made a crashed converter look like a
        # repository with nothing to convert, so where a row explains the emptiness
        # the warning says so. The rows are the same ones the JSON output carries, so
        # the human-readable and machine-readable answers cannot disagree.
        if not converted_paths:
            unproductive = [
                f"{name} ({row.failure})"
                for name, row in aggregated_results.converter_results.items()
                if getattr(row, "failure", None)
            ]
            if unproductive:
                ASH_LOGGER.warning(
                    "No files were converted, and at least one converter did not "
                    f"finish: {', '.join(unproductive)}"
                )
            else:
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

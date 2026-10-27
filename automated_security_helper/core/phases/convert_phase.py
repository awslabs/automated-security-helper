"""Implementation of the Convert phase."""

import inspect
from pathlib import Path
from typing import Any, Dict, List

from automated_security_helper.base.engine_phase import EnginePhase
from automated_security_helper.base.plugin_config import plugin_config_key
from automated_security_helper.core.enums import ExecutionPhase
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ConverterStatusInfo,
    waives_gate,
)
from automated_security_helper.utils.error_text import error_text, traceback_text
from automated_security_helper.utils.log import ASH_LOGGER, escape_markup
from automated_security_helper.utils.sandbox.scope import (
    converter_run_scope,
    plugin_probe_scope,
)


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


def _conversion_failure(run_scope: Any) -> str | None:
    """Why a converter that returned normally still lost coverage, or None.

    The spawns the scanner sandbox refused while its ``convert()`` ran, which
    converted nothing. The inputs a converter itself could not convert are its
    ``failed_inputs`` (``_input_record_fields``).
    """
    refused = getattr(run_scope, "refused_spawns", 0) or 0
    if not refused:
        return None
    return (
        f"could not convert: the scanner sandbox refused {refused} process(es) it "
        f"started ({getattr(run_scope, 'last_refusal', None) or 'no reason given'})"
    )


def _failure_field(failure: str | None) -> Dict[str, Any]:
    """The ``failure`` keyword for a converter's row, or nothing when there is none."""
    return {"failure": failure} if failure else {}


def _dependency_unavailable_reason(
    plugin_instance: Any, display_name: str, run_config: Any
) -> str:
    """The reason an unavailable converter's row records, as a MISSING scanner's
    row records its own (scan_phase): the reason the converter's dependency check
    recorded in ``dependency_unavailable_reason``, else a message naming it, which
    covers a check that recorded none and one that raised. Redacted with the
    values the run's configuration and the converter read from the environment,
    and with the home directory written as ``~``: the console's warning is where
    the converter's own words, paths included, are kept."""
    from automated_security_helper.utils.error_text import (
        config_environment_values,
        plugin_environment_values,
        text_without_values,
    )
    from automated_security_helper.utils.get_shortest_name import home_as_tilde

    try:
        recorded = getattr(plugin_instance, "dependency_unavailable_reason", None)
    except Exception:  # noqa: BLE001 -- a plugin's attribute read can raise
        recorded = None
    reason = (
        recorded
        if isinstance(recorded, str) and recorded
        else (
            f"{display_name}'s dependency check failed; ash.log has the "
            "converter's own message"
        )
    )
    values = plugin_environment_values(
        plugin_instance, config_environment_values(run_config)
    )
    return home_as_tilde(text_without_values(str.__str__(reason), values))


def _input_record_fields(plugin_instance: Any) -> Dict[str, Any]:
    """The ``refused_inputs`` and ``failed_inputs`` keywords for a converter's row.

    Each is omitted when empty, so ``to_simple_dict``, which dumps with
    ``exclude_unset``, renders a clean tree's row as it did before the fields
    existed. Read with ``getattr`` because a third-party converter need not derive
    from ``ConverterPluginBase``.
    """
    fields: Dict[str, Any] = {}
    for name in ("refused_inputs", "failed_inputs"):
        records = list(getattr(plugin_instance, name, None) or [])
        if records:
            fields[name] = records
    return fields


def _register_accepted_suppressions(
    plugin_instance: Any, plugin_context: Any, aggregated_results: Any
) -> None:
    """Mark the suppression behind each accepted failed input as used.

    The unused-suppressions report subtracts ``used_suppressions`` from the
    config's list, and ``ash merge`` unions the shards' sets, so an acceptance
    that never registered would be reported unused wherever the results travel,
    inviting the operator to delete a load-bearing entry. For a converter
    derived from ConverterPluginBase, ``record_failed_input`` recorded each
    acceptance's id as it was granted, already in the written form, on the
    record itself (``accepted_by``) and in the instance's private list; both
    are unioned in as they are. A record that carries no id (the id write
    failed inside its log-and-drop except, the record came from a third-party
    converter that never derived from ConverterPluginBase, or from a results
    file written before the field existed) has its granting entry re-derived
    below: its path through the matcher that granted it, on
    ``plugin_context``'s config, registered in the written form like every
    other writer. A record the ids cover is NOT re-matched, because the
    re-match can land on a different entry than the one that granted (an
    entry that expired since the grant no longer answers, and the next entry
    matching the path granted nothing), and a false "used" would hide a dead
    entry from the unused-suppressions report and from ``config lint
    --fix-unused`` for good. The re-match can miss for the same reason; the
    base class records at the match so neither direction rests on it.
    """
    # Bookkeeping only, so a failure here is logged and dropped: one call site
    # runs inside the phase's own except block, and raising there would replace
    # the error being handled.
    try:
        records = [
            record
            for record in (getattr(plugin_instance, "failed_inputs", None) or [])
            if getattr(record, "accepted", False)
            and getattr(record, "kind", None) == "input"
        ]
        ids = list(getattr(plugin_instance, "_accepted_suppression_ids", None) or [])
        for written in ids:
            aggregated_results.used_suppressions.add(written)
        uncovered = []
        for record in records:
            carried = getattr(record, "accepted_by", None)
            if isinstance(carried, str) and carried:
                aggregated_results.used_suppressions.add(carried)
            else:
                uncovered.append(record)
        if not uncovered:
            return
        from automated_security_helper.utils.suppression_matcher import (
            accepting_unconverted_input,
            recorded_suppressions,
            written_suppression_id,
        )

        config = getattr(plugin_context, "config", None)
        settings = getattr(config, "global_settings", None)
        suppressions = getattr(settings, "suppressions", None)
        # Built once: the record is the same for every re-match, and the loop
        # runs per uncovered record.
        recorded = recorded_suppressions(config)
        for record in uncovered:
            accepting = accepting_unconverted_input(
                str(getattr(record, "path", "")), suppressions
            )
            if accepting is not None:
                aggregated_results.used_suppressions.add(
                    written_suppression_id(accepting, recorded)
                )
    except Exception as error:
        # The type alone: a raw str(error) here can carry a path or a value
        # the matcher read, and this bookkeeping log holds no values to
        # redact it with (the same form the module check's own-failure log
        # uses in config_validator).
        ASH_LOGGER.debug(
            f"Could not register accepted suppressions as used: {type(error).__name__}"
        )


def _could_not_convert(plugin_instance: Any) -> str:
    """``"2 files could not be converted"`` for a converter's failed inputs, or ``""``.

    For the progress row and the CONVERT_COMPLETE message. A converter whose inputs
    all failed returns no paths, and without this it was reported as having found
    no files to convert, the message a tree without notebooks gets.

    Counts the records the completeness gate counts: one a suppression accepted
    is reported apart (``_accepted_inputs``), so the row and the warning cannot
    call reviewed work a failure while the exit code passes it.
    """
    count = len(_unaccepted_failed_inputs(plugin_instance))
    if not count:
        return ""
    return f"{count} {'file' if count == 1 else 'files'} could not be converted"


def _unaccepted_failed_inputs(holder: Any) -> List[Any]:
    """``holder``'s failed-input records that count as failures.

    A record that waives the gate (``waives_gate``: accepted, of kind "input")
    is left out -- the one trust rule, shared with ``incomplete_converters``.
    ``holder`` is a plugin instance or a recorded row; both carry
    ``failed_inputs``.
    """
    return [
        record
        for record in (getattr(holder, "failed_inputs", None) or [])
        if not waives_gate(record)
    ]


def _accepted_inputs(plugin_instance: Any) -> str:
    """``"1 input accepted by a suppression"`` for the accepted records, or ``""``."""
    count = len(list(getattr(plugin_instance, "failed_inputs", None) or [])) - len(
        _unaccepted_failed_inputs(plugin_instance)
    )
    if not count:
        return ""
    noun = "input" if count == 1 else "inputs"
    return f"{count} {noun} accepted by a suppression"


def _call_convert(plugin_instance: Any) -> Any:
    """Call a converter's ``convert()``, refusing one that asks for an argument.

    The contract is ``convert(self)``: this phase has always called it with no
    argument, and both built-in converters find their inputs in
    ``context.source_dir``. ``ConverterPluginBase`` and the converter docs declared
    ``convert(self, target)`` instead, so a converter written to them failed every
    scan with the interpreter's "missing 1 required positional argument: 'target'".

    A converter that requires any argument (the old ``convert(self, target)``, or
    the ``convert(self, source_path, target_path)`` an old docs page showed) is
    refused before it is called, with a message that names the converter and says
    to declare ``convert(self)``. ASH does not guess a value for it: passing the
    source directory as ``target`` would run code written against an interface that
    no longer exists, with an argument it may read differently.
    """
    convert = plugin_instance.convert
    if inspect.iscoroutinefunction(convert):
        # Called, it would return a coroutine that never runs, and the failure
        # would surface later as a TypeError about Path() and a coroutine.
        raise TypeError(
            f"{type(plugin_instance).__name__}.convert() is declared async, and ASH "
            "calls convert() synchronously. Declare it as def convert(self)."
        )
    try:
        parameters = inspect.signature(convert).parameters.values()
    except (TypeError, ValueError):
        # No introspectable signature (a C callable, say): call it as the contract
        # says and let it fail on its own terms if it disagrees.
        return convert()

    required = [
        p
        for p in parameters
        if p.default is inspect.Parameter.empty
        and p.kind
        not in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD)
    ]
    if not required:
        return convert()

    # Named by the parameter rather than rendered as a signature: a staticmethod
    # or a classmethod has no "self" to show.
    names = ", ".join(f"'{p.name}'" for p in required)
    noun = "the parameter" if len(required) == 1 else "the parameters"
    raise TypeError(
        f"{type(plugin_instance).__name__}.convert() requires {noun} {names}, which "
        "ASH does not supply: ASH calls convert() with no argument. Declare "
        "convert(self): find the inputs under self.context.source_dir and write the "
        "output under self.results_dir."
    )


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

            # Asked even though this converter is about to disappear, and that is the
            # point: it is the only moment anything can establish whether its absence
            # cost coverage. ``candidate_input_count`` is answered without the
            # converter's external tool, so it works precisely when the tool is what is
            # missing. A converter that does not report one answers None and the
            # completeness gate stays as strict as it was.
            #
            # Wrapped because this calls into plugin code, including third-party
            # converters. A count that raised has not shown the tree to be empty, so it
            # must not resolve to 0 -- that would exempt the row from the gate on the
            # strength of a failure. None is the strict answer.
            try:
                candidate_inputs = plugin_instance.candidate_input_count()
            except Exception as exc:
                ASH_LOGGER.debug(
                    f"Candidate-input count for converter {display_name} raised "
                    f"{exc!r}; recording no count so the completeness gate stays strict"
                )
                candidate_inputs = None

            aggregated_results.converter_results[display_name] = ConverterStatusInfo(
                dependencies_satisfied=dependencies_satisfied,
                dependency_unavailable_reason=(
                    None
                    if dependencies_satisfied
                    else _dependency_unavailable_reason(
                        plugin_instance,
                        display_name,
                        getattr(self.plugin_context, "config", None),
                    )
                ),
                excluded=not enabled or declined_by_python_only,
                failure=failure,
                candidate_inputs=candidate_inputs,
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

        # Get all converter plugins
        converter_classes = self.plugins

        # Create all converter instances upfront, then filter via the shared helper.
        all_converter_instances = []
        for plugin_class in converter_classes:
            try:
                # Under a sandbox, what a converter runs while it is constructed and
                # validated (nbconvert's version probe, its dependency check) runs
                # sandboxed, as a scanner's probes do, and installs nothing.
                with plugin_probe_scope(plugin_class, self.plugin_context):
                    plugin_instance = plugin_class(
                        context=self.plugin_context,
                        config=(
                            self.plugin_context.config.get_plugin_config(
                                plugin_type="converter",
                                plugin_name=plugin_config_key(plugin_class),
                            )
                            if self.plugin_context.config is not None
                            else None
                        ),
                    )
                all_converter_instances.append(plugin_instance)
            except Exception as e:
                failed_name = getattr(plugin_class, "__name__", "Unknown")
                ASH_LOGGER.error(
                    f"Error creating converter {failed_name}: {error_text(e)}"
                )
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
                    failure=f"{type(e).__name__}: {error_text(e)}",
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
                with plugin_probe_scope(plugin_instance, self.plugin_context):
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

        # One at a time, so the dependency check the filter repeats runs in that
        # converter's own probe scope too.
        filtered_instances = []
        for plugin_instance in all_converter_instances:
            with plugin_probe_scope(plugin_instance, self.plugin_context):
                filtered_instances.extend(
                    self.filter_enabled_plugins(
                        plugin_instances=[plugin_instance],
                        plugin_context=self.plugin_context,
                        python_only=python_based_plugins_only,
                    )
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

        if not enabled_converters:
            ASH_LOGGER.warning(
                "No enabled converter plugins found, skipping conversion phase"
            )
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
                    # Each name a description quotes is escaped once: the live
                    # display renders it as markup.
                    description=f"Starting converter: {escape_markup(plugin_name)}",
                    total=100,
                )

                # Update converter task to 50%
                self.progress_display.update_task(
                    phase=ExecutionPhase.CONVERT,
                    task_id=converter_task,
                    completed=50,
                    description=f"Running converter: {escape_markup(display_name)}",
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

                # convert() takes no argument; a converter that asks for one, the old
                # convert(self, target) declaration included, is refused. Under a
                # sandbox, the converter's tool runs confined like a scanner's.
                with converter_run_scope(
                    plugin_instance, self.plugin_context
                ) as run_scope:
                    convert_result_initial = _call_convert(plugin_instance)
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
                    not_converted = _could_not_convert(plugin_instance)
                    accepted = _accepted_inputs(plugin_instance)
                    # Both when both, in this branch too: an acceptance stays
                    # visible beside the converted count rather than vanishing
                    # whenever anything was converted.
                    outcome = "; ".join(
                        part for part in (not_converted, accepted) if part
                    )
                    also = f", {outcome}" if outcome else ""

                    # Update converter task to 100%. Each description is written
                    # inline, every value it quotes escaped once.
                    if not_converted:
                        self.progress_display.update_task(
                            phase=ExecutionPhase.CONVERT,
                            task_id=converter_task,
                            completed=100,
                            description=(
                                f"[yellow]({escape_markup(display_name)}) Converted "
                                f"{len(convert_result)} files, "
                                f"{escape_markup(outcome)}"
                            ),
                        )
                    elif accepted:
                        self.progress_display.update_task(
                            phase=ExecutionPhase.CONVERT,
                            task_id=converter_task,
                            completed=100,
                            description=(
                                f"[green]({escape_markup(display_name)}) Converted "
                                f"{len(convert_result)} files, "
                                f"{escape_markup(accepted)}"
                            ),
                        )
                    else:
                        self.progress_display.update_task(
                            phase=ExecutionPhase.CONVERT,
                            task_id=converter_task,
                            completed=100,
                            description=(
                                f"[green]({escape_markup(display_name)}) Converted "
                                f"{len(convert_result)} files"
                            ),
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
                            message=(
                                f"Converter {display_name} completed: "
                                f"{len(convert_result)} files converted{also}"
                            ),
                        )
                    except Exception as event_error:
                        ASH_LOGGER.error(
                            f"Failed to notify converter complete event: {str(event_error)}"
                        )
                else:
                    ASH_LOGGER.debug(
                        f"Converter {display_name} returned None or empty result"
                    )
                    not_converted = _could_not_convert(plugin_instance)
                    accepted = _accepted_inputs(plugin_instance)
                    # Both when both: an acceptance stays visible beside other
                    # failures rather than vanishing whenever anything failed.
                    outcome = "; ".join(
                        part for part in (not_converted, accepted) if part
                    )
                    if not outcome:
                        converters_with_no_files.append(display_name)

                    # Update converter task to 100%. A converter whose every input
                    # failed says so, rather than what a tree with none gets; one
                    # whose inputs were accepted by a suppression says that, in
                    # the acceptance's color rather than a failure's.
                    if not_converted:
                        self.progress_display.update_task(
                            phase=ExecutionPhase.CONVERT,
                            task_id=converter_task,
                            completed=100,
                            description=(
                                f"[red]({escape_markup(display_name)}) "
                                f"{escape_markup(outcome)}"
                            ),
                        )
                    elif accepted:
                        self.progress_display.update_task(
                            phase=ExecutionPhase.CONVERT,
                            task_id=converter_task,
                            completed=100,
                            description=(
                                f"[yellow]({escape_markup(display_name)}) "
                                f"{escape_markup(accepted)}"
                            ),
                        )
                    else:
                        self.progress_display.update_task(
                            phase=ExecutionPhase.CONVERT,
                            task_id=converter_task,
                            completed=100,
                            description=f"[yellow]({escape_markup(display_name)}) No files to convert",
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
                            message=(
                                f"Converter {display_name} completed: "
                                f"{outcome or 'no files to convert'}"
                            ),
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
                        **_input_record_fields(plugin_instance),
                        # Omitted when nothing was lost, like refused_inputs.
                        **_failure_field(_conversion_failure(run_scope)),
                    )
                )
                _register_accepted_suppressions(
                    plugin_instance, self.plugin_context, aggregated_results
                )

            except Exception as e:
                ASH_LOGGER.error(f"Error in converter {plugin_name}: {error_text(e)}")
                ASH_LOGGER.debug(f"Converter exception traceback: {traceback_text()}")

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
                        failure=f"{type(e).__name__}: {error_text(e)}",
                        converted_paths=plugin_converted_paths,
                        **_input_record_fields(plugin_instance),
                    )
                )
                _register_accepted_suppressions(
                    plugin_instance, self.plugin_context, aggregated_results
                )

                # Update converter task to show error. Skipped when add_task itself
                # is what raised, because there is no task id to update.
                if converter_task is not None:
                    self.progress_display.update_task(
                        phase=ExecutionPhase.CONVERT,
                        task_id=converter_task,
                        completed=100,
                        description=(
                            f"[red]({escape_markup(display_name)}) Failed: "
                            f"{escape_markup(error_text(e))}"
                        ),
                    )

        # Log a summary warning if no files were converted.
        #
        # The bare form of this warning is what made a crashed converter look like a
        # repository with nothing to convert, so where a row explains the emptiness
        # the warning says so. The rows are the same ones the JSON output carries, so
        # the human-readable and machine-readable answers cannot disagree.
        if not converted_paths:
            # An accepted record is not "did not finish": the row's count here
            # is the gate's count, so the warning and the exit code agree.
            unproductive = [
                f"{name} ({row.failure})"
                if getattr(row, "failure", None)
                else f"{name} ({len(_unaccepted_failed_inputs(row))} could not be converted)"
                for name, row in aggregated_results.converter_results.items()
                if getattr(row, "failure", None) or _unaccepted_failed_inputs(row)
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

        # Add summary row
        self.add_summary("Complete", f"Converted {len(converted_paths)} paths")

        return aggregated_results

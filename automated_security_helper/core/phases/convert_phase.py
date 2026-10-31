"""Implementation of the Convert phase."""

import inspect
from pathlib import Path
from typing import Any, Dict, List

from automated_security_helper.base.engine_phase import EnginePhase
from automated_security_helper.base.plugin_config import (
    declared_plugin_name,
    plugin_config_key,
    section_enabled,
)
from automated_security_helper.base.uv_tool_mixin import deferred_tool_version_probes
from automated_security_helper.core.enums import ExecutionPhase
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ConverterStatusInfo,
    FailedInputInfo,
    RefusedInputInfo,
    waives_gate,
)
from automated_security_helper.utils.error_text import (
    config_environment_values,
    error_text,
    plugin_environment_values,
    traceback_text,
)
from automated_security_helper.utils.log import ASH_LOGGER, escape_markup
from automated_security_helper.utils.sandbox.scope import (
    converter_run_scope,
    plugin_probe_scope,
    scope_shown_text,
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


def _constructor_failure_name(plugin_class: Any) -> str:
    """The name a converter whose constructor raised is recorded under.

    A constructed converter's row is keyed by its config's ``name``, which is the
    name its config class declares. There is no instance to ask here, so the
    declared name is read off the class, as ``plugin_config_key`` does, and only a
    converter that declares none falls back to its class name. Keyed on the class
    always, one converter was filed under two names: its class when the
    constructor raised and its configured name when it was built.
    """
    try:
        declared = declared_plugin_name(plugin_class)
    except Exception:  # noqa: BLE001 -- a plugin class can be anything
        declared = None
    return declared or getattr(plugin_class, "__name__", "Unknown")


def _unused_key(preferred: str, taken: Any, qualifier: str) -> str:
    """``preferred`` as a ``converter_results`` key no other converter holds.

    The rows are a dict keyed by display name, and nothing made the names unique:
    two registered converters sharing a config name (or, with no config, a class
    name) wrote one row, the later one over the earlier, so a failure row could be
    replaced by a clean one and the completeness gate never saw it. A taken name
    is qualified with the converter's own identity (``qualifier``), then
    numbered, so every converter keeps a row of its own.
    """
    if preferred not in taken:
        return preferred
    qualified = f"{preferred} ({qualifier})"
    if qualified not in taken:
        return qualified
    index = 2
    while f"{qualified} #{index}" in taken:
        index += 1
    return f"{qualified} #{index}"


def _row_keys(
    converter_instances: List[Any], aggregated_results: AshAggregatedResults
) -> Dict[int, str]:
    """The ``converter_results`` key of each instance, by ``id``, each unique.

    Computed once, after the filter and before any row is written, so the row a
    converter's run writes, the row its exception handler writes and the row
    the filtered-out pass writes all land under one key, and under a key no
    other converter of this run (a converter whose constructor raised included)
    is recorded under. The same key names the converter in its progress rows
    and in its CONVERT_START and CONVERT_COMPLETE events, so two converters
    sharing a display name are told apart there too.
    """
    taken = set(aggregated_results.converter_results)
    keys: Dict[int, str] = {}
    for plugin_instance in converter_instances:
        cls = plugin_instance.__class__
        key = _unused_key(
            _converter_display_name(plugin_instance),
            taken,
            f"{cls.__module__}.{cls.__name__}",
        )
        taken.add(key)
        keys[id(plugin_instance)] = key
    return keys


def _redaction_values(plugin_instance: Any, run_config: Any) -> tuple:
    """The values a converter's error text is redacted with: the run's
    configuration's environment values and the converter's own, as the
    dependency reason's are (``_dependency_unavailable_reason``)."""
    return plugin_environment_values(
        plugin_instance, config_environment_values(run_config)
    )


def _failure_text(error: BaseException, values: Any) -> str:
    """``'<type>: <message>'`` for a converter's row, redacted with ``values``.

    The text goes to the results file, ``to_simple_dict`` (sent off-host by
    some reporters), the HTML report's coverage notice, the progress row and
    ash.log, and every consumer treats it as already redacted. A converter's
    exception can quote a value its config read from the environment, so it is
    redacted here, once, before it is recorded anywhere.
    """
    return f"{type(error).__name__}: {error_text(error, values)}"


def _answers_python_only(plugin_instance: Any) -> bool:
    """Whether a converter says it is Python-only, read with a guard.

    ``is_python_only`` is plugin-supplied, so the exception set is open; a check
    that raises is read as "not Python-only", which is what
    ``filter_enabled_plugins`` does with the same call, so the pre-filter
    dependency skip and the filter agree on which converters a Python-only run
    leaves out.
    """
    try:
        return bool(plugin_instance.is_python_only())
    except Exception:
        return False


def _records(holder: Any, name: str, model: Any) -> List[Any]:
    """``holder``'s ``name`` records, each dict read as the record it becomes.

    The row's own validation turns a dict into a ``model`` record, so a dict
    that said ``accepted: true`` waived the completeness gate, while the
    progress text and the suppression bookkeeping read it with ``getattr``,
    found no ``accepted`` and called reviewed work a failure. Reading both
    from the same record keeps the text, the registered suppression and the
    gate in agreement. A dict the model refuses is left as given: the row's
    validation refuses it too and records why (``_execute_phase``'s handler).
    """
    records: List[Any] = []
    for record in getattr(holder, name, None) or []:
        if isinstance(record, dict):
            try:
                record = model.model_validate(record)
            except Exception:  # noqa: BLE001 -- the row's validation reports it
                pass
        records.append(record)
    return records


def _refused_over_limit(plugin_instance: Any) -> str:
    """``"1 archive refused over an extraction limit"`` for the refusals the
    completeness gate counts, or ``""``.

    A refusal that names a ``limit`` is an archive refused whole, so none of
    its contents reached the scanners: the gate fails the run on it
    (``incomplete_converters``), and the progress row and the CONVERT_COMPLETE
    message have to say so instead of "No files to convert", which is the
    message a tree without archives gets. A refusal without a limit (a link, a
    nested archive) refuses one input that is not to be read and does not
    count, here as in the gate.
    """
    count = sum(
        1
        for record in _records(plugin_instance, "refused_inputs", RefusedInputInfo)
        if getattr(record, "limit", None)
    )
    if not count:
        return ""
    noun = "archive" if count == 1 else "archives"
    return f"{count} {noun} refused over an extraction limit"


def _conversion_failure(run_scope: Any) -> str | None:
    """Why a converter that returned normally still lost coverage, or None.

    The spawns the scanner sandbox refused while its ``convert()`` ran, and the
    ones whose sandbox plan failed some other way (a program the backend could
    not find, a private directory it could not make); either converted nothing.
    The two are named apart: only the first is the sandbox's refusal, and a
    failed plan is the error the spawn would have raised unsandboxed. The inputs
    a converter itself could not convert are its ``failed_inputs``
    (``_input_record_fields``).
    """
    refused = getattr(run_scope, "refused_spawns", 0) or 0
    failed = getattr(run_scope, "failed_spawns", 0) or 0
    if not refused and not failed:
        return None
    reasons = []
    if refused:
        reasons.append(
            f"the scanner sandbox refused {refused} process(es) it started "
            f"({getattr(run_scope, 'last_refusal', None) or 'no reason given'})"
        )
    if failed:
        reasons.append(
            f"the sandbox could not plan {failed} process(es) it started "
            f"({getattr(run_scope, 'last_failure', None) or 'no reason given'})"
        )
    return "could not convert: " + "; ".join(reasons)


def _shown_loss(text: str, values: Any) -> str:
    """``_conversion_failure``'s text as every sink may show it.

    The scope's ``last_refusal`` is the sandbox's own sentence and its
    ``last_failure`` is a planning exception's text, so either can quote a value
    the converter's config read from the environment, or a path under the home
    directory. The text goes to the row, the progress row and the CONVERT_COMPLETE
    message, which reach the results file, the reports and the event subscribers,
    so it is redacted once here with the values every other failure text of this
    phase is redacted with (``scope_shown_text``, which also hides the values the
    scope held), and the home directory is written as ``~`` as the dependency
    reason's is (``_dependency_unavailable_reason``): ``scope_shown_text`` does
    not fold the home directory itself.
    """
    if not text:
        return text
    from automated_security_helper.utils.get_shortest_name import home_as_tilde

    return home_as_tilde(scope_shown_text(text, values))


def _failure_field(failure: str | None) -> Dict[str, Any]:
    """The ``failure`` keyword for a converter's row, or nothing when there is none."""
    return {"failure": failure} if failure else {}


def _converted_path_list(result: Any) -> List[str]:
    """The paths a converter's ``convert()`` returned, as posix strings.

    ``convert()`` is declared to return a list, but a converter that hands back a
    tuple, a set or a generator of the paths it wrote did convert them. Each of
    those was wrapped whole and given to ``Path()``, which raised ``TypeError``:
    a successful conversion was recorded as a failure with its outputs dropped. A
    single path (a string or a path object) is still one path, a set is sorted
    so the order does not depend on hashing, and an empty string names no file
    (it became the path ``.``) and is left out. Anything else that is not
    iterable still reaches ``Path()`` and fails there, loudly.
    """
    if result is None:
        return []
    if isinstance(result, (str, bytes, Path)) or not hasattr(result, "__iter__"):
        items: List[Any] = [result]
    elif isinstance(result, (set, frozenset)):
        items = sorted(result, key=str)
    elif isinstance(result, dict):
        # A mapping is no list of paths; Path() refuses it by name below.
        items = [result]
    else:
        items = list(result)
    return [Path(item).as_posix() for item in items if item is not None and item != ""]


def _redaction_values_or(plugin_instance: Any, run_config: Any, fallback: Any) -> Any:
    """``_redaction_values``, or ``fallback`` when the converter cannot answer.

    Used where the text being redacted is already an error out of the converter,
    so its own failure to name its values must not replace the error.
    """
    try:
        return _redaction_values(plugin_instance, run_config)
    except Exception:  # noqa: BLE001 -- plugin code
        return fallback


def _unproductive_reason(row: Any) -> str | None:
    """Why a converter's row explains an empty conversion, or None.

    The row's ``failure``; else the archives it refused whole over an extraction
    limit (a loss the completeness gate counts too); else the count of its failed
    inputs that are not accepted (the gate's count); else the reason its tool was
    unavailable. The refusal was left out, so a run whose only converter refused
    an archive logged the bare "No files were converted by any converter
    plugins" beside a gate that fails the run on that very row. So was the last,
    for a run whose only converter had been dropped for a missing tool.

    None for a row marked ``excluded``, whatever else it carries: the run was
    never meant to use that converter (the config turned it off, or the run
    declined it), and the completeness gate skips such a row first. A turned-off
    converter whose constructor raised carries a ``failure`` and is excluded, so
    reading the failure first listed it as a converter that "did not start".
    """
    if getattr(row, "excluded", False):
        return None
    failure = getattr(row, "failure", None)
    if failure:
        return str(failure)
    refused = _refused_over_limit(row)
    if refused:
        return refused
    unaccepted = _unaccepted_failed_inputs(row)
    if unaccepted:
        return f"{len(unaccepted)} could not be converted"
    if getattr(row, "dependencies_satisfied", True) is False:
        return str(
            getattr(row, "dependency_unavailable_reason", None)
            or "its dependencies are unavailable"
        )
    return None


def _why_no_converter_ran(aggregated_results: AshAggregatedResults) -> List[str]:
    """``"name (reason)"`` for each converter row that explains why none ran.

    A row with a ``failure``, or one whose tool was unavailable and that was not
    turned off. The reasons are the rows' own, already redacted. Used so the
    phase does not say "No enabled converter plugins found", the message for
    conversion turned off, when converters were configured and failed to start.
    """
    return [
        f"{name} ({reason})"
        for name, row in aggregated_results.converter_results.items()
        if (reason := _unproductive_reason(row))
    ]


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
    from automated_security_helper.utils.error_text import text_without_values
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
    values = _redaction_values(plugin_instance, run_config)
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
            for record in _records(plugin_instance, "failed_inputs", FailedInputInfo)
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
        for record in _records(holder, "failed_inputs", FailedInputInfo)
        if not waives_gate(record)
    ]


def _accepted_inputs(plugin_instance: Any) -> str:
    """``"1 input accepted by a suppression"`` for the accepted records, or ``""``."""
    count = len(_records(plugin_instance, "failed_inputs", FailedInputInfo)) - len(
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
        row_keys: Dict[int, str] | None = None,
        dependency_answers: Dict[int, bool] | None = None,
        filter_failures: Dict[int, str] | None = None,
    ) -> None:
        """Write a ``converter_results`` row for each converter the filter dropped.

        ``excluded`` and ``dependencies_satisfied`` carry different facts and are
        kept apart deliberately, matching ``ScannerStatusInfo`` where ``excluded``
        is the authoritative signal for SKIPPED and ``dependencies_satisfied`` for
        MISSING. "Turned off" must not send an operator looking for a tool to
        install, and "tool absent" must not read as a deliberate exclusion. A
        converter the config turned off never had its dependency check run, so
        its row says nothing about its tool (``dependencies_satisfied`` True, no
        reason), as a SKIPPED scanner's row does.

        ``row_keys`` is the key each instance's row is written under
        (``_row_keys``); an instance it does not name is keyed by its display name.

        ``dependency_answers`` is the one answer each checked converter's
        dependency check gave, by ``id``; an instance it does not name is read
        from its ``dependencies_satisfied`` attribute, which a converter that
        refuses the assignment never carries.

        ``filter_failures`` is what ``filter_enabled_plugins`` recorded for each
        instance whose own enabled or Python-only check raised, by ``id``
        (already redacted). Such an instance was dropped without any question
        answered, so its row is a failure that says which check raised, and it
        says nothing about the converter's tool unless a dependency answer was
        recorded for it.
        """
        row_keys = row_keys or {}
        dependency_answers = dependency_answers or {}
        filter_failures = filter_failures or {}
        # Identity, not membership. A converter instance is a pydantic model, whose
        # __eq__ compares field values, so `instance in filtered_instances` would
        # report a dropped converter as surviving whenever another instance of the
        # same class carries the same configuration.
        surviving = {id(instance) for instance in filtered_instances}

        for plugin_instance in all_converter_instances:
            if id(plugin_instance) in surviving:
                continue

            display_name = _converter_display_name(plugin_instance)
            row_key = row_keys.get(id(plugin_instance), display_name)
            enabled = section_enabled(getattr(plugin_instance, "config", None))
            declined_by_python_only = False
            if python_based_plugins_only:
                try:
                    declined_by_python_only = not plugin_instance.is_python_only()
                except Exception:
                    # is_python_only is plugin-supplied, so the exception set is
                    # open. An unanswerable question is not an exclusion, and the
                    # pre-filter loop skipped this converter's dependency check on
                    # the same answer (_answers_python_only). The text of what it
                    # raised is not read here: the filter recorded it, redacted,
                    # in ``filter_failures``, which is read below.
                    declined_by_python_only = False
            raised = filter_failures.get(id(plugin_instance))
            # The pre-filter loop asks the dependency question of an enabled
            # converter that the Python-only filter keeps, and of no other. A
            # converter the config turned off, one a Python-only run declined, and
            # one whose Python-only or enabled check raised (it is skipped there
            # too) never had its check run, so True here is "not asked", not a
            # claim about its tool.
            if id(plugin_instance) in dependency_answers:
                checked = dependency_answers[id(plugin_instance)]
            else:
                checked = bool(
                    getattr(plugin_instance, "dependencies_satisfied", False)
                )
            not_asked = (
                not enabled
                or declined_by_python_only
                or (
                    raised is not None and id(plugin_instance) not in dependency_answers
                )
            )
            dependencies_satisfied = not_asked or checked

            drop_is_explained = (
                not enabled or declined_by_python_only or not dependencies_satisfied
            )
            failure = None
            if raised is not None:
                # The filter recorded the exception its own check raised, so the
                # drop has a cause that can be named. Recorded as a failure: a
                # converter that could not say whether a Python-only run wants it
                # may have held files the scanners then never saw.
                failure = (
                    "dropped by the filter: its enabled or is_python_only() check "
                    f"raised {raised}"
                )
            elif not drop_is_explained:
                # Dropped although every predicate this method can evaluate says it
                # should have survived, and the filter recorded no exception. The
                # filter and these predicates disagree (an answer that changes
                # between two calls). Recorded as a failure rather than left as a
                # row that reads "ran and found nothing to convert", because the
                # whole point of these rows is that a converter which did not run
                # says so.
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
            # strength of a failure. None is the strict answer. The answer's type is
            # checked inside the same guard: the row's field is an int, so an answer
            # of another type (a str, a float, a Mock) failed the row's validation
            # outside the try and aborted the convert phase, and the scan with it.
            try:
                candidate_inputs = plugin_instance.candidate_input_count()
                if candidate_inputs is not None and (
                    isinstance(candidate_inputs, bool)
                    or not isinstance(candidate_inputs, int)
                ):
                    raise TypeError(
                        "candidate_input_count() returned a "
                        f"{type(candidate_inputs).__name__}, not an int"
                    )
            except Exception as exc:
                ASH_LOGGER.debug(
                    f"Candidate-input count for converter {display_name} raised "
                    f"{exc!r}; recording no count so the completeness gate stays strict"
                )
                candidate_inputs = None

            aggregated_results.converter_results[row_key] = ConverterStatusInfo(
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
        run_config = getattr(self.plugin_context, "config", None)
        # The values every failure text below is redacted with: the run's
        # configuration's environment values, before any converter adds its own.
        run_values = config_environment_values(run_config)

        # Create all converter instances upfront, then filter via the shared helper.
        all_converter_instances = []
        for plugin_class in converter_classes:
            # Resolved before the constructor, so the handler can read the
            # section's `enabled` off it: a converter the config turned off whose
            # constructor raised is recorded excluded, as the config asked, and not
            # as a failure the completeness gate fails the run on.
            plugin_config = None
            try:
                if self.plugin_context.config is not None:
                    plugin_config = self.plugin_context.config.get_plugin_config(
                        plugin_type="converter",
                        plugin_name=plugin_config_key(plugin_class),
                    )
                # Under a sandbox, what a converter runs while it is constructed and
                # validated (nbconvert's version probe, its dependency check) runs
                # sandboxed, as a scanner's probes do, and installs nothing. The
                # `uv tool run` version probe is deferred, as the scan phase defers
                # a scanner's: the converter's dependency check resolves it only
                # when the scan set holds something to convert, so a scan with no
                # notebook asks uv nothing about nbconvert.
                with (
                    plugin_probe_scope(plugin_class, self.plugin_context),
                    deferred_tool_version_probes(),
                ):
                    plugin_instance = plugin_class(
                        context=self.plugin_context,
                        config=plugin_config,
                    )
                all_converter_instances.append(plugin_instance)
            except Exception as e:
                # Keyed on the name the class declares (the one a constructed
                # instance's row carries), else on the class, with no instance to
                # ask; a second class of the same name is told apart by its module.
                failed_name = _unused_key(
                    _constructor_failure_name(plugin_class),
                    aggregated_results.converter_results,
                    getattr(plugin_class, "__module__", "unknown module"),
                )
                # Redacted with the config's environment values, as the scan
                # phase redacts a scanner's construction error: the text goes to
                # the results file, the HTML report, the progress row and ash.log,
                # and can name an option the config read from the environment.
                failure = _failure_text(e, run_values)
                ASH_LOGGER.error(f"Error creating converter {failed_name}: {failure}")
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
                    excluded=not section_enabled(plugin_config),
                    failure=failure,
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
        # The check is made here, once, and the filter below is told not to make it
        # again (check_dependencies=False). Made twice, a check that resolves and
        # installs a tool (the jupyter converter's resolves nbconvert through uv)
        # ran its install attempt, with its retries and its timeout, twice per
        # scan; and a check that answered differently the second time recorded
        # one answer in the row and acted on another. The one answer is kept by
        # converter in ``dependency_answers``, and also on the instance for the
        # code that reads it there.
        #
        # Not for a converter the config turned off, and not for a non-Python
        # converter on a Python-only run. The filter below drops both before
        # asking about their dependencies, and a dependency check can resolve
        # and install a tool (the jupyter converter's resolves nbconvert through
        # uv), which a run that left the converter out asked it not to do.
        dependency_answers: Dict[int, bool] = {}
        for plugin_instance in all_converter_instances:
            if not section_enabled(getattr(plugin_instance, "config", None)):
                continue
            if python_based_plugins_only and not _answers_python_only(plugin_instance):
                continue
            try:
                with plugin_probe_scope(plugin_instance, self.plugin_context):
                    # bool(): the row's field is a bool, and a check that answers
                    # with a truthy non-bool (a tool's path) passed the filter and
                    # then failed the row's validation, so a converter that ran
                    # was recorded as failed.
                    answer = bool(plugin_instance.validate_plugin_dependencies())
            except Exception as e:
                # Fail closed. A dependency check that raised has not shown the
                # dependency to be present. Said at warning, as the filter says a
                # check that raises, because the converter is dropped here and a
                # debug line is not seen on a default run.
                values = _redaction_values_or(plugin_instance, run_config, run_values)
                ASH_LOGGER.warning(
                    f"Excluding converter {_converter_display_name(plugin_instance)}: "
                    f"its dependency check raised {_failure_text(e, values)}"
                )
                answer = False
            dependency_answers[id(plugin_instance)] = answer
            # Separate from the check: a converter that refuses the assignment
            # (a frozen model, a property) must not turn a recorded answer into a
            # second failure, which the old assignment in the except arm did.
            try:
                plugin_instance.dependencies_satisfied = answer
            except Exception as e:  # noqa: BLE001 -- plugin code
                ASH_LOGGER.debug(
                    f"Converter {_converter_display_name(plugin_instance)} did not "
                    f"take its dependency answer: {type(e).__name__}"
                )

        # What the filter decides is the enabled flag and python-only mode, which
        # are in-process questions, so it needs no probe scope of its own: the
        # scope was there for the dependency check it no longer makes, and an
        # error opening it aborted the whole phase. A converter survives only
        # with the one dependency answer above True.
        filtered_instances = []
        # What the filter recorded for an instance whose own check raised, so its
        # row can name the check instead of guessing a cause.
        filter_failures: Dict[int, str] = {}
        for plugin_instance in all_converter_instances:
            admitted = self.filter_enabled_plugins(
                plugin_instances=[plugin_instance],
                plugin_context=self.plugin_context,
                python_only=python_based_plugins_only,
                check_dependencies=False,
                failures=filter_failures,
            )
            if admitted and dependency_answers.get(id(plugin_instance)) is True:
                filtered_instances.extend(admitted)

        # One key per converter, computed before any row below is written, so two
        # converters sharing a display name do not write one row over the other.
        row_keys = _row_keys(all_converter_instances, aggregated_results)

        # A row for every converter the filter dropped, so a converter that did not
        # run is present in the machine-readable output instead of being absent from
        # it. Without this the only trace was a debug log, and the phase's summary
        # warning was the one a repository with nothing to convert gets.
        self._record_filtered_out_converters(
            aggregated_results=aggregated_results,
            all_converter_instances=all_converter_instances,
            filtered_instances=filtered_instances,
            python_based_plugins_only=python_based_plugins_only,
            row_keys=row_keys,
            dependency_answers=dependency_answers,
            filter_failures=filter_failures,
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
            # "No enabled converter plugins" is what a run that turned conversion
            # off, or registered no converter, has to say. Converters that were
            # wanted and did not start (a constructor that raised, a tool that was
            # absent) are named with their reasons, so the line does not read as a
            # choice. Their rows say the same, and the completeness gate counts them.
            not_started = _why_no_converter_ran(aggregated_results)
            if not_started:
                ASH_LOGGER.warning(
                    "No converter ran, and at least one did not start, so "
                    f"conversion is skipped: {', '.join(not_started)}"
                )
            else:
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
            row_key = row_keys.get(id(plugin_instance), display_name)
            # Redaction values for everything this converter's failure can quote.
            values = _redaction_values_or(plugin_instance, run_config, run_values)
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
                    description=f"Running converter: {escape_markup(row_key)}",
                )

                # Call convert method directly - converters should handle finding their own targets
                ASH_LOGGER.debug(f"Calling convert() on {display_name}")

                # Notify converter start
                try:
                    from automated_security_helper.plugins.events import AshEventType

                    self.notify_event(
                        AshEventType.CONVERT_START,
                        converter=row_key,
                        converter_class=plugin_instance.__class__.__name__,
                        message=f"Starting converter: {row_key}",
                    )
                except Exception as event_error:
                    # error_text, not str(): a handler's ValidationError quotes its
                    # input values, and the text can carry escape sequences.
                    ASH_LOGGER.error(
                        "Failed to notify converter start event: "
                        f"{error_text(event_error, values)}"
                    )

                # convert() takes no argument; a converter that asks for one, the old
                # convert(self, target) declaration included, is refused. Under a
                # sandbox, the converter's tool runs confined like a scanner's.
                with converter_run_scope(
                    plugin_instance, self.plugin_context
                ) as run_scope:
                    convert_result_initial = _call_convert(plugin_instance)
                # Ensure all convert_result are strings in case some are Paths
                convert_result = _converted_path_list(convert_result_initial)
                # Read here, before any progress row or event below says how the
                # run went: the spawns the sandbox refused while convert() ran
                # converted nothing, and "No files to convert" is not what a
                # converter whose tool was refused has to report. Redacted here,
                # once, like every other text a converter's row carries
                # (``_failure_text``): the sandbox keeps the refusal's and the
                # failed plan's own words, which can quote the argv it did not
                # run, and a converter's argv can hold a value its config read
                # from the environment. The scope is closed by now, so the
                # values are this converter's, passed.
                sandbox_loss = _shown_loss(_conversion_failure(run_scope) or "", values)

                if len(convert_result) > 0:
                    ASH_LOGGER.debug(
                        f"Converter {display_name} returned {len(convert_result)} paths"
                    )
                    plugin_converted_paths.extend(convert_result)
                    converted_paths.extend(convert_result)
                    not_converted = _could_not_convert(plugin_instance)
                    refused = _refused_over_limit(plugin_instance)
                    accepted = _accepted_inputs(plugin_instance)
                    # Both when both, in this branch too: an acceptance stays
                    # visible beside the converted count rather than vanishing
                    # whenever anything was converted. An archive refused whole
                    # is lost coverage like a failed input, and is said with it.
                    outcome = "; ".join(
                        part
                        for part in (not_converted, refused, sandbox_loss, accepted)
                        if part
                    )
                    also = f", {outcome}" if outcome else ""

                    # Update converter task to 100%. Each description is written
                    # inline, every value it quotes escaped once.
                    if not_converted or refused or sandbox_loss:
                        self.progress_display.update_task(
                            phase=ExecutionPhase.CONVERT,
                            task_id=converter_task,
                            completed=100,
                            description=(
                                f"[yellow]({escape_markup(row_key)}) Converted "
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
                                f"[green]({escape_markup(row_key)}) Converted "
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
                                f"[green]({escape_markup(row_key)}) Converted "
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
                            converter=row_key,
                            converter_class=plugin_instance.__class__.__name__,
                            converted_files=convert_result,
                            file_count=len(convert_result),
                            message=(
                                f"Converter {row_key} completed: "
                                f"{len(convert_result)} files converted{also}"
                            ),
                        )
                    except Exception as event_error:
                        ASH_LOGGER.error(
                            "Failed to notify converter complete event: "
                            f"{error_text(event_error, values)}"
                        )
                else:
                    ASH_LOGGER.debug(
                        f"Converter {display_name} returned None or empty result"
                    )
                    not_converted = _could_not_convert(plugin_instance)
                    refused = _refused_over_limit(plugin_instance)
                    accepted = _accepted_inputs(plugin_instance)
                    # Both when both: an acceptance stays visible beside other
                    # failures rather than vanishing whenever anything failed. An
                    # archive refused whole over an extraction limit is a loss the
                    # completeness gate fails the run on, so it is said here too,
                    # not reported as "No files to convert". The same for a run
                    # whose tool the scanner sandbox refused to start.
                    outcome = "; ".join(
                        part
                        for part in (not_converted, refused, sandbox_loss, accepted)
                        if part
                    )
                    if not outcome:
                        converters_with_no_files.append(display_name)

                    # Update converter task to 100%. A converter whose every input
                    # failed says so, rather than what a tree with none gets; one
                    # whose inputs were accepted by a suppression says that, in
                    # the acceptance's color rather than a failure's.
                    if not_converted or refused or sandbox_loss:
                        self.progress_display.update_task(
                            phase=ExecutionPhase.CONVERT,
                            task_id=converter_task,
                            completed=100,
                            description=(
                                f"[red]({escape_markup(row_key)}) "
                                f"{escape_markup(outcome)}"
                            ),
                        )
                    elif accepted:
                        self.progress_display.update_task(
                            phase=ExecutionPhase.CONVERT,
                            task_id=converter_task,
                            completed=100,
                            description=(
                                f"[yellow]({escape_markup(row_key)}) "
                                f"{escape_markup(accepted)}"
                            ),
                        )
                    else:
                        self.progress_display.update_task(
                            phase=ExecutionPhase.CONVERT,
                            task_id=converter_task,
                            completed=100,
                            description=f"[yellow]({escape_markup(row_key)}) No files to convert",
                        )

                    # Notify converter complete (no files)
                    try:
                        from automated_security_helper.plugins.events import (
                            AshEventType,
                        )

                        self.notify_event(
                            AshEventType.CONVERT_COMPLETE,
                            converter=row_key,
                            converter_class=plugin_instance.__class__.__name__,
                            converted_files=[],
                            file_count=0,
                            message=(
                                f"Converter {row_key} completed: "
                                f"{outcome or 'no files to convert'}"
                            ),
                        )
                    except Exception as event_error:
                        ASH_LOGGER.error(
                            "Failed to notify converter complete event: "
                            f"{error_text(event_error, values)}"
                        )

                # This converter survived the filter, whose enabled check passed it,
                # and its one dependency check (above) answered True, so its row
                # says so: True and False here are what the phase decided, not a
                # read of config.enabled (which a converter without a config has
                # not got).
                aggregated_results.converter_results[row_key] = ConverterStatusInfo(
                    dependencies_satisfied=True,
                    excluded=False,
                    converted_paths=plugin_converted_paths,
                    **_input_record_fields(plugin_instance),
                    # Omitted when nothing was lost, like refused_inputs.
                    **_failure_field(sandbox_loss),
                )
                _register_accepted_suppressions(
                    plugin_instance, self.plugin_context, aggregated_results
                )

            except Exception as e:
                failure = _failure_text(e, values)
                ASH_LOGGER.error(f"Error in converter {plugin_name}: {failure}")
                ASH_LOGGER.debug(
                    f"Converter exception traceback: {traceback_text(values=values)}"
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
                # excluded is False and dependencies_satisfied True because reaching
                # this loop means the converter survived the filter, which admits
                # only a converter whose one dependency check answered True; neither
                # is read off the instance, so recording a failure cannot itself
                # raise.
                #
                # The row is built twice at most. The exception being handled can
                # be the success row's own validation refusing one of this
                # converter's failed_inputs or refused_inputs records, and a row
                # built here with the same records raised the same way, out of
                # the handler, so one malformed record aborted the whole scan. The
                # second attempt leaves the records out and says so in the
                # failure, so the converter's failure is recorded whatever shape
                # its records are in.
                row_fields: Dict[str, Any] = {
                    "dependencies_satisfied": True,
                    "excluded": False,
                    "converted_paths": plugin_converted_paths,
                }
                try:
                    row = ConverterStatusInfo(
                        failure=failure,
                        **row_fields,
                        **_input_record_fields(plugin_instance),
                    )
                except Exception as row_error:
                    ASH_LOGGER.error(
                        f"Could not record the input records of converter "
                        f"{plugin_name}: {error_text(row_error, values)}"
                    )
                    row = ConverterStatusInfo(
                        failure=(
                            f"{failure}; its failed and refused input records could "
                            f"not be recorded: {error_text(row_error, values)}"
                        ),
                        **row_fields,
                    )
                aggregated_results.converter_results[row_key] = row
                _register_accepted_suppressions(
                    plugin_instance, self.plugin_context, aggregated_results
                )

                # A subscriber that saw CONVERT_START is told this converter ended,
                # as a reporter that raised is (ERROR in place of CONVERT_COMPLETE,
                # which is how a subscriber learns a converter succeeded or found
                # nothing). Guarded like the other two notifications: the handler
                # runs inside the phase, and a subscriber that raises must not end
                # the phase's other converters.
                try:
                    from automated_security_helper.plugins.events import AshEventType

                    self.notify_event(
                        AshEventType.ERROR,
                        message=f"Error in converter {row_key}: {failure}",
                        converter=row_key,
                        converter_class=plugin_instance.__class__.__name__,
                        phase="convert",
                    )
                except Exception as event_error:
                    ASH_LOGGER.error(
                        "Failed to notify converter error event: "
                        f"{error_text(event_error, values)}"
                    )

                # Update converter task to show error. Skipped when add_task itself
                # is what raised, because there is no task id to update. The same
                # call may be what raised in the try above (a progress display that
                # fails), and a second raise from here escaped the phase and ended
                # the scan, so a display that fails is logged and the next converter
                # goes on.
                if converter_task is not None:
                    try:
                        self.progress_display.update_task(
                            phase=ExecutionPhase.CONVERT,
                            task_id=converter_task,
                            completed=100,
                            description=(
                                f"[red]({escape_markup(row_key)}) Failed: "
                                f"{escape_markup(error_text(e, values))}"
                            ),
                        )
                    except Exception as display_error:
                        ASH_LOGGER.error(
                            f"Could not update the progress row of converter "
                            f"{plugin_name}: {error_text(display_error, values)}"
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
            #
            # An archive refused whole over a limit is a loss the gate counts too,
            # so the warning names it instead of the generic "nothing to convert".
            # A converter dropped because its tool was unavailable explains an
            # empty result as well as a crash does, and the gate counts it (its
            # row has dependencies_satisfied False and is not excluded), so it is
            # listed with its reason instead of leaving the bare wording.
            unproductive = [
                f"{name} ({reason})"
                for name, row in aggregated_results.converter_results.items()
                if (reason := _unproductive_reason(row))
            ]
            if unproductive:
                ASH_LOGGER.warning(
                    "No files were converted, and at least one converter did not "
                    f"finish or refused an archive: {', '.join(unproductive)}"
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

"""Implementation of the Scan phase."""

import os
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Any, Optional, Set, Tuple

from automated_security_helper.base.converter_plugin import ConverterPluginBase
from automated_security_helper.base.engine_phase import EnginePhase
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.reporter_plugin import ReporterPluginBase
from automated_security_helper.base.plugin_config import (
    plugin_config_key,
    section_enabled,
)
from automated_security_helper.core.constants import (
    PYTHON_ONLY_SKIPPED_REASON,
    SHARD_SPLIT_REASON_PREFIX,
)
from automated_security_helper.core.enums import ExecutionPhase, ScannerStatus
from automated_security_helper.core.exceptions import ScannerSelectionError
from automated_security_helper.core.scanner_selection import (
    SelectionOrigin,
    community_scanner_refusal,
    exclusions_matching_no_scanner,
    refuse_selection_matching_no_scanner,
    selection_after_exclusions,
    unloaded_community_hint,
    unloaded_community_scanners,
    selection_names,
)
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerTargetStatusInfo,
)
from automated_security_helper.models.scan_results_container import ScanResultsContainer
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    plugin_explains_its_own_refusal,
    plugin_missing_dependency_reason,
)
from automated_security_helper.models.core import IgnorePathWithReason
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.core.cancellation import raise_if_cancelled
from automated_security_helper.utils.get_shortest_name import home_as_tilde
from automated_security_helper.utils.error_text import (
    config_environment_values,
    error_text,
    plugin_environment_values,
    text_without_values,
    traceback_text,
)
from automated_security_helper.utils.log import ASH_LOGGER, NO_MARKUP, escape_markup
from automated_security_helper.base.uv_tool_mixin import deferred_tool_version_probes
from automated_security_helper.utils.subprocess_utils import (
    recording_in_tree_refusals,
)
from automated_security_helper.utils.sandbox.scope import (
    plugin_probe_scope,
    sandbox_refusal_grades_missing,
)
from automated_security_helper.utils.sarif_utils import (
    get_severity_metrics_from_sarif,
)
from automated_security_helper.models.scanner_validation import (
    ScannerValidationManager,
    scanner_display_name,
)
from automated_security_helper.core.phases.scanner_selection import operator_selection
from automated_security_helper.core.phases.scanner_executor import ScannerExecutor
from automated_security_helper.core.phases.scan_result_processor import (
    ScanResultProcessor,
)
from automated_security_helper.core.sharding import (
    ShardAssignment,
    partition_scanners,
    scanners_to_exclude,
    validate_shard_selection,
)


#: Where ASH's own shipped plugin classes live.
#:
#: Used to decide whether the configuration's declared scanner roster applies to a
#: run. A run whose plugin set contains a class from this package resolved the
#: shipped built-in set, so the built-in roster is the honest expected set for it. A
#: run handed plugin classes by its caller -- a library embedding, or a test double
#: -- did not resolve that set, and measuring it against the built-in roster would
#: report every built-in scanner the caller did not supply as missing.
_BUILTIN_PLUGIN_MODULE_PREFIX = "automated_security_helper.plugin_modules.ash_builtin"


#: The path segment that marks a plugin module as contributing scanners.
#:
#: A failed module in the scanner region costs the run scanners, which belongs in
#: `scanner_results` where both completeness gates read. A failed reporter or
#: converter module is recorded too, in `metadata.plugin_load_errors`, but not
#: there: that dict is keyed by scanner name and rendered as a scanner column, and
#: putting a reporter in it would report a scanner that does not exist.
_SCANNER_MODULE_MARKER = ".scanners"


def _declared_scanner_roster(config) -> List[str]:
    """Scanner names *config* declares, in the spelling an operator writes.

    NOT DERIVED FROM THE RESOLVED PLUGIN SET, which is the entire point.
    `expected_scanners` used to come from `self._scanner_tasks`, built from
    `plugin_modules('scanner')`; the completed set comes from the same resolve. Both
    sides of the completeness comparison therefore came from one resolve, and a
    scanner that never joined it was absent from both -- so the comparison could not
    detect it. Measured: a phase whose only scanner failed to construct logged
    "completeness rate: 100.0%".

    `ScannerConfigSegment` declares one typed field per built-in scanner, fixed at
    class-definition time. It is trustworthy wherever there is a config at all:
    `config/ash_config.py` imports each scanner's *config* class from the same
    module as the scanner, so an unimportable scanner module fails config resolution
    first and loudly, rather than shrinking this roster.

    The field ALIAS is preferred over the field name -- `detect-secrets`, not
    `detect_secrets` -- because that is `config.name` on the instantiated plugin,
    which is what `scanner_results` is keyed by and what `--exclude-scanners`
    matches. Comparing a roster of underscored names against hyphenated rows would
    report all ten scanners missing on a healthy run.

    Extras (`__pydantic_extra__`) are included: a third-party scanner an operator
    configured is one they expect to run, and its silent absence is the same defect.
    An extras section the configuration turns off (`enabled: false`) is listed too:
    the roster is what the configuration declares, not what is switched on, and the
    documentation says a scanner that is left off is still listed. A disabled
    section whose module is not loaded has no row to be matched against, which is
    what any section that never loaded looks like here; the roster cannot tell the
    two apart, and it does not try to. A built-in field is listed whatever its flag
    says, because its module always loads and a disabled one gets its SKIPPED row.
    """
    scanners_segment = getattr(config, "scanners", None)
    if scanners_segment is None:
        return []

    roster: List[str] = []
    for field_name, field_info in (
        getattr(type(scanners_segment), "model_fields", {}) or {}
    ).items():
        roster.append(getattr(field_info, "alias", None) or field_name)
    roster.extend(getattr(scanners_segment, "model_extra", None) or {})

    seen = set()
    unique: List[str] = []
    for name in roster:
        key = str(name).lower().strip()
        if key and key not in seen:
            seen.add(key)
            unique.append(str(name))
    return unique


def _missing_dependency_reason(plugin_instance, values: Iterable[str] = ()) -> str:
    """The reason a MISSING row records for a scanner whose dependency check failed.

    :func:`plugin_missing_dependency_reason` when the plugin's hook answers with
    text; otherwise a message naming the scanner.

    Returned as the plugin gave it. The caller logs it so to ash.log and records
    ``home_as_tilde`` of it in the results.
    """
    reason = plugin_missing_dependency_reason(plugin_instance, values)
    if reason:
        # As the plugin gave it; the caller logs it so and tildes it for the results.
        return reason
    return _generic_missing_dependency_reason(plugin_instance)


def _generic_missing_dependency_reason(plugin_instance) -> str:
    """The reason when the scanner's dependency check gave none: names the scanner."""
    return (
        f"{_scanner_display_name(plugin_instance)}'s dependency check failed; "
        "ash.log has the scanner's own message"
    )


def _nothing_to_scan_reason(plugin_instance, values: Iterable[str] = ()) -> str | None:
    """``ScannerPluginBase.nothing_to_scan_reason``, guarded for any plugin.

    Only a non-empty string is a reason. A plugin without the hook, a test double
    answering with a Mock, and a hook that raises all leave the scanner MISSING:
    this answer can turn MISSING into SKIPPED, so anything short of a clear "there
    is nothing here" must not.

    The reason comes back redacted with ``values``, the config's environment
    values and the plugin's own (``utils.error_text.plugin_environment_values``):
    it can name a path or option either read from the environment, and the
    caller logs it and stores it in the results.
    """
    ask = getattr(plugin_instance, "nothing_to_scan_reason", None)
    if not callable(ask):
        return None
    try:
        reason = ask()
    except Exception as e:
        ASH_LOGGER.warning(
            f"{type(plugin_instance).__name__}.nothing_to_scan_reason() raised "
            f"{type(e).__name__}: {error_text(e, values)}; "
            "the scanner is judged on its dependencies alone"
        )
        return None
    if not (isinstance(reason, str) and reason):
        return None
    return text_without_values(reason, values)


def _scanner_display_name(plugin_instance) -> str:
    """Return the name a scanner is identified by everywhere in this phase.

    One rule, shared with the validation tracker through
    ``scanner_display_name``: it has to agree exactly with the name
    ``--exclude-scanners`` is matched against and with the name the tracker
    registers the instance under. Shard selection is implemented as an
    exclusion, so a copy of this rule that drifted would assign a shard a name
    the exclusion check never matches -- the scanner would run on every shard,
    and its findings would be counted once per shard.
    """
    # Read inside a guard: this runs for every instance outside the per-scanner
    # try blocks (the shard partition, the registration loop), and a plugin whose
    # config access raises ended the whole scan phase there. Such a plugin is
    # identified by its class, as one with no configured name is.
    try:
        return scanner_display_name(plugin_instance)
    except Exception:  # noqa: BLE001 -- plugin code
        return plugin_instance.__class__.__name__.lower()


def _regular_files_under(directory: Any) -> Iterable[str]:
    """Each regular file under ``directory``, as a string, in walk order.

    An entry whose stat fails (a symlink whose target is in a directory this
    user cannot search, a file removed mid-walk) is skipped and logged at
    debug: ``Path.is_file`` raised out of the walk, and one such entry aborted
    the whole scan before any scanner ran. A directory that cannot be listed is
    skipped with its subtree and logged at WARNING, naming it, and the walk goes
    on with every other directory: the ``rglob`` walk this replaces ended at the
    first such error (pathlib skips a PermissionError per directory and raises
    any other OSError out of the iterator), so every file not yet listed was
    dropped from the scan set with one debug line to say so, and for a scanner
    a silently partial file list is a coverage hole nothing downstream reports.
    """

    def directory_skipped(error: OSError) -> None:
        ASH_LOGGER.warning(
            f"Could not list {error.filename or directory}, so nothing under it is "
            f"scanned: {error.strerror or error}"
        )

    for root, _dirs, files in os.walk(str(directory), onerror=directory_skipped):
        for name in files:
            path = Path(root) / name
            try:
                if path.is_file():
                    yield str(path)
            except OSError as e:
                ASH_LOGGER.debug(f"Skipping {path} while listing files: {e}")


def _not_selected_reasons(selection: Any, names: Any) -> List[str]:
    """The reasons a not-selected scanner is recorded with, from its selection.

    One wording per answer of ``operator_selection``, in the order the main
    loop states them, so the SKIPPED row of a scanner left out at registration
    (a refused or duplicate name) reads as the row of one left out in the main
    loop does.
    """
    reasons: List[str] = []
    if selection.excluded:
        reasons.append(f"excluded from this run ({names.exclusion})")
    if not selection.in_allowlist:
        reasons.append(f"not named by {names.allowlist}")
    if not selection.enabled:
        reasons.append("disabled in the configuration (enabled: false)")
    if not selection.python_only_ok:
        reasons.append(PYTHON_ONLY_SKIPPED_REASON)
    return reasons


def _selected_holder_first(
    instances: List[Any], is_selected: Callable[[Any], bool]
) -> List[Any]:
    """*instances*, with each shared scanner name's first selected holder first.

    The first scanner to carry a name is the one that runs; every later holder
    is recorded under a row of its own. That order was the order of discovery,
    so a name whose first holder the operator left out (a Python-only run
    reaching a scanner that needs a tool) and whose later holder was selected
    ran nothing under the name: the selected holder was recorded as a
    duplicate and the unselected one as the name's row. Selection is decided
    for every holder here, before any is registered. Each name keeps the
    positions its holders had; only which holder takes the first of them
    changes, and the others follow in discovery order. A name with no selected
    holder keeps its order, and a name carried once is untouched.
    """
    positions_by_name: Dict[str, List[int]] = {}
    for position, instance in enumerate(instances):
        key = _scanner_display_name(instance).lower().strip()
        positions_by_name.setdefault(key, []).append(position)
    ordered = list(instances)
    for positions in positions_by_name.values():
        if len(positions) < 2:
            continue
        chosen = next((p for p in positions if is_selected(instances[p])), None)
        if chosen is None or chosen == positions[0]:
            continue
        holders = [instances[chosen]] + [instances[p] for p in positions if p != chosen]
        for position, holder in zip(positions, holders):
            ordered[position] = holder
    return ordered


def _holds_a_regular_file(directory: Any) -> bool:
    """Whether any regular file sits under ``directory``, whatever its name.

    The converted tree used to count only when some name under it contained a
    dot (``rglob("*.*")``), so an archive whose extracted members carry no
    extension (``Dockerfile``, ``id_rsa``, a script without a suffix) was
    converted and then never scanned. A file is a file whatever it is called.
    """
    return next(iter(_regular_files_under(directory)), None) is not None


def _loses_builtin_scanners(failed_module: str) -> bool:
    """Whether a load error for ``failed_module`` cost the run every built-in scanner.

    The built-in plugin package itself failing to import is recorded under the
    package's own path, which carries no scanner-region marker and resolves no
    scanner class, so the roster was never recorded and the scanner-region
    filter dropped the error: a run that lost all ten shipped scanners exited
    clean with zero scanners. The package root is the one module whose loss is
    every scanner's.
    """
    return failed_module == _BUILTIN_PLUGIN_MODULE_PREFIX


def _unconstructed_scanner_name(plugin_config: Any, plugin_class: type) -> str:
    """The name a scanner that did not construct is recorded under.

    Its section's ``name``, read from the dict ``get_plugin_config`` returns as
    well as from a model, else the name the scanner declares for itself. Read
    with ``getattr`` alone, a dict section never gave a name, so the row went
    under the lowercased class name (``snykcodescanner`` for ``snyk-code``),
    which ``--exclude-scanners``, the shard partition and the reports do not use.
    """
    if isinstance(plugin_config, dict):
        name = plugin_config.get("name")
    else:
        name = getattr(plugin_config, "name", None)
    if isinstance(name, str) and name:
        if _is_one_path_component(name):
            return name
        # The row's name becomes a directory under scanners/ when its results
        # container is written (scan_result_processor), so a configured name
        # with a separator, "..", or a NUL would put ASH.ScanResults.json
        # outside the output directory. A constructed scanner's name is
        # validated by its config model; this one never constructed, so its
        # section was never validated. The class's key stands in.
        ASH_LOGGER.warning(
            f"Scanner section name {name!r} is not a plain name and is not used "
            f"for the record of its construction failure; recorded as "
            f"{_unconstructed_scanner_fallback_name(plugin_class)!r}"
        )
    return _unconstructed_scanner_fallback_name(plugin_class)


def _unconstructed_scanner_fallback_name(plugin_class: type) -> str:
    """The class's key, or the lowercased class name when even that is a path.

    plugin_config_key reads the name the class declares in its config model's
    ``name`` default; a declared default is a literal in the code and never a
    path in practice, but the record name must be one path component whatever
    a class declares, and a class name is an identifier.
    """
    key = plugin_config_key(plugin_class)
    if _is_one_path_component(key):
        return key
    return getattr(plugin_class, "__name__", "unknown").lower()


def _is_one_path_component(name: str) -> bool:
    """Whether *name* can only ever name one entry of one directory.

    No path separator of either kind, no colon (a Windows drive letter,
    ``C:x``, would replace the ``scanners/`` base), not the current or parent
    directory, no NUL. The check is on the characters, not the platform: a
    results tree written on one platform is read on another.
    """
    if name in (".", "..") or "\x00" in name:
        return False
    return "/" not in name and "\\" not in name and ":" not in name


#: The checkpoint the scan phase appends to a model's validation_checkpoints
#: once its last step has returned (``_record_scan_phase_completed``, called
#: right after ``_validate_result_completeness``). Its presence is the record
#: that the scan phase ran to its end on that model. A marker of its own, not
#: the completeness checkpoint (``result_completeness``): that one is written
#: inside ``_validate_result_completeness``'s try, which catches every error of
#: the completeness pass and lets the phase return normally, so a pass that
#: raised left a completed scan with no record of it.
SCAN_PHASE_COMPLETION_CHECKPOINT = "scan_phase_completed"


def scan_phase_completed(aggregated_results: Any) -> bool:
    """Whether the scan phase ran to its end on *aggregated_results*.

    Read from the phase's own record, the marker it appends once its last step
    has returned, not from the model's existence: the engine holds its model
    from construction, so a model exists before any phase ran, and a scan phase
    that raised midway leaves a partial one. The orchestrator asks this before
    writing a results file for a run that failed after the scan phase, so that a
    failure before or inside the scan phase writes nothing.
    """
    checkpoints = getattr(aggregated_results, "validation_checkpoints", None) or []
    return any(
        isinstance(checkpoint, dict)
        and checkpoint.get("checkpoint_name") == SCAN_PHASE_COMPLETION_CHECKPOINT
        for checkpoint in checkpoints
    )


class _NoProgress:
    """Stands in for a progress display the caller did not give.

    ``progress_display`` defaults to None, and the phase calls ``add_task`` and
    ``update_task`` on it unconditionally, after the whole filter loop has run. A
    library or MCP caller that built a phase with the default failed there with an
    AttributeError. Every call is accepted and does nothing; ``add_task`` answers
    a task id as the real display does.
    """

    def add_task(self, *args: Any, **kwargs: Any) -> int:
        return 0

    def __getattr__(self, name: str) -> Callable[..., None]:
        def accept(*args: Any, **kwargs: Any) -> None:
            return None

        return accept


class ScanPhase(EnginePhase):
    """Implementation of the Scan phase."""

    def __init__(
        self,
        plugin_context: PluginContext,
        plugins: List[ConverterPluginBase | ScannerPluginBase | ReporterPluginBase]
        | None = None,
        progress_display: Optional[Any] = None,
        asharp_model: Optional[AshAggregatedResults] = None,
        plugin_filter: Optional[Callable[[Any], bool]] = None,
    ) -> None:
        """Initialize the ScanPhase with validation manager.

        Args:
            plugin_context: Plugin context with paths and configuration
            plugins: List of plugins to use
            progress_display: Progress display to use for reporting progress
            asharp_model: AshAggregatedResults to update with results
            plugin_filter: The event handlers this phase's notifications reach
        """
        super().__init__(
            plugin_context,
            plugins or [],
            progress_display if progress_display is not None else _NoProgress(),
            asharp_model,
            plugin_filter=plugin_filter,
        )
        self.validation_manager = ScannerValidationManager(plugin_context)
        # Whether _execute_phase has run on this object, so a second run starts
        # from a clean validation record (see there).
        self._has_executed = False
        # Set when this run is one shard of several; read by the caller to stamp
        # provenance onto the results so `ash merge` can verify coverage.
        self._shard_assignment: ShardAssignment | None = None
        # The scanners that completed in this phase's run. Set from construction,
        # because the engine reads it when the phase ends, which can be before the
        # run starts (a SCAN_PHASE_START handler raised): an AttributeError there
        # would replace what was raised.
        self._completed_scanners: List[ScannerPluginBase] = []

    @property
    def phase_name(self) -> str:
        """Return the name of this phase."""
        return "scan"

    def _track_scanner_state(self, scanner_name: str, **state: Any) -> None:
        """``validation_manager.update_scanner_state``, for a scanner that is
        recorded whether or not the tracker admits its name.

        The tracker refuses a name that is empty or ends in "Scanner" with a
        ValueError. The row that calls this was written already (an ERROR row
        for a constructor that raised, a SKIPPED row for a scanner the run did
        not select), and that row is the record; the tracker's refusal is logged
        and does not abort the scan.
        """
        try:
            self.validation_manager.update_scanner_state(scanner_name, **state)
        except ValueError as e:
            ASH_LOGGER.debug(
                f"The scanner tracker refused the name {scanner_name!r}: "
                f"{error_text(e)}; the scanner's row stands"
            )

    def _record_refused_scanner_name(
        self,
        display_name: str,
        plugin_instance: Any,
        error: ValueError,
        aggregated_results: AshAggregatedResults,
    ) -> AshAggregatedResults:
        """Record ERROR for a constructed scanner whose name the tracker refused.

        The scanner did construct, so it has a row under the name it carries;
        it does not run, because every later step registers it under that name
        and would be refused the same way. ERROR, not SKIPPED: the operator did
        not leave it out, and the completeness gate has to see it.
        """
        refusal = (
            f"Scanner {display_name} was not run: its configured name is refused "
            f"({type(error).__name__}: {error_text(error)}). A scanner's name is the "
            "name it is selected and reported by, and cannot be empty or end in "
            "'Scanner'."
        )
        return self._record_scanner_error(display_name, refusal, aggregated_results)

    @staticmethod
    def _later_holder_row_name(
        display_name: str,
        plugin_instance: Any,
        aggregated_results: AshAggregatedResults,
    ) -> str:
        """The row name for a scanner that is not the first to carry *display_name*.

        The name followed by the scanner's class in parentheses, so the row cannot
        replace the first holder's row, which is keyed by the name alone. The
        qualifier is plain characters only, because the row's name is a directory
        in the results tree. ``#N`` is added while the name is already a row, so
        two later holders of one name get two rows. Both recorders for a later
        holder (the ERROR row of a name that is refused and the SKIPPED row of one
        the operator did not select) name the row here, so the two cannot differ
        on what a later holder's row is called.
        """
        later = plugin_instance.__class__
        later_text = f"{later.__module__}.{later.__name__}"
        qualifier = "".join(c if c.isalnum() or c in "._-" else "_" for c in later_text)
        taken = {
            key.lower().strip() for key in (aggregated_results.scanner_results or {})
        }
        row_name = f"{display_name} ({qualifier})"
        index = 2
        while row_name.lower().strip() in taken:
            row_name = f"{display_name} ({qualifier} #{index})"
            index += 1
        return row_name

    def _record_duplicate_scanner_name(
        self,
        display_name: str,
        plugin_instance: Any,
        first_instance: Any,
        aggregated_results: AshAggregatedResults,
        *,
        first_runs: bool = True,
    ) -> AshAggregatedResults:
        """Record ERROR for a scanner whose name another scanner already carries.

        Two registered scanner classes with one configured name were both queued.
        Both ran, the second's row replaced the first's in ``scanner_results``, their
        results shared one directory, and the shard provenance counted the name once.
        The first to carry the name runs. The later one is recorded under a row of its
        own, named by its class so it cannot replace the first's, and does not run:
        ERROR, not SKIPPED, because the operator did not leave it out and the
        completeness gate has to see it. The caller settles selection first: a later
        holder of the name the operator did not select is recorded SKIPPED like any
        other, not here, under the same row name. *first_runs* is False when the
        first holder's name was refused by the tracker, so the text does not say it
        runs.
        """
        later = plugin_instance.__class__
        earlier = first_instance.__class__
        later_text = f"{later.__module__}.{later.__name__}"
        earlier_text = f"{earlier.__module__}.{earlier.__name__}"
        row_name = self._later_holder_row_name(
            display_name, plugin_instance, aggregated_results
        )
        first_fate = (
            "which runs"
            if first_runs
            else "whose name the scanner tracker refused, so neither runs"
        )
        refusal = (
            f"Scanner {later_text} was not run: its name {display_name!r} is already "
            f"carried by {earlier_text}, {first_fate}. A scanner's name keys its row, "
            "its results directory, its shard and the --scanners and "
            "--exclude-scanners matching, so two scanners cannot share one. Give "
            "one of them a different configured name."
        )
        return self._record_scanner_error(row_name, refusal, aggregated_results)

    def _write_results_guarded(
        self,
        display_name: str,
        container: ScanResultsContainer,
        aggregated_results: Any,
    ) -> AshAggregatedResults:
        """Write *container* through the result processor; a failed write is logged.

        The recorders for a scanner that did not run (not selected, a refused or
        duplicate name, a check that raised) write a results container for the
        row, and ``process_container`` makes the scanner's results directory as
        it writes (it refuses a link at any path component). Unguarded, one
        scanner's failed write ended the whole phase before any scanner ran,
        from a path the operator had nothing to do with. The row the caller
        writes next is the record, so it is written whether or not the file was.
        """
        try:
            return self._process_results(
                results=container, aggregated_results=aggregated_results
            )
        except Exception as write_error:  # noqa: BLE001 -- a write of one row's file
            ASH_LOGGER.error(
                f"Could not write the results of scanner {display_name}: "
                + error_text(
                    write_error,
                    config_environment_values(
                        getattr(self.plugin_context, "config", None)
                    ),
                )
            )
            return aggregated_results

    def _record_scanner_error(
        self, display_name: str, error_text_: str, aggregated_results: Any
    ) -> AshAggregatedResults:
        """Record ERROR for a constructed scanner that did not run, with *error_text_*
        as its one error, and leave it out of the run.

        ERROR, not SKIPPED: the operator did not leave the scanner out, and the
        completeness gate has to see it. ``dependencies_satisfied`` is True because
        no dependency was checked (the construction-failure row says why False
        would mislead).
        """
        ASH_LOGGER.error(error_text_)
        container = ScanResultsContainer(
            scanner_name=display_name,
            status=ScannerStatus.ERROR,
            duration=None,
            errors=[error_text_],
        )
        aggregated_results = self._write_results_guarded(
            display_name, container, aggregated_results
        )
        aggregated_results.scanner_results[display_name] = ScannerTargetStatusInfo(
            status=ScannerStatus.ERROR,
            dependencies_satisfied=True,
            excluded=False,
        )
        return aggregated_results

    def _record_scanner_not_selected(
        self,
        display_name: str,
        reason: str,
        aggregated_results: AshAggregatedResults,
        excluded_scanner_names: List[str],
    ) -> AshAggregatedResults:
        """Record *display_name* as SKIPPED because it was not selected to run.

        One recording path for every reason a scanner is not part of this run --
        the operator narrowed with ``--scanners``, the config disabled it, or a
        Python-only run excluded it, or its platform is not supported. Extracted
        because the selection decision is made at several points of the filter
        loop, and a copy of this bookkeeping at each would be a chance for them to
        diverge on what a not-selected scanner looks like in the report.

        SKIPPED with ``excluded=True`` rather than MISSING, and
        ``dependencies_satisfied=True`` rather than the truth about the tool,
        because neither is a claim about the tool: this scanner was never asked
        to run, so whether its dependencies are present is not a fact about this
        scan. It is also what keeps the completeness gate off a scan that did
        everything it was asked to do.
        """
        ASH_LOGGER.info(f"Scanner {display_name} excluded from execution: {reason}")

        self._track_scanner_state(
            display_name,
            registration_status="registered",
            enablement_status="excluded",
            enablement_reason=f"Scanner excluded during filtering: {reason}",
            queued_for_execution=False,
            execution_completed=False,
        )

        aggregated_results = self._write_results_guarded(
            display_name,
            ScanResultsContainer.for_excluded(display_name, reason=reason),
            aggregated_results,
        )

        aggregated_results.scanner_results[display_name] = ScannerTargetStatusInfo(
            status=ScannerStatus.SKIPPED,
            excluded=True,
            dependencies_satisfied=True,
            skipped_reason=reason,
        )
        # Counted as excluded only once its row is written. Appended first, a raise
        # between the two left the scanner counted as excluded and, with no row,
        # recorded MISSING as one that "left filtering with no status".
        excluded_scanner_names.append(display_name)
        return aggregated_results

    def _execute_phase(
        self,
        aggregated_results: AshAggregatedResults,
        enabled_scanners: List[str] | None = None,
        excluded_scanners: List[str] | None = None,
        parallel: bool = True,
        max_workers: int = 4,
        global_ignore_paths: List[IgnorePathWithReason] | None = None,
        python_based_plugins_only: bool = False,
        shard_index: int | None = None,
        shard_count: int | None = None,
        selection_origin: SelectionOrigin = "cli",
        **kwargs,
    ) -> AshAggregatedResults:
        """Coordinate the Scan phase: filter plugins, run executor, process results.

        Args:
            enabled_scanners: List of scanner names to enable
            parallel: Whether to run scanners in parallel
            max_workers: Maximum number of worker threads for parallel execution
            global_ignore_paths: List of paths to ignore globally
            shard_index: Zero-based index of this shard, when the scan is split
                across executors. Requires shard_count.
            shard_count: Total number of shards. Requires shard_index.
            selection_origin: Who made the selection, so a SKIPPED row and the
                refusal of an allowlist that matches no scanner name what the
                caller used: "cli" for --scanners and --exclude-scanners, "mcp"
                for the MCP workspace tool's scanners and excluded_scanners
                parameters.
            **kwargs: Additional arguments

        Returns:
            AshAggregatedResults: Results of the scan

        Raises:
            ShardSelectionError: If the shard selection cannot be used as given.
            ScannerSelectionError: If *enabled_scanners* is non-empty and none of
                its entries name a registered scanner.
        """
        if enabled_scanners is None:
            enabled_scanners = []
        if excluded_scanners is None:
            excluded_scanners = []
        if global_ignore_paths is None:
            global_ignore_paths = []

        # Validated before any filesystem work or plugin instantiation, so an
        # operator whose CI matrix produced a contradictory pair is told that
        # rather than watching a partial scan run to completion and exit 0.
        validate_shard_selection(shard_index, shard_count)

        # The exclusions taken out of the allowlist, as the engine does when it is
        # built. A phase called directly (a library, the MCP tool) with an
        # allowlist its own exclusions empty ran zero scanners and reported clean,
        # because the backstop below compared the allowlist as given. Idempotent for
        # an engine's call, which already passed the subtracted list; raises when
        # the exclusions cancel a non-empty allowlist.
        enabled_scanners = selection_after_exclusions(
            enabled_scanners, excluded_scanners, selection_origin
        )

        # Not mutated in place: excluded_scanners is the caller's list, and the
        # shard's additions are scoped to this invocation. Appending to the
        # caller's object would make a second call in the same process inherit
        # the first shard's exclusions.
        excluded_scanners = list(excluded_scanners)
        # What the caller excluded, before the shard split adds to it, so a row can
        # say which of the two left a scanner out.
        operator_excluded = {name.lower().strip() for name in excluded_scanners}
        names = selection_names(selection_origin)

        ASH_LOGGER.debug("Entering: ScanPhase.execute()")

        # Reset state for new execution
        self._completed_scanners = []
        self._scan_results = {}
        self._global_ignore_paths = global_ignore_paths or []
        self._max_workers = max_workers
        # The shard provenance of an earlier run on this object is not this run's:
        # a second execute without shards kept it and went on mutating it, so an
        # unsharded run's results read as one shard of the earlier split.
        self._shard_assignment = None
        # The validation record likewise: scanners of an earlier run it still
        # tracked were backfilled into this run's results. Only a real manager is
        # replaced, and only on a later run, so a manager a caller set up before
        # the first run is the one that run uses.
        if self._has_executed and type(self.validation_manager) is (
            ScannerValidationManager
        ):
            self.validation_manager = ScannerValidationManager(self.plugin_context)
        self._has_executed = True
        # Any regular file, whatever its name: see _holds_a_regular_file.
        self._include_work_dir = _holds_a_regular_file(self.plugin_context.work_dir)

        # Build the result processor (owns _process_results and validation metrics)
        self._result_processor = ScanResultProcessor(
            plugin_context=self.plugin_context,
            validation_manager=self.validation_manager,
        )

        # Compute the source file list once so scanners don't each re-glob. The
        # walk skips an entry it cannot stat instead of aborting the scan.
        source_files = list(_regular_files_under(self.plugin_context.source_dir))
        if self._include_work_dir:
            # Each file once: a work directory inside the source tree (an output
            # directory under the project) was walked by both listings.
            already_listed = set(source_files)
            source_files.extend(
                path
                for path in _regular_files_under(self.plugin_context.work_dir)
                if path not in already_listed
            )
        # Store on the context so individual scanners can access it
        self.plugin_context.cached_source_files = source_files
        ASH_LOGGER.debug(f"Cached {len(source_files)} source files for scanner use")

        # Debug logging for scanner filtering parameters
        ASH_LOGGER.debug(f"Enabled scanners parameter: {enabled_scanners}")
        ASH_LOGGER.debug(f"Excluded scanners parameter: {excluded_scanners}")
        ASH_LOGGER.debug(f"Python-based plugins only: {python_based_plugins_only}")

        try:
            ASH_LOGGER.info("Building scanner tasks...")

            # Build list of scanner tasks for execution (no queue needed)
            self._scanner_tasks: List[
                Tuple[str, ScannerPluginBase, List[Dict[str, Any]]]
            ] = []

            # Get all scanner plugins
            scanner_classes = self.plugins

            # Create scanner instances for validation and processing
            scanner_instances = []
            # Names of scanners whose constructor raised. They resolved: the ERROR row
            # recorded for each is the result, so a selection naming one is not
            # unresolved and must not be told its module is missing, and the
            # allowlist backstop below must not call it a name that matches nothing.
            construction_failed: Set[str] = set()
            # Scanners this run does not execute, by name, for the enablement
            # validation. Started here, before construction, so a scanner the run
            # did not select whose constructor raised is counted with the others.
            excluded_scanner_names: List[str] = []
            # The operator's names, compared as everywhere in this phase.
            operator_allowlist = {name.lower().strip() for name in enabled_scanners}
            if scanner_classes:
                ASH_LOGGER.debug(
                    f"Creating instances for {len(scanner_classes)} scanner classes"
                )
                for plugin_class in scanner_classes:
                    # Bound before the try, not inside it. The except clause below
                    # interpolates this name, so an exception raised before the
                    # assignment produced a NameError inside the handler instead of
                    # the error it was written to report.
                    plugin_name = getattr(plugin_class, "__name__", "Unknown").lower()
                    plugin_config = None
                    try:
                        ASH_LOGGER.debug(
                            f"Creating scanner instance for class: {plugin_name}"
                        )

                        # Resolved into a local before the constructor call, so the
                        # handler below can read `config.name` off it. That is the
                        # only authoritative name a scanner has, and in the case that
                        # actually occurs -- a constructor that raises after its
                        # config resolved -- it is available. Recording the row under
                        # a class-derived name instead would put a scanner in the
                        # results under a name nothing else in the run matches:
                        # --exclude-scanners, the shard partition and every report
                        # key on config.name.
                        if self.plugin_context.config is not None:
                            plugin_config = (
                                self.plugin_context.config.get_plugin_config(
                                    plugin_type="scanner",
                                    plugin_name=plugin_config_key(plugin_class),
                                )
                            )

                        # Create scanner instance. Under a sandbox, the tool probes
                        # some scanners run while they are constructed run sandboxed.
                        # Their `uv tool run` version probes are deferred until the
                        # scanner is selected (see the dependency check below): a
                        # scanner this run will not execute must not be resolved
                        # against the package index.
                        with (
                            plugin_probe_scope(plugin_class, self.plugin_context),
                            deferred_tool_version_probes(),
                        ):
                            plugin_instance = plugin_class(
                                config=plugin_config,
                                context=self.plugin_context,
                            )
                        scanner_instances.append(plugin_instance)
                        ASH_LOGGER.debug(f"Created scanner instance for: {plugin_name}")
                    except Exception as e:
                        # A construction failure has to leave a row, or it shrinks
                        # the denominator.
                        #
                        # The reconciliation loop further down walks
                        # scanner_instances, and a class that never constructed is
                        # not in it -- so before this branch recorded anything, such
                        # a scanner appeared nowhere at all: absent from
                        # scanner_results, absent from every summary_stats counter
                        # (which still summed correctly over the scanners that
                        # remained), and therefore invisible to both completeness
                        # gates. Expected and completed were both derived from the
                        # set that survived construction, so no comparison could
                        # detect a scanner that never joined it. Measured on this
                        # tree: a phase whose only scanner failed to construct
                        # logged "completeness rate: 100.0%".
                        #
                        # ERROR rather than MISSING, and the two are not
                        # interchangeable even though both fail the gate. MISSING
                        # carries the remediation "install the tool", and nothing
                        # here established that any tool is absent -- a constructor
                        # raising is a defect or a misconfiguration. ERROR says the
                        # scanner was reached and produced no result, which is what
                        # happened. This is deliberately the opposite choice from
                        # the filtering-escape reconciliation below, which is
                        # MISSING because it is reached before any dependency
                        # question is asked; the two paths are told apart by which
                        # status they carry.
                        # The configured name, else the name the class declares,
                        # which is what --scanners, the workspace pre-flight and
                        # the engine's check match; _unconstructed_scanner_name
                        # reads it from a dict section as well as from a model.
                        failed_name = _unconstructed_scanner_name(
                            plugin_config, plugin_class
                        )
                        failed_key = failed_name.lower().strip()
                        construction_failed.add(failed_key)
                        # Selection before diagnosis, as for a scanner that did
                        # construct: one the operator excluded, left out of the
                        # allowlist or disabled in the configuration was never
                        # going to run, so its constructor raising is not a
                        # failure of this scan. Recorded SKIPPED, excluded, like
                        # the other not-selected scanners, and the error at debug;
                        # recorded ERROR, it failed the completeness gate on a run
                        # that ran everything it selected.
                        not_selected_reasons = []
                        if failed_key in operator_excluded:
                            not_selected_reasons.append(
                                f"excluded from this run ({names.exclusion})"
                            )
                        if operator_allowlist and failed_key not in operator_allowlist:
                            not_selected_reasons.append(
                                f"not named by {names.allowlist}"
                            )
                        if not section_enabled(plugin_config):
                            not_selected_reasons.append(
                                "disabled in the configuration (enabled: false)"
                            )
                        if not_selected_reasons:
                            ASH_LOGGER.debug(
                                f"Scanner {failed_name} could not be constructed "
                                f"({type(e).__name__}), and was not selected to run"
                            )
                            aggregated_results = self._record_scanner_not_selected(
                                failed_name,
                                ", ".join(not_selected_reasons),
                                aggregated_results,
                                excluded_scanner_names,
                            )
                            continue
                        # With the config's environment values: a constructor's
                        # error can name an option the config read from the
                        # environment, and this text goes to the report, ash.log,
                        # the results files and scanner_reasons.
                        construction_error = (
                            f"Scanner {failed_name} could not be constructed, so it "
                            f"did not run: {type(e).__name__}: "
                            + error_text(
                                e,
                                config_environment_values(
                                    getattr(self.plugin_context, "config", None)
                                ),
                            )
                        )
                        ASH_LOGGER.error(construction_error)
                        # `errors` passed to the constructor so the field is set
                        # from the start. `add_error` would also keep it (it
                        # reassigns the field for the `exclude_unset=True` dump),
                        # but the constructor states the whole row in one place.
                        container = ScanResultsContainer(
                            scanner_name=failed_name,
                            status=ScannerStatus.ERROR,
                            duration=None,
                            errors=[construction_error],
                        )
                        # Guarded, as every other recorder of a scanner that did
                        # not run: this write is inside the handler of the
                        # constructor's own failure, so one failed write of the
                        # row's file ended the whole phase from here. The row
                        # below is the record.
                        aggregated_results = self._write_results_guarded(
                            failed_name, container, aggregated_results
                        )
                        aggregated_results.scanner_results[failed_name] = (
                            ScannerTargetStatusInfo(
                                status=ScannerStatus.ERROR,
                                # True, because no dependency was checked. False
                                # would tell an operator to install a tool that may
                                # well be present, which is the misdirection the
                                # Windows semgrep case cost.
                                dependencies_satisfied=True,
                                excluded=False,
                            )
                        )
                        # With the class: the tracker accepts a configured name
                        # ending in "Scanner" only when it can compare the name
                        # with the class's own, and this row is written before
                        # validate_registered_scanners has done so. Without the
                        # class the tracker refuses such a name; the wrapper
                        # keeps the refusal from aborting the phase, but the
                        # scanner's state would then go untracked.
                        self._track_scanner_state(
                            failed_name,
                            registration_status="registered",
                            plugin_class=plugin_class,
                            queued_for_execution=False,
                            execution_completed=False,
                            failure_reason=construction_error,
                        )

            # Validate registered scanners after creating instances
            if scanner_instances:
                # CRITICAL: Initialize validation manager state for all registered
                # scanners. One at a time, and before validate_registered_scanners,
                # which registers the same names: the tracker refuses a name that
                # is empty or ends in "Scanner" (a class name where a scanner name
                # belongs), with a ValueError that used to escape here and abort
                # the whole scan for one such plugin. The refused scanner is
                # recorded ERROR under its name and left out of the run, and the
                # others are registered as before.
                admitted_instances = []
                # The first instance to carry a name, by name. Rows, results
                # directories, the shard partition and --exclude-scanners all key
                # on the name, so a second scanner class that carries one already
                # taken would run beside the first and overwrite its row. An
                # instance is the name's first holder once the tracker accepted
                # it; a holder whose name the tracker refused is kept apart, so
                # a later holder is told the first does not run.
                first_by_name: Dict[str, Any] = {}
                refused_by_name: Dict[str, Any] = {}
                scanner_instances = _selected_holder_first(
                    scanner_instances,
                    lambda candidate: (
                        operator_selection(
                            candidate,
                            _scanner_display_name(candidate),
                            enabled_scanners=enabled_scanners,
                            excluded_scanners=excluded_scanners,
                            python_only=python_based_plugins_only,
                        ).selected
                    ),
                )
                for plugin_instance in scanner_instances:
                    display_name = _scanner_display_name(plugin_instance)
                    name_key = display_name.lower().strip()
                    if name_key in first_by_name or name_key in refused_by_name:
                        # Selection before diagnosis, as for every scanner that
                        # does not run: a later holder the operator excluded,
                        # left out of the allowlist or disabled, or that a
                        # Python-only run leaves out, was never going to run, so
                        # its shared name is not a failure of this scan. Recorded
                        # ERROR, it failed the completeness gate on a run that ran
                        # everything it selected.
                        later_selection = operator_selection(
                            plugin_instance,
                            display_name,
                            enabled_scanners=enabled_scanners,
                            excluded_scanners=excluded_scanners,
                            python_only=python_based_plugins_only,
                        )
                        if not later_selection.selected:
                            ASH_LOGGER.debug(
                                f"Scanner {display_name}'s name is carried by an "
                                f"earlier scanner, and it was not selected to run"
                            )
                            # Under a row of its own, as the ERROR row of a
                            # later holder is: recorded under the name, it
                            # replaced the first holder's row, marked that
                            # row excluded and put the name on the excluded
                            # list although the first holder may run.
                            aggregated_results = self._record_scanner_not_selected(
                                self._later_holder_row_name(
                                    display_name, plugin_instance, aggregated_results
                                ),
                                ", ".join(
                                    _not_selected_reasons(later_selection, names)
                                ),
                                aggregated_results,
                                excluded_scanner_names,
                            )
                            continue
                        aggregated_results = self._record_duplicate_scanner_name(
                            display_name,
                            plugin_instance,
                            first_by_name.get(name_key) or refused_by_name[name_key],
                            aggregated_results,
                            first_runs=name_key in first_by_name,
                        )
                        continue
                    try:
                        self.validation_manager.update_scanner_state(
                            display_name,
                            registration_status="registered",
                            plugin_class=plugin_instance.__class__,
                        )
                    except ValueError as e:
                        # The refused scanner exists and has a row, so its name
                        # is a known name for the allowlist check below (a
                        # `--scanners` naming only it is not a misspelling), and
                        # selection comes before diagnosis, as for a scanner
                        # whose constructor raised: one the operator excluded,
                        # left out of the allowlist or disabled, or that a
                        # Python-only run leaves out, was never going to run, so
                        # its refused name is not a failure of this scan and is
                        # recorded SKIPPED, excluded, not ERROR. The one selection
                        # rule (operator_selection, the main loop's), not a copy:
                        # the copy here read three of its four answers and left
                        # --python-only out, so in such a run a non-Python-only
                        # scanner with a refused name was ERROR where the main
                        # loop would have recorded it SKIPPED.
                        refused_by_name[name_key] = plugin_instance
                        construction_failed.add(name_key)
                        refused_selection = operator_selection(
                            plugin_instance,
                            display_name,
                            enabled_scanners=enabled_scanners,
                            excluded_scanners=excluded_scanners,
                            python_only=python_based_plugins_only,
                        )
                        if not refused_selection.selected:
                            ASH_LOGGER.debug(
                                f"Scanner {display_name}'s name is refused by the "
                                f"tracker ({error_text(e)}), and it was not selected "
                                f"to run"
                            )
                            aggregated_results = self._record_scanner_not_selected(
                                display_name,
                                ", ".join(
                                    _not_selected_reasons(refused_selection, names)
                                ),
                                aggregated_results,
                                excluded_scanner_names,
                            )
                            continue
                        aggregated_results = self._record_refused_scanner_name(
                            display_name, plugin_instance, e, aggregated_results
                        )
                        continue
                    first_by_name[name_key] = plugin_instance
                    admitted_instances.append(plugin_instance)
                scanner_instances = admitted_instances
            if scanner_instances:
                self.validation_manager.validate_registered_scanners(scanner_instances)
            else:
                ASH_LOGGER.warning(
                    "No scanner instances created during plugin discovery!"
                )

            # Resolve the operator's allowlist against the names that exist.
            #
            # Selection is matched by string equality against a scanner's configured
            # name, and nothing checked that a name given on the command line named
            # a scanner at all. Measured on this tree against a one-file fixture:
            #
            #   ash scan --scanners detect_secrets   # the name is detect-secrets
            #     scanner_results: ten SKIPPED
            #     summary_stats:   passed=0 failed=0 missing=0 skipped=10 error=0
            #     exit code:       0
            #
            # Zero findings from zero scanners is indistinguishable from a clean
            # scan, and SKIPPED cannot be what gives it away: SKIPPED is how
            # sharding and --exclude-scanners record work a run was never meant to
            # do, so the completeness gate has to tolerate it. That leaves an
            # unresolvable allowlist with no existing gate to fall foul of, which is
            # why it gets one of its own here.
            #
            # Here rather than at CLI parse time, which was the obvious
            # alternative. A scanner's selectable name is config.name on an
            # *instantiated* plugin; scanner classes carry no class-level name and
            # cannot be constructed without a plugin context, so no earlier layer
            # can know these names without guessing -- the same reason the shard
            # partition below is computed here. This is the first point at which the
            # names are authoritative, and it is still before any scanner has run,
            # so the operator gets a refusal instead of a report about nothing.
            #
            # Refused only when nothing resolved. A partly unresolvable allowlist
            # warns and continues: such a run still scans and reports what did
            # resolve, so it is not the silent-zero case, and a CI matrix whose
            # runners load different plugin modules can produce that shape
            # legitimately. The unresolved name is named either way, and a name
            # that belongs to a community module ASH ships but that this run did
            # not import is named with the module to add, in the warning and in
            # the refusal alike.
            #
            # A registered class whose construction raised counts as registered
            # here. It exists, and its ERROR row above already says why it did not
            # run; refusing the run as a misspelled name would replace that cause
            # with spelling advice and turn the failure into a usage error.
            if enabled_scanners and scanner_instances:
                registered_names = {
                    _scanner_display_name(instance).lower().strip()
                    for instance in scanner_instances
                }
                known_names = registered_names | construction_failed
                requested = [(name, name.lower().strip()) for name in enabled_scanners]
                unresolved = [name for name, key in requested if key not in known_names]
                # The module hint and the refusal text are the engine's too
                # (core.scanner_selection): one text for the construction-time
                # check and this backstop. "Not loaded" is judged from the
                # classes handed to this phase, not sys.modules.
                hint = unloaded_community_hint(
                    unloaded_community_scanners(
                        unresolved, known_names, scanner_classes
                    )
                )
                if unresolved:
                    ASH_LOGGER.warning(
                        "No registered scanner matches "
                        f"{', '.join(sorted(unresolved))}. Registered scanners: "
                        f"{', '.join(sorted(registered_names))}"
                        + (f". {hint}" if hint else "")
                    )
                # A refusal whose requested names are all unresolved and at least one
                # is a community scanner from an unloaded module names the module to
                # add, not spelling, and the misspelled names beside it.
                refusal = community_scanner_refusal(
                    list(enabled_scanners), known_names, scanner_classes
                )
                if refusal:
                    raise ScannerSelectionError(refusal)
                # ScanExecutionEngine makes the same refusal when it is built, from
                # the registered classes; this is the backstop for an engine built
                # some other way. known_names, so a scanner whose construction
                # raised is not refused as a name that matches nothing.
                refuse_selection_matching_no_scanner(
                    list(enabled_scanners), known_names, selection_origin
                )

                # The third silent-zero shape: names that resolve, and a
                # Python-only run that leaves every one of them out. The two
                # refusals above cannot see it (each name matches a scanner), and
                # the run executed nothing and exited clean.
                if python_based_plugins_only:
                    wanted = [
                        _scanner_display_name(instance)
                        for instance in scanner_instances
                        if operator_selection(
                            instance,
                            _scanner_display_name(instance),
                            enabled_scanners=enabled_scanners,
                            excluded_scanners=excluded_scanners,
                        ).selected
                    ]
                    runnable = [
                        name
                        for instance, name in (
                            (i, _scanner_display_name(i)) for i in scanner_instances
                        )
                        if operator_selection(
                            instance,
                            name,
                            enabled_scanners=enabled_scanners,
                            excluded_scanners=excluded_scanners,
                            python_only=True,
                        ).selected
                    ]
                    if wanted and not runnable:
                        raise ScannerSelectionError(
                            f"Every scanner {names.allowlist} selects is left out by "
                            "the Python-only run (--python-only runs only Python-only "
                            f"scanners): {', '.join(sorted(wanted))}. Refused rather "
                            "than run, because this run would execute no scanner and "
                            "report itself clean. Drop --python-only, or name a "
                            "Python-only scanner."
                        )

            # An exclusion that matches no registered scanner excludes nothing, and a
            # misspelled one leaves the scanner the operator meant to skip running.
            # Said, not refused: a command line shared by installs that differ in
            # their plugins can name a scanner this one does not have.
            unmatched_exclusions = exclusions_matching_no_scanner(
                excluded_scanners,
                {_scanner_display_name(instance) for instance in scanner_instances}
                | set(construction_failed),
            )
            if unmatched_exclusions:
                ASH_LOGGER.warning(
                    f"No registered scanner matches the {names.exclusion} name "
                    f"{', '.join(unmatched_exclusions)}, so it excludes nothing. "
                    "Check the spelling: names use hyphens, not underscores."
                )

            # Apply the shard selection here, and not earlier.
            #
            # A shard has to be expressed in the same names --exclude-scanners
            # matches on, which is config.name on an *instantiated* plugin.
            # Scanner classes carry no class-level name and cannot be constructed
            # without a plugin context, so no earlier layer -- CLI, orchestrator,
            # execution engine -- can know these names. A layer that guessed would
            # assign a mis-guessed name to no shard at all, dropping that scanner
            # from every shard and so from the whole scan.
            #
            # Taken over every registered scanner, before the dependency and
            # enabled filters below. Partitioning the post-filter set instead
            # would make the split depend on which tools happen to be installed
            # on this runner, so a runner missing semgrep would shift every later
            # scanner to a different shard than its siblings computed -- some
            # scanners running twice and others not at all. Here, a tool missing
            # on one runner is reported MISSING by the shard that owns it, which
            # is a visible failure rather than a silent gap.
            #
            # Also when no scanner was constructed: a sharded run that resolved
            # nothing still ran as shard i of n, and with no record of that its
            # results read as an unsharded scan, which `ash merge` would not hold
            # to the split the other shards made.
            if shard_count is not None:
                all_scanner_names = [
                    _scanner_display_name(instance) for instance in scanner_instances
                ]
                assigned = partition_scanners(
                    all_scanner_names, shard_index, shard_count
                )
                # What the operator's selection asks for, over every candidate,
                # through the helper the selection loop below uses. Taken before
                # this shard's exclusions are folded in just below, so it says what
                # every shard of this run asks for, not only this one. The
                # Python-only filter is included: a scanner a --python-only run
                # leaves out was not asked for.
                intended = sorted(
                    {
                        _scanner_display_name(instance).lower().strip()
                        for instance in scanner_instances
                        if operator_selection(
                            instance,
                            _scanner_display_name(instance),
                            enabled_scanners=enabled_scanners,
                            excluded_scanners=excluded_scanners,
                            python_only=python_based_plugins_only,
                        ).selected
                    }
                )
                excluded_scanners = scanners_to_exclude(
                    all_scanner_names,
                    assigned,
                    already_excluded=excluded_scanners,
                )
                self._shard_assignment = ShardAssignment(
                    shard_index=shard_index,
                    shard_count=shard_count,
                    assigned_scanners=assigned,
                    # The set the partition was taken from, not just this shard's
                    # slice. Without it every shard can be internally consistent
                    # while the union has a hole -- an executor missing a plugin
                    # module resolves a smaller set, partitions it validly, and
                    # nothing at merge time can tell. Recorded here because this
                    # is the only layer that knows the resolved names; see the
                    # comment above on why no earlier layer can.
                    candidate_scanners=sorted(set(all_scanner_names)),
                    intended_scanners=intended,
                    python_only=bool(python_based_plugins_only),
                )
                ASH_LOGGER.info(
                    f"Shard {shard_index} of {shard_count} runs "
                    f"{len(assigned)} of {len(set(all_scanner_names))} scanners: "
                    f"{', '.join(assigned) if assigned else '(none)'}"
                )

            # Filter enabled scanners
            enabled_scanner_classes = []
            enabled_scanner_names = []

            # Initialize lists to track scanner states for validation.
            # excluded_scanner_names was started above the construction loop.
            # Scanners whose tool is absent and that have nothing to scan; SKIPPED.
            nothing_to_scan_names: List[str] = []
            dependency_error_scanners = {}
            # Scanners this run INTENDED to execute, recorded for the shard
            # provenance below. Collected here rather than derived from
            # enabled_scanner_names because those two sets answer different
            # questions: this one stops at the selection filters, so a scanner whose
            # tool turned out to be absent is still in it.
            selected_scanner_names: List[str] = []

            # Process scanners
            if scanner_instances:
                ASH_LOGGER.debug(
                    f"Processing {len(scanner_instances)} scanner instances"
                )
                for plugin_instance in scanner_instances:
                    try:
                        plugin_name = getattr(
                            plugin_instance.__class__, "__name__", "Unknown"
                        ).lower()
                        ASH_LOGGER.debug(f"Processing scanner instance: {plugin_name}")

                        # Use the configured name if available. Shared helper:
                        # this must agree with the name the shard partition was
                        # computed over, since a shard is applied as an exclusion.
                        display_name = _scanner_display_name(plugin_instance)
                        ASH_LOGGER.debug(f"Scanner display name: {display_name}")

                        # Check if scanner is in the excluded list. The shared
                        # helper is the one the shard provenance asks, so what this
                        # loop runs and what a shard records it asked for agree.
                        selection = operator_selection(
                            plugin_instance,
                            display_name,
                            enabled_scanners=enabled_scanners,
                            excluded_scanners=excluded_scanners,
                        )
                        is_excluded = selection.excluded
                        if is_excluded:
                            # The shard split is applied as an exclusion, so the row
                            # says which of the two left this scanner out.
                            excluded_reason = (
                                f"excluded from this run ({names.exclusion})"
                            )
                            if (
                                self._shard_assignment is not None
                                and display_name.lower().strip()
                                not in operator_excluded
                                and display_name.lower().strip()
                                not in {
                                    name.lower().strip()
                                    for name in self._shard_assignment.assigned_scanners
                                }
                            ):
                                excluded_reason = (
                                    SHARD_SPLIT_REASON_PREFIX
                                    + f"{self._shard_assignment.shard_index} of "
                                    f"{self._shard_assignment.shard_count})"
                                )
                            # The same line, and the same text, as
                            # _record_scanner_not_selected writes for the other
                            # selections, so ash.log says what the row says.
                            ASH_LOGGER.info(
                                f"Scanner {display_name} excluded from execution: "
                                f"{excluded_reason}"
                            )

                            # Create a ScanResultsContainer with excluded=True
                            results_container = ScanResultsContainer.for_excluded(
                                display_name, reason=excluded_reason
                            )

                            # Guarded like the other recorders for a scanner that
                            # does not run: a refused write of this container used
                            # to escape to the loop's own except and the row was
                            # then recorded MISSING ("left filtering with no
                            # status") over a scanner the operator excluded.
                            aggregated_results = self._write_results_guarded(
                                display_name, results_container, aggregated_results
                            )

                            # Do NOT add to completed scanners - this scanner was excluded and didn't run
                            # self._completed_scanners.append(plugin_instance)

                            aggregated_results.scanner_results[display_name] = (
                                ScannerTargetStatusInfo(
                                    status=ScannerStatus.SKIPPED,
                                    excluded=True,
                                    dependencies_satisfied=True,
                                    skipped_reason=excluded_reason,
                                )
                            )
                            # Tracked as excluded for the enablement validation
                            # once its row is written, as in
                            # _record_scanner_not_selected: appended first, a
                            # raise before the row left it counted as excluded.
                            excluded_scanner_names.append(display_name)

                            continue

                        # Selection before diagnosis.
                        #
                        # A scanner the operator did not select does not need its
                        # dependencies, and asking anyway gave two scanners in the
                        # identical position -- not selected -- different statuses
                        # depending on whether their tool happened to be installed.
                        # Measured on a host without cfn-nag, grype and syft:
                        # `ash scan --scanners bandit` recorded those three MISSING
                        # and the six tool-present scanners it also left out SKIPPED.
                        # With the completeness gate on by default that is a non-zero
                        # exit for a scan that ran everything it was asked to run.
                        #
                        # Every selection test is dependency-free and comes first:
                        # these two, and the Python-only filter below, which asks
                        # `filter_enabled_plugins` with its dependency check turned
                        # off. Asked with it on, the helper would return False for a
                        # scanner whose tool is absent, and that scanner would be
                        # recorded SKIPPED, erasing the MISSING signal this ordering
                        # exists to preserve.
                        is_in_enabled_scanners = selection.in_allowlist
                        # The hasattr is structurally always true, and is kept only
                        # because a bare attribute access here would read as an
                        # assumption rather than a checked one.
                        #
                        # It matters that it cannot be false, because the filter this
                        # replaced -- EnginePhase.filter_enabled_plugins -- treats a
                        # config with no `enabled` attribute as *enabled*, and this
                        # expression treats it as not selected. If that state were
                        # reachable, a third-party scanner would have gone from running
                        # to being recorded SKIPPED, and SKIPPED is invisible to the
                        # completeness gate. Measured on this tree, it is not:
                        #
                        #   - config=None raises ScannerError("Configuration is
                        #     empty") in ScannerPluginBase.model_post_init, so no
                        #     instance with a None config exists to reach this line.
                        #   - config=<object without 'enabled'> is rejected by pydantic
                        #     ("Input should be a valid dictionary or instance of
                        #     ScannerPluginConfigBase"), because the field is annotated
                        #     to that type.
                        #   - every ScannerPluginConfigBase inherits `enabled: bool =
                        #     True` from PluginConfigBase, and a pydantic model field
                        #     cannot be removed per instance.
                        #
                        # So the two forms are equivalent in every reachable state, and
                        # "restoring parity" by writing `not hasattr(...) or ...` would
                        # change nothing while implying it fixed something.
                        is_enabled = selection.enabled
                        if not (is_in_enabled_scanners and is_enabled):
                            not_selected_reasons = []
                            if not is_enabled:
                                not_selected_reasons.append(
                                    "disabled in the configuration (enabled: false)"
                                )
                            if not is_in_enabled_scanners:
                                not_selected_reasons.append(
                                    f"not named by {names.allowlist}"
                                )
                            aggregated_results = self._record_scanner_not_selected(
                                display_name,
                                ", ".join(not_selected_reasons),
                                aggregated_results,
                                excluded_scanner_names,
                            )
                            continue

                        # The Python-only filter is a selection too, so it is decided
                        # here, before the platform and dependency checks below. A
                        # scanner a --python-only run leaves out does not need its
                        # tool, and asking anyway recorded cfn-nag, grype, npm-audit,
                        # opengrep and syft MISSING on a host without their tools, so
                        # the completeness gate failed a run that ran everything it
                        # selected. The shared helper is asked without its dependency
                        # check, which ScanPhase makes itself below so that an absent
                        # tool is recorded MISSING rather than dropped.
                        check_failures: Dict[int, str] = {}
                        passes_python_only = bool(
                            self.filter_enabled_plugins(
                                plugin_instances=[plugin_instance],
                                plugin_context=self.plugin_context,
                                python_only=python_based_plugins_only,
                                check_dependencies=False,
                                failures=check_failures,
                            )
                        )
                        if python_based_plugins_only:
                            ASH_LOGGER.info(
                                f"Scanner {display_name}: Python-only check result: "
                                f"{passes_python_only}"
                            )
                        if id(plugin_instance) in check_failures:
                            # The check RAISED: the filter dropped the scanner,
                            # but a selected scanner whose own check failed is a
                            # failure to record, not an exclusion. Recorded as
                            # SKIPPED "not Python-only", the loss was invisible
                            # to the completeness gate.
                            aggregated_results = self._record_scanner_error(
                                display_name,
                                f"Scanner {display_name} was not run: its enabled or "
                                f"Python-only check raised "
                                f"({check_failures[id(plugin_instance)]})",
                                aggregated_results,
                            )
                            continue
                        if not passes_python_only:
                            aggregated_results = self._record_scanner_not_selected(
                                display_name,
                                PYTHON_ONLY_SKIPPED_REASON,
                                aggregated_results,
                                excluded_scanner_names,
                            )
                            continue

                        # Past every filter that expresses what the operator asked
                        # for -- the --exclude-scanners check above, the --scanners
                        # allowlist, the scanner's own enabled flag and
                        # --python-only -- so this is the last point at which
                        # "intended to run" is still true of a scanner whose tool may
                        # turn out to be missing. Recorded here and not after the
                        # dependency and platform checks below for that reason: a
                        # selection that dropped a MISSING scanner would make the
                        # merge-time question "did any shard ask for this"
                        # indistinguishable from "could any shard run it".
                        selected_scanner_names.append(display_name)

                        # A scanner that declares this PLATFORM unsupported is SKIPPED,
                        # not MISSING, and this has to be asked before the dependency
                        # check because that check answers with one boolean and cannot
                        # carry the distinction.
                        #
                        # MISSING means "this scanner was supposed to run and did not",
                        # which fails the completeness gate and tells an operator to
                        # install something. Neither is true of a tool that has no build
                        # for this platform. Measured on semgrep on windows-latest: it
                        # logged "Semgrep is not supported on Windows and will be
                        # skipped", was recorded MISSING, and its installer status was
                        # INSTALLED with a real path -- so nothing was unprovisioned and
                        # no install would have helped. Every Windows leg failed the gate
                        # for it.
                        #
                        # AFTER the selection check above, deliberately. A scanner that
                        # was not selected for this run should be reported that way; the
                        # platform is only the reason when the operator did ask for it.
                        #
                        # BOTH THE `getattr` AND THE `isinstance` ARE LOAD-BEARING, and
                        # each was measured rather than added defensively.
                        #
                        # `getattr`: a scanner plugin is not required to inherit
                        # ScannerPluginBase, so a plugin written before this hook existed
                        # does not have it. Calling it unguarded raises AttributeError,
                        # which the loop's own except-and-continue then swallows -- so the
                        # scanner is dropped from the run silently, which is precisely the
                        # class of failure the completeness gate exists to end. Measured
                        # against two suites in test_scan_phase_validation_paths.py, whose
                        # plugin doubles are plain classes: both went quiet rather than
                        # loud. An out-of-tree scanner would have done the same on upgrade.
                        # Absent means "declares nothing", which is the base class default.
                        #
                        # `isinstance`: the hook is annotated `str | None`, and requiring a
                        # real non-empty str is what stops a plugin double from tripping
                        # this branch -- a bare MagicMock returns a truthy Mock from any
                        # method, which would route every mock-backed scanner in the suite
                        # to SKIPPED and quietly turn the gate into "tolerate everything".
                        declare_unsupported = getattr(
                            plugin_instance, "unsupported_platform_reason", None
                        )
                        unsupported_reason = (
                            declare_unsupported()
                            if callable(declare_unsupported)
                            else None
                        )
                        if isinstance(unsupported_reason, str) and unsupported_reason:
                            # The plugin's own text, redacted of the values the
                            # config and the plugin read from the environment as
                            # every other plugin-supplied reason here is: this one
                            # is logged and stored in the results.
                            unsupported_reason = text_without_values(
                                unsupported_reason,
                                plugin_environment_values(
                                    plugin_instance,
                                    config_environment_values(
                                        getattr(self.plugin_context, "config", None)
                                    ),
                                ),
                            )
                            aggregated_results = self._record_scanner_not_selected(
                                display_name,
                                f"not supported on this platform: {unsupported_reason}",
                                aggregated_results,
                                excluded_scanner_names,
                            )
                            continue

                        # Check dependencies early. Not under a sandbox
                        # refusal the executor grades ERROR -- a backend the
                        # operator named that is unavailable, or a refusal
                        # that is not about availability, such as a planted
                        # symlink: the scanner's probes may not run
                        # unsandboxed, so the check could only fail for the
                        # sandbox, and the MISSING it then recorded blamed the
                        # tool. Queued unchecked instead; the executor refuses
                        # it before scan(), naming the refusal first even when
                        # the tool is also missing, so there is one grading
                        # site. An unavailable backend under auto is MISSING
                        # either way, so the check runs and its reason names
                        # the sandbox.
                        ASH_LOGGER.debug(f"Validating dependencies for: {display_name}")
                        # Whatever tool lookups the check makes, a refused in-tree
                        # copy is what the MISSING row says, with its path and the
                        # remedy, rather than "Dependencies not satisfied". Read here
                        # so every scanner's own validate_plugin_dependencies counts.
                        with (
                            plugin_probe_scope(
                                plugin_instance, self.plugin_context
                            ) as probe_refusal,
                            recording_in_tree_refusals() as in_tree_reasons,
                        ):
                            sandbox_refused = (
                                probe_refusal is not None
                                and not sandbox_refusal_grades_missing(probe_refusal)
                            )
                            if sandbox_refused:
                                ASH_LOGGER.debug(
                                    f"Scanner {display_name} queued without its "
                                    "dependency check: its scanner sandbox was "
                                    f"refused: {probe_refusal}",
                                    extra=NO_MARKUP,
                                )
                            else:
                                # The version probe construction deferred, now that
                                # this scanner is selected. getattr: a scanner
                                # plugin need not inherit PluginBase (see
                                # unsupported_platform_reason above).
                                resolve_version = getattr(
                                    plugin_instance,
                                    "resolve_deferred_tool_version",
                                    None,
                                )
                                if callable(resolve_version):
                                    resolve_version()
                                plugin_instance.dependencies_satisfied = (
                                    plugin_instance.validate_plugin_dependencies()
                                )
                        if (
                            not sandbox_refused
                            and not plugin_instance.dependencies_satisfied
                        ):
                            # A scanner whose own file selection finds nothing to scan
                            # loses this scan nothing by lacking its tool, so it is
                            # SKIPPED, as it is when the tool is present and the scan
                            # evaluates no target. Asked only here, after the
                            # dependency check failed, so a scan with the tool present
                            # does not pay for the selection twice. A scanner that has
                            # something to scan falls through to MISSING.
                            # Redacted with the plugin's own values too: its
                            # reason is its text, as its MISSING reason is.
                            nothing_reason = _nothing_to_scan_reason(
                                plugin_instance,
                                plugin_environment_values(
                                    plugin_instance,
                                    config_environment_values(
                                        getattr(self.plugin_context, "config", None)
                                    ),
                                ),
                            )
                            if nothing_reason is not None:
                                # The reason is the plugin's own text, which can
                                # quote paths from the scan set: data to Rich, as
                                # on the MISSING line below.
                                ASH_LOGGER.info(
                                    f"Scanner {display_name} has nothing to scan "
                                    f"({nothing_reason}), so its unavailable "
                                    "dependencies cost this scan nothing: SKIPPED",
                                    extra=NO_MARKUP,
                                )
                                nothing_to_scan_names.append(display_name)
                                # ash.log keeps the reason as given, home directory
                                # included, as for MISSING below; the results get it
                                # written with the home directory as ~.
                                stored_nothing_reason = home_as_tilde(nothing_reason)
                                self.validation_manager.update_scanner_state(
                                    display_name,
                                    registration_status="registered",
                                    enablement_status="excluded",
                                    enablement_reason=(
                                        f"Nothing to scan: {stored_nothing_reason}"
                                    ),
                                    queued_for_execution=False,
                                    execution_completed=False,
                                )
                                # targets_attempted=0 is the claim "looked, found
                                # nothing", which the unified metrics read as
                                # SKIPPED; excluded stays False because nothing
                                # deselected it, and dependencies_satisfied True
                                # because the tool was not needed.
                                # Guarded: unguarded, a failed write of the
                                # row's file reached the handler of this
                                # scanner's filtering, and a scanner that had
                                # nothing to scan was recorded MISSING.
                                aggregated_results = self._write_results_guarded(
                                    display_name,
                                    ScanResultsContainer(
                                        scanner_name=display_name,
                                        status=ScannerStatus.SKIPPED,
                                        duration=None,
                                        targets_attempted=0,
                                        # Explicit, so the serialized report
                                        # (dumped exclude_unset) carries the
                                        # full claim rather than an attempt
                                        # count with no failure accounting.
                                        targets_failed=0,
                                        skipped_reason=stored_nothing_reason,
                                    ),
                                    aggregated_results,
                                )
                                aggregated_results.scanner_results[display_name] = (
                                    ScannerTargetStatusInfo(
                                        status=ScannerStatus.SKIPPED,
                                        dependencies_satisfied=True,
                                        excluded=False,
                                        skipped_reason=stored_nothing_reason,
                                    )
                                )
                                continue

                            # Redacted with the config's environment values first:
                            # the plugin's explanation can name an option the config
                            # read from the environment, and a value under the home
                            # directory no longer matches once it is written as ~.
                            # The plugin's own values too
                            # (plugin_environment_values), as ash dependencies
                            # install redacts its line.
                            environment_values = plugin_environment_values(
                                plugin_instance,
                                config_environment_values(
                                    getattr(self.plugin_context, "config", None)
                                ),
                            )
                            # A refused in-tree copy is the reason, with its path
                            # and the remedy; otherwise the plugin's own
                            # explanation (_missing_dependency_reason).
                            #
                            # Both, when the scanner has words of its own: a refused
                            # in-tree copy recorded while the check ran is not
                            # necessarily why the check failed, and used alone it
                            # replaced the scanner's own explanation. The base
                            # hook's generic answer ("not found on PATH") is not
                            # added beside a refusal, which it would contradict,
                            # and the generic sentence below only stands in when
                            # neither has anything to say.
                            own_reason = plugin_missing_dependency_reason(
                                plugin_instance, environment_values
                            )
                            reason_parts = list(in_tree_reasons)
                            if (
                                own_reason
                                and own_reason not in reason_parts
                                and (
                                    not reason_parts
                                    or plugin_explains_its_own_refusal(
                                        plugin_instance, own_reason
                                    )
                                )
                            ):
                                reason_parts.append(own_reason)
                            raw_reason = text_without_values(
                                "; ".join(reason_parts)
                                if reason_parts
                                else _generic_missing_dependency_reason(
                                    plugin_instance
                                ),
                                environment_values,
                            )
                            # ash.log keeps the reason as the plugin gave it, absolute
                            # paths included: this WARNING is the only line it has for
                            # a missing tool. The reason can carry paths, which are
                            # data to Rich. The results get it without the home
                            # directory (see home_as_tilde).
                            ASH_LOGGER.warning(
                                f"Scanner {display_name} dependencies are not "
                                f"satisfied, marking as MISSING: {raw_reason}",
                                extra=NO_MARKUP,
                            )
                            missing_reason = home_as_tilde(raw_reason)
                            # Track dependency error for validation
                            dependency_error_scanners[display_name] = [missing_reason]

                            # Create a ScanResultsContainer with dependencies_satisfied=False
                            results_container = ScanResultsContainer.for_missing_deps(
                                display_name, reason=missing_reason
                            )
                            if missing_reason:
                                results_container.add_error(missing_reason)

                            # Process the container through the guarded write to
                            # store duration info: the row below is the record,
                            # and a failed write of its file must not turn a
                            # scanner whose dependencies are absent into the
                            # unclassified MISSING of the reconciliation.
                            aggregated_results = self._write_results_guarded(
                                display_name, results_container, aggregated_results
                            )

                            # Do NOT add to completed scanners - this scanner didn't actually run due to missing dependencies
                            # self._completed_scanners.append(plugin_instance)

                            aggregated_results.scanner_results[display_name] = (
                                ScannerTargetStatusInfo(
                                    status=ScannerStatus.MISSING,
                                    dependencies_satisfied=False,
                                    excluded=False,
                                    missing_reason=missing_reason,
                                )
                            )

                            continue

                        # Every selection filter and the dependency check have passed.
                        # Add a single task per scanner that will handle both source
                        # and converted directories.
                        task_list = [
                            {
                                "path": self.plugin_context.source_dir,
                                "type": "source",
                            },
                        ]
                        if self._include_work_dir:
                            task_list.append(
                                {
                                    "path": self.plugin_context.work_dir,
                                    "type": "converted",
                                }
                            )
                        self._scanner_tasks.append(
                            (
                                display_name,
                                plugin_instance,
                                task_list,
                            )
                        )
                        enabled_scanner_classes.append(plugin_instance.__class__)
                        enabled_scanner_names.append(display_name)
                        ASH_LOGGER.debug(
                            f"Added scanner {display_name} to execution tasks"
                        )

                        # CRITICAL: Update validation manager state for queued scanners
                        self.validation_manager.update_scanner_state(
                            display_name,
                            registration_status="registered",
                            enablement_status="enabled",
                            enablement_reason="Scanner passed all checks and was queued for execution",
                            queued_for_execution=True,
                            execution_completed=False,
                        )
                    except Exception as e:
                        # Redacted with the config's environment values and the
                        # plugin's own: the exception can name an option either
                        # read from the environment, and this goes to ash.log.
                        environment_values = plugin_environment_values(
                            plugin_instance,
                            config_environment_values(
                                getattr(self.plugin_context, "config", None)
                            ),
                        )
                        ASH_LOGGER.error(
                            f"Error checking scanner {getattr(plugin_instance.__class__, '__name__', 'Unknown')}: "
                            f"{error_text(e, environment_values)}"
                        )
                        # Add stack trace for debugging
                        ASH_LOGGER.debug(
                            f"Stack trace: {traceback_text(values=environment_values)}"
                        )
            else:
                ASH_LOGGER.warning("No scanner classes found!")

            # Completed after the filter loop, because the selection is not known
            # before it. The assignment itself has to be recorded before the loop --
            # it is applied as an exclusion the loop reads -- so the two halves of
            # the provenance are necessarily written at different points, and this is
            # the second half rather than a second record.
            #
            # Mutated rather than rebuilt: the object is read by the execution engine
            # only after this method returns, and rebuilding it would duplicate the
            # shard_index/shard_count/candidate_scanners arguments, which is one more
            # place for the two constructions to drift apart.
            if self._shard_assignment is not None:
                self._shard_assignment.selected_scanners = sorted(
                    set(selected_scanner_names)
                )

            # Every registered scanner has to leave this loop accounted for.
            #
            # The loop above ends in `except Exception: continue`, so any scanner
            # whose filtering raised leaves it having written nothing: it is not in
            # enabled_scanner_names, not in excluded_scanner_names, not in
            # dependency_error_scanners, and has no scanner_results entry. The
            # unsupported_platform_reason hook is one way in -- the getattr guard
            # covers a plugin that does not HAVE the hook, not one whose hook raises,
            # which a third-party scanner's can do for reasons of its own (a missing
            # config file, a helper that shells out) -- but the escape predates that
            # hook and is not specific to it. Anything that raises before the
            # recording lines takes the same route.
            #
            # WHAT THAT ACTUALLY PRODUCED, MEASURED RATHER THAN REASONED ABOUT, and it
            # is not the absence it looks like. Later in this phase
            # _validate_result_completeness calls
            # ScannerValidationManager.ensure_complete_results, which backfills an
            # entry for every registered scanner missing from the results. For a
            # scanner that escaped here, validate_scanner_enablement below has already
            # labelled it enablement_status="disabled" ("Scanner is disabled (reason
            # unknown)"), and determine_scanner_status_from_execution_data maps
            # "disabled" to "excluded", so _create_missing_scanner_result_entry writes:
            #
            #   status=SKIPPED  excluded=True  dependencies_satisfied=True
            #
            # byte for byte what a scanner the operator deliberately deselected gets. A
            # scanner that crashed is recorded as one nobody asked to run. That is
            # worse than no entry, because SKIPPED is on the completeness allowlist:
            # incomplete_scanners() returns [] for it and
            # .github/scripts/assert_scanners_completed.py tolerates it, so the crash
            # is invisible to both gates. Measured on a real ScannerValidationManager;
            # the committed suite's own _classify() helper replaces the validation
            # manager with a MagicMock, which is why the absence is what a test sees
            # and the mislabel is what a scan gets.
            #
            # Recorded MISSING, which is the only status that means "was selected and
            # did not run". ERROR was the alternative and is wrong: it means the
            # scanner ran and failed, and this one never started. excluded=False is the
            # load-bearing field either way -- it is the claim that nobody deselected
            # this scanner, and it is what stops ensure_complete_results from taking
            # the "properly excluded" branch and reasserting SKIPPED.
            #
            # dependencies_satisfied stays True, and ScanResultsContainer.for_missing_deps
            # is deliberately NOT used even though it is the factory this status usually
            # comes from: it hard-codes dependencies_satisfied=False, and nothing here
            # checked a dependency. Filtering can raise before validate_plugin_dependencies
            # is ever called -- the platform hook is asked first -- so False would tell an
            # operator to install a tool that may well be present, which is the same
            # misdirection HEAD's parent commit removed from the Windows semgrep case.
            # It follows _record_scanner_not_selected's stated reasoning: whether the
            # tool is present is not a fact this scan established. The resulting triple
            # (MISSING, deps=True, excluded=False) is produced by no other path, so a
            # results file carrying one says which of the three it was.
            #
            # Before validate_scanner_enablement and before the executor, so the entry
            # exists ahead of both readers of it; ensure_complete_results then finds
            # the name already present and leaves it alone.
            #
            # Reconciled against scanner_instances, not against scanner_classes. A
            # class whose *instantiation* raised (the try/except above the registration
            # loop) never becomes an instance, has no configured name -- config.name on
            # an instance is the only authoritative name a scanner has -- and so cannot
            # be recorded under the name a report would use. That gap is a different
            # mechanism with its own logged error, and inventing a class-derived name
            # for it here would put a scanner in the results under a name nothing else
            # in the run agrees with.
            if scanner_instances:
                accounted = {
                    name.lower().strip()
                    for name in list(aggregated_results.scanner_results or {})
                    + enabled_scanner_names
                }
                for plugin_instance in scanner_instances:
                    display_name = _scanner_display_name(plugin_instance)
                    if display_name.lower().strip() in accounted:
                        continue
                    unclassified_reason = (
                        "Scanner filtering raised before this scanner was classified, "
                        "so it was neither queued nor recorded; see the 'Error "
                        "checking scanner' line above for the exception."
                    )
                    ASH_LOGGER.error(
                        f"Scanner {display_name} was registered but left filtering "
                        f"with no status. Recording it MISSING. {unclassified_reason}"
                    )
                    # dependencies_satisfied assigned, not left at its default, so
                    # the per-target report carries it: the rebuild reads that report
                    # (see unified_metrics.dependencies_recorded_satisfied) and would
                    # otherwise take MISSING to mean the dependencies were absent.
                    container = ScanResultsContainer(
                        scanner_name=display_name,
                        status=ScannerStatus.MISSING,
                        duration=None,
                        missing_reason=unclassified_reason,
                        dependencies_satisfied=True,
                    )
                    container.add_error(unclassified_reason)
                    # Guarded: this scanner is here because something in its own
                    # filtering raised, and writing its results container can
                    # raise the same way (a results directory that cannot be made).
                    # Unguarded, one scanner's failed write ended the whole phase
                    # before any scanner ran. The row below is the record, so it is
                    # written whether or not the container was.
                    try:
                        aggregated_results = self._process_results(
                            results=container,
                            aggregated_results=aggregated_results,
                        )
                    except Exception as write_error:
                        ASH_LOGGER.error(
                            f"Could not write the results of scanner {display_name}: "
                            + error_text(
                                write_error,
                                config_environment_values(
                                    getattr(self.plugin_context, "config", None)
                                ),
                            )
                        )
                    aggregated_results.scanner_results[display_name] = (
                        ScannerTargetStatusInfo(
                            status=ScannerStatus.MISSING,
                            dependencies_satisfied=True,
                            excluded=False,
                            missing_reason=unclassified_reason,
                        )
                    )
                    self.validation_manager.update_scanner_state(
                        display_name,
                        registration_status="registered",
                        queued_for_execution=False,
                        execution_completed=False,
                        failure_reason=unclassified_reason,
                    )

            # Record the completeness denominator, and the plugins that never
            # arrived to be counted in it.
            #
            # Both of these are about the same defect from opposite ends. The roster
            # is what the run was SUPPOSED to account for, read from a declaration
            # rather than from the resolve it is checking. The load errors are the
            # measured reason a resolve came up short. Either alone leaves a gap: a
            # roster with no load errors cannot say why a scanner is absent, and load
            # errors with no roster cannot say that anything is absent when the module
            # that failed was never expected on this runner.
            # Imported here rather than at module level: `plugins.loader` imports
            # the built-in plugin package, whose scanner modules import
            # `config.ash_config`, which carries forward references this module is
            # part of resolving. A top-level import turns that into a
            # PydanticUndefinedAnnotation at collection time.
            from automated_security_helper.plugins.loader import recorded_load_errors

            # THIS run's record, carried on its context: a process-wide record
            # put an earlier run's failure into a clean run's results.
            load_errors = recorded_load_errors(
                getattr(self.plugin_context, "plugin_load_record", None) or {}
            )
            if load_errors:
                aggregated_results.metadata.plugin_load_errors = dict(load_errors)

            # A scanner-region module that failed to import gets a row, so that import
            # loss reaches the exit code and not only a log line.
            #
            # Per-module import isolation turns a hard startup failure into a degraded
            # run, which is the right direction only if the degradation is loud. This
            # is the arm that makes it loud: nothing else in this phase puts import
            # loss in front of `incomplete_scanners`.
            #
            # KEYED BY THE MODULE PATH, WHICH IS A KNOWN COSMETIC COST. `scanner_results`
            # is rendered as a scanner column, so a report can show a dotted path where
            # a scanner name belongs. That is confusing but recoverable -- a reader can
            # work out what it means -- and a silently absent scanner is not. Removing
            # this block is a one-line revert if a maintainer prefers clean reports;
            # keeping it also preserves the option for whoever resolves the maintainer
            # decision on whether import loss should affect the exit code at all, which
            # dropping it would settle in one direction unasked.
            #
            # This row is why `cli.merge._verify_scanner_union` needed narrowing. That
            # check refuses any `scanner_results` key no shard's `assigned_scanners`
            # claims, and a module path can never be claimed, so before the narrowing a
            # sharded merge refused on every run that lost a module -- through a check
            # no flag gates. The two changes are one decision and should not be
            # separated.
            for failed_module, error in load_errors.items():
                # Only the scanner region lands in scanner_results; see
                # _SCANNER_MODULE_MARKER for why. The built-in package root is
                # admitted with it: its import failing lost every shipped scanner
                # (_loses_builtin_scanners).
                if not (
                    failed_module.endswith(_SCANNER_MODULE_MARKER)
                    or f"{_SCANNER_MODULE_MARKER}." in failed_module
                    or _loses_builtin_scanners(failed_module)
                ):
                    continue
                if failed_module in aggregated_results.scanner_results:
                    continue
                module_error = (
                    f"Plugin module {failed_module} failed to import, so the scanners "
                    f"it declares did not run: {error}"
                )
                ASH_LOGGER.error(module_error)
                container = ScanResultsContainer(
                    scanner_name=failed_module,
                    status=ScannerStatus.ERROR,
                    duration=None,
                    errors=[module_error],
                )
                aggregated_results = self._write_results_guarded(
                    failed_module, container, aggregated_results
                )
                aggregated_results.scanner_results[failed_module] = (
                    ScannerTargetStatusInfo(
                        status=ScannerStatus.ERROR,
                        # Nothing here checked a dependency. The module did not
                        # import, which may or may not be about a dependency, and
                        # False would tell an operator to install a tool on the
                        # strength of a guess.
                        dependencies_satisfied=True,
                        excluded=False,
                    )
                )

            # Gated on the run having resolved ASH's own plugin package, not applied
            # unconditionally. See _BUILTIN_PLUGIN_MODULE_PREFIX: a caller that
            # supplies its own plugin classes -- a library embedding, ten harnesses
            # in this repository's own suite -- did not resolve the built-in set, and
            # measuring such a run against the built-in roster would report every
            # scanner the caller did not supply as one that went missing.
            # Or TRIED to resolve it and lost it whole: a run whose built-in
            # package failed to import resolved no built-in class, and without
            # the roster its zero scanners passed every completeness check.
            resolved_builtin_plugins = any(
                str(getattr(plugin_class, "__module__", "")).startswith(
                    _BUILTIN_PLUGIN_MODULE_PREFIX
                )
                for plugin_class in scanner_classes or []
            ) or any(_loses_builtin_scanners(module) for module in load_errors)
            if resolved_builtin_plugins:
                aggregated_results.metadata.expected_scanners = (
                    _declared_scanner_roster(self.plugin_context.config)
                )

            # Validate scanner enablement after filtering
            self.validation_manager.validate_scanner_enablement(
                enabled_scanners=enabled_scanner_names,
                excluded_scanners=excluded_scanner_names + nothing_to_scan_names,
                dependency_errors=dependency_error_scanners,
            )

            # Validate scanner tasks after population
            self._validate_scanner_tasks(aggregated_results)

            # Add comprehensive debugging for scanner filtering
            ASH_LOGGER.info("Scanner Filtering Summary:")
            ASH_LOGGER.info(
                f"   Total scanner classes found: {len(scanner_classes) if scanner_classes else 0}"
            )
            ASH_LOGGER.info(
                f"   Enabled scanners after filtering: {len(enabled_scanner_names)}"
            )
            ASH_LOGGER.info(f"   Enabled scanner names: {enabled_scanner_names}")

            # Count scanners in different states from the collections the loop
            # above actually wrote.
            #
            # These two numbers used to be re-derived by walking
            # additional_reports looking for a "source" key, and both were
            # structurally pinned at 0: _process_results keys that dict by
            # ScanResultsContainer.target_type, which is None for the excluded and
            # missing-dependency containers built during preparation (filed under
            # the string "None", the key they have once the results are saved
            # as JSON and read back), so the "source" key the walk required was
            # never there. Measured on a host
            # without cfn-nag, grype and syft: preparation logged
            # "Missing dependencies: 0" while validation, reading
            # dependency_error_scanners through the validation manager, reported
            # Missing_Deps (3) for the same run. A wrong count is worse than no
            # count, because "Total accounted for" was silently just the enabled
            # count and read as a reconciliation.
            #
            # Keying additional_reports by `target_type or "source"` instead was
            # rejected: ScannerStatisticsCalculator.get_scanner_status_info and
            # cli.merge both read the "None" key deliberately to tell a shard's
            # own scanners from the ones it recorded as not its own, so renaming
            # it would break the distributed path to fix a log line.
            excluded_scanners_count = len(excluded_scanner_names)
            missing_deps_count = len(dependency_error_scanners)
            for scanner_name in excluded_scanner_names:
                ASH_LOGGER.debug(f"   Scanner {scanner_name}: EXCLUDED")
            for scanner_name in dependency_error_scanners:
                ASH_LOGGER.debug(f"   Scanner {scanner_name}: MISSING DEPENDENCIES")

            ASH_LOGGER.info(f"   Excluded scanners: {excluded_scanners_count}")
            ASH_LOGGER.info(f"   Nothing to scan: {len(nothing_to_scan_names)}")
            ASH_LOGGER.info(f"   Missing dependencies: {missing_deps_count}")
            # Scoped to preparation on purpose. A scanner can still be marked
            # MISSING later, in ScannerExecutor, when its scan() returns False
            # (the template's answer for unavailable dependencies; an empty dict
            # or list is a result the executor refuses to grade, ERROR) --
            # that discovery happens after this line and cannot be counted here,
            # so the label says what the number covers rather than implying it is
            # the final tally.
            ASH_LOGGER.info(
                "   Total accounted for after preparation: "
                f"{len(enabled_scanner_names) + excluded_scanners_count + len(nothing_to_scan_names) + missing_deps_count}"
            )

            ASH_LOGGER.verbose(
                f"Prepared {len(enabled_scanner_names)} enabled scanners: {enabled_scanner_names}"
            )

            # Create the main scan task with initial progress
            scan_task = self.progress_display.add_task(
                phase=ExecutionPhase.SCAN,
                description=f"Preparing {len(enabled_scanner_names)} scanners...",
                total=100,
            )

            # Update the main task to show it's started
            self.progress_display.update_task(
                phase=ExecutionPhase.SCAN,
                task_id=scan_task,
                completed=30,
                description=f"Prepared {len(enabled_scanner_names)} scanners for execution",
            )

            # Build the executor, wiring it to our result processor. The scan
            # runs the executor's own per-scanner path; this phase's
            # per-scanner methods are not hooks (see _safe_execute_scanner).
            executor = ScannerExecutor(
                plugin_context=self.plugin_context,
                progress_display=self.progress_display,
                scanner_tasks=self._scanner_tasks,
                max_workers=max_workers,
                notify_fn=self.notify_event,
                process_results_fn=self._result_processor.process_container,
            )
            # Propagate global_ignore_paths so _execute_scanner can use it
            executor._global_ignore_paths = self._global_ignore_paths

            # Execute scanners based on mode. The executor's completions are
            # synced back for the validation methods even when the run ends by
            # raising (a cancel is a ScanCancelled), so a scanner that finished
            # before it stays recorded.
            try:
                if parallel:
                    self.progress_display.update_task(
                        phase=ExecutionPhase.SCAN,
                        task_id=scan_task,
                        completed=40,
                        description=f"Executing {len(enabled_scanner_names)} scanners in parallel...",
                    )
                    results = executor.run_parallel(aggregated_results)
                else:
                    self.progress_display.update_task(
                        phase=ExecutionPhase.SCAN,
                        task_id=scan_task,
                        completed=40,
                        description=f"Executing {len(enabled_scanner_names)} scanners sequentially...",
                    )
                    results = executor.run_sequential(aggregated_results)
            finally:
                self._completed_scanners = executor.completed_scanners

            if isinstance(results, AshAggregatedResults):
                aggregated_results = results

            # Expose executor on self so delegation stubs (_execute_scanner etc.) work
            self._executor = executor

            # Validate execution completion after scanner execution
            self._validate_execution_completion(aggregated_results)

            self.progress_display.update_task(
                phase=ExecutionPhase.SCAN,
                task_id=scan_task,
                completed=90,
                description="Finalizing scan results...",
            )

            # Validate result completeness before finalizing scan results
            self._validate_result_completeness(aggregated_results)
            # Unconditional, and after the completeness pass has returned: the
            # pass swallows its own errors, so its checkpoint is not a record
            # that the phase reached its end. The orchestrator reads this one.
            self._record_scan_phase_completed(aggregated_results)

            # A scanner busy in Python, not waiting on a child process, returns
            # after a cancel rather than stopping at it, and when it was the last
            # to start no scanner start was left to check the cancel. A no-op
            # outside a cancellable scan; see core/cancellation.py.
            raise_if_cancelled()

            # The results file is not written here. It used to be, and that was
            # before the engine's changed-files narrowing, final suppression pass,
            # metrics rebuild and report phase, while the MCP progress tracker
            # reads the file's existence as the scan being complete. The
            # orchestrator writes it once every phase has run
            # (ASHScanOrchestrator._execute_scan), and the CLI rewrites it after.

            # The metrics consistency check is not run here: neither side of it is
            # final yet. See _validate_metrics_consistency.

            self.progress_display.update_task(
                phase=ExecutionPhase.SCAN,
                task_id=scan_task,
                completed=100,
                description=f"Scanners complete: {len(self._completed_scanners)} scanners executed",
            )

            self.add_summary(
                "Complete", f"Executed {len(self._completed_scanners)} scanners"
            )

            return aggregated_results

        except Exception as e:
            # The summary row is a progress task description, which the display
            # reads as markup; the error's text quotes paths and tool output,
            # and can name a configured option, so it is redacted with the
            # config's environment values.
            environment_values = config_environment_values(
                getattr(self.plugin_context, "config", None)
            )
            described = error_text(e, environment_values)
            self.add_summary("Failed", f"Error: {escape_markup(described)}")
            ASH_LOGGER.error(f"Execution failed: {described}")
            raise
        finally:
            if hasattr(self, "_scanner_tasks"):
                self._scanner_tasks = []

    def _extract_metrics_from_sarif(self, sarif_report: SarifReport):
        """Extract severity metrics from a SARIF report.

        Args:
            sarif_report: SARIF report to extract metrics from

        Returns:
            Tuple[ScannerSeverityCount, int]: Severity counts and total finding count

        Note:
            This method is kept for backward compatibility. For new code, use
            ScannerStatisticsCalculator.extract_sarif_counts_for_scanner instead.
        """
        from automated_security_helper.models.asharp_model import AshAggregatedResults

        # Create a temporary AshAggregatedResults with the SARIF report
        temp_model = AshAggregatedResults()
        temp_model.sarif = sarif_report

        sev_count = get_severity_metrics_from_sarif(
            sarif_report=sarif_report, plugin_context=self.plugin_context
        )

        total_findings = sev_count.total + sev_count.suppressed

        return sev_count, total_findings

    def _make_executor_for_delegation(self) -> "ScannerExecutor":
        """Return a ScannerExecutor suitable for direct method delegation in tests.

        Results go through self._process_results, which uses
        self._result_processor when execute() prepared one and otherwise
        builds a ScanResultProcessor, so a direct caller's results are
        processed rather than dropped.
        """
        executor = ScannerExecutor(
            plugin_context=self.plugin_context,
            progress_display=self.progress_display,
            scanner_tasks=getattr(self, "_scanner_tasks", []),
            max_workers=getattr(self, "_max_workers", 4),
            notify_fn=self.notify_event,
            process_results_fn=self._process_results,
        )
        executor._global_ignore_paths = getattr(self, "_global_ignore_paths", [])
        return executor

    def _merge_completed_scanners(self, executor_completed) -> None:
        """Fold an executor's completed scanners into the phase's.

        By identity, keeping order: scanner plugins are pydantic models with
        no __hash__, so a set would raise on the first real plugin, and it
        would scramble completion order besides.
        """
        merged = list(self._completed_scanners)
        for plugin in executor_completed:
            if not any(plugin is seen for seen in merged):
                merged.append(plugin)
        self._completed_scanners = merged

    def _execute_scanner(
        self,
        scanner_name: str,
        scanner_plugin: ScannerPluginBase,
        scan_targets: List[Dict[str, Any]],
    ) -> List[ScanResultsContainer]:
        """Delegate to ScannerExecutor._execute_scanner.

        Like the other per-scanner methods here, this serves direct callers
        and is not a hook: a scan runs the executor's own per-scanner path,
        so overriding this method changes no scan (see _safe_execute_scanner).
        """
        executor = self._make_executor_for_delegation()
        return executor._execute_scanner(scanner_name, scanner_plugin, scan_targets)

    def _execute_scanners_sequential(
        self, aggregated_results: AshAggregatedResults
    ) -> AshAggregatedResults | None:
        """Delegate to ScannerExecutor.run_sequential.

        _execute_phase builds its own executor and never comes through here;
        this method serves direct callers with the executor's loop, so there
        is one copy of each progress description and one completion rule.
        Completions are synced back even when the run ends by raising (a
        cancel is a ScanCancelled), so a scanner that finished first stays
        recorded.
        """
        executor = self._make_executor_for_delegation()
        try:
            return executor.run_sequential(aggregated_results)
        finally:
            self._merge_completed_scanners(executor.completed_scanners)

    def _execute_scanners_parallel(
        self, aggregated_results: AshAggregatedResults
    ) -> AshAggregatedResults | None:
        """Delegate to ScannerExecutor.run_parallel.

        The executor runs a single task sequentially, caps the pool at
        self._max_workers, and records a completed scanner only on success
        with no error-status container. As in the sequential method,
        completions are synced back even when the run ends by raising.
        """
        executor = self._make_executor_for_delegation()
        try:
            return executor.run_parallel(aggregated_results)
        finally:
            self._merge_completed_scanners(executor.completed_scanners)

    def _process_results(
        self, results: ScanResultsContainer, aggregated_results: AshAggregatedResults
    ) -> AshAggregatedResults:
        """Delegate to ScanResultProcessor.process_container."""
        # Built only when the phase has none: the default of a getattr is
        # evaluated on every call, so each result built a processor (and its
        # validation manager) it then discarded.
        processor = getattr(self, "_result_processor", None)
        if processor is None:
            processor = ScanResultProcessor(plugin_context=self.plugin_context)
        return processor.process_container(results, aggregated_results)

    def _safe_execute_scanner(
        self,
        scanner_name: str,
        scanner_plugin: ScannerPluginBase,
        scan_targets: List[Dict[str, Any]],
    ) -> List[ScanResultsContainer]:
        """Delegate to ScannerExecutor._safe_execute_scanner.

        This method's direct callers predate the executor and read a plain
        container list, so the executor's succeeded flag is dropped here. A
        direct call records no completion: the executor records one only in
        its run loops. A cancelled scan starts no further scanner, and
        nothing at all is built for one, so the check comes before the
        executor.

        The per-scanner methods on this phase (this one, _execute_scanner and
        the two run-loop delegators) are not hooks. A scan runs
        ScannerExecutor's own per-scanner path, so a subclass that overrides
        one of them changes no scan, and these delegators build that same
        executor, so a direct call runs the same path. A test that stands in
        for a scanner's run patches ScannerExecutor._execute_scanner, which
        the scan and these delegators both resolve per call.
        """
        raise_if_cancelled()
        executor = self._make_executor_for_delegation()
        results_list, _scanner_succeeded = executor._safe_execute_scanner(
            scanner_name, scanner_plugin, scan_targets
        )
        return results_list

    def _validate_metrics_consistency(self, aggregated_results: AshAggregatedResults):
        """Validate that scanner_results totals match summary_stats.

        Logs a warning per metric whose totals differ. The tally is
        ``unified_metrics.metrics_consistency_discrepancies``, which
        ``populate_metrics_from_unified_source`` runs after it writes both sides.
        That is where a scan checks this: at the end of this phase neither side is
        final -- a scanner that ran has no row until the rebuild, and summary_stats
        is filled in only when the results file is written, which the orchestrator
        does once after every phase (``save_model`` fills it whenever
        scanner_results is empty) -- so the same check run at the end of this
        phase would warn about every scan in which every scanner ran and found
        something.

        Args:
            aggregated_results: The AshAggregatedResults to validate
        """
        from automated_security_helper.core.unified_metrics import (
            metrics_consistency_discrepancies,
        )

        discrepancies = metrics_consistency_discrepancies(
            aggregated_results, logger=ASH_LOGGER
        )
        for discrepancy in discrepancies:
            ASH_LOGGER.warning(f"Metrics consistency check failed for {discrepancy}")
        if not discrepancies:
            ASH_LOGGER.debug("Metrics consistency check passed - all totals match")

    def _validate_scanner_tasks(self, aggregated_results: AshAggregatedResults) -> None:
        """Validate scanner tasks after population and handle missing scanners.

        This method validates that all expected scanners have tasks in the list,
        reports the ones that do not (they will not run, and
        ``handle_queue_validation_errors`` records why), and handles validation
        errors gracefully to ensure scan continuity.

        Args:
            aggregated_results: The aggregated results object to add validation errors to
        """
        try:
            ASH_LOGGER.info("Starting scanner tasks validation")

            ASH_LOGGER.debug(f"Validating {len(self._scanner_tasks)} scanner tasks")

            # Validate the scanner tasks
            validation_checkpoint = self.validation_manager.validate_task_queue(
                self._scanner_tasks
            )

            # An enabled scanner with no task will not run, and nothing re-queues it.
            # handle_queue_validation_errors below records the reason on its state.
            missing_scanners = validation_checkpoint.get_missing_scanners()
            if missing_scanners:
                ASH_LOGGER.info(
                    f"Found {len(missing_scanners)} enabled scanners with no task: "
                    f"{', '.join(missing_scanners)}"
                )

                # Notify about missing scanners via event system
                try:
                    from automated_security_helper.plugins.events import AshEventType

                    self.notify_event(
                        AshEventType.WARNING,
                        message=f"Scanner tasks validation found {len(missing_scanners)} missing scanners",
                        missing_scanners=missing_scanners,
                        phase="scan",
                        validation_checkpoint="scanner_tasks_validation",
                    )
                except Exception as event_error:
                    ASH_LOGGER.debug(
                        f"Failed to notify validation warning event: {str(event_error)}"
                    )

            # Handle validation errors gracefully
            self.validation_manager.handle_queue_validation_errors(
                validation_checkpoint=validation_checkpoint,
                scan_results=aggregated_results,
            )

            # Add validation results to aggregated results for debugging
            checkpoint_dict = {
                "checkpoint_name": validation_checkpoint.checkpoint_name,
                "timestamp": validation_checkpoint.timestamp.isoformat(),
                "expected_scanners": validation_checkpoint.expected_scanners,
                "actual_scanners": validation_checkpoint.actual_scanners,
                "discrepancies": validation_checkpoint.discrepancies,
                "errors": validation_checkpoint.errors,
                "metadata": validation_checkpoint.metadata,
            }
            aggregated_results.validation_checkpoints.append(checkpoint_dict)

            # Add validation summary to metadata for easy access
            if not hasattr(aggregated_results.metadata, "validation_summary"):
                aggregated_results.metadata.validation_summary = {}

            aggregated_results.metadata.validation_summary[
                "scanner_tasks_validation"
            ] = {
                "timestamp": validation_checkpoint.timestamp.isoformat(),
                "expected_count": len(validation_checkpoint.expected_scanners),
                "actual_count": len(validation_checkpoint.actual_scanners),
                "missing_count": len(missing_scanners),
                "has_issues": validation_checkpoint.has_issues(),
            }

            # Log validation summary and notify via events
            if validation_checkpoint.has_issues():
                total_issues = len(validation_checkpoint.discrepancies) + len(
                    validation_checkpoint.errors
                )
                ASH_LOGGER.warning(
                    f"Scanner tasks validation completed with {total_issues} issues"
                )

                # Notify about validation issues
                try:
                    from automated_security_helper.plugins.events import AshEventType

                    self.notify_event(
                        AshEventType.WARNING,
                        message=f"Scanner tasks validation completed with {total_issues} issues",
                        total_issues=total_issues,
                        discrepancies=validation_checkpoint.discrepancies,
                        errors=validation_checkpoint.errors,
                        phase="scan",
                        validation_checkpoint="scanner_tasks_validation",
                    )
                except Exception as event_error:
                    ASH_LOGGER.debug(
                        f"Failed to notify validation warning event: {str(event_error)}"
                    )
            else:
                ASH_LOGGER.info("Scanner tasks validation completed successfully")

                # Notify about successful validation
                try:
                    from automated_security_helper.plugins.events import AshEventType

                    self.notify_event(
                        AshEventType.INFO,
                        message="Scanner tasks validation completed successfully",
                        expected_count=len(validation_checkpoint.expected_scanners),
                        actual_count=len(validation_checkpoint.actual_scanners),
                        phase="scan",
                        validation_checkpoint="scanner_tasks_validation",
                    )
                except Exception as event_error:
                    ASH_LOGGER.debug(
                        f"Failed to notify validation info event: {str(event_error)}"
                    )

        except Exception as e:
            error_msg = f"Error during scanner tasks validation: {error_text(e)}"
            ASH_LOGGER.error(error_msg)

            # Notify about validation error via event system
            try:
                from automated_security_helper.plugins.events import AshEventType

                self.notify_event(
                    AshEventType.ERROR,
                    message=error_msg,
                    exception=error_text(e),
                    phase="scan",
                    validation_checkpoint="scanner_tasks_validation",
                )
            except Exception as event_error:
                ASH_LOGGER.debug(
                    f"Failed to notify validation error event: {str(event_error)}"
                )

            # Add error to validation manager for tracking
            self.validation_manager.add_queue_validation_error(error_msg)

            # Ensure scan continues despite validation error
            ASH_LOGGER.info("🔄 Scanner tasks validation failed but scan will continue")

            # Add stack trace for debugging
            ASH_LOGGER.debug(
                f"Scanner tasks validation error stack trace: {traceback_text()}"
            )

    def _validate_execution_completion(
        self, aggregated_results: AshAggregatedResults
    ) -> None:
        """Validate execution completion after scanner execution.

        This method validates that all expected scanners completed execution,
        logs execution discrepancies, and handles validation errors gracefully
        to ensure scan continuity.

        Args:
            aggregated_results: The aggregated results object to add validation errors to
        """
        try:
            ASH_LOGGER.info("Starting execution completion validation")

            # Extract completed scanner names from self._completed_scanners
            completed_scanner_names = []
            if self._completed_scanners:
                for scanner_plugin in self._completed_scanners:
                    # The name the scanner was queued, registered and recorded
                    # under (_scanner_display_name). A copy of that rule that read
                    # config.name directly yielded None for a scanner with no
                    # configured name: it was reported as a different scanner than
                    # the one queued, and sorted() below raised on the None and
                    # skipped the whole validation.
                    completed_scanner_names.append(
                        _scanner_display_name(scanner_plugin)
                    )

            # Remove duplicates and sort for consistent output
            completed_scanner_names = sorted(set(completed_scanner_names))

            ASH_LOGGER.debug(
                f"Extracted {len(completed_scanner_names)} completed scanner names: {completed_scanner_names}"
            )

            # Validate execution completion
            validation_checkpoint = (
                self.validation_manager.validate_execution_completion(
                    completed_scanner_names
                )
            )

            # Check for execution discrepancies
            missing_scanners = validation_checkpoint.get_missing_scanners()
            unexpected_scanners = validation_checkpoint.get_unexpected_scanners()

            if missing_scanners or unexpected_scanners:
                total_discrepancies = len(missing_scanners) + len(unexpected_scanners)
                ASH_LOGGER.warning(
                    f"Found {total_discrepancies} execution completion discrepancies"
                )

                # Notify about execution discrepancies via event system
                try:
                    from automated_security_helper.plugins.events import AshEventType

                    self.notify_event(
                        AshEventType.WARNING,
                        message=f"Execution completion validation found {total_discrepancies} discrepancies",
                        missing_scanners=missing_scanners,
                        unexpected_scanners=unexpected_scanners,
                        phase="scan",
                        validation_checkpoint="execution_completion_validation",
                    )
                except Exception as event_error:
                    ASH_LOGGER.debug(
                        f"Failed to notify execution completion warning event: {str(event_error)}"
                    )

                # Generate detailed execution discrepancy report
                discrepancy_report = (
                    self.validation_manager.report_execution_discrepancies(
                        validation_checkpoint
                    )
                )

                # Log detailed discrepancy information
                if missing_scanners:
                    ASH_LOGGER.warning(
                        f"Missing scanner completions ({len(missing_scanners)}): {', '.join(missing_scanners)}"
                    )
                    for scanner_name in missing_scanners:
                        scanner_state = self.validation_manager.get_scanner_state(
                            scanner_name
                        )
                        if scanner_state and scanner_state.failure_reason:
                            ASH_LOGGER.warning(
                                f"  - {scanner_name}: {scanner_state.failure_reason}"
                            )

                if unexpected_scanners:
                    ASH_LOGGER.info(
                        f"Unexpected scanner completions ({len(unexpected_scanners)}): {', '.join(unexpected_scanners)}"
                    )

                # Add discrepancy report to aggregated results for debugging.
                #
                # Assigned unconditionally. This was guarded by
                # `if not hasattr(metadata, "execution_discrepancy_report")`,
                # which could never be true: ReportMetadata DECLARES that field
                # with a default of {}, so hasattr is always True and the
                # assignment was dead code. The report would have stayed {} even
                # once report_execution_discrepancies existed again.
                #
                # Note the asymmetry with result_completeness_report below, which
                # is NOT a declared field, so its identical-looking guard did
                # fire. Restoring the two methods without this change would have
                # left one report populated and the other permanently empty.
                #
                # There is nothing to preserve by guarding: this method runs once
                # per scan and recomputes the report from the checkpoint.
                aggregated_results.metadata.execution_discrepancy_report = (
                    discrepancy_report
                )

            # Add validation results to aggregated results for debugging
            checkpoint_dict = {
                "checkpoint_name": validation_checkpoint.checkpoint_name,
                "timestamp": validation_checkpoint.timestamp.isoformat(),
                "expected_scanners": validation_checkpoint.expected_scanners,
                "actual_scanners": validation_checkpoint.actual_scanners,
                "discrepancies": validation_checkpoint.discrepancies,
                "errors": validation_checkpoint.errors,
                "metadata": validation_checkpoint.metadata,
            }
            aggregated_results.validation_checkpoints.append(checkpoint_dict)

            # Add validation summary to metadata for easy access
            if not hasattr(aggregated_results.metadata, "validation_summary"):
                aggregated_results.metadata.validation_summary = {}

            aggregated_results.metadata.validation_summary[
                "execution_completion_validation"
            ] = {
                "timestamp": validation_checkpoint.timestamp.isoformat(),
                "expected_count": len(validation_checkpoint.expected_scanners),
                "completed_count": len(validation_checkpoint.actual_scanners),
                "missing_count": len(missing_scanners),
                "unexpected_count": len(unexpected_scanners),
                "completion_rate": validation_checkpoint.metadata.get(
                    "completion_rate", 0.0
                ),
                "has_issues": validation_checkpoint.has_issues(),
            }

            # Log validation summary and notify via events
            if validation_checkpoint.has_issues():
                total_issues = len(validation_checkpoint.discrepancies) + len(
                    validation_checkpoint.errors
                )
                ASH_LOGGER.warning(
                    f"Execution completion validation completed with {total_issues} issues"
                )

                # Notify about validation issues
                try:
                    from automated_security_helper.plugins.events import AshEventType

                    self.notify_event(
                        AshEventType.WARNING,
                        message=f"Execution completion validation completed with {total_issues} issues",
                        total_issues=total_issues,
                        discrepancies=validation_checkpoint.discrepancies,
                        errors=validation_checkpoint.errors,
                        completion_rate=validation_checkpoint.metadata.get(
                            "completion_rate", 0.0
                        ),
                        phase="scan",
                        validation_checkpoint="execution_completion_validation",
                    )
                except Exception as event_error:
                    ASH_LOGGER.debug(
                        f"Failed to notify execution completion warning event: {str(event_error)}"
                    )
            else:
                completion_rate = validation_checkpoint.metadata.get(
                    "completion_rate", 0.0
                )
                ASH_LOGGER.info(
                    f"Execution completion validation passed - completion rate: {completion_rate:.1%}"
                )

                # Notify about successful validation
                try:
                    from automated_security_helper.plugins.events import AshEventType

                    self.notify_event(
                        AshEventType.INFO,
                        message=f"Execution completion validation passed with {completion_rate:.1%} completion rate",
                        expected_count=len(validation_checkpoint.expected_scanners),
                        completed_count=len(validation_checkpoint.actual_scanners),
                        completion_rate=completion_rate,
                        phase="scan",
                        validation_checkpoint="execution_completion_validation",
                    )
                except Exception as event_error:
                    ASH_LOGGER.debug(
                        f"Failed to notify execution completion info event: {str(event_error)}"
                    )

        except Exception as e:
            error_msg = f"Error during execution completion validation: {error_text(e)}"
            ASH_LOGGER.error(error_msg)

            # Notify about validation error via event system
            try:
                from automated_security_helper.plugins.events import AshEventType

                self.notify_event(
                    AshEventType.ERROR,
                    message=error_msg,
                    exception=error_text(e),
                    phase="scan",
                    validation_checkpoint="execution_completion_validation",
                )
            except Exception as event_error:
                ASH_LOGGER.debug(
                    f"Failed to notify execution completion error event: {str(event_error)}"
                )

            # Ensure scan continues despite validation error
            ASH_LOGGER.info(
                "🔄 Execution completion validation failed but scan will continue"
            )

            # Add stack trace for debugging
            ASH_LOGGER.debug(
                f"Execution completion validation error stack trace: {traceback_text()}"
            )

    def _record_scan_phase_completed(
        self, aggregated_results: AshAggregatedResults
    ) -> None:
        """Append the marker ``scan_phase_completed`` reads, in the checkpoint shape.

        The orchestrator used to read the completeness checkpoint as this
        record. That checkpoint is appended inside ``_validate_result_completeness``'s
        try, whose except logs "scan will continue" and returns: a completeness
        pass that raised (``ensure_complete_results``, the report, a state read)
        left the phase returning normally with no marker, and the orchestrator
        then treated a completed scan as incomplete and wrote no results file
        after a later phase's failure. The marker is written here, after that
        pass has returned, whatever it did.
        """
        aggregated_results.validation_checkpoints.append(
            {
                "checkpoint_name": SCAN_PHASE_COMPLETION_CHECKPOINT,
                "timestamp": datetime.now().isoformat(),
                "expected_scanners": [],
                "actual_scanners": [],
                "discrepancies": [],
                "errors": [],
                "metadata": {"phase": "scan"},
            }
        )

    def _validate_result_completeness(
        self, aggregated_results: AshAggregatedResults
    ) -> None:
        """Validate result completeness before finalizing scan results.

        This method ensures all originally registered scanners appear in the final
        aggregated results. Missing scanners are added with appropriate status and
        failure reasons to provide complete visibility into scan coverage.

        Args:
            aggregated_results: The aggregated scan results to validate and potentially modify
        """
        try:
            ASH_LOGGER.info("Validating result completeness...")

            # The rows that were there before, so what the call added can be told
            # from what it only listed.
            rows_before = set(aggregated_results.scanner_results or {})

            # Call the validation manager to ensure complete results
            validation_checkpoint = self.validation_manager.ensure_complete_results(
                aggregated_results
            )

            # Extract validation results for reporting
            missing_scanners = validation_checkpoint.get_missing_scanners()
            unexpected_scanners = validation_checkpoint.get_unexpected_scanners()
            # ensure_complete_results lists every scanner that had no result, and
            # adds an entry only for one that was not deliberately excluded. Said
            # as "added" for all of them, a scanner left out of this run was
            # reported as one the validation had to supply.
            rows_after = set(aggregated_results.scanner_results or {})
            added_scanners = [
                name
                for name in missing_scanners
                if name in rows_after and name not in rows_before
            ]
            left_out_scanners = [
                name for name in missing_scanners if name not in added_scanners
            ]

            # Report validation results
            if missing_scanners or unexpected_scanners:
                total_adjustments = len(added_scanners) + len(unexpected_scanners)
                if total_adjustments:
                    ASH_LOGGER.info(
                        f"Result completeness validation made {total_adjustments} adjustments"
                    )

                    # Notify about result completeness adjustments via event system
                    try:
                        from automated_security_helper.plugins.events import (
                            AshEventType,
                        )

                        self.notify_event(
                            AshEventType.INFO,
                            message=f"Result completeness validation made {total_adjustments} adjustments",
                            missing_scanners=missing_scanners,
                            added_scanners=added_scanners,
                            unexpected_scanners=unexpected_scanners,
                            total_adjustments=total_adjustments,
                            phase="scan",
                            validation_checkpoint="result_completeness_validation",
                        )
                    except Exception as event_error:
                        ASH_LOGGER.debug(
                            f"Failed to notify result completeness info event: {str(event_error)}"
                        )

                # Generate detailed result completeness report
                completeness_report = (
                    self.validation_manager.report_result_completeness(
                        validation_checkpoint
                    )
                )

                # Log detailed adjustment information
                if added_scanners:
                    ASH_LOGGER.info(
                        f"Added missing scanners ({len(added_scanners)}): {', '.join(added_scanners)}"
                    )
                    for scanner_name in added_scanners:
                        scanner_state = self.validation_manager.get_scanner_state(
                            scanner_name
                        )
                        if scanner_state and scanner_state.failure_reason:
                            ASH_LOGGER.info(
                                f"  - {scanner_name}: {scanner_state.failure_reason}"
                            )
                if left_out_scanners:
                    ASH_LOGGER.debug(
                        "Scanners with no result that were left out, not added "
                        f"({len(left_out_scanners)}): {', '.join(left_out_scanners)}"
                    )

                if unexpected_scanners:
                    ASH_LOGGER.info(
                        f"Found unexpected scanners ({len(unexpected_scanners)}): {', '.join(unexpected_scanners)}"
                    )

                # Add completeness report to aggregated results for debugging.
                #
                # Also unconditional, for the same reason and for symmetry with
                # the execution report above. This guard did fire today, because
                # result_completeness_report is not a declared field on
                # ReportMetadata -- but relying on that is relying on the absence
                # of a field declaration, which the next person to add one would
                # silently break. Same one-run-per-scan argument applies.
                setattr(
                    aggregated_results.metadata,
                    "result_completeness_report",
                    completeness_report,
                )

            # Add validation results to aggregated results for debugging
            checkpoint_dict = {
                "checkpoint_name": validation_checkpoint.checkpoint_name,
                "timestamp": validation_checkpoint.timestamp.isoformat(),
                "expected_scanners": validation_checkpoint.expected_scanners,
                "actual_scanners": validation_checkpoint.actual_scanners,
                "discrepancies": validation_checkpoint.discrepancies,
                "errors": validation_checkpoint.errors,
                "metadata": validation_checkpoint.metadata,
            }
            aggregated_results.validation_checkpoints.append(checkpoint_dict)

            # Add validation summary to metadata for easy access
            if not hasattr(aggregated_results.metadata, "validation_summary"):
                aggregated_results.metadata.validation_summary = {}

            aggregated_results.metadata.validation_summary[
                "result_completeness_validation"
            ] = {
                "timestamp": validation_checkpoint.timestamp.isoformat(),
                "expected_count": len(validation_checkpoint.expected_scanners),
                "final_count": len(validation_checkpoint.actual_scanners),
                "missing_count": len(missing_scanners),
                "unexpected_count": len(unexpected_scanners),
                "completeness_rate": validation_checkpoint.metadata.get(
                    "completeness_rate", 0.0
                ),
                "has_issues": validation_checkpoint.has_issues(),
            }

            # Log validation summary and notify via events
            if validation_checkpoint.has_issues():
                total_issues = len(validation_checkpoint.discrepancies) + len(
                    validation_checkpoint.errors
                )
                ASH_LOGGER.warning(
                    f"Result completeness validation completed with {total_issues} issues"
                )

                # Notify about validation issues
                try:
                    from automated_security_helper.plugins.events import AshEventType

                    self.notify_event(
                        AshEventType.WARNING,
                        message=f"Result completeness validation completed with {total_issues} issues",
                        total_issues=total_issues,
                        discrepancies=validation_checkpoint.discrepancies,
                        errors=validation_checkpoint.errors,
                        completeness_rate=validation_checkpoint.metadata.get(
                            "completeness_rate", 0.0
                        ),
                        phase="scan",
                        validation_checkpoint="result_completeness_validation",
                    )
                except Exception as event_error:
                    ASH_LOGGER.debug(
                        f"Failed to notify result completeness warning event: {str(event_error)}"
                    )
            else:
                completeness_rate = validation_checkpoint.metadata.get(
                    "completeness_rate", 0.0
                )
                ASH_LOGGER.info(
                    f"Result completeness validation passed - completeness rate: {completeness_rate:.1%}"
                )

                # Notify about successful validation
                try:
                    from automated_security_helper.plugins.events import AshEventType

                    self.notify_event(
                        AshEventType.INFO,
                        message=f"Result completeness validation passed with {completeness_rate:.1%} completeness rate",
                        expected_count=len(validation_checkpoint.expected_scanners),
                        final_count=len(validation_checkpoint.actual_scanners),
                        completeness_rate=completeness_rate,
                        phase="scan",
                        validation_checkpoint="result_completeness_validation",
                    )
                except Exception as event_error:
                    ASH_LOGGER.debug(
                        f"Failed to notify result completeness info event: {str(event_error)}"
                    )

        except Exception as e:
            error_msg = f"Error during result completeness validation: {error_text(e)}"
            ASH_LOGGER.error(error_msg)

            # Notify about validation error via event system
            try:
                from automated_security_helper.plugins.events import AshEventType

                self.notify_event(
                    AshEventType.ERROR,
                    message=error_msg,
                    exception=error_text(e),
                    phase="scan",
                    validation_checkpoint="result_completeness_validation",
                )
            except Exception as event_error:
                ASH_LOGGER.debug(
                    f"Failed to notify result completeness error event: {str(event_error)}"
                )

            # Ensure scan continues despite validation error
            ASH_LOGGER.info(
                "🔄 Result completeness validation failed but scan will continue"
            )

            # Add stack trace for debugging
            ASH_LOGGER.debug(
                f"Result completeness validation error stack trace: {traceback_text()}"
            )

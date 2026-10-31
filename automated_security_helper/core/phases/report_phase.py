"""Implementation of the Report phase."""

import os
from pathlib import Path
from typing import (
    Any,
    Callable,
    Collection,
    Dict,
    Iterable,
    List,
    Optional,
    Sequence,
    Set,
    Tuple,
    cast,
)
from automated_security_helper.base.engine_phase import EnginePhase
from automated_security_helper.base.plugin_config import plugin_config_key
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.reporter_plugin import (
    confined_report_path,
    enabled_value_kind,
    off_host_reporter_refused,
    reporter_companion_file_names,
    reporter_file_name,
    reporter_file_names,
    reporter_format_name,
    reporter_matches_requested_formats,
    warn_off_host_section_without_enabled,
)
from automated_security_helper.config.operator_only_options import reporter_section
from automated_security_helper.core.cancellation import (
    ScanCancelled,
    raise_if_cancelled,
)
from automated_security_helper.core.enums import ExecutionPhase
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.utils.atomic_write import write_text_atomically
from automated_security_helper.utils.error_text import (
    config_environment_values,
    error_text,
    traceback_text,
)
from automated_security_helper.utils.inner_run_outcome import record_reports_written
from automated_security_helper.utils.log import ASH_LOGGER, NO_MARKUP, escape_markup
from automated_security_helper.utils.redacted_model import without_env_scalars
from automated_security_helper.utils.report_path_links import (
    ensure_reports_dir,
    refuse_colliding_report_names,
    refuse_linked_report_paths,
    refuse_report_names_outside,
)
from automated_security_helper.utils.secret_masking import mask_secrets_in_results
from automated_security_helper.utils.undecodable_text import recorded

#: The reporter for this format is switched off in configuration. This is the
#: common case and the one an operator can fix in a line: ``yaml`` and ``spdx``
#: both ship ``enabled: bool = False``, so asking for either produces nothing
#: until the config says otherwise. Verified by measurement rather than inferred
#: -- enabling each one produces ``ash.yaml`` and ``ash.spdx.json`` respectively.
FORMAT_REPORTER_DISABLED = "reporter-disabled"

#: The reporter's own dependency check refused. Distinct from
#: :data:`FORMAT_REPORTER_DISABLED` because it sends the operator somewhere
#: entirely different -- to credentials, a network, or an install -- rather than
#: to the config file. Conflating the two told an operator with no AWS credentials
#: that they had disabled a reporter they had never touched.
FORMAT_REPORTER_DEPENDENCIES = "reporter-dependencies-unsatisfied"

#: ``--python-based-plugins-only`` excluded the reporter. Its own category because
#: the fix is to drop that flag, not to change any configuration or install
#: anything -- the reporter is enabled and its dependencies are fine.
FORMAT_REPORTER_NOT_PYTHON = "reporter-non-python-excluded"

#: No reporter in this run produces this format. ``ExportFormat`` carries members
#: that name no reporter -- ``aggregated`` and ``dict`` are internal result shapes
#: rather than report formats, ``asff`` is the Security Hub reporter's payload but
#: that reporter is named ``aws-security-hub``, and ``custom`` is a placeholder --
#: and members naming the AWS reporters, which exist only when
#: ``ash_plugin_modules`` loads their module. ``--output-formats`` and the config's
#: ``output_formats`` accept all of them, and only this check tells the operator
#: that asking for one produces nothing.
FORMAT_NO_REPORTER = "no-reporter"

#: A reporter for this format exists but could not be created, so there is no
#: instance to ask why it is not run. Its own cause, because telling the
#: operator that no reporter has the format (and to load a plugin module they
#: have already loaded) sent them away from the "Error creating reporter" line
#: that names the real problem.
FORMAT_REPORTER_FAILED = "reporter-failed-to-build"

#: The reporter exists and is enabled, but it could not name the files it writes,
#: so the phase left it out before any reporter ran. Its own cause: the line the
#: phase logged for it names the reporter and says why, and sending the operator
#: to credentials and a network (the dependency reason) was the wrong place.
FORMAT_REPORTER_FILES_UNNAMED = "reporter-files-unnamed"

#: What to tell the operator for each cause, and where to send them. Keyed by
#: reason so that adding a reason without a message is a ``KeyError`` at the point
#: of logging rather than a diagnosis that silently prints nothing -- the failure
#: mode this whole module exists to prevent.
_FORMAT_REASON_MESSAGES = {
    FORMAT_REPORTER_DISABLED: (
        "its reporter is disabled in the configuration. Set "
        "'reporters.{fmt}.enabled: true' in the ASH config, or pass "
        "--config-overrides reporters.{fmt}.enabled=true, to get this report. "
        "A reporter that sends findings off the host is turned on only by the "
        "operator's own config or by --config-overrides: a config file inside "
        "the scanned repository does not count."
    ),
    FORMAT_REPORTER_FAILED: (
        "its reporter could not be created. The 'Error creating reporter' line "
        "above names the reporter and says why."
    ),
    FORMAT_REPORTER_FILES_UNNAMED: (
        "its reporter could not name the files it writes, so it was not run. The "
        "'is not run: it could not name the files it writes' line above names the "
        "reporter and says why."
    ),
    FORMAT_REPORTER_DEPENDENCIES: (
        "its reporter's dependencies are not satisfied. It is enabled, but its "
        "own dependency check refused -- typically missing credentials, no "
        "network, or an uninstalled tool. Check that reporter's requirements."
    ),
    FORMAT_REPORTER_NOT_PYTHON: (
        "--python-based-plugins-only excluded its reporter, which has non-Python "
        "dependencies. Drop that flag to get this report."
    ),
    # Worded for either source of the list: --output-formats or the config's
    # output_formats.
    FORMAT_NO_REPORTER: (
        "no reporter produces it in this run. The name is a valid output format, "
        "but no loaded reporter has it. A reporter from a plugin module, such as "
        "the AWS reporters, is loaded only when ash_plugin_modules lists that "
        "module."
    ),
}


def _entries_under(directory: Path) -> Optional[set]:
    """Every path under ``directory``, files and directories, as a set, or None
    when the listing did not complete.

    For the report phase's cancel cleanup: what the reports directory held
    before the reporters ran, and what it holds after. An absent directory is
    an empty set. A listing that raised part way (``exists`` or the walk) is
    None, never a partial set: the cleanup removes what appeared since the
    baseline, and a partial baseline would make pre-existing entries (an
    earlier run's reports kept by ``--use-existing``) look new and be removed.
    ``rglob`` does not descend into a linked directory, so nothing outside the
    directory is ever listed, or later removed.
    """
    entries: set = set()
    try:
        if not directory.exists():
            return entries
        for path in directory.rglob("*"):
            entries.add(path)
    except OSError as e:
        ASH_LOGGER.debug(f"Could not finish listing {directory}: {e}")
        return None
    return entries


def _excluded_reporter_reason(
    instance: object, python_only: bool, off_host_refused: bool = False
) -> str:
    """Why ``filter_enabled_plugins`` dropped this reporter.

    *off_host_refused*: the phase held this reporter back before the filter
    because it sends findings off the host and its section does not set
    ``enabled: true``. It never reached the filter, and when its config could
    not be set disabled (``_disable``) it still reads as enabled, so without
    this it fell through to the dependency reason, which sent the operator to
    credentials instead of to the setting that turns it on.

    Determined by elimination rather than by re-running the checks, and the order
    matters. ``validate_plugin_dependencies`` performs IO for some reporters --
    ``SecurityHubReporter`` and ``BedrockSummaryReporter`` call AWS inside it -- so
    calling it a second time here would put a duplicate live API round trip on
    every scan that names an unproducible format. The two cheap, side-effect-free
    conditions are therefore tested first, and anything left over is attributed to
    the dependency check, which is the only remaining reason
    ``filter_enabled_plugins`` drops an instance.

    Attributing the remainder by elimination also covers the case where the
    dependency check *raised*: ``filter_enabled_plugins`` swallows the exception
    and skips the reporter, and "dependencies are not satisfied" is the honest
    thing to tell an operator about a check that blew up.
    """
    config = getattr(instance, "config", None)
    if off_host_refused:
        return FORMAT_REPORTER_DISABLED
    # Any falsy value, as filter_enabled_plugins drops on (``not enabled``), and
    # not only an explicit False: a plugin config that allows None or 0 for the
    # flag was dropped as disabled and reported as having unsatisfied dependencies.
    if config is not None and not getattr(config, "enabled", True):
        return FORMAT_REPORTER_DISABLED
    if python_only:
        try:
            if not instance.is_python_only():
                return FORMAT_REPORTER_NOT_PYTHON
        except Exception as e:  # noqa: BLE001 -- a broken check must not break reporting
            # Falling through to FORMAT_REPORTER_DEPENDENCIES is the documented
            # attribution-by-elimination described above, so no control flow
            # changes here. The exception is logged because otherwise a reporter
            # with a broken is_python_only() is silently reattributed to a
            # dependency problem it does not have.
            ASH_LOGGER.debug(
                f"{type(instance).__name__}.is_python_only() raised {e!r}; "
                "attributing the exclusion to unsatisfied dependencies"
            )
    return FORMAT_REPORTER_DEPENDENCIES


def unsatisfied_output_formats(
    output_formats: Iterable[object],
    selected_instances: Sequence[object],
    all_instances: Sequence[object],
    python_based_plugins_only: bool = False,
    off_host_refused: Collection[int] = (),
    failed_to_build: Collection[str] = (),
    files_unnamed: Collection[int] = (),
) -> Dict[str, str]:
    """Requested formats that will produce no report, and why.

    Why this exists
    ---------------
    ``--output-formats`` is validated against ``ExportFormat`` at the CLI, so a
    typo fails loudly. What did *not* fail loudly was naming a perfectly valid
    format that no reporter would answer: the run selected zero reporters, wrote
    nothing, and exited 0. An empty ``reports/`` directory was the operator's only
    signal, and the closing scan summary still pointed at report paths that were
    never written. Silence was the defect; the mismatched comparison in
    :func:`~automated_security_helper.base.reporter_plugin.reporter_matches_requested_formats`
    was merely its most common cause.

    Every cause is reported as its own reason, and that granularity is the point.
    Collapsing them would tell an operator who asked for ``yaml`` -- which ships
    ``enabled: False`` -- that ASH cannot produce yaml, when in fact one line of
    config fixes it. The four reasons send the operator to four different places:
    the config file, their credentials or install, the flag they passed, or nowhere
    because nothing can produce that format.

    Args:
        output_formats: What the operator asked for. Empty yields an empty result:
            no explicit request means nothing was asked for and denied.
        selected_instances: Reporters that survived every filter and will run.
        all_instances: Every reporter that could be constructed, before the
            enabled/dependency/python-only filters. Supplies both the evidence that
            a format's reporter exists and the instance whose state names the cause.
        python_based_plugins_only: Whether ``--python-based-plugins-only`` was
            passed. Needed to tell a reporter excluded by that flag from one whose
            dependencies are genuinely unsatisfied.
        off_host_refused: ``id()`` of each instance the phase held back because it
            sends findings off the host and its section does not enable it.
        failed_to_build: The names of the reporters that could not be created, so
            a requested format of one is told apart from a format no reporter has.
        files_unnamed: ``id()`` of each enabled instance the phase left out because
            it could not name the files it writes.

    Returns:
        Format name -> the reason it will produce nothing, one of the
        ``FORMAT_*`` constants. Empty when every requested format will be produced,
        which is the normal case.
    """
    requested = [str(getattr(fmt, "value", fmt)) for fmt in output_formats or []]
    if not requested:
        return {}

    selected_names = {
        str(name)
        for name in (reporter_format_name(inst) for inst in selected_instances)
        if name is not None
    }
    # Keyed by name so the reason can be read off the excluded instance itself
    # rather than guessed from the format string.
    known_by_name = {
        str(reporter_format_name(inst)): inst
        for inst in all_instances
        if reporter_format_name(inst) is not None
    }

    unsatisfied: Dict[str, str] = {}
    for fmt in requested:
        if fmt in selected_names:
            continue
        instance = known_by_name.get(fmt)
        if instance is not None and id(instance) in files_unnamed:
            unsatisfied[fmt] = FORMAT_REPORTER_FILES_UNNAMED
        elif instance is not None:
            unsatisfied[fmt] = _excluded_reporter_reason(
                instance, python_based_plugins_only, id(instance) in off_host_refused
            )
        elif fmt in failed_to_build:
            unsatisfied[fmt] = FORMAT_REPORTER_FAILED
        else:
            unsatisfied[fmt] = FORMAT_NO_REPORTER
    return unsatisfied


def _log_unsatisfied_output_formats(unsatisfied: Dict[str, str]) -> None:
    """Tell the operator, once per format, that a requested format produces nothing.

    Logged at ERROR, not WARNING, and the reason is ``--quiet``. ``--quiet`` maps
    the console to ERROR level, and it is what CI uses -- so at WARNING these
    messages reached ``ash.log`` and nothing else. A CI job that asked for
    ``markdown`` and expects to upload ``reports/ash.summary.md`` would get an
    empty directory and a clean console, which is the exact silence this diagnosis
    exists to break. ERROR is a statement about the operator's request not being
    honoured, and it does not change the exit code: that stays a verdict about the
    code under scan.

    Not raised, either. A run asked for ``markdown,asff`` must still write the
    markdown report; failing the whole scan over one unproducible format would cost
    the operator every other report and, for ``ash scan``, the findings verdict
    along with it.
    """
    for fmt, reason in sorted(unsatisfied.items()):
        detail = _FORMAT_REASON_MESSAGES[reason].format(fmt=fmt)
        ASH_LOGGER.error(
            f"No report will be written for requested format '{fmt}': {detail}"
        )


def _warn_if_configured_but_not_enabled(
    plugin_instance, plugin_config, output_formats
) -> None:
    """Warn when an off-host reporter has a config section that does not enable it.

    An off-host reporter runs only when its section sets ``enabled: true``
    (``off_host_reporter_refused``). A section that sets its options and leaves
    ``enabled`` out, or gives it a value that is not the boolean ``true`` (a
    quoted ``"true"``, say), reads as wanting it to run, and the reporter
    shipping enabled once made that true; so the skip is said once at WARNING,
    with the type ``enabled`` is set to (not its value, which a config file can
    read from the environment). No section, an empty one, ``enabled:
    false``, or requested formats that leave the reporter out (it would not run
    whatever its section said) are skipped quietly.
    """
    if not isinstance(plugin_config, dict) or not plugin_config:
        return
    # The section is an external plugin's, which the segment models keep as an
    # extra and never validate, so a value a config file read from the
    # environment is still the resolver's marker here. Read through the
    # downcast view: the type this warning names is the one the file gave (a
    # str), never the marker class (utils/redacted_model.EnvResolvedScalar).
    plugin_config = without_env_scalars(plugin_config)
    if plugin_config.get("enabled") is False:
        return
    if not reporter_matches_requested_formats(plugin_instance, output_formats):
        return
    # The key its section is read under, which the remedy names.
    name = plugin_config_key(type(plugin_instance))
    if "enabled" not in plugin_config:
        # The shared voice (base/reporter_plugin.py): once per process, since a
        # workspace's projects each read the same section, naming the key that
        # turns the reporter on and the override that sets it.
        warn_off_host_section_without_enabled(type(plugin_instance), plugin_config)
        return
    # The value's type, never the value: a config file can read it from the
    # environment.
    value = plugin_config["enabled"]
    kind = enabled_value_kind(value)
    ASH_LOGGER.warning(
        f"Reporter '{name}' sends findings off the host and is not run: its config "
        f"section sets enabled to {kind}, and only the boolean true turns it on "
        f"(reporters.{name}.enabled). To run it, set reporters.{name}.enabled: true "
        f"in the operator's config, or pass --config-overrides "
        f"reporters.{name}.enabled=true.",
        extra=NO_MARKUP,
    )


def _disable(plugin_instance) -> bool:
    """Set a reporter's config to disabled; False when its config cannot be set."""
    config = getattr(plugin_instance, "config", None)
    if config is None or not hasattr(config, "enabled"):
        return False
    try:
        config.enabled = False
    except (AttributeError, TypeError, ValueError):
        return False
    return getattr(config, "enabled", None) is False


class ReportPhase(EnginePhase):
    """Implementation of the Report phase."""

    def __init__(
        self,
        plugin_context: PluginContext,
        plugins: Optional[Sequence[type]] = None,
        progress_display: Optional[Any] = None,
        asharp_model: Optional[AshAggregatedResults] = None,
        plugin_filter: Optional[Callable[[Any], bool]] = None,
    ) -> None:
        # ``plugins`` is the list of reporter CLASSES to run, and given none the
        # phase runs none. A scan's engine hands it the reporters of the run's
        # own plugin modules (plugin_modules, filtered by plugins_of), and
        # `ash merge` the ones reporter_classes_for_run gives it; the phase
        # never reads the process-wide registry for them. EnginePhase types
        # ``plugins`` as plugin instances, which no caller passes, so the list
        # is cast where it is handed over.
        super().__init__(
            plugin_context=plugin_context,
            plugins=cast(Any, plugins),
            progress_display=progress_display,
            asharp_model=asharp_model,
            plugin_filter=plugin_filter,
        )

    @property
    def phase_name(self) -> str:
        """Return the name of this phase."""
        return "report"

    def _reporters_that_name_their_files(self, reporters: List[object]) -> List[object]:
        """*reporters* without the ones whose file names cannot be read.

        A reporter declares the files it writes (``companion_file_names``), and
        the phase reads every declaration before any reporter runs. That method
        is plugin code: one that raises aborted the phase before a single report
        was written. The reporter is logged and left out instead.
        """
        values = config_environment_values(getattr(self.plugin_context, "config", None))
        kept: List[object] = []
        for plugin_instance in reporters:
            try:
                reporter_file_names(plugin_instance)
            except Exception as e:  # noqa: BLE001 -- plugin-supplied declaration
                ASH_LOGGER.error(
                    f"Reporter {type(plugin_instance).__name__} is not run: it could "
                    f"not name the files it writes: {error_text(e, values)}",
                    extra=NO_MARKUP,
                )
                continue
            kept.append(plugin_instance)
        return kept

    @staticmethod
    def _warn_if_an_earlier_report_remains(
        report_dir: Path,
        plugin_instance: object,
        display_name: str,
        written: Collection[str] = (),
    ) -> None:
        """Say so when a reporter wrote nothing and an earlier run's file is there.

        A reporter that raised, returned None or returned an empty report wrote
        no file, and ``reports/`` can still hold the file an earlier run of it
        wrote (a report over existing results keeps the directory). That file is
        not this run's report, and nothing else said so. It is left in place: it
        may be the only copy. Never raises.

        *written* names the report files this run has written. A reporter that
        raised after its own file was written (in the progress update that follows
        the write, say) left this run's file there, and it is not from an earlier
        run.
        """
        try:
            file_name = reporter_file_name(plugin_instance)
            if file_name in written:
                return
            earlier = confined_report_path(report_dir, file_name)
            if earlier is not None and os.path.lexists(earlier):
                ASH_LOGGER.warning(
                    f"Reporter {display_name} wrote no report this run; "
                    f"{earlier.name} in {report_dir} is from an earlier run.",
                    extra=NO_MARKUP,
                )
        except Exception as e:  # noqa: BLE001 -- a notice must not fail the phase
            ASH_LOGGER.debug(f"Could not look for an earlier report: {e}")

    def _execute_phase(
        self,
        report_dir: Path,
        aggregated_results: AshAggregatedResults,
        cli_output_formats=None,
        python_based_plugins_only: bool = False,
        **kwargs,
    ) -> AshAggregatedResults:
        """Execute the Report phase.

        All or nothing for a cancelled scan. The phase checks for a cancel before
        each reporter and before writing what one returned, and a cancel that
        stops it removes every report it had written: the engine checks only
        between phases, so a cancel_scan landing here let every reporter write,
        and a scan with no previous results set aside kept those reports. The
        files this phase wrote, by path, are removed, and so is every other
        entry that appeared under the reports directory while it ran (a
        reporter's own companion files and directories), compared against a
        listing taken before the reporters ran; when that listing did not
        complete, only the files this phase wrote go. The reports directory
        goes with them if this phase created it and nothing else is in it. The
        previous results, where they were set aside, are put back by whoever
        settles them (core/previous_results.py).

        Args:
            report_dir(Path): The directory to save reports to.
            cli_output_formats: Output formats specified via CLI, which override config
            **kwargs: Additional arguments
        """
        self._written_reports: List[Path] = []
        # What the reporters that send findings off the host left in the reports
        # directory. Not removed by a cancel: what they sent has left the host,
        # and these files are the local record of it.
        self._off_host_records: Set[Path] = set()
        created_report_dir = not report_dir.exists()
        # What the reports directory held before any reporter ran. A reporter
        # can write a file of its own beside the one this phase writes for it
        # (the unused-suppressions reporter's markdown), under a name this phase
        # never learns, so by-path removal of what it wrote left those behind
        # and, with them, the directory. Everything new is removed instead.
        self._report_dir_before = _entries_under(report_dir)
        try:
            return self._write_reports(
                report_dir=report_dir,
                aggregated_results=aggregated_results,
                cli_output_formats=cli_output_formats,
                python_based_plugins_only=python_based_plugins_only,
                **kwargs,
            )
        except ScanCancelled:
            self._remove_written_reports(report_dir, created_report_dir)
            raise

    def _remove_written_reports(self, report_dir: Path, created: bool) -> None:
        """Remove the reports this phase wrote, and every other entry that appeared
        under the reports directory while it ran. Never raises: a cancel is
        propagating."""
        for path in self._written_reports:
            try:
                path.unlink(missing_ok=True)
            except OSError as e:
                ASH_LOGGER.error(
                    f"Could not remove {path}, written before the scan was cancelled: {e}"
                )
        # A reporter's own companion files, and any directory it made. Files
        # first, then directories deepest first, so each is empty when its turn
        # comes. A link is removed as a link, never followed. Only against a
        # baseline that completed: with none (the before-listing raised, or a
        # caller ran this without taking one) nothing new can be told from
        # what was there, and pre-existing entries stay. The files the
        # off-host reporters left are the record of what they sent, and stay.
        kept = getattr(self, "_off_host_records", set())
        before = getattr(self, "_report_dir_before", None)
        after = _entries_under(report_dir) if before is not None else None
        appeared = (
            [path for path in after if path not in before and path not in kept]
            if after is not None
            else []
        )
        if before is None:
            ASH_LOGGER.debug(
                f"The listing of {report_dir} before the reporters ran did not "
                f"complete; only the reports this phase wrote are removed"
            )
        for path in sorted(appeared, key=lambda p: len(p.parts), reverse=True):
            try:
                if path.is_dir() and not path.is_symlink():
                    path.rmdir()
                else:
                    path.unlink(missing_ok=True)
            except OSError as e:
                ASH_LOGGER.error(
                    f"Could not remove {path}, written by a reporter before the scan "
                    f"was cancelled: {e}"
                )
        if created:
            try:
                report_dir.rmdir()
            except OSError:
                pass  # not empty, or already gone: left as it is
        if self._written_reports or appeared:
            ASH_LOGGER.info(
                f"The scan was cancelled during the report phase; removed the "
                f"{len(self._written_reports)} report(s) it had written and "
                f"{len(appeared)} other entr{'y' if len(appeared) == 1 else 'ies'} "
                f"that appeared under {report_dir} while it ran"
            )
        if kept:
            ASH_LOGGER.info(
                f"Kept {len(kept)} file(s) from the reporters that send findings "
                "off the host: what they sent had already left, and these are the "
                "record of it"
            )

    def _write_reports(
        self,
        report_dir: Path,
        aggregated_results: AshAggregatedResults,
        cli_output_formats=None,
        python_based_plugins_only: bool = False,
        **kwargs,
    ) -> AshAggregatedResults:
        """The phase itself; _execute_phase removes what it wrote if it is cancelled."""
        ASH_LOGGER.debug("Entering: ReportPhase._execute_phase()")
        ensure_reports_dir(report_dir)

        # Every reporter reads the same results, so the secret values findings
        # expose are masked once, here, before any of them runs; see
        # utils/secret_masking.py.
        mask_secrets_in_results(aggregated_results)

        # Every reporter reads these results field by field, so a file name set on
        # one after it was validated is read in the record form
        # (utils/undecodable_text.py). Re-bound, not forked: the reporters, this
        # phase's summary and the run after it (which takes what this returns) all
        # use the same object, which is the one given when there is no such name.
        aggregated_results = recorded(aggregated_results)
        self.asharp_model = aggregated_results
        ASH_LOGGER.info("Preparing report data...")

        # Get output formats from config
        output_formats = getattr(self.plugin_context.config, "output_formats", [])

        # If CLI output formats are provided, they override the config
        if cli_output_formats:
            output_formats = cli_output_formats
            ASH_LOGGER.info(f"Using CLI-specified output formats: {output_formats}")
        elif output_formats:
            ASH_LOGGER.info(
                "Using the output formats from the configuration: "
                f"{[str(getattr(fmt, 'value', fmt)) for fmt in output_formats]}"
            )

        # Create a list of reporter classes
        reporter_classes = self.plugins

        # Create all reporter instances upfront, then filter via the shared helper.
        all_reporter_instances = []
        # A reporter that sends findings off the host and whose config section
        # does not set enabled: true is disabled, whatever its own default: the
        # shared filter below then drops it as disabled, before any dependency
        # check, and a requested format it would have satisfied is reported as
        # disabled, not missing. Only an instance whose config cannot be set
        # disabled is held back here instead.
        off_host_refused = set()
        # The names of the reporters that could not be created, so a requested
        # format of one is not diagnosed as a format no reporter has.
        failed_to_build: Set[str] = set()
        for plugin_class in reporter_classes:
            try:
                # An off-host reporter's section comes from the operator's
                # configuration when the scanned repository wrote this one
                # (config/operator_only_options.reporter_section). Inside the
                # try, as the construction is: a lookup that raises is logged
                # and skips this one reporter, instead of escaping the loop
                # and aborting every report.
                plugin_config = reporter_section(
                    self.plugin_context.config, plugin_class
                )
                # Decided before the reporter is built: a refused reporter is
                # built turned off, so an enabled value its own model would
                # refuse (null, a list, a string) is said once, at WARNING,
                # not logged as its model's error.
                refused = off_host_reporter_refused(plugin_class, plugin_config)
                build_config = plugin_config
                if refused and isinstance(plugin_config, dict):
                    build_config = {**plugin_config, "enabled": False}
                plugin_instance = plugin_class(
                    context=self.plugin_context,
                    config=build_config,
                )
            except Exception as e:
                # Logged as written (NO_MARKUP): the text names the reporter's
                # fields. Redacted with the config's environment values: the
                # exception can name a configured option, and error_text alone
                # only replaces a ValidationError's refused inputs.
                ASH_LOGGER.error(
                    f"Error creating reporter {getattr(plugin_class, '__name__', 'Unknown')}: "
                    f"{error_text(e, config_environment_values(getattr(self.plugin_context, 'config', None)))}",
                    extra=NO_MARKUP,
                )
                try:
                    failed_to_build.add(plugin_config_key(plugin_class))
                except Exception:  # noqa: BLE001 -- a class with no readable name
                    pass
                continue
            all_reporter_instances.append(plugin_instance)
            if refused:
                _warn_if_configured_but_not_enabled(
                    plugin_instance, plugin_config, output_formats
                )
                if not _disable(plugin_instance):
                    off_host_refused.add(id(plugin_instance))

        # The format filter runs first, then the enabled/python/dependency check
        # on what is left. A reporter's dependency check can contact a remote
        # service (Security Hub calls DescribeHub, the other AWS reporters STS),
        # so it runs only for the reporters this run will use: `-f sarif` checks
        # nothing else.
        #
        # Matched on the reporter's configured name, not on its extension. The
        # extension is a filename suffix and the requested formats are format
        # names; comparing them matched only the four reporters where the two
        # strings coincide and silently skipped the rest. See
        # reporter_matches_requested_formats for the full account and for why
        # renaming the extensions instead was rejected.
        def _display_name(plugin_instance) -> str:
            name = getattr(getattr(plugin_instance, "config", None), "name", None)
            return name or plugin_instance.__class__.__name__

        requested_reporters: List[object] = []
        for plugin_instance in all_reporter_instances:
            if id(plugin_instance) in off_host_refused:
                ASH_LOGGER.debug(
                    f"Reporter {_display_name(plugin_instance)} sends findings off "
                    "the host and its config does not enable it, skipping"
                )
                continue
            if not reporter_matches_requested_formats(plugin_instance, output_formats):
                ASH_LOGGER.debug(
                    f"Reporter {_display_name(plugin_instance)} format "
                    f"'{reporter_format_name(plugin_instance)}' not in requested "
                    f"formats {output_formats}, skipping"
                )
                continue
            requested_reporters.append(plugin_instance)

        enabled_reporters: List[object] = self.filter_enabled_plugins(
            plugin_instances=requested_reporters,
            plugin_context=self.plugin_context,
            python_only=python_based_plugins_only,
        )
        # Every file name a reporter declares is read below, for the link and
        # collision checks, before any reporter runs. One whose declaration raises
        # is left out here, with its own error, so it cannot abort the phase and
        # take every other report with it.
        named_reporters = self._reporters_that_name_their_files(enabled_reporters)
        kept_ids = {id(plugin_instance) for plugin_instance in named_reporters}
        files_unnamed = {
            id(plugin_instance)
            for plugin_instance in enabled_reporters
            if id(plugin_instance) not in kept_ids
        }
        enabled_reporters = named_reporters
        enabled_reporter_names = [
            _display_name(plugin_instance) for plugin_instance in enabled_reporters
        ]

        ASH_LOGGER.verbose(
            f"Prepared {len(enabled_reporter_names)} enabled reporters: {enabled_reporter_names}"
        )

        # Account for every requested format that will produce nothing. Checked
        # against all_reporter_instances rather than enabled_reporters so that a
        # reporter which exists but is disabled is reported as disabled instead of
        # as nonexistent.
        _log_unsatisfied_output_formats(
            unsatisfied_output_formats(
                output_formats=output_formats,
                selected_instances=enabled_reporters,
                all_instances=all_reporter_instances,
                python_based_plugins_only=python_based_plugins_only,
                off_host_refused=off_host_refused,
                failed_to_build=failed_to_build,
                files_unnamed=files_unnamed,
            )
        )

        # Before any reporter runs. A link at the reports directory, or at a file
        # one of these reporters writes there (named by the reporter itself), stops
        # the run with ReportPathLinkRefused: the write through it would be refused
        # and the link left for the next reader. See utils/report_path_links.py.
        # A report file name that is not a file in the reports directory (an
        # extension that skipped its config's validation), or such a name among
        # the files a reporter writes beside its report, refuses the run as well,
        # rather than leaving that file unwritten.
        refuse_report_names_outside(
            report_dir,
            [
                reporter_file_name(plugin_instance)
                for plugin_instance in enabled_reporters
            ],
            [
                (
                    reporter_format_name(plugin_instance)
                    or type(plugin_instance).__name__,
                    name,
                )
                for plugin_instance in enabled_reporters
                for name in reporter_companion_file_names(plugin_instance)
            ],
        )
        # Nor two reporters writing one file, where the one that runs last would
        # replace the other's report: an extension naming another reporter's file,
        # such as a CycloneDX report written to ash.sarif, which the exit code reads.
        refuse_colliding_report_names(
            report_dir,
            [
                (
                    f"the {reporter_format_name(plugin_instance) or type(plugin_instance).__name__} reporter",
                    reporter_file_names(plugin_instance),
                )
                for plugin_instance in enabled_reporters
            ],
        )
        refuse_linked_report_paths(
            report_dir,
            [
                name
                for plugin_instance in enabled_reporters
                for name in reporter_file_names(plugin_instance)
            ],
        )

        # Create the main report task with initial progress
        report_task = self.progress_display.add_task(
            phase=ExecutionPhase.REPORT,
            description=f"Preparing {len(enabled_reporter_names)} reporters...",
            total=100,
        )

        # Update the main task to show it's started
        self.progress_display.update_task(
            phase=ExecutionPhase.REPORT,
            task_id=report_task,
            completed=20,
            description=f"Generating reports with {len(enabled_reporter_names)} reporters...",
        )

        # Directly invoke each reporter plugin
        results = []
        # The report files written below, each with its reporter's format, recorded
        # in the results at the end.
        written_files: List[Tuple[str, Optional[str]]] = []
        if enabled_reporters:
            ASH_LOGGER.debug(
                f"Processing {len(enabled_reporters)} enabled reporter classes"
            )
            for plugin_instance in enabled_reporters:
                # A cancelled scan runs no further reporter. Outside the try:
                # ScanCancelled is a BaseException and must not be logged as
                # this reporter's failure.
                raise_if_cancelled()
                # Bound before the try, not inside it. The handler below reads
                # all three: unbound on the first reporter (add_task raised),
                # they made the handler die with a NameError and take every
                # remaining reporter with it; left from the previous iteration,
                # they blamed and repainted the wrong reporter.
                plugin_name = plugin_instance.__class__.__name__
                # The configured name if it has one, else the class name: a
                # config whose name is None named the reporter 'None' in the
                # logs, the progress rows and the events.
                display_name = _display_name(plugin_instance)
                # A reporter that sends findings off the host has sent them by the
                # time report() returns, so a cancel seen then does not discard the
                # record of it (see below).
                sends_off_host = (
                    getattr(plugin_instance, "sends_off_host", False) is True
                )
                entries_before = _entries_under(report_dir) if sends_off_host else None
                reporter_task = None
                try:
                    ASH_LOGGER.debug(f"Initializing reporter: {plugin_name}")

                    # Create a task for this reporter
                    reporter_task = self.progress_display.add_task(
                        phase=ExecutionPhase.REPORT,
                        # Each name a description quotes is escaped once: the
                        # live display renders it as markup.
                        description=f"Starting reporter: {escape_markup(plugin_name)}",
                        total=100,
                    )

                    # Update reporter task to 50%
                    self.progress_display.update_task(
                        phase=ExecutionPhase.REPORT,
                        task_id=reporter_task,
                        completed=50,
                        description=f"Running reporter: {escape_markup(display_name)}",
                    )

                    # Call report method directly
                    ASH_LOGGER.debug(f"Calling report() on {display_name}")

                    # Notify reporter start
                    try:
                        from automated_security_helper.plugins.events import (
                            AshEventType,
                        )

                        self.notify_event(
                            AshEventType.REPORT_START,
                            reporter=display_name,
                            reporter_class=plugin_instance.__class__.__name__,
                            message=f"Starting reporter: {display_name}",
                        )
                    except Exception as event_error:
                        ASH_LOGGER.error(
                            f"Failed to notify reporter start event: {str(event_error)}"
                        )

                    report_result = plugin_instance.report(aggregated_results)
                    if sends_off_host:
                        # What an off-host reporter wrote while it ran is the local
                        # record of what it sent. A cancel stops the next reporter,
                        # and removes the reports of the local ones, but not these:
                        # the upload cannot be taken back, and removing the record
                        # of it hid that it happened. A listing that did not
                        # complete (None) tells nothing new from what was there, so
                        # only the report file recorded below is kept.
                        entries_after = _entries_under(report_dir)
                        if entries_before is not None and entries_after is not None:
                            self._off_host_records.update(
                                entries_after - entries_before
                            )
                    else:
                        # Cancelled while the reporter built its report: not written.
                        raise_if_cancelled()

                    if report_result:
                        ASH_LOGGER.debug(f"Reporter {display_name} returned a report")

                        # ash.<extension>, or ash.txt without one: the name the
                        # link check above examined.
                        output_filename = reporter_file_name(plugin_instance)

                        # Write the report to a file
                        output_file = confined_report_path(report_dir, output_filename)
                        if output_file is None:
                            raise ValueError(
                                f"{display_name}'s report file {output_filename!r} "
                                f"is not a file in {report_dir}; nothing was written"
                            )
                        ASH_LOGGER.info(
                            f"Writing {display_name} report to {output_file}"
                        )
                        # Atomically: open(path, "w") creates the file empty before
                        # writing it, so a reader waiting for the report to exist
                        # (an MCP client, or the integration fixture) could read it
                        # empty or half-written. See utils/atomic_write.py.
                        write_text_atomically(output_file, report_result)
                        if sends_off_host:
                            self._off_host_records.add(output_file)
                        else:
                            self._written_reports.append(output_file)

                        results.append(report_result)
                        written_files.append(
                            (output_filename, reporter_format_name(plugin_instance))
                        )

                        # Update reporter task to 100%
                        self.progress_display.update_task(
                            phase=ExecutionPhase.REPORT,
                            task_id=reporter_task,
                            completed=100,
                            description=f"[green]({escape_markup(display_name)}) Generated report: {escape_markup(output_filename)}",
                        )

                        # Notify reporter complete
                        try:
                            from automated_security_helper.plugins.events import (
                                AshEventType,
                            )

                            self.notify_event(
                                AshEventType.REPORT_COMPLETE,
                                reporter=display_name,
                                reporter_class=plugin_instance.__class__.__name__,
                                output_file=str(output_file),
                                output_filename=output_filename,
                                message=f"Reporter {display_name} completed: {output_filename}",
                            )
                        except Exception as event_error:
                            ASH_LOGGER.error(
                                f"Failed to notify reporter complete event: {str(event_error)}"
                            )
                    elif report_result is None:
                        # An enabled reporter that returned nothing at all did not
                        # decide it had nothing to say. `report` is annotated
                        # `-> str | None`, but no reporter in this repository
                        # returns None on a path that succeeded: None is what a
                        # handler produces when it swallows an exception, or what a
                        # method evaluates to when its only `return` sits inside a
                        # `try` whose `except` is the last statement in the body.
                        #
                        # This arm used to be shared with the empty-string case
                        # below: logged at DEBUG, which is invisible at default
                        # verbosity and absent from the console at --quiet, then the
                        # task was painted a yellow "No report generated" and
                        # counted among the phase's normal outcomes. So a crashed
                        # reporter and a reporter with nothing to report were
                        # indistinguishable to an operator, to the progress display
                        # and to every event subscriber -- and the crash is the one
                        # that needs acting on.
                        #
                        # This is the class fix for that: it covers every reporter,
                        # including ones not written yet, rather than each reporter
                        # separately deciding how loudly to fail.
                        error_msg = (
                            f"Reporter {display_name} produced no report. It "
                            "returned None, which means it could not build its "
                            "artefact -- no file was written for it."
                        )
                        ASH_LOGGER.error(error_msg)
                        self._warn_if_an_earlier_report_remains(
                            report_dir, plugin_instance, display_name
                        )

                        # Marked the way the exception handler below marks its own
                        # failures, deliberately: the two are the same outcome seen
                        # from either side of a reporter's own try/except, and a
                        # reader comparing the two arms should find them agreeing.
                        self.progress_display.update_task(
                            phase=ExecutionPhase.REPORT,
                            task_id=reporter_task,
                            completed=100,
                            description=f"[red]({escape_markup(display_name)}) Failed: no report returned",
                        )

                        # ERROR rather than REPORT_COMPLETE. REPORT_COMPLETE is how
                        # a subscriber learns a reporter succeeded, and this one did
                        # not; emitting it with a null output_file asked every
                        # subscriber to re-derive that distinction for itself.
                        try:
                            from automated_security_helper.plugins.events import (
                                AshEventType,
                            )

                            self.notify_event(
                                AshEventType.ERROR,
                                message=error_msg,
                                reporter=display_name,
                                reporter_class=plugin_instance.__class__.__name__,
                                phase="report",
                            )
                        except Exception as event_error:
                            ASH_LOGGER.error(
                                f"Failed to notify reporter error event: {str(event_error)}"
                            )
                    else:
                        # A falsy report that is not None -- in practice an empty
                        # string. Separated from the arm above because a reporter
                        # that returned a string did run to completion, so this is
                        # not a crash. It is still not a normal outcome: no file is
                        # written, and an enabled reporter asked for by name that
                        # emits nothing is the silence
                        # _log_unsatisfied_output_formats exists to break. WARNING
                        # rather than the previous DEBUG for that reason, and not
                        # ERROR because nothing here says the run is wrong.
                        ASH_LOGGER.warning(
                            f"Reporter {display_name} returned an empty report; "
                            "no file was written for it."
                        )
                        self._warn_if_an_earlier_report_remains(
                            report_dir, plugin_instance, display_name
                        )

                        # Update reporter task to 100%
                        self.progress_display.update_task(
                            phase=ExecutionPhase.REPORT,
                            task_id=reporter_task,
                            completed=100,
                            description=f"[yellow]({escape_markup(display_name)}) No report generated",
                        )

                        # Notify reporter complete (no report)
                        try:
                            from automated_security_helper.plugins.events import (
                                AshEventType,
                            )

                            self.notify_event(
                                AshEventType.REPORT_COMPLETE,
                                reporter=display_name,
                                reporter_class=plugin_instance.__class__.__name__,
                                output_file=None,
                                output_filename=None,
                                message=f"Reporter {display_name} completed: no report generated",
                            )
                        except Exception as event_error:
                            ASH_LOGGER.error(
                                f"Failed to notify reporter complete event: {str(event_error)}"
                            )

                except Exception as e:
                    # Redacted with the config's environment values: a
                    # reporter's exception can name a configured option (an
                    # account id, a bucket), and this goes to ash.log.
                    environment_values = config_environment_values(
                        getattr(self.plugin_context, "config", None)
                    )
                    described = error_text(e, environment_values)
                    ASH_LOGGER.error(f"Error in reporter {plugin_name}: {described}")
                    ASH_LOGGER.debug(
                        "Reporter exception traceback: "
                        f"{traceback_text(values=environment_values)}"
                    )
                    self._warn_if_an_earlier_report_remains(
                        report_dir,
                        plugin_instance,
                        display_name,
                        [name for name, _format in written_files],
                    )

                    # The same ERROR event the None-returning arm sends: a reporter
                    # that raised got REPORT_START and then nothing, so a
                    # subscriber could not tell it failed from one still running.
                    try:
                        from automated_security_helper.plugins.events import (
                            AshEventType,
                        )

                        self.notify_event(
                            AshEventType.ERROR,
                            message=f"Error in reporter {plugin_name}: {described}",
                            reporter=display_name,
                            reporter_class=plugin_instance.__class__.__name__,
                            phase="report",
                        )
                    except Exception as event_error:
                        ASH_LOGGER.error(
                            f"Failed to notify reporter error event: "
                            f"{error_text(event_error, environment_values)}"
                        )

                    # Update reporter task to show error. Unconditional, as the
                    # three sibling arms are: update_task tolerates a None task
                    # id (add_task returns None when the display is off, and
                    # None is what reporter_task holds when add_task itself
                    # raised), and a caller that records descriptions through
                    # update_task (a test, a wrapped display) must see the
                    # failure whether or not a display is showing.
                    self.progress_display.update_task(
                        phase=ExecutionPhase.REPORT,
                        task_id=reporter_task,
                        completed=100,
                        description=(
                            f"[red]({escape_markup(display_name)}) Failed: "
                            f"{escape_markup(described)}"
                        ),
                    )
        else:
            ASH_LOGGER.warning("No enabled reporters found matching requested formats")

        # A cancel that landed after the last reporter's write (while its
        # REPORT_COMPLETE handlers ran, or while an off-host reporter's was kept
        # past its report) is seen here: the loop checks only before a reporter, so
        # the phase ended as if it had finished and the scan ended cancelled with
        # every report kept.
        raise_if_cancelled()

        # Update progress
        self.progress_display.update_task(
            phase=ExecutionPhase.REPORT,
            task_id=report_task,
            completed=100,
            description=f"Reporters complete: {len(results)} reports generated from {len(enabled_reporters)} reporters",
        )

        # Add summary row
        self.add_summary("Complete", f"Generated {len(results)} reports")

        # So the exit code is counted only from the file this run's SARIF reporter
        # wrote: --use-existing keeps reports/, so with no SARIF reporter selected
        # the ash.sarif there is an earlier run's, and another reporter's extension
        # can name that file (utils/inner_run_outcome.py).
        #
        # record_reports_written adds to a record an earlier ReportPhase of this
        # same process left on the model, and replaces any other. `ash merge`
        # runs two phases on one results model: the local reporters, then the
        # off-host ones, and the second's record used to replace the first's, so
        # the SARIF the first wrote was no longer recorded and the exit code fell
        # back to the in-memory metrics. A record that carries another process's
        # token, or none, is not this run's and is not carried over: its files
        # are not passed back in here, so a loader that did not strip the run
        # records cannot make an earlier run's report this run's.
        record_reports_written(aggregated_results, written_files)

        return aggregated_results

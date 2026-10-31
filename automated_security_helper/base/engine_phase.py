"""Base class for execution engine phases."""

from abc import ABC, abstractmethod
from typing import Any, Callable, Optional, Sequence

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugins import ash_plugin_manager
from automated_security_helper.plugins.events import AshEventType
from automated_security_helper.utils.error_text import (
    config_environment_values,
    error_text,
    plugin_environment_values,
)
from automated_security_helper.utils.log import ASH_LOGGER


class EnginePhase(ABC):
    """Base class for execution engine phases with observer pattern support."""

    #: Which event handlers this phase's events reach. An engine hands the
    #: constructor its scan's ``plugins.loader.scan_handler_filter`` as
    #: ``plugin_filter``, kept here: the handlers of the run's own plugins plus
    #: every handler the embedding program subscribed from outside the plugin
    #: namespace, so a phase event (SCAN_START, *_PHASE_COMPLETE) reaches the
    #: same handlers the engine's EXECUTION_* events reach. A scope set on the
    #: phase afterward is combined with the handed filter, so a handler either
    #: one admits is notified. None, for a phase built outside an engine with no
    #: filter, reaches every subscriber.
    plugin_scope: Optional[Callable[[Any], bool]] = None

    def __init__(
        self,
        plugin_context: PluginContext,
        plugins: Sequence[type] | None = None,
        progress_display: Optional[Any] = None,
        asharp_model: Optional[AshAggregatedResults] = None,
        plugin_filter: Optional[Callable[[Any], bool]] = None,
    ):
        """Initialize the engine phase.

        Args:
            plugin_context: Plugin context with paths and configuration
            plugins: The plugin classes the phase builds and runs (classes, not
                instances: each phase constructs them with its context and config)
            progress_display: Progress display to use for reporting progress
            asharp_model: AshAggregatedResults to update with results
            plugin_filter: The event handlers this phase's notifications reach;
                the scan's ``plugins.loader.scan_handler_filter``, kept as
                ``plugin_scope``. None leaves the scope to be set on the phase.
        """
        if plugins is None:
            plugins = []
        self.plugin_context = plugin_context
        self.plugins = plugins
        self.plugin_filter = plugin_filter
        self.progress_display = progress_display
        self.asharp_model = asharp_model or AshAggregatedResults()
        if plugin_filter is not None:
            self.plugin_scope = plugin_filter

    @property
    @abstractmethod
    def phase_name(self) -> str:
        """Return the name of this phase."""

    def notify_event(self, event_type, **kwargs):
        """Notify plugins of an event with the current context.

        Args:
            event_type: The event type to notify
            **kwargs: Additional data to include in the notification

        Returns:
            List: Results from all event handlers
        """
        # Include the plugin context in all notifications
        event_data = {
            "phase": self.phase_name,
            "plugin_context": self.plugin_context,
            **kwargs,
        }
        ASH_LOGGER.debug(
            f"EnginePhase.notify_event: Notifying event {event_type} from phase {self.phase_name}"
        )
        return ash_plugin_manager.notify(
            event_type, handler_filter=self._event_handler_filter(), **event_data
        )

    def _event_handler_filter(self) -> Optional[Callable[[Any], bool]]:
        """Which handlers this phase's events reach: the scope AND the filter handed in.

        ``plugin_scope`` is the run's plugin set (``loader.plugins_of``), which
        the engine sets on a phase after building it; ``plugin_filter`` is what
        the engine handed the constructor, the scan's ``scan_handler_filter``,
        which admits those plugins and every handler subscribed from outside
        the plugin namespace (the embedding program's). Passing the scope alone
        dropped the program's handlers from every phase event (SCAN_START,
        SCAN_COMPLETE, CONVERT_*, REPORT_*, *_PHASE_*) although they still got
        the engine's EXECUTION_* events. A handler either one admits is notified;
        with one of the two unset, that one decides; with neither, every
        subscriber is.
        """
        scope, handed = self.plugin_scope, self.plugin_filter
        if scope is None or handed is None or scope is handed:
            return scope if scope is not None else handed

        def admits(callback: Any) -> bool:
            return bool(scope(callback) or handed(callback))

        return admits

    def _notify_phase_event(self, event: Any, **kwargs) -> None:
        """Notify a phase's START event; a handler that raises ends the run.

        A *_PHASE_START handler's exception propagates as itself: that is the
        contract the engine's own tests pin (a failing start handler ends the
        run before the phase's work, with the phase's completions read cleanly
        on the way out), and nothing of the phase has run yet, so nothing is
        lost. The COMPLETE event is the one guarded (``_notify_phase_complete``):
        there a raising handler discarded a finished phase's results.
        """
        self.notify_event(event, **kwargs)

    def _notify_phase_complete(self, event: Any, **kwargs) -> None:
        """Notify a phase's COMPLETE event, logging a handler that raises.

        Every other notification site in the phases catches and logs a
        handler's failure; this one did not, so one raising *_PHASE_COMPLETE
        handler discarded a finished phase's results. The START event is not
        guarded this way (``_notify_phase_event``).

        The handler is plugin code and its exception can quote anything, a value
        the run's configuration read from the environment included, so the text
        is redacted with the configuration's values before it is logged, as the
        engine's other error lines are.
        """
        try:
            self.notify_event(event, **kwargs)
        except Exception as error:  # noqa: BLE001 -- handlers are plugin-supplied
            values = config_environment_values(
                getattr(self.plugin_context, "config", None)
            )
            ASH_LOGGER.error(
                f"Failed to notify {event} event for phase {self.phase_name}: "
                f"{error_text(error, values)}"
            )

    def execute(
        self,
        aggregated_results: AshAggregatedResults,
        python_based_plugins_only: bool = False,
        **kwargs,
    ) -> AshAggregatedResults:
        """Execute the phase with observer pattern support.

        This implementation handles the common event notifications.
        Subclasses should override _execute_phase instead of this method.

        Args:
            python_based_plugins_only: If True, only execute plugins that are Python-only
            **kwargs: Additional arguments for the phase

        Returns:
            AshAggregatedResults: Phase-specific results
        """
        # Notify phase start
        start_event_name = f"{self.phase_name.upper()}_PHASE_START"
        try:
            start_event = AshEventType[start_event_name]
        except KeyError:
            ASH_LOGGER.warning(
                f"No AshEventType member '{start_event_name}'; falling back to string"
            )
            start_event = start_event_name
        ASH_LOGGER.debug(f"EnginePhase.execute: Notifying {start_event} event")
        self._notify_phase_event(start_event, **kwargs)

        # Execute the phase-specific logic
        ASH_LOGGER.debug(
            f"EnginePhase.execute: Executing phase-specific logic for {self.phase_name}"
        )
        results = self._execute_phase(
            aggregated_results=aggregated_results,
            python_based_plugins_only=python_based_plugins_only,
            **kwargs,
        )

        # Defensive type checking to catch unexpected return types
        if not isinstance(results, AshAggregatedResults):
            error_msg = (
                f"Phase {self.phase_name} returned unexpected type {type(results).__name__} "
                f"instead of AshAggregatedResults. This indicates a critical error in phase execution."
            )
            ASH_LOGGER.error(error_msg)
            ASH_LOGGER.debug(f"Unexpected results value: {results}")
            raise TypeError(error_msg)

        if isinstance(results, AshAggregatedResults):
            # Should update the instance then return it once done, so allow
            # overriding if it was returned.
            aggregated_results = results

        # Update summary statistics if the method exists
        if hasattr(self, "_update_summary_stats") and callable(
            getattr(self, "_update_summary_stats")
        ):
            ASH_LOGGER.debug(
                f"EnginePhase.execute: Updating summary statistics for {self.phase_name}"
            )
            self._update_summary_stats()

        # Notify phase complete
        complete_event_name = f"{self.phase_name.upper()}_PHASE_COMPLETE"
        try:
            complete_event = AshEventType[complete_event_name]
        except KeyError:
            ASH_LOGGER.warning(
                f"No AshEventType member '{complete_event_name}'; falling back to string"
            )
            complete_event = complete_event_name
        ASH_LOGGER.debug(f"EnginePhase.execute: Notifying {complete_event} event")
        self._notify_phase_complete(complete_event, results=results, **kwargs)

        return results

    @abstractmethod
    def _execute_phase(
        self,
        aggregated_results: AshAggregatedResults,
        python_based_plugins_only: bool = False,
        **kwargs,
    ) -> AshAggregatedResults:
        """Execute the phase-specific logic.

        Subclasses must implement this method instead of overriding execute().

        Args:
            python_based_plugins_only: If True, only execute plugins that are Python-only
            **kwargs: Additional arguments for the phase

        Returns:
            AshAggregatedResults: Phase-specific results
        """

    def filter_enabled_plugins(
        self,
        plugin_instances: list,
        plugin_context: Any,
        python_only: bool = False,
        check_dependencies: bool = True,
        failures: Optional[dict] = None,
    ) -> list:
        """Return only the plugins that are enabled and have satisfied dependencies.

        This replaces the duplicated filtering loop in ConvertPhase, ReportPhase,
        and ScanPhase.  Callers that need the display_name for their own tracking
        should inspect ``instance.config.name`` after filtering.

        Args:
            plugin_instances: Pre-instantiated plugin objects to filter.
            plugin_context: Current plugin context (used for future extension).
            python_only: When True, exclude plugins where is_python_only() is False.
            check_dependencies: When False, select on the enabled flag and
                ``python_only`` only. ScanPhase passes False: it decides what a run
                selects before it asks for any tool, and records an absent tool
                itself, as MISSING.
            failures: When given, a dict the method fills with the text of the
                exception a dropped instance's own check raised, keyed by
                ``id(instance)``. A caller that reads it can tell a plugin whose
                check RAISED from one the check excluded, and record the first as
                a failure rather than as an exclusion: without it, under
                ``--python-only`` a selected scanner whose check raised was
                recorded SKIPPED as not Python-only.

        Returns:
            Filtered list of plugin instances in original order.
        """
        result = []
        for instance in plugin_instances:
            try:
                if hasattr(instance, "config") and hasattr(instance.config, "enabled"):
                    if not instance.config.enabled:
                        continue
                if python_only and not instance.is_python_only():
                    continue
                if check_dependencies and not instance.validate_plugin_dependencies():
                    continue
                result.append(instance)
            except Exception as e:
                # The exception is plugin-sourced text: redacted of the values
                # the config read from the environment AND of the plugin's own
                # (plugin_environment_values: a plugin can know a value the
                # run's configuration does not, and its check's exception can
                # quote it), and of escape sequences, as every other place that
                # shows an error it did not raise. The text reaches the scan
                # phase's ERROR row, ash.log and the reports.
                values = plugin_environment_values(
                    instance,
                    config_environment_values(getattr(plugin_context, "config", None)),
                )
                described = f"{type(e).__name__}: {error_text(e, values)}"
                if failures is not None:
                    failures[id(instance)] = described
                # Swallowed deliberately: one plugin whose enabled/dependency
                # check raises must not take down the whole phase, and every
                # caller already treats an absent instance as "not enabled".
                # Narrowing the type was rejected -- validate_plugin_dependencies
                # and is_python_only are plugin-supplied, so the exception set is
                # open by design.
                #
                # Logged as a warning, not at DEBUG, because the plugin otherwise
                # vanishes from a default run with no trace: DEBUG reaches neither
                # the console nor ash.log by default, and
                # report_phase._excluded_reporter_reason attributes every leftover
                # exclusion to unsatisfied dependencies, so a plugin that blew up
                # here is reported to the operator as merely unsatisfied.
                ASH_LOGGER.warning(
                    f"Excluding {type(instance).__name__} from the "
                    f"{self.phase_name} phase: its enabled/dependency check "
                    f"raised {described}"
                )
        return result

    def add_summary(self, status: str, details: str) -> None:
        """Add a summary row for this phase.

        Args:
            status: Status of the phase (e.g., "Complete", "Failed")
            details: Additional details about the phase result
        """
        if self.progress_display:
            self.progress_display.add_summary_row(self.phase_name, status, details)

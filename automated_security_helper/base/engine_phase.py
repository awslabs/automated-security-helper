"""Base class for execution engine phases."""

from abc import ABC, abstractmethod
from typing import Any, List, Optional

from automated_security_helper.base.converter_plugin import ConverterPluginBase
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.reporter_plugin import ReporterPluginBase
from automated_security_helper.base.scanner_plugin import ScannerPluginBase
from automated_security_helper.core.enums import ExecutionPhase
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugins import ash_plugin_manager
from automated_security_helper.utils.log import ASH_LOGGER


class EnginePhase(ABC):
    """Base class for execution engine phases with observer pattern support."""

    def __init__(
        self,
        plugin_context: PluginContext,
        plugins: List[
            ConverterPluginBase | ScannerPluginBase | ReporterPluginBase
        ] = [],
        progress_display: Optional[Any] = None,
        asharp_model: Optional[AshAggregatedResults] = None,
    ):
        """Initialize the engine phase.

        Args:
            plugin_context: Plugin context with paths and configuration
            progress_display: Progress display to use for reporting progress
            asharp_model: AshAggregatedResults to update with results
        """
        self.plugin_context = plugin_context
        self.plugins = plugins
        self.progress_display = progress_display
        self.asharp_model = asharp_model or AshAggregatedResults()
        self.phase_task = None

    @property
    @abstractmethod
    def phase_name(self) -> str:
        """Return the name of this phase."""
        pass

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
        return ash_plugin_manager.notify(event_type, **event_data)

    def execute(self, python_based_plugins_only: bool = False, **kwargs) -> Any:
        """Execute the phase with observer pattern support.

        This implementation handles the common event notifications.
        Subclasses should override _execute_phase instead of this method.

        Args:
            python_based_plugins_only: If True, only execute plugins that are Python-only
            **kwargs: Additional arguments for the phase

        Returns:
            Any: Phase-specific results
        """
        # Initialize progress
        self.initialize_progress()

        # Notify phase start
        start_event = f"{self.phase_name.upper()}_START"
        ASH_LOGGER.debug(f"EnginePhase.execute: Notifying {start_event} event")
        self.notify_event(start_event, **kwargs)

        # Execute the phase-specific logic
        ASH_LOGGER.debug(
            f"EnginePhase.execute: Executing phase-specific logic for {self.phase_name}"
        )
        results = self._execute_phase(
            python_based_plugins_only=python_based_plugins_only, **kwargs
        )

        # Update summary statistics if the method exists
        if hasattr(self, "_update_summary_stats") and callable(
            getattr(self, "_update_summary_stats")
        ):
            ASH_LOGGER.debug(
                f"EnginePhase.execute: Updating summary statistics for {self.phase_name}"
            )
            self._update_summary_stats()

        # Notify phase complete
        complete_event = f"{self.phase_name.upper()}_COMPLETE"
        ASH_LOGGER.debug(f"EnginePhase.execute: Notifying {complete_event} event")
        self.notify_event(complete_event, results=results, **kwargs)

        # Update progress to complete
        # Don't update the progress here, let the phase implementation handle it
        # self.update_progress(100, f"{self.phase_name.capitalize()} phase complete")

        return results

    @abstractmethod
    def _execute_phase(self, python_based_plugins_only: bool = False, **kwargs) -> Any:
        """Execute the phase-specific logic.

        Subclasses must implement this method instead of overriding execute().

        Args:
            python_based_plugins_only: If True, only execute plugins that are Python-only
            **kwargs: Additional arguments for the phase

        Returns:
            Any: Phase-specific results
        """
        pass

    def initialize_progress(self, description: str = None) -> None:
        """Initialize progress tracking for this phase.

        Args:
            description: Initial description for the progress task
        """
        if self.progress_display:
            if not description:
                description = f"Initializing {self.phase_name} phase..."

            # # Convert string phase name to ExecutionPhase enum
            # phase_enum = None
            # if self.phase_name == "convert":
            #     phase_enum = ExecutionPhase.CONVERT
            # elif self.phase_name == "scan":
            #     phase_enum = ExecutionPhase.SCAN
            # elif self.phase_name == "report":
            #     phase_enum = ExecutionPhase.REPORT
            # else:
            #     # Default to CONVERT if unknown
            #     phase_enum = ExecutionPhase.CONVERT

            # Don't create a task here - let the phase implementation create its own task
            # with proper initial progress
            # self.phase_task = self.progress_display.add_task(
            #     phase=phase_enum, description=description, total=100
            # )

    def update_progress(self, completed: int, description: str = None) -> None:
        """Update progress for this phase.

        Args:
            completed: Percentage completed (0-100)
            description: Updated description for the progress task
        """
        if self.progress_display and self.phase_task is not None:
            # Convert string phase name to ExecutionPhase enum
            phase_enum = None
            if self.phase_name == "convert":
                phase_enum = ExecutionPhase.CONVERT
            elif self.phase_name == "scan":
                phase_enum = ExecutionPhase.SCAN
            elif self.phase_name == "report":
                phase_enum = ExecutionPhase.REPORT
            else:
                # Default to CONVERT if unknown
                phase_enum = ExecutionPhase.CONVERT

            self.progress_display.update_task(
                phase=phase_enum,
                task_id=self.phase_task,
                completed=completed,
                description=description
                or f"{self.phase_name} phase: {completed}% complete",
            )

            # Notify progress event
            progress_event = f"{self.phase_name.upper()}_PROGRESS"
            self.notify_event(
                progress_event, completed=completed, description=description
            )

    def add_summary(self, status: str, details: str) -> None:
        """Add a summary row for this phase.

        Args:
            status: Status of the phase (e.g., "Complete", "Failed")
            details: Additional details about the phase result
        """
        if self.progress_display:
            self.progress_display.add_summary_row(self.phase_name, status, details)

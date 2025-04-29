"""Implementation of the Convert phase."""

from pathlib import Path
from typing import List

from automated_security_helper.base.engine_phase import EnginePhase
from automated_security_helper.core.progress import ExecutionPhase
from automated_security_helper.plugins import ash_plugin_manager
from automated_security_helper.plugins.events import AshEventType
from automated_security_helper.plugins.interfaces import IConverter
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

        # Get all converter plugins using the plugin manager
        converters = ash_plugin_manager.plugin_modules(IConverter)
        converted_paths = []

        # Update progress to 20%
        self.update_progress(
            20, f"Found {len(converters) if converters else 0} converters"
        )

        # If no converters found, still update progress to 100%
        if not converters or len(converters) == 0:
            self.update_progress(100, "No converters to run")
            return converted_paths

        # Process each target in the source directory
        source_dir = self.plugin_context.source_dir
        if source_dir.is_dir():
            # Process the source directory itself
            target_paths = self._process_target(source_dir, converters)
            if target_paths:
                converted_paths.extend(target_paths)

        # Update main task to 100%
        self.update_progress(
            100, f"Preparation complete: {len(converted_paths)} paths converted"
        )

        # Add summary row
        self.add_summary("Complete", f"Converted {len(converted_paths)} paths")

        return converted_paths

    def _process_target(self, target: Path, converters) -> List[Path]:
        """Process a single target with all converters.

        Args:
            target: Target path to process
            converters: List of converter classes

        Returns:
            List[Path]: List of converted paths
        """
        converted_paths = []

        # Create task for this target
        target_task = self.progress_display.add_task(
            phase=ExecutionPhase.CONVERT,
            description=f"Processing target: {target.name}",
            total=100,
        )

        # Update target task to 50%
        self.progress_display.update_task(
            phase=ExecutionPhase.CONVERT,
            task_id=target_task,
            completed=50,
            description=f"Processing target: {target.name}",
        )

        # Notify plugins about this specific target
        results = self.notify_event(
            AshEventType.CONVERT_TARGET,
            target=target,
            plugin_context=self.plugin_context,
        )

        # Collect all converted paths from the results
        for result in results:
            if result:
                if isinstance(result, list):
                    converted_paths.extend(result)
                else:
                    converted_paths.append(result)

        # Update target task to 100%
        self.progress_display.update_task(
            phase=ExecutionPhase.CONVERT,
            task_id=target_task,
            completed=100,
            description=f"Completed target: {target.name}",
        )

        return converted_paths

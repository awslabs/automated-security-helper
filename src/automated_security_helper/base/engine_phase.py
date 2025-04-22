"""Base class for execution engine phases."""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Optional

from automated_security_helper.config.ash_config import ASHConfig
from automated_security_helper.models.asharp_model import ASHARPModel


class EnginePhase(ABC):
    """Base class for execution engine phases."""

    def __init__(
        self,
        source_dir: Path,
        output_dir: Path,
        work_dir: Path,
        config: Optional[ASHConfig] = None,
        progress_display: Optional[Any] = None,
        asharp_model: Optional[ASHARPModel] = None,
    ):
        """Initialize the engine phase.

        Args:
            source_dir: Source directory to scan
            output_dir: Output directory for scan results
            work_dir: Working directory for temporary files
            config: Optional ASHConfig to use for configuration
            progress_display: Progress display to use for reporting progress
            asharp_model: ASHARPModel to update with results
        """
        self.source_dir = source_dir
        self.output_dir = output_dir
        self.work_dir = work_dir
        self.config = config
        self.progress_display = progress_display
        self.asharp_model = asharp_model or ASHARPModel()
        self.phase_task = None

    @property
    @abstractmethod
    def phase_name(self) -> str:
        """Return the name of this phase."""
        pass

    @abstractmethod
    def execute(self, **kwargs) -> Any:
        """Execute the phase.

        Args:
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
                description = f"Starting {self.phase_name} phase..."
            self.phase_task = self.progress_display.add_task(
                phase=self.phase_name, description=description, total=100
            )

    def update_progress(self, completed: int, description: str = None) -> None:
        """Update progress for this phase.

        Args:
            completed: Percentage completed (0-100)
            description: Updated description for the progress task
        """
        if self.progress_display and self.phase_task is not None:
            self.progress_display.update_task(
                phase=self.phase_name,
                task_id=self.phase_task,
                completed=completed,
                description=description
                or f"{self.phase_name} phase: {completed}% complete",
            )

    def add_summary(self, status: str, details: str) -> None:
        """Add a summary row for this phase.

        Args:
            status: Status of the phase (e.g., "Complete", "Failed")
            details: Additional details about the phase result
        """
        if self.progress_display:
            self.progress_display.add_summary_row(self.phase_name, status, details)

"""Event types for the ASH plugin system."""

from enum import Enum, auto


class AshEventType(Enum):
    """Standard event types for ASH plugins."""

    # Execution lifecycle events
    EXECUTION_START = auto()  # Start of the full execution
    EXECUTION_PROGRESS = auto()  # Report progress for the execution
    EXECUTION_COMPLETE = auto()  # End of the full execution

    # Phase lifecycle events
    CONVERT_PHASE_START = auto()  # Start of the phase
    CONVERT_START = auto()  # Start of a plugin
    CONVERT_PHASE_PROGRESS = auto()  # Report progress for the phase
    CONVERT_COMPLETE = auto()  # End of a plugin
    CONVERT_PHASE_COMPLETE = auto()  # End of the phase

    SCAN_PHASE_START = auto()  # Start of the phase
    SCAN_START = auto()  # Start of a plugin
    SCAN_PHASE_PROGRESS = auto()  # Report progress for the phase
    SCAN_COMPLETE = auto()  # End of a plugin
    SCAN_PHASE_COMPLETE = auto()  # End of the phase

    REPORT_PHASE_START = auto()  # Start of the phase
    REPORT_START = auto()  # Start of a plugin
    REPORT_PHASE_PROGRESS = auto()  # Report progress for the phase
    REPORT_COMPLETE = auto()  # End of a plugin
    REPORT_PHASE_COMPLETE = auto()  # End of the phase

    INSPECT_PHASE_START = auto()  # Start of the phase
    INSPECT_START = auto()  # Start of a plugin
    INSPECT_PHASE_PROGRESS = auto()  # Report progress for the phase
    INSPECT_COMPLETE = auto()  # End of a plugin
    INSPECT_PHASE_COMPLETE = auto()  # End of the phase

    # General events
    ERROR = auto()
    WARNING = auto()
    INFO = auto()

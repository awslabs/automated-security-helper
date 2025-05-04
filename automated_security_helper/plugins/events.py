"""Event types for the ASH plugin system."""

from enum import Enum, auto


class AshEventType(Enum):
    """Standard event types for ASH plugins."""

    # Phase lifecycle events
    CONVERT_START = auto()
    CONVERT_TARGET = auto()  # For individual target conversion
    CONVERT_PROGRESS = auto()
    CONVERT_COMPLETE = auto()

    SCAN_START = auto()
    SCAN_TARGET = auto()  # For individual target scanning
    SCAN_PROGRESS = auto()
    SCAN_COMPLETE = auto()

    REPORT_START = auto()
    REPORT_GENERATE = auto()  # For report generation
    REPORT_PROGRESS = auto()
    REPORT_COMPLETE = auto()

    # General events
    ERROR = auto()
    WARNING = auto()
    INFO = auto()

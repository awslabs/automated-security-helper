"""Module containing the ScanResultsContainer class for wrapping scanner results."""

from datetime import datetime
from pathlib import Path
from typing import Annotated, Any, Dict, Literal, List

from pydantic import BaseModel, Field

from automated_security_helper.core.enums import ScannerStatus


class ScanResultsContainer(BaseModel):
    """Container for scanner results with metadata."""

    scanner_name: str = "unknown"
    report_type: Annotated[
        Literal[
            "text",
            "json",
            "yaml",
            "sarif",
            "cyclonedx",
            "cyclonedx_xml",
            "html",
            "junitxml",
            "spdx",
            "pdf",
        ],
        Field(
            description="Type of report, e.g., 'static_analysis', 'sarif', etc.",
        ),
    ] = "text"
    path: Annotated[
        str | None,
        Field(
            description="Path to the report file in the output directory, if there is a physical report.",
        ),
    ] = None
    target: Path | None = None
    target_type: str | None = None
    exit_code: int = 0
    finding_count: int = 0
    start_time: datetime | None = None
    end_time: datetime | None = None
    duration: float | None = 0
    metadata: Dict[str, Any] = {}
    raw_results: Any | None = None
    severity_counts: Dict[str, int] = Field(
        default_factory=lambda: {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
            "suppressed": 0,
            "total": 0,
        }
    )
    scanner_severity_threshold: (
        Literal["ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL"] | None
    ) = None
    status: ScannerStatus = ScannerStatus.PASSED
    dependencies_satisfied: bool = True
    excluded: bool = False
    errors: List[str] = Field(default_factory=list)
    exception: str | None = None
    stack_trace: str | None = None

    def add_metadata(self, key: str, value: Any) -> None:
        """Add metadata to the container.

        Args:
            key: Metadata key
            value: Metadata value
        """
        self.metadata[key] = value

    def add_error(self, error: str) -> None:
        """Add an error message to the container.

        Args:
            error: Error message to add
        """
        if error not in self.errors:
            self.errors.append(error)

    def set_exception(self, exception: Exception) -> None:
        """Set exception information including stack trace.

        Args:
            exception: Exception that occurred
        """
        import traceback

        self.exception = str(exception)
        self.stack_trace = traceback.format_exc()
        self.add_error(str(exception))
        self.status = ScannerStatus.FAILED

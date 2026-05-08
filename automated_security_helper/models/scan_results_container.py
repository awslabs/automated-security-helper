"""Module containing the ScanResultsContainer class for wrapping scanner results."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Annotated, Any, Dict, Literal, List, Optional

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

    # ---- Factory methods ------------------------------------------------

    @classmethod
    def for_excluded(cls, scanner_name: str) -> "ScanResultsContainer":
        """Build a container for a scanner that was excluded via configuration."""
        return cls(
            scanner_name=scanner_name,
            excluded=True,
            status=ScannerStatus.SKIPPED,
            duration=None,
        )

    @classmethod
    def for_missing_deps(cls, scanner_name: str) -> "ScanResultsContainer":
        """Build a container for a scanner whose dependencies were not satisfied."""
        return cls(
            scanner_name=scanner_name,
            dependencies_satisfied=False,
            status=ScannerStatus.MISSING,
            duration=None,
        )

    @classmethod
    def for_failure(
        cls,
        scanner_name: str,
        errors: Optional[List[str]] = None,
        exception: Optional[BaseException] = None,
    ) -> "ScanResultsContainer":
        """Build a container for a scanner that failed to execute cleanly."""
        container = cls(
            scanner_name=scanner_name,
            status=ScannerStatus.FAILED,
        )
        if errors:
            for err in errors:
                container.add_error(err)
        if exception is not None:
            container.set_exception(exception)
            # set_exception already sets status to FAILED
        return container

    # ---- Threshold evaluation ------------------------------------------

    def determine_status(self, threshold: str | None) -> ScannerStatus:
        """Determine PASSED/FAILED status by comparing severity_counts to threshold.

        Mirrors the cascade that previously lived in scan_phase.py: any finding at
        or above the configured severity threshold fails the scanner. Does not
        mutate the container's current status — the caller assigns the result.
        """
        # Treat a None/empty threshold the same as the most permissive level
        # so severity counts are only ignored when configured to ignore.
        if not threshold:
            return ScannerStatus.PASSED

        counts = self.severity_counts or {}
        critical = counts.get("critical", 0) or 0
        high = counts.get("high", 0) or 0
        medium = counts.get("medium", 0) or 0
        low = counts.get("low", 0) or 0
        info = counts.get("info", 0) or 0

        if critical > 0:
            return ScannerStatus.FAILED
        if high > 0 and threshold in ("ALL", "LOW", "MEDIUM", "HIGH"):
            return ScannerStatus.FAILED
        if medium > 0 and threshold in ("ALL", "LOW", "MEDIUM"):
            return ScannerStatus.FAILED
        if low > 0 and threshold in ("ALL", "LOW"):
            return ScannerStatus.FAILED
        if info > 0 and threshold == "ALL":
            return ScannerStatus.FAILED
        return ScannerStatus.PASSED

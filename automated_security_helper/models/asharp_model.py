# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from datetime import datetime, timezone
import json
from pathlib import Path
from pydantic import AnyUrl, BaseModel, ConfigDict, Field, PrivateAttr, field_validator

from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.constants import ASH_DOCS_URL, ASH_REPO_URL
from automated_security_helper.core.enums import ExportFormat, ScannerStatus
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.schemas.cyclonedx_bom_1_6_schema import CycloneDXReport
from typing import TYPE_CHECKING, Annotated, Dict, Any, Optional, Union, List
from automated_security_helper.schemas.sarif_schema_model import (
    PropertyBag,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils.get_ash_version import get_ash_version
from automated_security_helper.utils.log import ASH_LOGGER

if TYPE_CHECKING:
    from automated_security_helper.config.ash_config import AshConfig

__all__ = ["AshAggregatedResults"]


_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
_VALID_INCREMENT_FIELDS = _SEVERITY_ORDER + ("suppressed",)


class ScannerSeverityCount(BaseModel):
    """Information about scanner status."""

    model_config = ConfigDict(
        str_strip_whitespace=True,
        extra="allow",
        arbitrary_types_allowed=True,
    )
    suppressed: int = (
        0  # Suppressed findings take precedence over other severity levels
    )
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0

    @property
    def total(self) -> int:
        """Sum of all non-suppressed severity counts.

        Subclasses (e.g., SummaryStats) may override ``total`` with a plain int
        field; in that case, the stored value is returned.
        """
        declared = self.__dict__.get("total")
        if declared is not None:
            return declared
        return self.critical + self.high + self.medium + self.low + self.info

    @total.setter
    def total(self, value: int) -> None:
        """Allow subclasses that redeclare total as a field to set it."""
        self.__dict__["total"] = value

    def actionable_count(self, threshold: str) -> int:
        """Count findings at or above the given severity threshold.

        threshold is case-insensitive. Valid values: critical, high, medium, low, info.
        """
        if not isinstance(threshold, str):
            raise ValueError(f"Invalid severity threshold: {threshold!r}")
        key = threshold.lower()
        if key not in _SEVERITY_ORDER:
            raise ValueError(f"Invalid severity threshold: {threshold!r}")
        idx = _SEVERITY_ORDER.index(key)
        return sum(getattr(self, name) for name in _SEVERITY_ORDER[: idx + 1])

    def increment(self, severity: str) -> None:
        """Increment the named severity field by 1.

        severity is case-insensitive. Valid values: critical, high, medium, low, info, suppressed.
        """
        if not isinstance(severity, str):
            raise ValueError(f"Invalid severity: {severity!r}")
        key = severity.lower()
        if key not in _VALID_INCREMENT_FIELDS:
            raise ValueError(f"Invalid severity: {severity!r}")
        setattr(self, key, getattr(self, key) + 1)

    def max_severity(self) -> str:
        """Return the name of the highest non-zero severity, or "none" if all zero.

        suppressed is not considered.
        """
        for name in _SEVERITY_ORDER:
            if getattr(self, name) > 0:
                return name
        return "none"


class SummaryStats(ScannerSeverityCount):
    """Summary statistics for the final report"""

    start: str | datetime | None = None
    end: str | datetime | None = None
    duration: float = 0.0
    total: int = 0
    actionable: int = 0
    passed: int = 0
    failed: int = 0
    missing: int = 0
    skipped: int = 0
    suppressed: int = 0  # Add suppressed count to summary stats

    def bump(self, key: str, amount: int = 1) -> int:
        setattr(self, key, getattr(self, key) + amount)
        return getattr(self, key)

    def set_timing(
        self,
        start: str | datetime | None,
        end: str | datetime | None,
        duration: float,
    ) -> None:
        """Set start, end, and duration in a single call."""
        self.start = start
        self.end = end
        self.duration = duration


class ScannerTargetStatusInfo(BaseModel):
    """Information about scanner status."""

    model_config = ConfigDict(
        str_strip_whitespace=True,
        extra="allow",
        arbitrary_types_allowed=True,
    )

    status: ScannerStatus = ScannerStatus.PASSED
    dependencies_satisfied: bool = True
    excluded: bool = False
    severity_counts: ScannerSeverityCount = ScannerSeverityCount()
    finding_count: int | None = 0
    actionable_finding_count: int | None = 0
    suppressed_finding_count: int | None = 0
    exit_code: int | None = 0
    duration: float | None = 0.0

    @property
    def total_duration(self) -> float:
        """Alias for duration; returns 0.0 when duration is None."""
        return self.duration or 0.0


class ScannerStatusInfo(BaseModel):
    """Information about scanner status."""

    model_config = ConfigDict(
        str_strip_whitespace=True,
        extra="allow",
        arbitrary_types_allowed=True,
    )

    severity_threshold: str | None = None
    status: ScannerStatus | None = None
    dependencies_satisfied: bool = True
    excluded: bool = False

    source: ScannerTargetStatusInfo = ScannerTargetStatusInfo()
    converted: ScannerTargetStatusInfo = ScannerTargetStatusInfo()

    @property
    def is_dual_layer(self) -> bool:
        """True when both source and converted targets show non-default state.

        A target is "non-default" if its status is not PASSED, or if any of its
        severity counts (including suppressed) are non-zero.
        """
        def _non_default(t: ScannerTargetStatusInfo) -> bool:
            if t.status != ScannerStatus.PASSED:
                return True
            sc = t.severity_counts
            return (
                sc.critical
                + sc.high
                + sc.medium
                + sc.low
                + sc.info
                + sc.suppressed
            ) > 0

        return _non_default(self.source) and _non_default(self.converted)


class ConverterStatusInfo(BaseModel):
    """Information about converter status."""

    model_config = ConfigDict(
        str_strip_whitespace=True,
        extra="allow",
        arbitrary_types_allowed=True,
    )

    dependencies_satisfied: bool = True
    excluded: bool = False

    converted_paths: List[str] = []


class ReportMetadata(BaseModel):
    """Metadata for security reports."""

    model_config = ConfigDict(
        str_strip_whitespace=True,
        extra="allow",
        arbitrary_types_allowed=True,
        json_encoders={
            datetime: lambda v: v.isoformat(),
            ExportFormat: lambda v: str(v),
        },
    )

    report_id: Annotated[
        str | None,
        Field(
            min_length=1,
            pattern=r"^[A-Za-z][\/\.\w-]+$",
            description="Unique identifier for the report",
        ),
    ] = None
    generated_at: Annotated[str | None, Field()] = None
    project_name: Annotated[
        str | None, Field(min_length=1, description="Name of the project being scanned")
    ] = None
    tool_version: Annotated[
        str | None, Field(min_length=1, description="Version of the security tool")
    ] = None
    description: Annotated[
        str | None, Field(min_length=1, description="Description of the tool/scan")
    ] = None
    summary_stats: Annotated[
        SummaryStats,
        Field(description="Summary statistics (e.g., count by severity)"),
    ] = SummaryStats()
    validation_summary: Annotated[
        Dict[str, Any],
        Field(
            default_factory=dict,
            description="Summary of ASH component validation results for the report",
        ),
    ]
    execution_discrepancy_report: Annotated[
        Dict[str, Any],
        Field(default_factory=dict, description="Discrepancy report for ASH execution"),
    ]

    @field_validator("project_name")
    @classmethod
    def validate_non_empty_str(cls, v: str, info) -> str:
        """Validate string fields are not empty."""
        v = v.strip()
        if not v:
            raise ValueError(f"{info.field_name} cannot be empty")
        return v

    @field_validator("generated_at")
    @classmethod
    def validate_datetime(cls, v: Union[str, datetime, None] = None) -> str:
        """Validate that value is timestamp or, if empty, set to current datetime"""
        if not v:
            v = datetime.now(timezone.utc)
        if isinstance(v, str):
            v = datetime.fromisoformat(v.strip())
        return v.isoformat(timespec="seconds")

    def model_post_init(self, context):
        super().model_post_init(context)
        default_timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
        if not self.generated_at:
            self.generated_at = default_timestamp
        if not self.report_id:
            self.report_id = (
                f"ASH-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
            )


class AshAggregatedResults(BaseModel):
    """Main model class for parsing security scan reports from ASH tooling."""

    model_config = ConfigDict(
        extra="ignore",
        str_strip_whitespace=True,
        arbitrary_types_allowed=True,
    )

    name: str = Field(default="ASH Scan Report", description="Name of the report")
    description: str = Field(
        default="Automated Security Helper - Aggregated Report",
        description="The description of the generated report.",
    )
    metadata: ReportMetadata = Field(
        default_factory=lambda: ReportMetadata(
            report_id="ASH-" + datetime.now(timezone.utc).strftime("%Y%m%d"),
            project_name="ASH",
            # tool_name="ASH",
            tool_version=get_ash_version(),
            description="Automated Security Helper Aggregated Report Post-processor",
            summary_stats=SummaryStats(),
        )
    )
    ash_config: Annotated[
        Optional["AshConfig"],
        Field(description="The full ASH configuration used during this scan."),
    ] = None
    scanner_results: Dict[str, ScannerTargetStatusInfo] = Field(default_factory=dict)
    converter_results: Dict[str, ConverterStatusInfo] = Field(default_factory=dict)
    sarif: Annotated[
        SarifReport | None,
        Field(description="The SARIF formatted vulnerability report"),
    ] = SarifReport(
        version="2.1.0",
        runs=[
            Run(
                tool=Tool(
                    driver=ToolComponent(
                        name="AWS Labs - Automated Security Helper",
                        fullName="awslabs/automated-security-helper",
                        version=get_ash_version(),
                        organization="Amazon Web Services",
                        downloadUri=AnyUrl(ASH_REPO_URL),
                        informationUri=AnyUrl(ASH_DOCS_URL),
                    ),
                    extensions=[],
                ),
                results=[],
                invocations=[],
                properties=PropertyBag(),
            )
        ],
    )
    cyclonedx: Annotated[
        CycloneDXReport | None,
        Field(description="The CycloneDXReport formatted SBOM report"),
    ] = CycloneDXReport()
    additional_reports: Annotated[
        Dict[str, Any],
        Field(
            description="Dictionary of additional reports where the keys are the scanner name and the values are the outputs of the scanner."
        ),
    ] = {}
    validation_checkpoints: Annotated[
        List[Dict[str, Any]],
        Field(
            description="List of validation checkpoints captured during the scan process for debugging and monitoring.",
            default_factory=list,
        ),
    ]
    used_suppressions: Annotated[
        set[str],
        Field(
            description="Set of suppression IDs that were actually applied to findings during the scan.",
            default_factory=set,
        ),
    ]

    # Private cache for to_flat_vulnerabilities() — the method mutates
    # summary_stats.suppressed and scanner_results as a side effect, so
    # we memoize the result to keep the method idempotent when reporters
    # call it multiple times during rendering.
    _flat_cache: Optional[List[FlatVulnerability]] = PrivateAttr(default=None)

    @field_validator("ash_config")
    @classmethod
    def validate_ash_config(cls, v: Any):
        from automated_security_helper.config.ash_config import AshConfig

        try:
            return AshConfig.model_validate(v)
        except Exception as e:
            ASH_LOGGER.error(f"Failed to validate ASH config: {e}")
        return get_default_config()

    def model_post_init(self, context):
        """Initialize aggregator and trend analyzer with current findings."""
        if self.scanner_results is None:
            self.scanner_results = {}
        return super().model_post_init(context)

    def metadata_only(self) -> dict:
        """Produces a simplified version of the aggregated results without the
            sarif or cyclonedx properties.

        Returns:
            dict: A simple dictionary representation of the AshAggregatedResults
        """
        return self.metadata.model_dump(
            by_alias=True,
            exclude=["sarif", "cyclonedx"],
            exclude_unset=True,
            mode="json",
        )

    def to_simple_dict(self) -> dict:
        """Convert the AshAggregatedResults to a simple dictionary representation.

        Returns:
            dict: A simple dictionary representation of the AshAggregatedResults
        """
        conf = {}
        if self.ash_config is not None:
            conf = self.ash_config.model_dump(by_alias=True, exclude_unset=True)
        if len(conf.keys()) == 0:
            conf = get_default_config()
        simple_dict = {
            "name": self.name,
            "description": self.description,
            "metadata": self.metadata.model_dump(by_alias=True, exclude_unset=True),
            "converter_results": {
                k: v.model_dump(by_alias=True, exclude_unset=True)
                for k, v in sorted(self.converter_results.items())
            },
            "scanner_results": {
                k: v.model_dump(by_alias=True, exclude_unset=True)
                for k, v in sorted(self.scanner_results.items())
            },
            "ash_config": conf,
        }
        return simple_dict

    def to_flat_vulnerabilities(self) -> List[FlatVulnerability]:
        """Convert the AshAggregatedResults to a list of flattened vulnerability objects.

        The first call materializes the list and applies legacy side effects
        (bumping summary_stats.suppressed, updating scanner_results). Subsequent
        calls return the memoized list so the method is safe to call from
        reporters multiple times per run.

        Returns:
            List[FlatVulnerability]: A list of flattened vulnerability objects
        """
        if self._flat_cache is not None:
            return self._flat_cache

        flat_vulns: List[FlatVulnerability] = []

        if self.sarif and self.sarif.runs:
            for run in self.sarif.runs:
                if not run.results:
                    continue

                tool_name = "Unknown"
                tool_type = "UNKNOWN"
                if run.tool and run.tool.driver:
                    tool_name = run.tool.driver.name
                    driver_props = getattr(run.tool.driver, "properties", None)
                    driver_tags = getattr(driver_props, "tags", None) if driver_props else None
                    if driver_tags:
                        for tag in driver_tags:
                            if tag.upper() in {
                                "SAST",
                                "DAST",
                                "SCA",
                                "IAC",
                                "SECRETS",
                                "CONTAINER",
                                "SBOM",
                            }:
                                tool_type = tag.upper()
                                break

                for result in run.results:
                    flat_vuln = FlatVulnerability.from_sarif_result(
                        result, tool_name, tool_type
                    )
                    flat_vulns.append(flat_vuln)

                    if flat_vuln.is_suppressed:
                        self._apply_suppression_side_effects(flat_vuln.scanner)

        for scanner_name, results in self.additional_reports.items():
            if results is None:
                continue
            if isinstance(results, dict) and "severity_counts" in results:
                continue
            if isinstance(results, list):
                for finding in results:
                    if not isinstance(finding, dict):
                        continue
                    flat_vulns.append(
                        FlatVulnerability.from_additional_report(finding, scanner_name)
                    )

        self._flat_cache = flat_vulns
        return flat_vulns

    def _apply_suppression_side_effects(self, scanner: Optional[str]) -> None:
        """Bump summary_stats.suppressed and the matching scanner_results entry.

        Extracted from the inline SARIF processing in to_flat_vulnerabilities()
        so the conversion factory can stay side-effect free. Preserves the
        legacy behavior: one ``suppressed`` bump per suppressed finding plus an
        increment to the scanner_results entry when one exists.
        """
        self.metadata.summary_stats.bump("suppressed")

        if not scanner:
            return
        key = scanner.lower()
        if key not in self.scanner_results:
            return

        target_info: ScannerTargetStatusInfo | dict = self.scanner_results[key]
        if isinstance(target_info, dict):
            target_info = ScannerTargetStatusInfo.model_validate(target_info)
        if target_info is None:
            return

        if target_info.suppressed_finding_count is None:
            target_info.suppressed_finding_count = 1
        else:
            target_info.suppressed_finding_count += 1

        if not hasattr(target_info.severity_counts, "suppressed"):
            target_info.severity_counts.suppressed = 1
        else:
            target_info.severity_counts.suppressed += 1

    @classmethod
    def from_json(cls, json_data: Union[str, Dict[str, Any]]) -> "AshAggregatedResults":
        """Parse JSON data into an AshAggregatedResults instance.

        Args:
            json_data: Either a JSON string or dictionary containing the report data.
                Must include metadata and findings fields.

        Returns:
            AshAggregatedResults instance populated with the report data.

        Raises:
            ValidationError: If the JSON data is missing required fields or has invalid values.
        """
        if isinstance(json_data, str):
            return cls.model_validate_json(json_data)
        return cls.model_validate(json_data)

    def save_model(self, output_dir: Path) -> None:
        """Save AshAggregatedResults as JSON alongside aggregated results.

        This method populates the final metrics right before saving to ensure
        all metrics are aligned and based on the final processed SARIF data.
        """
        # Populate final metrics right before saving (if not already done)
        if not self.scanner_results:
            self._populate_final_metrics()

        report_dir = output_dir.joinpath("reports")
        report_dir.mkdir(parents=True, exist_ok=True)

        # Save aggregated results as JSON
        json_path = output_dir.joinpath("ash_aggregated_results.json")
        json_path.write_text(
            self.model_dump_json(
                by_alias=True,
                exclude_unset=True,
                exclude_none=True,
            )
        )

    def _populate_final_metrics(self) -> None:
        """Populate scanner_results and summary_stats from final SARIF data.

        This ensures all metrics are aligned and based on the final processed
        SARIF data after all suppressions have been applied.
        """
        from automated_security_helper.core.unified_metrics import (
            _populate_summary_stats_from_unified_metrics,
            get_unified_scanner_metrics,
        )

        ASH_LOGGER.debug("Populating final metrics from unified scanner metrics")

        try:
            # Get unified metrics from the final SARIF data
            unified_metrics = get_unified_scanner_metrics(self)
            ASH_LOGGER.debug(f"Got {len(unified_metrics)} unified metrics")

            # Note: scanner_results should remain as ScannerStatusInfo objects
            # The unified metrics are computed separately when needed
            ASH_LOGGER.debug(
                f"Unified metrics computed for {len(unified_metrics)} scanners"
            )

            # Populate summary_stats from unified metrics using the canonical
            # module-level helper in core.unified_metrics.
            _populate_summary_stats_from_unified_metrics(self, unified_metrics)

            ASH_LOGGER.debug(
                f"Populated final metrics for {len(unified_metrics)} scanners"
            )

        except Exception as e:
            ASH_LOGGER.error(f"Error populating final metrics: {str(e)}")
            import traceback

            ASH_LOGGER.error(f"Stack trace: {traceback.format_exc()}")
            # Don't raise to avoid breaking the save operation

    @classmethod
    def load_model(cls, json_path: Path) -> Optional["AshAggregatedResults"]:
        """Load AshAggregatedResults from JSON file."""
        if not json_path.exists():
            return None

        with open(json_path) as f:
            json_data = json.load(f)

        return cls.from_json(json_data)


# Resolve the AshConfig forward reference so model_validate_json works
# regardless of import order (e.g. in isolated uvx environments).
# Uses a deferred function to avoid circular imports since ash_config.py
# imports from this module's package.
def _resolve_forward_refs():
    try:
        from automated_security_helper.config.ash_config import AshConfig  # noqa: F401

        AshAggregatedResults.model_rebuild()
    except ImportError:
        pass  # Will be resolved when AshConfig is eventually imported


_resolve_forward_refs()


if __name__ == "__main__":
    model = AshAggregatedResults()
    print(model.model_dump_json(indent=2))

#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
File-based scan tracking utilities for ASH MCP server.

This module provides utility functions to check for the existence of result files
and parse scan result files to extract progress information. It implements a more
reliable approach to track scan progress and completion than event-based tracking.
"""

from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Set

from automated_security_helper.core.resource_management.exceptions import (
    MCPResourceError,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.utils.log import ASH_LOGGER

# Configure module logger
_logger = ASH_LOGGER


class ScannerStatus(Enum):
    """Status of an individual scanner."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class ScannerProgress:
    """
    Progress information for an individual scanner.

    This class tracks the progress of a single scanner, including its status,
    target types (source or converted), duration, and finding counts.
    """

    def __init__(
        self,
        scanner_name: str,
        target_type: str,
        status: ScannerStatus = ScannerStatus.PENDING,
        duration: Optional[float] = None,
        finding_count: int = 0,
        severity_counts: Dict[str, int] = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
            "suppressed": 0,
        },
    ):
        """
        Initialize a scanner progress tracker.

        Args:
            scanner_name: Name of the scanner
            target_type: Type of target being scanned ("source" or "converted")
            status: Current status of the scanner
            duration: Duration of the scan in seconds (if completed)
            finding_count: Number of findings detected
            severity_counts: Dictionary mapping severity levels to counts
        """
        self.scanner_name = scanner_name
        self.target_type = target_type
        self.status = status
        self.duration = duration
        self.finding_count = finding_count
        self.severity_counts = severity_counts or {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
            "suppressed": 0,
        }
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None

    def mark_running(self) -> None:
        """Mark the scanner as running and record the start time."""
        self.status = ScannerStatus.RUNNING
        self.start_time = datetime.now()

    def mark_completed(self) -> None:
        """Mark the scanner as completed and calculate duration."""
        self.status = ScannerStatus.COMPLETED
        self.end_time = datetime.now()
        if self.start_time:
            self.duration = (self.end_time - self.start_time).total_seconds()

    def mark_failed(self) -> None:
        """Mark the scanner as failed and calculate duration."""
        self.status = ScannerStatus.FAILED
        self.end_time = datetime.now()
        if self.start_time:
            self.duration = (self.end_time - self.start_time).total_seconds()

    def mark_skipped(self) -> None:
        """Mark the scanner as skipped."""
        self.status = ScannerStatus.SKIPPED

    def update_findings(self, findings: List[Dict[str, Any]]) -> None:
        """
        Update finding counts based on a list of findings.

        Args:
            findings: List of finding dictionaries
        """
        self.finding_count = len(findings)
        self.severity_counts = extract_findings_summary(findings)

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the scanner progress to a dictionary.

        Returns:
            Dictionary representation of the scanner progress
        """
        return {
            "scanner_name": self.scanner_name,
            "target_type": self.target_type,
            "status": self.status.value,
            "duration": self.duration,
            "finding_count": self.finding_count,
            "severity_counts": self.severity_counts,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
        }


class ScanProgress:
    """
    Aggregate progress information for a complete scan.

    This class aggregates progress information from multiple scanners and
    provides an overall view of the scan progress.
    """

    def __init__(
        self,
        scan_id: str,
        status: str = "in_progress",
        start_time: Optional[datetime] = None,
    ):
        """
        Initialize a scan progress tracker.

        Args:
            scan_id: ID of the scan
            status: Current status of the scan
            start_time: Start time of the scan
        """
        self.scan_id = scan_id
        self.status = status
        self.scanners: Dict[str, Dict[str, ScannerProgress]] = {}
        self.start_time = start_time or datetime.now()
        self.end_time: Optional[datetime] = None
        self.duration: Optional[float] = None
        self.total_findings: int = 0
        self.severity_counts: Dict[str, int] = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
            "suppressed": 0,
        }

    def add_scanner_progress(self, scanner_progress: ScannerProgress) -> None:
        """
        Add or update progress information for a scanner.

        Args:
            scanner_progress: Scanner progress information
        """
        scanner_name = scanner_progress.scanner_name
        target_type = scanner_progress.target_type

        # Initialize scanner dictionary if it doesn't exist
        if scanner_name not in self.scanners:
            self.scanners[scanner_name] = {}

        # Add or update scanner progress
        self.scanners[scanner_name][target_type] = scanner_progress

        # Update total findings and severity counts
        self.update_totals()

    def update_totals(self) -> None:
        """Update total findings and severity counts from all scanners."""
        self.total_findings = 0
        self.severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
            "suppressed": 0,
        }

        for scanner_dict in self.scanners.values():
            for scanner_progress in scanner_dict.values():
                self.total_findings += scanner_progress.finding_count
                for severity, count in scanner_progress.severity_counts.items():
                    if severity in self.severity_counts:
                        self.severity_counts[severity] += count

    def mark_completed(self) -> None:
        """Mark the scan as completed and calculate duration."""
        self.status = "completed"
        self.end_time = datetime.now()
        self.duration = (self.end_time - self.start_time).total_seconds()

    def mark_failed(self) -> None:
        """Mark the scan as failed and calculate duration."""
        self.status = "failed"
        self.end_time = datetime.now()
        self.duration = (self.end_time - self.start_time).total_seconds()

    @property
    def completed_scanners(self) -> int:
        """
        Get the number of completed scanners.

        Returns:
            Number of completed scanners
        """
        count = 0
        for scanner_dict in self.scanners.values():
            for scanner_progress in scanner_dict.values():
                if scanner_progress.status == ScannerStatus.COMPLETED:
                    count += 1
        return count

    @property
    def total_scanners(self) -> int:
        """
        Get the total number of scanners.

        Returns:
            Total number of scanners
        """
        count = 0
        for scanner_dict in self.scanners.values():
            count += len(scanner_dict)
        return count

    @property
    def is_complete(self) -> bool:
        """
        Check if the scan is complete.

        Returns:
            True if the scan is complete, False otherwise
        """
        return self.status in ["completed", "failed"]

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the scan progress to a dictionary.

        Returns:
            Dictionary representation of the scan progress
        """
        scanner_progress_dict = {}
        for scanner_name, target_dict in self.scanners.items():
            scanner_progress_dict[scanner_name] = {
                target_type: progress.to_dict()
                for target_type, progress in target_dict.items()
            }

        return {
            "scan_id": self.scan_id,
            "status": self.status,
            "is_complete": self.is_complete,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration": self.duration,
            "completed_scanners": self.completed_scanners,
            "total_scanners": self.total_scanners,
            "total_findings": self.total_findings,
            "severity_counts": self.severity_counts,
            "scanners": scanner_progress_dict,
        }


def check_scan_completion(
    output_dir: Path = Path.cwd().joinpath(".ash", "ash_output"),
) -> bool:
    """
    Check if a scan has completed by looking for the aggregated results file.

    Args:
        output_dir: Path to the scan output directory

    Returns:
        True if the scan has completed, False otherwise
    """
    aggregated_results_path = output_dir / "ash_aggregated_results.json"
    return aggregated_results_path.exists()


def find_scanner_result_files(
    output_dir: Path = Path.cwd().joinpath(".ash", "ash_output"),
) -> Dict[str, Dict[str, Path]]:
    """
    Find individual scanner result files to determine partial progress.

    Args:
        output_dir: Path to the scan output directory

    Returns:
        Dictionary mapping scanner names to target types and result file paths
    """
    scanner_results: Dict[str, Dict[str, Path]] = {}

    # Look for scanner result files in the pattern:
    # .ash/ash_output/scanners/{scanner_name}/{target_type}/ASH.ScanResults.json
    scanners_dir = output_dir / "scanners"

    if not scanners_dir.exists():
        return scanner_results

    for scanner_dir in scanners_dir.iterdir():
        if not scanner_dir.is_dir():
            continue

        scanner_name = scanner_dir.name
        scanner_results[scanner_name] = {}

        for target_dir in scanner_dir.iterdir():
            if not target_dir.is_dir():
                continue

            target_type = target_dir.name
            result_file = target_dir / "ASH.ScanResults.json"

            if result_file.exists():
                scanner_results[scanner_name][target_type] = result_file

    return scanner_results


def get_completed_scanners(
    output_dir: Path = Path.cwd().joinpath(".ash", "ash_output"),
) -> Set[str]:
    """
    Get the set of scanners that have completed at least one target.

    Args:
        output_dir: Path to the scan output directory

    Returns:
        Set of scanner names that have completed at least one target
    """
    scanner_results = find_scanner_result_files(output_dir)
    return set(scanner_results.keys())


def get_scanner_progress(
    output_dir: Path = Path.cwd().joinpath(".ash", "ash_output"),
) -> Dict[str, Dict[str, Any]]:
    """
    Get progress information for each scanner.

    Args:
        output_dir: Path to the scan output directory

    Returns:
        Dictionary mapping scanner names to progress information
    """
    scanner_progress: Dict[str, Dict[str, Any]] = {}
    scanner_results = find_scanner_result_files(output_dir)

    for scanner_name, target_results in scanner_results.items():
        scanner_progress[scanner_name] = {
            "targets_completed": list(target_results.keys()),
            "targets_count": len(target_results),
            "findings": [],
        }

        # Parse result files to extract findings
        for target_type, result_file in target_results.items():
            try:
                findings = parse_scanner_result_file(result_file)
                scanner_progress[scanner_name]["findings"].extend(findings)
            except Exception as e:
                _logger.warning(
                    f"Failed to parse result file for scanner {scanner_name}, target {target_type}: {str(e)}"
                )

    return scanner_progress


def parse_scanner_result_file(
    result_file: Path = Path.cwd().joinpath(
        ".ash", "ash_output", "ash_aggregated_results.json"
    ),
) -> List[Dict[str, Any]]:
    """
    Parse a scanner result file to extract findings.

    Args:
        result_file: Path to the scanner result file

    Returns:
        List of findings from the scanner result file
    """
    from automated_security_helper.core.resource_management.error_handling import (
        safe_read_json_file,
    )

    # Use safe_read_json_file for robust error handling
    data, error = safe_read_json_file(result_file, required=True)

    if error:
        _logger.warning(f"Error reading result file {result_file}: {str(error)}")
        return []

    # Extract findings from the result file
    # The structure is expected to be:
    # {
    #   "findings": [
    #     {
    #       "id": "...",
    #       "severity": "...",
    #       ...
    #     },
    #     ...
    #   ]
    # }

    if data and "findings" in data and isinstance(data["findings"], list):
        return data["findings"]
    else:
        _logger.warning(f"Unexpected result file structure: {result_file}")
        return []


def parse_aggregated_results(
    output_dir: Path = Path.cwd().joinpath(".ash", "ash_output"),
) -> Dict[str, Any] | None:
    """
    Parse the aggregated results file to extract scan results.

    Args:
        output_dir: Path to the scan output directory

    Returns:
        Dictionary containing the parsed aggregated results

    Raises:
        MCPResourceError: If the aggregated results file is not found or cannot be parsed
    """
    from automated_security_helper.core.resource_management.error_handling import (
        safe_read_json_file,
        ErrorCategory,
    )

    aggregated_results_path = output_dir / "ash_aggregated_results.json"

    # Use safe_read_json_file for robust error handling
    data, error = safe_read_json_file(aggregated_results_path, required=True)

    if error:
        # Enhance the error with additional context
        if error.context.get("error_category") == ErrorCategory.FILE_NOT_FOUND.value:
            raise MCPResourceError(
                f"Aggregated results file not found: {aggregated_results_path}",
                context={
                    "output_dir": str(output_dir),
                    "error_category": ErrorCategory.FILE_NOT_FOUND.value,
                    "suggestions": [
                        "Check if the scan has completed",
                        "Verify the output directory path is correct",
                        "Ensure the scan process has write permissions to the output directory",
                    ],
                },
            )
        else:
            # For other errors, propagate with enhanced context
            error.context["output_dir"] = str(output_dir)
            raise error

    return data


def create_scan_progress_from_files(
    scan_id: str, output_dir: Path = Path.cwd().joinpath(".ash", "ash_output")
) -> ScanProgress:
    """
    Create a ScanProgress object by analyzing scan result files.

    Args:
        scan_id: ID of the scan
        output_dir: Path to the scan output directory

    Returns:
        ScanProgress object with information from scan result files
    """
    # Check if scan has completed
    is_complete = check_scan_completion(output_dir)

    # Create scan progress object
    scan_progress = ScanProgress(scan_id=scan_id)

    if is_complete:
        try:
            # Parse aggregated results for completed scans
            results = parse_aggregated_results(output_dir)

            if results:
                # Update scan progress with aggregated results
                scan_progress.mark_completed()

                # Extract findings from aggregated results
                findings = []

                # Try to extract findings from SARIF data if available
                if (
                    "sarif" in results
                    and results["sarif"]
                    and "runs" in results["sarif"]
                ):
                    for run in results["sarif"]["runs"]:
                        if "results" in run:
                            for result in run["results"]:
                                # Convert SARIF result to a simplified finding
                                finding = {
                                    "id": result.get("ruleId", "unknown"),
                                    "severity": result.get("level", "MEDIUM").upper(),
                                    "scanner": run.get("tool", {})
                                    .get("driver", {})
                                    .get("name", "unknown"),
                                }
                                findings.append(finding)

                # If no findings were found in SARIF, check scanner_results
                if not findings and "scanner_results" in results:
                    for scanner_name, scanner_info in results[
                        "scanner_results"
                    ].items():
                        # Create a finding for each scanner with severity counts
                        severity_counts = scanner_info.get("severity_counts", {})
                        for severity, count in severity_counts.items():
                            if count > 0:
                                finding = {
                                    "id": f"{scanner_name}-{severity.lower()}",
                                    "severity": severity.upper(),
                                    "scanner": scanner_name,
                                    "count": count,
                                }
                                findings.append(finding)

                # Create scanner progress objects for each completed scanner
                for scanner_name, scanner_info in results.get(
                    "scanner_results", {}
                ).items():
                    # Filter findings for this scanner
                    scanner_findings = [
                        f for f in findings if f.get("scanner") == scanner_name
                    ]

                    # Create scanner progress for source target
                    source_progress = ScannerProgress(
                        scanner_name=scanner_name,
                        target_type="source",
                        status=ScannerStatus.COMPLETED,
                        finding_count=scanner_info.get("finding_count", 0),
                    )

                    # Update severity counts from scanner_info
                    if "severity_counts" in scanner_info:
                        source_progress.severity_counts = scanner_info[
                            "severity_counts"
                        ]
                    else:
                        source_progress.update_findings(scanner_findings)

                    source_progress.mark_completed()

                    # Add to scan progress
                    scan_progress.add_scanner_progress(source_progress)

            return scan_progress

        except MCPResourceError as e:
            # Handle errors parsing aggregated results
            _logger.error(f"Error parsing aggregated results: {str(e)}")
            scan_progress.mark_failed()
            return scan_progress
    else:
        # Find individual scanner result files
        scanner_results = find_scanner_result_files(output_dir)

        # Create scanner progress objects for each scanner with results
        for scanner_name, target_results in scanner_results.items():
            for target_type, result_file in target_results.items():
                try:
                    # Parse scanner result file
                    findings = parse_scanner_result_file(result_file)

                    # Create scanner progress
                    scanner_progress = ScannerProgress(
                        scanner_name=scanner_name,
                        target_type=target_type,
                        status=ScannerStatus.COMPLETED,
                        finding_count=len(findings),
                    )
                    scanner_progress.update_findings(findings)
                    scanner_progress.mark_completed()

                    # Add to scan progress
                    scan_progress.add_scanner_progress(scanner_progress)

                except Exception as e:
                    _logger.warning(
                        f"Error parsing result file for scanner {scanner_name}, target {target_type}: {str(e)}"
                    )

        return scan_progress


def get_scan_progress_info(
    output_dir: Path = Path.cwd().joinpath(".ash", "ash_output"),
) -> Dict[str, Any]:
    """
    Get comprehensive scan progress information.

    Args:
        output_dir: Path to the scan output directory

    Returns:
        Dictionary containing scan progress information
    """
    # Check if scan has completed
    is_complete = check_scan_completion(output_dir)

    if is_complete:
        try:
            # Parse aggregated results for completed scans
            results = parse_aggregated_results(output_dir)

            # Extract key information from results
            findings = []

            if results:
                # Try to extract findings from SARIF data if available
                if (
                    "sarif" in results
                    and results["sarif"]
                    and "runs" in results["sarif"]
                ):
                    for run in results["sarif"]["runs"]:
                        if "results" in run:
                            findings.extend(run["results"])

                # Extract scanner names from scanner_results
                scanners_completed = list(results.get("scanner_results", {}).keys())

                # Extract severity counts from metadata if available
                findings_summary = {}
                if "metadata" in results and "summary_stats" in results["metadata"]:
                    summary_stats = results["metadata"]["summary_stats"]
                    findings_summary = summary_stats
                else:
                    findings_summary = extract_findings_summary(findings)

            completion_time = (
                results.get("metadata", {}).get(
                    "generated_at", datetime.now().isoformat()
                )
                if results
                else datetime.now().isoformat()
            )

            return {
                "status": "completed",
                "is_complete": True,
                "scanners_completed": scanners_completed,
                "total_scanners": len(scanners_completed),
                "findings_count": len(findings),
                "findings": findings,
                "findings_summary": findings_summary,
                "completion_time": completion_time,
            }
        except MCPResourceError as e:
            # Handle errors parsing aggregated results
            return {
                "status": "error",
                "is_complete": True,
                "error": str(e),
                "context": e.context if hasattr(e, "context") else {},
            }
    else:
        # Get partial progress for incomplete scans
        scanner_progress = get_scanner_progress(output_dir)
        completed_scanners = get_completed_scanners(output_dir)

        # Aggregate findings from all scanners
        all_findings = []
        for scanner_info in scanner_progress.values():
            all_findings.extend(scanner_info.get("findings", []))

        return {
            "status": "in_progress",
            "is_complete": False,
            "scanners_completed": list(completed_scanners),
            "total_scanners": len(
                completed_scanners
            ),  # This is an estimate since we don't know the total yet
            "findings_count": len(all_findings),
            "findings": all_findings,
            "findings_summary": extract_findings_summary(all_findings),
            "scanner_progress": scanner_progress,
        }


def extract_findings_summary(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    """
    Extract a summary of findings by severity.

    Args:
        findings: List of findings

    Returns:
        Dictionary mapping severity levels to counts
    """
    summary = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
        "suppressed": 0,
    }

    for finding in findings:
        severity = finding.get("severity", "UNKNOWN").upper()
        if severity in summary:
            summary[severity] += 1

    return summary


def validate_output_directory(output_dir: Path) -> Tuple[bool, Optional[str]]:
    """
    Validate that the output directory exists and has the expected structure.

    Args:
        output_dir: Path to the scan output directory

    Returns:
        Tuple of (is_valid, error_message)
    """
    from automated_security_helper.core.resource_management.error_handling import (
        validate_directory_path,
    )

    # Use validate_directory_path for robust error handling
    error = validate_directory_path(output_dir)
    if error:
        return False, str(error)

    # Check if the directory has the expected structure
    scanners_dir = output_dir / "scanners"
    if not scanners_dir.exists() and not check_scan_completion(output_dir):
        return (
            False,
            "Invalid output directory structure: missing 'scanners' directory and no aggregated results",
        )

    return True, None


def get_scan_results(
    output_dir: Path = Path.cwd().joinpath(".ash", "ash_output"),
) -> Dict[str, Any]:
    """
    Get the results of a completed scan.

    Args:
        scan_id: ID of the scan (can be None or arbitrary if just looking for results in output_dir)
        output_dir: Path to the scan output directory

    Returns:
        Dictionary containing scan results information

    Raises:
        MCPResourceError: If the scan results cannot be retrieved
    """
    from automated_security_helper.core.resource_management.error_handling import (
        validate_directory_path,
        ErrorCategory,
    )

    scan_id = None

    # Validate output directory
    error = validate_directory_path(output_dir)
    if error:
        raise error

    # Check if scan has completed by looking for the aggregated results file
    is_complete = check_scan_completion(output_dir)

    if not is_complete:
        raise MCPResourceError(
            f"Scan results not available in {output_dir}.",
            context={
                # "scan_id": scan_id,
                "output_dir": str(output_dir),
                "error_category": ErrorCategory.SCAN_INCOMPLETE.value,
                "suggestions": [
                    "Wait for the scan to complete",
                    "Check if the scan process is still running",
                    "Verify that the scan was started correctly",
                    "Ensure the output directory is correct",
                ],
            },
        )

    try:
        # Parse aggregated results
        int_results_dict = parse_aggregated_results(output_dir)
        results: AshAggregatedResults = AshAggregatedResults(**int_results_dict)

        # Validate result structure
        is_valid, validation_error = validate_result_structure(results)
        if not is_valid:
            raise MCPResourceError(
                f"Invalid result structure: {validation_error}",
                context={
                    # "scan_id": scan_id,
                    "output_dir": str(output_dir),
                    "error_category": ErrorCategory.INVALID_FORMAT.value,
                    "suggestions": [
                        "Check if the scan completed successfully",
                        "Verify that the results file was not corrupted",
                        "Ensure the scan process has proper permissions",
                    ],
                },
            )

        # Build comprehensive results object
        results_dict = results.model_dump(
            exclude=[
                "ash_config",
                "sarif",
                "cyclonedx",
            ],
            exclude_none=True,
            exclude_unset=True,
            by_alias=True,
            mode="json",
        )
        metadata = results_dict.get("metadata", {})
        scanners_completed = []
        for scanner_name, scanner_results in results_dict.get(
            "scanner_results", {}
        ).items():
            if scanner_results.get("status", "UNKNOWN") in ["PASSED", "FAILED"]:
                scanners_completed.append(scanner_name)

        # Use a generated scan_id if none was provided
        result_scan_id = (
            scan_id if scan_id else f"scan-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        )

        return {
            "scan_id": result_scan_id,
            "status": "completed",
            "is_complete": True,
            "actionable_findings": metadata.get("summary_stats", {}).get("actionable"),
            "summary_stats": metadata.get("summary_stats", {}),
            "scanner_reports": results_dict.get("additional_reports", {}),
            "total_scanners": len(scanners_completed),
            "completion_time": metadata.get("generated_at", datetime.now().isoformat()),
            "raw_results": results_dict,
        }
    except MCPResourceError as e:
        # Re-raise with additional context if needed
        if "scan_id" not in e.context:
            e.context["scan_id"] = scan_id
        if "output_dir" not in e.context:
            e.context["output_dir"] = str(output_dir)
        raise e
    except Exception as e:
        # Handle unexpected errors
        raise MCPResourceError(
            f"Unexpected error retrieving scan results: {str(e)}",
            context={
                "scan_id": scan_id,
                "cwd": str(Path.cwd()),
                "output_dir": str(output_dir),
                "error_category": ErrorCategory.UNEXPECTED_ERROR.value,
                "error_type": type(e).__name__,
                "error_message": str(e),
            },
        )


def extract_scan_summary(results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract a summary of scan results.

    Args:
        results: Dictionary containing scan results

    Returns:
        Dictionary containing a summary of the scan results
    """
    findings = results.get("findings", [])
    severity_counts = extract_findings_summary(findings)

    # Group findings by scanner
    findings_by_scanner: Dict[str, List[Dict[str, Any]]] = {}
    for finding in findings:
        scanner = finding.get("scanner", "unknown")
        if scanner not in findings_by_scanner:
            findings_by_scanner[scanner] = []
        findings_by_scanner[scanner].append(finding)

    # Create scanner summaries
    scanner_summaries = {}
    for scanner, scanner_findings in findings_by_scanner.items():
        scanner_summaries[scanner] = {
            "finding_count": len(scanner_findings),
            "severity_counts": extract_findings_summary(scanner_findings),
        }

    return {
        "findings_count": len(findings),
        "severity_counts": severity_counts,
        "scanners_completed": results.get("scanners_completed", []),
        "scanner_summaries": scanner_summaries,
        "has_critical": severity_counts.get("CRITICAL", 0) > 0,
        "has_high": severity_counts.get("HIGH", 0) > 0,
        "completion_time": results.get("completion_time"),
    }


def validate_result_structure(
    results: Dict[str, Any] | AshAggregatedResults,
) -> Tuple[bool, Optional[str]]:
    """
    Validate the structure of scan results.

    Args:
        results: Dictionary containing scan results

    Returns:
        Tuple of (is_valid, error_message)
    """
    if isinstance(results, AshAggregatedResults):
        return True, None

    # Check for required fields - we need either sarif or scanner_results
    if "sarif" not in results and "scanner_results" not in results:
        return (
            False,
            "Missing required fields: either 'sarif' or 'scanner_results' must be present",
        )

    # If sarif is present, validate its structure
    if "sarif" in results:
        sarif = results["sarif"]
        if not isinstance(sarif, dict):
            return False, "SARIF data must be a dictionary"

        if "runs" not in sarif:
            return False, "SARIF data is missing 'runs' field"

        if not isinstance(sarif["runs"], list):
            return False, "SARIF 'runs' must be a list"

    # If scanner_results is present, validate its structure
    if "scanner_results" in results:
        scanner_results = results["scanner_results"]
        if not isinstance(scanner_results, dict):
            return False, "scanner_results must be a dictionary"

    return True, None


def resolve_output_directory(source_dir=None, output_dir=None):
    """
    Resolve the output directory path based on the provided parameters.

    Args:
        source_dir: Path to the source directory that was scanned
        output_dir: Path to the scan output directory

    Returns:
        Resolved absolute Path object to the output directory
    """
    # Start with the current working directory as a base
    cwd = Path.cwd()

    # Case 1: Both source_dir and output_dir are provided
    if source_dir and output_dir:
        # If output_dir is absolute, use it directly
        if Path(output_dir).is_absolute():
            return Path(output_dir)
        # If output_dir is relative, resolve it relative to source_dir
        else:
            # If source_dir is absolute, use it directly
            if Path(source_dir).is_absolute():
                return Path(source_dir) / output_dir
            # If source_dir is relative, resolve it relative to cwd
            else:
                return (cwd / source_dir) / output_dir

    # Case 2: Only source_dir is provided
    elif source_dir:
        # If source_dir is absolute, use it directly
        if Path(source_dir).is_absolute():
            return Path(source_dir) / ".ash" / "ash_output"
        # If source_dir is relative, resolve it relative to cwd
        else:
            return (cwd / source_dir) / ".ash" / "ash_output"

    # Case 3: Only output_dir is provided
    elif output_dir:
        # If output_dir is absolute, use it directly
        if Path(output_dir).is_absolute():
            return Path(output_dir)
        # If output_dir is relative, resolve it relative to cwd
        else:
            return cwd / output_dir

    # Case 4: Neither is provided, use default in current directory
    else:
        return cwd / ".ash" / "ash_output"


def get_scan_results_with_error_handling(
    output_dir: Path,
) -> Dict[str, Any]:
    """
    Get scan results with comprehensive error handling.

    This function wraps get_scan_results with additional error handling to provide
    more detailed error information and graceful degradation for various failure scenarios.

    Args:
        output_dir: Path to the scan output directory

    Returns:
        Dictionary containing scan results or error information
    """
    from automated_security_helper.core.resource_management.error_handling import (
        validate_directory_path,
        ErrorCategory,
        create_error_response,
    )

    try:
        # # Validate scan ID
        # error = validate_scan_id(scan_id)
        # if error:
        #     return create_error_response(
        #         error=error,
        #         operation="get_scan_results",
        #         suggestions=[
        #             "Check that the scan ID is correct",
        #             "Verify that the scan exists in the registry",
        #             "Ensure the scan ID format is valid",
        #         ],
        #     )

        # Validate output directory
        error = validate_directory_path(output_dir)
        if error:
            return create_error_response(
                error=error,
                operation="get_scan_results",
                suggestions=[
                    "Check that the output directory exists",
                    "Verify that the output directory path is correct",
                    "Ensure the output directory has proper permissions",
                ],
            )

        # Check if scan has completed
        is_complete = check_scan_completion(output_dir)
        if not is_complete:
            return create_error_response(
                error=MCPResourceError(
                    f"Scan of output_dir {output_dir} is not complete. Results are not available.",
                    context={
                        # "scan_id": scan_id,
                        "output_dir": str(output_dir),
                        "error_category": ErrorCategory.SCAN_INCOMPLETE.value,
                    },
                ),
                operation="get_scan_results",
                suggestions=[
                    "Wait for the scan to complete",
                    "Check if the scan process is still running",
                    "Verify that the scan was started correctly",
                ],
            )

        # Get scan results
        results = get_scan_results(output_dir)
        return results

    except MCPResourceError as e:
        # Handle MCPResourceError with enhanced context
        return create_error_response(
            error=e,
            operation="get_scan_results",
        )
    except Exception as e:
        # Handle unexpected errors
        _logger.error(f"Unexpected error getting scan results: {str(e)}", exc_info=True)
        return create_error_response(
            error=MCPResourceError(
                f"Unexpected error getting scan results: {str(e)}",
                context={
                    # "scan_id": scan_id,
                    "cwd": str(Path.cwd()),
                    "output_dir": str(output_dir),
                    "error_category": ErrorCategory.UNEXPECTED_ERROR.value,
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                },
            ),
            operation="get_scan_results",
        )

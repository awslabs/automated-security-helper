# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Centralized scanner statistics calculator.

This module provides a centralized implementation for extracting statistics from the final
aggregated SARIF file. It ensures all calculations are based on the final SARIF data,
not individual scanner reports, and provides a consistent way to identify scanners and
count findings across all components of ASH.

The ScannerStatisticsCalculator class is responsible for the low-level details of parsing
the SARIF data structures and aggregating counts. It handles edge cases such as missing data,
excluded scanners, and scanners with missing dependencies.

This module is used by the unified_metrics module to provide a consistent API for all
components that need to display or process scanner statistics.

Example usage:
    ```python
    from automated_security_helper.core.scanner_statistics_calculator import ScannerStatisticsCalculator

    # Extract statistics for all scanners
    scanner_stats = ScannerStatisticsCalculator.extract_scanner_statistics(asharp_model)

    # Get summary statistics
    summary_stats = ScannerStatisticsCalculator.get_summary_statistics(asharp_model)
    ```
"""

from typing import Dict, Any, Optional, Tuple

from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.constants import ASH_DEFAULT_SEVERITY_LEVEL
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.utils.log import ASH_LOGGER


class ScannerStatisticsCalculator:
    """Centralized calculator for scanner statistics from SARIF data.

    This class provides static methods for extracting and calculating scanner statistics
    from the final aggregated SARIF data. It handles the low-level details of parsing
    the data structures and aggregating counts, ensuring that all calculations are
    consistent across all components of ASH.

    The class is designed to be used by the unified_metrics module, which provides
    a higher-level API for accessing scanner statistics. However, it can also be
    used directly if more fine-grained control over the statistics calculation is needed.

    Key responsibilities:
    - Extracting statistics from the final SARIF data
    - Identifying scanners and counting findings
    - Calculating actionable findings based on thresholds
    - Determining scanner status based on findings and configuration
    - Calculating summary statistics across all scanners
    """

    @staticmethod
    def extract_scanner_statistics(
        asharp_model: AshAggregatedResults,
    ) -> Dict[str, Dict[str, Any]]:
        """Extract statistics for all scanners from the final aggregated SARIF file.

        This method processes the final SARIF data to extract statistics for all scanners.
        It iterates through all scanner names in the scanner_results dictionary and
        calculates statistics for each scanner, including:

        - Counts for different severity levels (critical, high, medium, low, info)
        - Count of suppressed findings
        - Total number of findings
        - Number of actionable findings based on threshold
        - Scanner duration
        - Threshold information
        - Status information (excluded, dependencies missing)

        Args:
            asharp_model: The AshAggregatedResults model containing the final SARIF data

        Returns:
            Dictionary mapping scanner names to their statistics, with each statistics
            dictionary containing the following keys:
            - suppressed: Number of suppressed findings
            - critical: Number of critical findings
            - high: Number of high findings
            - medium: Number of medium findings
            - low: Number of low findings
            - info: Number of informational findings
            - total: Total number of non-suppressed findings
            - actionable: Number of findings at or above the threshold severity
            - duration: Time taken by the scanner in seconds
            - threshold: Severity threshold used for this scanner
            - threshold_source: Source of the threshold ("global", "config", etc.)
            - excluded: Whether the scanner was explicitly excluded
            - dependencies_missing: Whether the scanner has missing dependencies
        """
        scanner_stats = {}

        # Get scanner names from multiple sources:
        # 1. SARIF data (scanners that produced SARIF results)
        # 2. Additional reports (scanners that produced non-SARIF results)
        # 3. Scanner results (scanners that have status information)
        from automated_security_helper.utils.log import ASH_LOGGER

        sarif_scanner_names = ScannerStatisticsCalculator._get_scanner_names_from_sarif(
            asharp_model
        )
        additional_reports_scanners = (
            list(asharp_model.additional_reports.keys())
            if asharp_model.additional_reports
            else []
        )
        scanner_results_scanners = (
            list(asharp_model.scanner_results.keys())
            if asharp_model.scanner_results
            else []
        )

        # Combine all sources
        scanner_names = list(
            set(
                sarif_scanner_names
                + additional_reports_scanners
                + scanner_results_scanners
            )
        )

        ASH_LOGGER.debug("Scanner Discovery Summary:")
        ASH_LOGGER.debug(
            f"   SARIF scanners: {len(sarif_scanner_names)} - {sorted(sarif_scanner_names)}"
        )
        ASH_LOGGER.debug(
            f"   Additional reports scanners: {len(additional_reports_scanners)} - {sorted(additional_reports_scanners)}"
        )
        ASH_LOGGER.debug(
            f"   Scanner results scanners: {len(scanner_results_scanners)} - {sorted(scanner_results_scanners)}"
        )
        ASH_LOGGER.debug(
            f"   Combined unique scanners: {len(scanner_names)} - {sorted(scanner_names)}"
        )

        # Extract statistics for each scanner
        for scanner_name in scanner_names:
            suppressed, critical, high, medium, low, info = (
                ScannerStatisticsCalculator.extract_sarif_counts_for_scanner(
                    asharp_model, scanner_name
                )
            )

            threshold, threshold_source = (
                ScannerStatisticsCalculator.get_scanner_threshold_info(
                    asharp_model, scanner_name
                )
            )

            excluded, dependencies_missing, error = (
                ScannerStatisticsCalculator.get_scanner_status_info(
                    asharp_model, scanner_name
                )
            )

            total = critical + high + medium + low + info + suppressed

            # Calculate actionable findings based on threshold
            actionable = ScannerStatisticsCalculator.calculate_actionable_count(
                critical, high, medium, low, info, threshold
            )

            # Calculate duration from additional_reports (where container data is stored)
            duration = 0.0

            # First try to get duration from additional_reports (where full container data is stored)
            if (
                scanner_name in asharp_model.additional_reports
                and "source" in asharp_model.additional_reports[scanner_name]
            ):
                container_data = asharp_model.additional_reports[scanner_name]["source"]
                if isinstance(container_data, dict) and "duration" in container_data:
                    # Handle None duration (for skipped/missing scanners) by keeping it as None
                    duration = (
                        container_data["duration"]
                        if container_data["duration"] is not None
                        else None
                    )
                    ASH_LOGGER.debug(
                        f"Got duration for {scanner_name} from additional_reports: {duration}"
                    )

            # Fallback to scanner_results if available (for backward compatibility)
            elif scanner_name in asharp_model.scanner_results:
                scanner_status_info = asharp_model.scanner_results[scanner_name]

                # Debug logging
                from automated_security_helper.utils.log import ASH_LOGGER

                ASH_LOGGER.debug(
                    f"Processing {scanner_name}: type={type(scanner_status_info)}"
                )
                ASH_LOGGER.debug(
                    f"   Has 'source': {hasattr(scanner_status_info, 'source')}"
                )
                ASH_LOGGER.debug(
                    f"   Has 'converted': {hasattr(scanner_status_info, 'converted')}"
                )
                ASH_LOGGER.debug(
                    f"   Has 'duration': {hasattr(scanner_status_info, 'duration')}"
                )

                # Handle both old ScannerStatusInfo and new ScannerMetrics structures
                if hasattr(scanner_status_info, "source") and hasattr(
                    scanner_status_info, "converted"
                ):
                    # Old ScannerStatusInfo structure
                    ASH_LOGGER.debug("   Using OLD ScannerStatusInfo structure")
                    source_duration = (
                        float(scanner_status_info.source.duration)
                        if hasattr(scanner_status_info.source, "duration")
                        else 0
                    )
                    converted_duration = (
                        float(scanner_status_info.converted.duration)
                        if hasattr(scanner_status_info.converted, "duration")
                        else 0
                    )
                    duration = source_duration + converted_duration
                elif hasattr(scanner_status_info, "duration"):
                    # New ScannerMetrics structure
                    ASH_LOGGER.debug("   Using NEW ScannerMetrics structure")
                    duration = scanner_status_info.duration or 0.0
                else:
                    ASH_LOGGER.debug("   Unknown structure, using default duration")

            # Store statistics for this scanner
            scanner_stats[scanner_name] = {
                "suppressed": suppressed,
                "critical": critical,
                "high": high,
                "medium": medium,
                "low": low,
                "info": info,
                "total": total,
                "actionable": actionable,
                "duration": duration,
                "threshold": threshold,
                "threshold_source": threshold_source,
                "excluded": excluded,
                "dependencies_missing": dependencies_missing,
                "error": error,
            }

        return scanner_stats

    @staticmethod
    def _get_scanner_names_from_sarif(asharp_model: AshAggregatedResults) -> list:
        """Extract unique scanner names from SARIF data.

        This method scans through the SARIF results to find all unique scanner names
        that have produced findings. This is used when scanner_results is not yet
        populated but we need to know which scanners ran.

        Args:
            asharp_model: The AshAggregatedResults model containing SARIF data

        Returns:
            List of unique scanner names found in the SARIF data
        """
        from automated_security_helper.utils.log import ASH_LOGGER

        scanner_names = set()
        total_results = 0
        results_with_scanner_name = 0

        if asharp_model.sarif and asharp_model.sarif.runs:
            for run_idx, run in enumerate(asharp_model.sarif.runs):
                if not run.results:
                    ASH_LOGGER.debug(f"SARIF run {run_idx} has no results")
                    continue

                run_results = len(run.results)
                total_results += run_results
                ASH_LOGGER.debug(f"SARIF run {run_idx} has {run_results} results")

                for result_idx, result in enumerate(run.results):
                    scanner_name = (
                        ScannerStatisticsCalculator._get_scanner_name_from_result(
                            result
                        )
                    )
                    if scanner_name:
                        scanner_names.add(scanner_name)
                        results_with_scanner_name += 1
                    else:
                        ASH_LOGGER.debug(
                            f"Result {result_idx} in run {run_idx} has no scanner_name"
                        )

        scanner_list = list(scanner_names)
        ASH_LOGGER.debug("SARIF Scanner Discovery:")
        ASH_LOGGER.debug(f"   Total SARIF results: {total_results}")
        ASH_LOGGER.debug(f"   Results with scanner_name: {results_with_scanner_name}")
        ASH_LOGGER.debug(f"   Unique scanners found: {len(scanner_list)}")
        ASH_LOGGER.debug(f"   Scanner names: {sorted(scanner_list)}")

        return scanner_list

    @staticmethod
    def extract_sarif_counts_for_scanner(
        asharp_model: AshAggregatedResults, scanner_name: str
    ) -> Tuple[int, int, int, int, int, int]:
        """Extract severity counts from the final processed SARIF data for a specific scanner.

        This method processes the SARIF data to ensure we capture both native scanner suppressions
        and ASH-applied suppressions. It uses the scanner_name property in each finding's
        PropertyBag for scanner identification.

        The method iterates through all results in the SARIF runs and counts findings for the
        specified scanner, categorizing them by severity level. It handles suppressed findings
        separately, ensuring they don't contribute to the severity counts.

        If no findings are found in the SARIF data for the specified scanner, the method falls
        back to using the counts from scanner_results, which might be the case for scanners
        that were excluded or had missing dependencies.

        Args:
            asharp_model: The AshAggregatedResults model containing the final SARIF data
            scanner_name: Name of the scanner to extract counts for

        Returns:
            Tuple of (suppressed, critical, high, medium, low, info) counts for the specified scanner

        Note:
            The method maps SARIF levels to severity levels as follows:
            - error -> critical
            - warning -> medium
            - note -> low
            - none -> info
            - (default) -> info
        """
        # Initialize counters
        suppressed = 0
        critical = 0
        high = 0
        medium = 0
        low = 0
        info = 0

        # Process the main SARIF report
        if asharp_model.sarif and asharp_model.sarif.runs:
            for run in asharp_model.sarif.runs:
                if not run.results:
                    continue

                # Process each result in the run
                for result in run.results:
                    # Check if this result belongs to the scanner we're interested in
                    result_scanner = (
                        ScannerStatisticsCalculator._get_scanner_name_from_result(
                            result
                        )
                    )

                    if (
                        result_scanner
                        and result_scanner.lower() == scanner_name.lower()
                    ):
                        # Check if finding is suppressed (either native or ASH-applied)
                        is_suppressed = False
                        if result.suppressions and len(result.suppressions) > 0:
                            is_suppressed = True
                            suppressed += 1

                        # Only count in severity bucket if not suppressed
                        if not is_suppressed:
                            # Check if scanner provides issue_severity in properties (e.g., Bandit)
                            properties = result.properties or {}
                            issue_severity = (
                                properties.get("issue_severity", "").upper()
                                if hasattr(properties, "get")
                                else ""
                            )

                            # If issue_severity is provided, use it as the primary severity indicator
                            if issue_severity and issue_severity in [
                                "CRITICAL",
                                "HIGH",
                                "MEDIUM",
                                "LOW",
                                "INFO",
                            ]:
                                if issue_severity == "CRITICAL":
                                    critical += 1
                                elif issue_severity == "HIGH":
                                    high += 1
                                elif issue_severity == "MEDIUM":
                                    medium += 1
                                elif issue_severity == "LOW":
                                    low += 1
                                elif issue_severity == "INFO":
                                    info += 1
                            else:
                                # Fall back to SARIF level mapping for scanners that don't use issue_severity
                                if result.level:
                                    level = str(result.level).lower()
                                    if level == "error":
                                        critical += 1
                                    elif level == "warning":
                                        medium += (
                                            1  # Most scanners map warning to medium
                                        )
                                    elif level == "note":
                                        low += 1
                                    elif level == "none":
                                        info += 1
                                    else:
                                        info += 1
                                else:
                                    # Default to info if no level specified
                                    info += 1

        # # Verify that the total number of findings matches what we expect
        # total_findings = critical + high + medium + low + info + suppressed

        return suppressed, critical, high, medium, low, info

    @staticmethod
    def _get_scanner_name_from_result(result: Any) -> Optional[str]:
        """Extract the scanner name from a SARIF result.

        This helper method attempts to determine the scanner name from a SARIF result
        by checking various properties and tags. It follows a hierarchical approach:

        1. First, it checks for a scanner_name property in the result's properties
        2. Then, it checks for scanner_details.tool_name in the properties
        3. Finally, it checks for common scanner names in the tags

        If none of these checks yield a scanner name, the method returns None.

        Args:
            result: A SARIF result object from which to extract the scanner name

        Returns:
            The scanner name if found, or None if the scanner name could not be determined
        """
        # First check for scanner_name in properties
        if result.properties and hasattr(result.properties, "scanner_name"):
            return result.properties.scanner_name

        # Then check for scanner_details.tool_name
        if result.properties and hasattr(result.properties, "scanner_details"):
            scanner_details = result.properties.scanner_details
            if hasattr(scanner_details, "tool_name"):
                return scanner_details.tool_name

        # Check for tags that might indicate scanner name
        if result.properties and hasattr(result.properties, "tags"):
            for tag in result.properties.tags:
                # Common scanner names that might appear in tags
                if tag.lower() in [
                    "bandit",
                    "semgrep",
                    "checkov",
                    "cfn-nag",
                    "cdk-nag",
                    "detect-secrets",
                    "grype",
                    "syft",
                    "npm-audit",
                ]:
                    return tag

        # If we can't determine the scanner from the result, return None
        return None

    @staticmethod
    def calculate_actionable_count(
        critical: int, high: int, medium: int, low: int, info: int, threshold: str
    ) -> int:
        """Calculate the number of actionable findings based on the threshold.

        This method determines how many findings are considered "actionable" based on
        the specified severity threshold. Findings at or above the threshold severity
        level are considered actionable.

        The threshold values and their meanings are:
        - "ALL": All findings are actionable (critical, high, medium, low, info)
        - "LOW": Findings of low severity or higher are actionable (critical, high, medium, low)
        - "MEDIUM": Findings of medium severity or higher are actionable (critical, high, medium)
        - "HIGH": Findings of high severity or higher are actionable (critical, high)
        - "CRITICAL": Only critical findings are actionable

        Args:
            critical: Number of critical findings
            high: Number of high findings
            medium: Number of medium findings
            low: Number of low findings
            info: Number of info findings
            threshold: Severity threshold ("ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL")

        Returns:
            Number of actionable findings based on the threshold
        """
        if threshold == "ALL":
            return critical + high + medium + low + info
        elif threshold == "LOW":
            return critical + high + medium + low
        elif threshold == "MEDIUM":
            return critical + high + medium
        elif threshold == "HIGH":
            return critical + high
        elif threshold == "CRITICAL":
            return critical
        return 0

    @staticmethod
    def get_scanner_threshold_info(
        asharp_model: AshAggregatedResults, scanner_name: str
    ) -> Tuple[str, str]:
        """Get the threshold and threshold source for a scanner.

        This method determines the severity threshold that should be used for a specific scanner
        and identifies the source of that threshold. It follows a hierarchical approach to
        determine the threshold:

        1. First, it gets the global threshold from the ASH configuration
        2. Then, it checks for a scanner-specific threshold in the scanner's configuration
        3. If a scanner-specific threshold is found, it uses that instead of the global threshold

        The threshold source indicates where the threshold was defined:
        - "global": The threshold is from the global_settings section in the ASH configuration
        - "config": The threshold is from the scanner's configuration in the ASH configuration

        Args:
            asharp_model: The AshAggregatedResults model containing the ASH configuration
            scanner_name: Name of the scanner to get the threshold for

        Returns:
            Tuple of (threshold, threshold_source), where threshold is one of
            "ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL" and threshold_source is
            one of "global", "config"
        """
        # Get global severity threshold from config
        global_threshold = ASH_DEFAULT_SEVERITY_LEVEL

        try:
            ash_conf = asharp_model.ash_config
        except Exception as e:
            ASH_LOGGER.error(f"Error loading config, using default: {e}")
            ash_conf = get_default_config()

        # Check for global_settings.severity_threshold
        if (
            ash_conf
            and hasattr(ash_conf, "global_settings")
            and hasattr(ash_conf.global_settings, "severity_threshold")
        ):
            global_threshold = ash_conf.global_settings.severity_threshold

        # Get scanner-specific configuration
        scanner_config_entry = None
        if hasattr(ash_conf, "get_plugin_config") and callable(
            ash_conf.get_plugin_config
        ):
            scanner_config_entry = ash_conf.get_plugin_config(
                plugin_type="scanner",
                plugin_name=scanner_name,
            )

        # Initialize scanner_threshold to None
        scanner_threshold = None
        scanner_threshold_def = "global"

        # Check for scanner-specific configuration overrides
        if (
            scanner_config_entry
            and isinstance(scanner_config_entry, dict)
            and "options" in scanner_config_entry
        ):
            options = scanner_config_entry["options"]
            if (
                "severity_threshold" in options
                and options["severity_threshold"] is not None
            ):
                scanner_threshold = options["severity_threshold"]
                scanner_threshold_def = "config"
        elif scanner_config_entry and hasattr(scanner_config_entry, "options"):
            if hasattr(scanner_config_entry.options, "severity_threshold"):
                scanner_threshold_from_config = (
                    scanner_config_entry.options.severity_threshold
                )
                if scanner_threshold_from_config is not None:
                    scanner_threshold = scanner_threshold_from_config
                    scanner_threshold_def = "config"

        # Use scanner-specific threshold for evaluation if available, otherwise use global
        evaluation_threshold = (
            scanner_threshold if scanner_threshold is not None else global_threshold
        )

        return evaluation_threshold, scanner_threshold_def

    @staticmethod
    def get_scanner_status_info(
        asharp_model: AshAggregatedResults, scanner_name: str
    ) -> Tuple[bool, bool, bool]:
        """Get scanner status information.

        This method retrieves status information for a specific scanner, including
        whether it was excluded from the scan and whether it has missing dependencies.

        The information is extracted from the scanner_results dictionary in the
        AshAggregatedResults model. If the scanner is not found in the dictionary,
        the method returns (False, False), indicating that the scanner was neither
        excluded nor missing dependencies.

        Args:
            asharp_model: The AshAggregatedResults model containing scanner results
            scanner_name: Name of the scanner to get status information for

        Returns:
            Tuple of (excluded, dependencies_missing), where:
            - excluded: True if the scanner was explicitly excluded from the scan
            - dependencies_missing: True if the scanner has missing dependencies
            - error: True if the scanner failed to run or generate results
        """
        excluded = False
        dependencies_missing = False
        error = False
        if (
            scanner_name in asharp_model.additional_reports
            and "None" in asharp_model.additional_reports[scanner_name]
            and asharp_model.additional_reports[scanner_name]["None"]["scanner_name"]
            == scanner_name
        ):
            status = asharp_model.additional_reports[scanner_name]["None"]["status"]
            if status == "SKIPPED":
                excluded = True
            elif status == "MISSING":
                dependencies_missing = True
            elif status == "ERROR":
                error = True
            else:
                # For any other status, treat as excluded for backward compatibility
                excluded = True
        elif scanner_name in asharp_model.scanner_results:
            scanner_status_info = asharp_model.scanner_results[scanner_name]

            # Handle both old ScannerStatusInfo and new ScannerMetrics structures
            if hasattr(scanner_status_info, "excluded"):
                excluded = scanner_status_info.excluded
            if hasattr(scanner_status_info, "dependencies_satisfied"):
                # Old ScannerStatusInfo structure
                dependencies_missing = not scanner_status_info.dependencies_satisfied
            elif hasattr(scanner_status_info, "dependencies_missing"):
                # New ScannerMetrics structure
                dependencies_missing = scanner_status_info.dependencies_missing
        elif (
            scanner_name in asharp_model.additional_reports
            and "source" in asharp_model.additional_reports[scanner_name]
            and asharp_model.additional_reports[scanner_name]["source"]["scanner_name"]
            and asharp_model.additional_reports[scanner_name]["source"]["status"]
        ):
            # If the scanner is not found in the dictionary, check for errors
            status = asharp_model.additional_reports[scanner_name]["source"]["status"]
            if status == "SKIPPED":
                excluded = True
            elif status == "MISSING":
                dependencies_missing = True
            elif status == "ERROR":
                error = True
            elif status != "PASSED":
                # For any other status, treat as excluded for backward compatibility
                excluded = True
        else:
            # If the scanner is not found in the dictionary, check for errors
            error = True

        return excluded, dependencies_missing, error

    @staticmethod
    def get_scanner_status(
        asharp_model: AshAggregatedResults, scanner_name: str
    ) -> str:
        """Determine the status of a scanner based on its findings and configuration.

        This method calculates the status of a scanner based on its findings, configuration,
        and execution status. The possible statuses are:

        - "SKIPPED": The scanner was explicitly excluded from the scan
        - "MISSING": The scanner has missing dependencies
        - "FAILED": The scanner found actionable findings (at or above the threshold)
        - "PASSED": The scanner did not find any actionable findings

        The method first checks if the scanner was excluded or has missing dependencies.
        If neither of these conditions is true, it calculates the number of actionable
        findings based on the scanner's threshold and determines the status accordingly.

        Args:
            asharp_model: The AshAggregatedResults model containing scanner results
            scanner_name: Name of the scanner to get the status for

        Returns:
            Status string: "PASSED", "FAILED", "SKIPPED", or "MISSING"
        """
        excluded, dependencies_missing, error = (
            ScannerStatisticsCalculator.get_scanner_status_info(
                asharp_model, scanner_name
            )
        )

        if error:
            return "ERROR"

        if excluded:
            return "SKIPPED"

        if dependencies_missing:
            return "MISSING"

        # Get actionable findings count
        suppressed, critical, high, medium, low, info = (
            ScannerStatisticsCalculator.extract_sarif_counts_for_scanner(
                asharp_model, scanner_name
            )
        )

        threshold, _ = ScannerStatisticsCalculator.get_scanner_threshold_info(
            asharp_model, scanner_name
        )

        actionable = ScannerStatisticsCalculator.calculate_actionable_count(
            critical, high, medium, low, info, threshold
        )

        return "FAILED" if actionable > 0 else "PASSED"

    @staticmethod
    def get_summary_statistics(asharp_model: AshAggregatedResults) -> Dict[str, Any]:
        """Calculate summary statistics across all scanners.

        This method aggregates statistics across all scanners to provide a high-level
        overview of the scan results. It first extracts statistics for all scanners
        using the extract_scanner_statistics method, then aggregates the counts and
        statuses to produce summary statistics.

        The summary statistics include:
        - Total number of scanners
        - Number of passed, failed, skipped, and missing scanners
        - Total number of findings across all severity levels
        - Total number of suppressed findings
        - Total number of actionable findings

        Args:
            asharp_model: The AshAggregatedResults model containing scanner results

        Returns:
            Dictionary with summary statistics containing the following keys:
            - total_scanners: Total number of scanners
            - passed_scanners: Number of scanners that passed
            - failed_scanners: Number of scanners that failed
            - skipped_scanners: Number of scanners that were skipped
            - missing_scanners: Number of scanners with missing dependencies
            - total_suppressed: Total number of suppressed findings
            - total_critical: Total number of critical findings
            - total_high: Total number of high findings
            - total_medium: Total number of medium findings
            - total_low: Total number of low findings
            - total_info: Total number of informational findings
            - total_findings: Total number of non-suppressed findings
            - total_actionable: Total number of actionable findings
        """
        scanner_stats = ScannerStatisticsCalculator.extract_scanner_statistics(
            asharp_model
        )

        # Initialize counters
        total_suppressed = 0
        total_critical = 0
        total_high = 0
        total_medium = 0
        total_low = 0
        total_info = 0
        total_findings = 0
        total_actionable = 0

        passed_count = 0
        failed_count = 0
        skipped_count = 0
        missing_count = 0

        # Aggregate statistics
        for scanner_name, stats in scanner_stats.items():
            total_suppressed += stats["suppressed"]
            total_critical += stats["critical"]
            total_high += stats["high"]
            total_medium += stats["medium"]
            total_low += stats["low"]
            total_info += stats["info"]
            total_findings += stats["total"]
            total_actionable += stats["actionable"]

            if stats["excluded"]:
                skipped_count += 1
            elif stats["dependencies_missing"]:
                missing_count += 1
            elif stats["actionable"] > 0:
                failed_count += 1
            else:
                passed_count += 1

        return {
            "total_scanners": len(scanner_stats),
            "passed_scanners": passed_count,
            "failed_scanners": failed_count,
            "skipped_scanners": skipped_count,
            "missing_scanners": missing_count,
            "total_suppressed": total_suppressed,
            "total_critical": total_critical,
            "total_high": total_high,
            "total_medium": total_medium,
            "total_low": total_low,
            "total_info": total_info,
            "total_findings": total_findings,
            "total_actionable": total_actionable,
        }

    @staticmethod
    def verify_sarif_finding_counts(asharp_model: AshAggregatedResults) -> bool:
        """Verify that the total number of findings matches the length of results in SARIF.

        This method is used for validation to ensure that the statistics calculation
        is accurate. It compares the total number of findings in the SARIF data with
        the total number of findings calculated from the scanner statistics.

        The method counts the number of results in the SARIF runs and compares it with
        the sum of total and suppressed findings from the scanner statistics. If the
        counts match, the method returns True, indicating that the statistics calculation
        is accurate.

        Args:
            asharp_model: The AshAggregatedResults model containing SARIF data

        Returns:
            True if the total number of findings matches the length of results in SARIF,
            False otherwise
        """
        # Count findings in SARIF
        sarif_finding_count = 0
        if asharp_model.sarif and asharp_model.sarif.runs:
            for run in asharp_model.sarif.runs:
                if run.results:
                    sarif_finding_count += len(run.results)

        # Count findings from scanner statistics
        scanner_stats = ScannerStatisticsCalculator.extract_scanner_statistics(
            asharp_model
        )
        stats_finding_count = sum(
            stats["total"] + stats["suppressed"] for stats in scanner_stats.values()
        )

        # Compare counts
        return sarif_finding_count == stats_finding_count

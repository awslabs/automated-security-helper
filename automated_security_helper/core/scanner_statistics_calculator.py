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

from automated_security_helper.core.constants import ASH_DEFAULT_SEVERITY_LEVEL
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerSeverityCount,
)
from automated_security_helper.models.scan_results_container import (
    ScanResultsContainer,
)
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.redacted_model import (
    EnvResolvedScalar,
    without_env_scalars,
)
from automated_security_helper.utils.scanner_names import SCANNER_TAG_NAMES
from automated_security_helper.utils.severity_ladder import (
    resolve_scanner_threshold,
    severity_fails_threshold,
)

#: The levels a target report can record it was graded against
#: (``ScanResultsContainer.scanner_severity_threshold``, written by the executor).
_RECORDED_LEVELS = frozenset({"ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL"})


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
            - threshold_from_env: Whether ``threshold`` is the written reference of a
              value read from the environment (provenance, not the text's shape)
            - excluded: Whether the scanner was explicitly excluded
            - dependencies_missing: Whether the scanner has missing dependencies
            - error: Whether the scanner failed to run or produced no usable results
            - evaluated_nothing: Whether a target-tracking scanner attempted zero targets.
              Distinct from ``excluded``: the operator wanted this scanner, it ran, and there
              was nothing for it to look at.
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
        # Only an entry shaped as the processor writes one, a mapping of target
        # reports with at least one serialized container among them
        # (``_is_report_shaped``), names a scanner. additional_reports is a
        # free-form dictionary a plugin may write to under any key (cli/merge.py
        # carries such entries through); read as a scanner, a list of findings,
        # a scalar, or a mapping of mappings that are no reports
        # ({"summary": {"files": 10}}) became a phantom row with no recorded
        # status, ERROR, that tripped the completeness gate.
        additional_reports_scanners = [
            name
            for name, reports in (asharp_model.additional_reports or {}).items()
            if isinstance(reports, dict)
            and any(
                ScannerStatisticsCalculator._is_report_shaped(report)
                for report in reports.values()
            )
        ]
        scanner_results_scanners = (
            list(asharp_model.scanner_results.keys())
            if asharp_model.scanner_results
            else []
        )

        # Combine all sources. One scanner under two spellings of its name is
        # one scanner: the counts below match SARIF findings to a name
        # case-insensitively, so a case-sensitive union counted every finding of
        # "Bandit" and "bandit" twice, in the per-scanner rows and in every
        # total. The spelling kept is the first met, scanner_results' first (the
        # rows the scan phase wrote), then the reports', then the SARIF's.
        scanner_names: list = []
        seen_names: set = set()
        for name in (
            scanner_results_scanners + additional_reports_scanners + sarif_scanner_names
        ):
            folded = name.lower() if isinstance(name, str) else name
            if folded in seen_names:
                continue
            seen_names.add(folded)
            scanner_names.append(name)

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

            # The grading value and the shown form from one resolution: the
            # actionable count below judges by the value, and the stats row,
            # which every report surface renders, carries the shown form.
            threshold, shown_threshold, threshold_source, threshold_from_env = (
                ScannerStatisticsCalculator._threshold_resolution(
                    asharp_model, scanner_name
                )
            )

            excluded, dependencies_missing, error = (
                ScannerStatisticsCalculator.get_scanner_status_info(
                    asharp_model, scanner_name
                )
            )

            evaluated_nothing = ScannerStatisticsCalculator.scanner_evaluated_nothing(
                asharp_model, scanner_name
            )

            total = critical + high + medium + low + info

            # Calculate actionable findings based on threshold
            actionable = ScannerStatisticsCalculator.calculate_actionable_count(
                critical, high, medium, low, info, threshold
            )

            # Calculate duration from additional_reports (where container data is
            # stored). None, not 0.0, for a scanner that did not run (excluded,
            # or its dependencies missing) and recorded none: 0.0 rendered as
            # "<1ms" in every table where ScannerMetrics documents None and
            # format_duration prints "N/A". A scanner that ran and recorded no
            # number (a null, a non-number) reads 0.0 below, the value its
            # formatting readers have always been given.
            duration: Optional[float] = None

            # First from the per-target reports, summed over every target the
            # scanner reported under: ScanPhase gives each scanner the source
            # tree and the converted tree, and reading the source report alone
            # dropped the converted tree's scan time. Only a mapping is read: a
            # results file put together by hand, or merged from another, can
            # hold a value under the scanner's name that is not a container (a
            # null, a list), and indexing it raised TypeError here, after the
            # scan ran. The reports are this scanner's own (``_own_reports``): one
            # naming another scanner is not read, one naming none is read for the
            # key it is filed under.
            reports = ScannerStatisticsCalculator._own_reports(
                asharp_model, scanner_name
            )
            recorded_durations = [
                report["duration"]
                for report in reports.values()
                if isinstance(report.get("duration"), (int, float))
                and not isinstance(report.get("duration"), bool)
            ]
            if recorded_durations:
                duration = float(sum(recorded_durations))
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
                    # Old ScannerStatusInfo structure. Each target is read as a
                    # mapping or an object (a results file read back holds plain
                    # dicts, which hasattr never matched, so this branch read 0
                    # for the very files it exists for), and only a recorded
                    # number counts: float(None) raised here.
                    ASH_LOGGER.debug("   Using OLD ScannerStatusInfo structure")
                    source_duration = ScannerStatisticsCalculator._recorded_duration(
                        scanner_status_info.source
                    )
                    converted_duration = ScannerStatisticsCalculator._recorded_duration(
                        scanner_status_info.converted
                    )
                    if source_duration is not None or converted_duration is not None:
                        duration = (source_duration or 0.0) + (
                            converted_duration or 0.0
                        )
                else:
                    # New ScannerMetrics structure: the row's own duration, when
                    # the row recorded one (a value that is not a number, or the
                    # model's unset default, is no record).
                    ASH_LOGGER.debug("   Using NEW ScannerMetrics structure")
                    duration = ScannerStatisticsCalculator._recorded_duration(
                        scanner_status_info
                    )

            if duration is None and not (excluded or dependencies_missing):
                # The scanner ran and recorded no duration (a report with a null
                # duration, a row holding text): the readers that format it
                # expect a number, so it reads 0.0 as it always has. Only a
                # scanner that did not run keeps None.
                duration = 0.0

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
                "threshold": shown_threshold,
                "threshold_source": threshold_source,
                "threshold_from_env": threshold_from_env,
                "excluded": excluded,
                "dependencies_missing": dependencies_missing,
                "error": error,
                "evaluated_nothing": evaluated_nothing,
            }

        return scanner_stats

    @staticmethod
    def _recorded_duration(holder: Any) -> Optional[float]:
        """The duration *holder* recorded, as a float, or None when it recorded none.

        *holder* is a per-target row or a scanner row: a mapping (a results file
        read back) or a model. A model's default is not a record: a row the scan
        phase wrote for a scanner that did not run carries the default 0.0,
        which is not a measured duration. A value that is not a number (a bool,
        a string) is no record either.
        """
        if isinstance(holder, dict):
            value = holder.get("duration")
        else:
            fields_set = getattr(holder, "model_fields_set", None)
            if (
                isinstance(fields_set, (set, frozenset))
                and "duration" not in fields_set
            ):
                return None
            value = getattr(holder, "duration", None)
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return None
        return float(value)

    @staticmethod
    def _is_report_shaped(report: Any) -> bool:
        """True when *report* has the shape ``ScanResultProcessor`` writes per target.

        A mapping that carries a ``status`` or a ``scanner_name`` key. Every
        serialized ``ScanResultsContainer`` has at least one: the constructor
        is given the name, and the executor and the factories assign the
        status; a results file written before ``scanner_name`` existed carries
        the status, and is read as the scanner it is filed under, as before. A
        plugin's free-form entry (``{"summary": {"files": 10}}`` under a key of
        its own) has neither. Counted as a scanner, it became an ERROR row (no
        status can be taken from it) that tripped the completeness gate.
        """
        return isinstance(report, dict) and (
            "status" in report or "scanner_name" in report
        )

    @staticmethod
    def _own_reports(
        asharp_model: AshAggregatedResults, scanner_name: str
    ) -> Dict[Any, Dict[str, Any]]:
        """The per-target reports filed under *scanner_name* that are this scanner's.

        A mapping that names another scanner is not one of them: ``additional_reports``
        is keyed by name, and a results file merged from another, or written by
        hand, can file a report under the wrong key. A report that names no scanner
        (one written before the field existed, or built by hand) is kept and read
        for the key it is filed under, as ``core.unified_metrics.own_target_reports``
        keeps it: the durations, the counters, the ERROR and partial-loss reads of
        the walks below are read for the key. Only a STATUS is never taken from a
        name-less report, because a status filed under the wrong key would flip a
        row: ``_recorded_report`` and ``get_scanner_status_info``'s fallback over
        these reports refuse one, so the scanner reads as having no recorded
        status. The key and the recorded name are matched in any case
        (``reports_for``, ``_same_scanner``): the name a row is read under is the
        union's first spelling, and the reports can sit under another.
        """
        reports = ScannerStatisticsCalculator.reports_for(asharp_model, scanner_name)
        if not isinstance(reports, dict):
            return {}
        return {
            key: report
            for key, report in reports.items()
            if isinstance(report, dict)
            and (
                report.get("scanner_name") is None
                or ScannerStatisticsCalculator._same_scanner(
                    report.get("scanner_name"), scanner_name
                )
            )
        }

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

        The severity counts recorded on the scanner's non-SARIF per-target reports
        (``_dict_result_counts``) are added to the SARIF counts whatever the SARIF holds:
        a scanner that returned a dict instead of SARIF has findings the merged SARIF
        never holds, and it can return SARIF for one target and a dict for another. A
        scanner with neither answers all zeros.

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
        from automated_security_helper.utils.sarif_utils import (
            _resolve_result_severity,
            is_result_suppressed,
        )

        counts = ScannerSeverityCount()

        if asharp_model.sarif:
            for result in asharp_model.sarif.get_all_results():
                result_scanner = (
                    ScannerStatisticsCalculator._get_scanner_name_from_result(result)
                )
                if not (
                    result_scanner and result_scanner.lower() == scanner_name.lower()
                ):
                    continue

                # Suppressed means a suppression IN EFFECT: one whose state is
                # rejected or underReview (SARIF 3.35.4) hides nothing, so its
                # finding is counted under its severity, as the exit code, the
                # flat finding and the workspace verdict count it.
                if is_result_suppressed(result):
                    counts.increment("suppressed")
                else:
                    counts.increment(_resolve_result_severity(result))

        # A scanner that returned a dict (``severity_counts`` or a ``findings``
        # list) instead of SARIF has findings the merged SARIF never holds: the
        # executor graded its row from the counts it read, and
        # ScanResultProcessor keeps those counts on the per-target report beside
        # the dict. Added here, whatever the SARIF holds, so the summary, the
        # scanner row and the exit code see the findings the row was graded on:
        # a scanner can return SARIF for one target and a dict for another, and
        # reading the dict counts only when the SARIF held nothing dropped that
        # dict target's findings whenever a sibling target had one SARIF result.
        # Only a report that still carries a dict ``raw_results`` is read: the
        # processor drops ``raw_results`` from a SARIF report's entry, and that
        # report's findings are in the SARIF above, so nothing is counted twice.
        dict_counts = ScannerStatisticsCalculator._dict_result_counts(
            asharp_model, scanner_name
        )
        for field in ("suppressed", "critical", "high", "medium", "low", "info"):
            setattr(counts, field, getattr(counts, field) + getattr(dict_counts, field))

        return (
            counts.suppressed,
            counts.critical,
            counts.high,
            counts.medium,
            counts.low,
            counts.info,
        )

    @staticmethod
    def _dict_result_counts(
        asharp_model: AshAggregatedResults, scanner_name: str
    ) -> ScannerSeverityCount:
        """The severity counts recorded on *scanner_name*'s non-SARIF target reports.

        Summed over every per-target report of the scanner (``_recorded_report``'s
        shape) whose ``raw_results`` is a dict: the executor read the counts from
        that dict and the processor left both on the report. A report whose counts
        do not validate, or whose result was SARIF (``raw_results`` dropped), adds
        nothing. All zero when the scanner has no such report. The reports are this
        scanner's own (``_own_reports``): one naming another scanner adds nothing,
        one naming none is counted for the key it is filed under.
        """
        total = ScannerSeverityCount()
        reports = ScannerStatisticsCalculator._own_reports(asharp_model, scanner_name)
        for report in reports.values():
            if not isinstance(report.get("raw_results"), dict) or not isinstance(
                report.get("severity_counts"), dict
            ):
                continue
            try:
                counts = ScannerSeverityCount.model_validate(report["severity_counts"])
            except ValueError:
                continue
            for field in ("suppressed", "critical", "high", "medium", "low", "info"):
                setattr(total, field, getattr(total, field) + getattr(counts, field))
        return total

    @staticmethod
    def dict_counts_unrecorded(
        asharp_model: AshAggregatedResults, scanner_name: str
    ) -> bool:
        """True when a dict-result target report of *scanner_name* carries no
        readable severity counts.

        Such a report comes from a results file written before the executor
        assigned a findings list's counts (incremented on the field's default,
        they were never marked set and the processor dumped the row without
        them), or carries counts that do not validate. Its findings sit in
        ``raw_results`` uncounted, so the finding counts read from the file say
        nothing about whether the gate failed; the recorded row's status is the
        only evidence left, and a reading that overrides it must not run. The
        reports are this scanner's own (``_own_reports``), as ``_dict_result_counts``
        reads them.
        """
        reports = ScannerStatisticsCalculator._own_reports(asharp_model, scanner_name)
        for report in reports.values():
            if not isinstance(report.get("raw_results"), dict):
                continue
            counts = report.get("severity_counts")
            if not isinstance(counts, dict):
                return True
            try:
                ScannerSeverityCount.model_validate(counts)
            except ValueError:
                return True
        return False

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
        # Only text names a scanner. A property that is present but null, or
        # not a string, is read from a SARIF file ASH did not write: returned as
        # it was, a null stopped the fallback chain and a non-string crashed the
        # sort of the names and the case-insensitive match.
        properties = getattr(result, "properties", None)
        if not properties:
            return None

        # First check for scanner_name in properties
        scanner_name = getattr(properties, "scanner_name", None)
        if isinstance(scanner_name, str) and scanner_name:
            return scanner_name

        # Then check for scanner_details.tool_name. attach_scanner_details stores
        # the details as a dict, which getattr never matched, so this fallback
        # never fired; a mapping and an object are both read.
        scanner_details = getattr(properties, "scanner_details", None)
        if isinstance(scanner_details, dict):
            tool_name = scanner_details.get("tool_name")
        else:
            tool_name = getattr(scanner_details, "tool_name", None)
        if isinstance(tool_name, str) and tool_name:
            return tool_name

        # Check for tags that might indicate scanner name. ``tags: null`` is a
        # list of none, not a TypeError.
        tags = getattr(properties, "tags", None)
        for tag in tags if isinstance(tags, (list, tuple)) else ():
            # Shared with models/flat_vulnerability.py rather than repeated here.
            # This list and that one were both written before opengrep shipped and
            # neither was updated, so the two agreed only by both being wrong.
            if isinstance(tag, str) and tag.lower() in SCANNER_TAG_NAMES:
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

        Delegated to ``utils.severity_ladder`` rather than encoded here. This used to
        be a fifth copy of the ladder, and it was the only copy whose unrecognised
        arm returned 0 instead of counting something -- so an off-table threshold
        made every scanner report zero actionable findings at every severity, and
        the summary table, ``summary_stats``, ``ash.flat.json`` and the Actionable
        column all read clean over real findings. An unrecognised threshold now
        gates on critical only, which is what ``determine_status`` and the junitxml
        reporter already do with one; the load-bearing property is that it is not
        zero, because zero is the one answer that describes a scan that found
        nothing.

        Case-sensitive on *threshold*, inherited from the ladder and deliberately
        not papered over here: upper-casing in this consumer alone would make
        ``"medium"`` gate at MEDIUM here and at CRITICAL everywhere else, which is
        the divergence the delegation exists to remove. Normalisation belongs at
        the boundary the value arrives through -- ``core.constants`` for the
        environment variable.

        A falsy threshold still counts nothing, and that is not the same state as
        an unrecognised one: ``None`` and ``""`` are how an operator turns the gate
        off, and the ladder preserves that reading.

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
        counts = {
            "CRITICAL": critical,
            "HIGH": high,
            "MEDIUM": medium,
            "LOW": low,
            "INFO": info,
        }
        return sum(
            count
            for severity, count in counts.items()
            if severity_fails_threshold(severity, threshold)
        )

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
            one of "global", "config", or "unavailable" when the results record
            no configuration (the threshold is then ASH_DEFAULT_SEVERITY_LEVEL)
        """
        threshold, _shown, source, _from_env = (
            ScannerStatisticsCalculator._threshold_resolution(
                asharp_model, scanner_name
            )
        )
        return threshold, source

    @staticmethod
    def get_scanner_threshold_details(
        asharp_model: AshAggregatedResults, scanner_name: str
    ) -> Tuple[str, str, str, bool]:
        """``get_scanner_threshold_info`` plus the shown form and the provenance.

        ``(grading value, shown form, source, from env)``, as
        :meth:`_threshold_resolution` answers them. For a caller that publishes
        a scanner's threshold outside the report surfaces (the workspace's
        unified results record each scanner's own grading threshold): ``from env``
        True says the grading value is the environment's, which the report rows
        never print, so such a caller leaves it out or records the shown form.
        """
        return ScannerStatisticsCalculator._threshold_resolution(
            asharp_model, scanner_name
        )

    @staticmethod
    def _threshold_resolution(
        asharp_model: AshAggregatedResults, scanner_name: str
    ) -> Tuple[str, str, str, bool]:
        """(grading value, shown form, source, from env) for one scanner's threshold.

        The shown form is what report surfaces print: an external section's
        env-read threshold answers its written reference (``${VARIABLE}``)
        instead of the resolved text, because the value came from the
        environment and printing it in a report row would publish it. The
        grading value is for grading only. The stats row reads all of it from
        this one resolution (``extract_scanner_statistics``), which is how the
        shown form reaches the emitter and the metrics table.

        ``from env`` is provenance: True only when the resolver marked the
        threshold as read from the environment. A ``${...}`` text the resolver
        left as written (a name it refuses to read, a quoted reference) is a
        plain str and answers False, whatever its shape.
        """
        # The configuration the results record. When there is none, or it cannot
        # be read, the threshold source says so; the configuration of the process
        # reading the results (ASH's defaults, or the file ASH_CONFIG names) is not
        # the one the scan ran with and is never consulted.
        try:
            ash_conf = asharp_model.ash_config
        except Exception as e:
            ASH_LOGGER.error(f"The recorded configuration could not be read: {e}")
            ash_conf = None
        if ash_conf is None:
            return (
                ASH_DEFAULT_SEVERITY_LEVEL,
                ASH_DEFAULT_SEVERITY_LEVEL,
                "unavailable",
                False,
            )

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
        # The form report surfaces show. None until a branch below finds a
        # spelling that differs from the grading value (today: the written
        # ${VARIABLE} reference of an env-read external threshold).
        shown_threshold = None
        threshold_from_env = False

        # Check for scanner-specific configuration overrides
        if (
            scanner_config_entry
            and isinstance(scanner_config_entry, dict)
            # Only a mapping holds options. A community plugin's section can
            # write ``options: null`` (or a scalar); read as a mapping it raised
            # TypeError here and aborted the metrics after the scan had run.
            and isinstance(scanner_config_entry.get("options"), dict)
        ):
            options = scanner_config_entry["options"]
            if (
                "severity_threshold" in options
                and options["severity_threshold"] is not None
            ):
                # A dict entry here is an external plugin's section, which the
                # segment models keep as an extra and never validate, so the
                # value can still be the env resolver's marker (a str
                # subclass). This is a non-validating consumer: take the
                # downcast view at the read, so the threshold returned for
                # grading is a plain str whatever a later consumer stores or
                # serializes it into. An env-read threshold is SHOWN as its
                # written reference: the value came from the environment, and
                # the summary row reaches every rendered report. The model
                # branch below reads a validated section, whose fields are
                # already plain.
                raw_threshold = options["severity_threshold"]
                scanner_threshold = without_env_scalars(raw_threshold)
                if not isinstance(scanner_threshold, str):
                    # An external section is never validated, so its threshold
                    # can be a number or a list. Graded as its text: the ladder
                    # reads an unrecognised threshold as CRITICAL only, and the
                    # row shows what the file wrote. The stats row's
                    # ``threshold`` is a str field that refused the raw value
                    # and aborted the summary after the scan had run.
                    scanner_threshold = str(scanner_threshold)
                if isinstance(raw_threshold, EnvResolvedScalar):
                    # Read from the environment only when the variable was set;
                    # a used default is the file's own level and graded as such.
                    # An instance copied from older state has no such slot and
                    # reads as set, like a marker built from the name alone.
                    threshold_from_env = getattr(
                        raw_threshold, "from_environment", True
                    )
                    # What the resolver says the row shows: the reference
                    # without its default (a glued tail kept) when the variable
                    # was read, the default's value when it was used. An
                    # instance copied from older state has no shown slot and
                    # degrades to the rebuilt name. Only a read carries a kept
                    # form: a used default is the file's own literal, so its
                    # raw text is not kept and the row shows what is graded.
                    if threshold_from_env:
                        shown_threshold = getattr(raw_threshold, "shown", None) or (
                            "${" + raw_threshold.variable + "}"
                        )
                else:
                    # A builtin scanner's section reaches here too:
                    # get_plugin_config serializes the typed section to a
                    # dict, and validation already made the value a plain
                    # word, so no marker can carry the shown form. The load
                    # recorded the read with its written reference; consult
                    # that record at this field's own path.
                    shown_threshold = (
                        ScannerStatisticsCalculator._recorded_reference_shown(
                            ash_conf,
                            (
                                "scanners",
                                scanner_name,
                                "options",
                                "severity_threshold",
                            ),
                        )
                    )
                    # The record holds only a reference whose variable the
                    # load read, so a recorded reference is an environment read.
                    threshold_from_env = shown_threshold is not None
                scanner_threshold_def = "config"
        elif scanner_config_entry and hasattr(scanner_config_entry, "options"):
            if hasattr(scanner_config_entry.options, "severity_threshold"):
                scanner_threshold_from_config = (
                    scanner_config_entry.options.severity_threshold
                )
                if scanner_threshold_from_config is not None:
                    scanner_threshold = scanner_threshold_from_config
                    scanner_threshold_def = "config"
                    # A typed (builtin) section validates an env-read value to
                    # the plain resolved word, so no marker survives here. The
                    # load recorded the read with its written reference, so
                    # the shown form comes from that record at this field's
                    # own path.
                    shown_threshold = (
                        ScannerStatisticsCalculator._recorded_reference_shown(
                            ash_conf,
                            ("scanners", scanner_name, "options", "severity_threshold"),
                        )
                    )
                    threshold_from_env = shown_threshold is not None

        # The scanner's own threshold when it has one, otherwise the global one: the
        # rule ScannerExecutor grades each target's report by, from the same helper.
        evaluation_threshold, scanner_threshold_def = resolve_scanner_threshold(
            scanner_threshold, ash_conf
        )
        # The kept reference form describes where the scanner's own threshold
        # came from. Keep it while the resolver still sources the graded value
        # from that config entry, and show what is graded, with its source,
        # otherwise. The test is the source and not the text: should the
        # resolver normalize the value (strip, upper-case) the source stays
        # "config", and the graded text is still derived from the variable, so
        # printing it would put the environment's value in every report. A
        # literal config value has no kept form to drop and shows the graded
        # value either way.
        if scanner_threshold_def != "config":
            shown_threshold = None
            threshold_from_env = False
        # resolve_scanner_threshold answers source "config" for every non-None
        # scanner threshold and never substitutes the global one, so a kept
        # reference form cannot be paired with another source.
        if shown_threshold is None and scanner_threshold_def == "global":
            # The global threshold is a validated field too; same record read.
            shown_threshold = ScannerStatisticsCalculator._recorded_reference_shown(
                ash_conf, ("global_settings", "severity_threshold")
            )
            threshold_from_env = shown_threshold is not None
        # A results file read back: the configuration record keeps a threshold
        # the scan read from the environment as the reference its file wrote,
        # never the level. The record's own read is then the reference text (an
        # external plugin's section, never validated) or the field's default (a
        # typed section, with the field listed as unreadable), and neither is
        # the level the scan graded with: the first graded CRITICAL only, the
        # second the default. The executor records the graded level on each
        # target report (ScanResultsContainer.scanner_severity_threshold), so
        # the read-back grades from that record, and never re-reads its own
        # environment, which can differ from the scan's. The shown form stays
        # the reference. A literal threshold the record can hold is read as
        # before, whatever the reports say.
        recorded_level = ScannerStatisticsCalculator._recorded_graded_level(
            asharp_model, scanner_name
        )
        if recorded_level is not None:
            from automated_security_helper.config.environment_record import (
                referenced_name,
            )

            own_path = ("scanners", scanner_name, "options", "severity_threshold")
            global_path = ("global_settings", "severity_threshold")
            reference_name = referenced_name(evaluation_threshold)
            if reference_name is not None:
                # An external section's threshold, read back as its reference.
                shown_threshold = "${" + reference_name + "}"
                evaluation_threshold = recorded_level
                threshold_from_env = True
            elif (
                unreadable := ScannerStatisticsCalculator._unreadable_reference_shown(
                    ash_conf, own_path
                )
            ) is not None:
                # A typed section's threshold, listed unreadable and read as
                # its default, which sent the resolution to the global one.
                shown_threshold = unreadable
                evaluation_threshold = recorded_level
                scanner_threshold_def = "config"
                threshold_from_env = True
            elif (
                scanner_threshold_def == "global"
                and (
                    unreadable
                    := ScannerStatisticsCalculator._unreadable_reference_shown(
                        ash_conf, global_path
                    )
                )
                is not None
            ):
                shown_threshold = unreadable
                evaluation_threshold = recorded_level
                threshold_from_env = True
        if shown_threshold is None:
            shown_threshold = evaluation_threshold
        return (
            evaluation_threshold,
            shown_threshold,
            scanner_threshold_def,
            threshold_from_env,
        )

    @staticmethod
    def _recorded_reference_shown(
        ash_conf: Any, path: Tuple[Any, ...]
    ) -> Optional[str]:
        """The bare ``${NAME}`` of the environment reference the config load
        recorded at *path*, or None when the field was written literally.

        Read-only consumption of ``AshConfig._environment_references`` (the
        record resolve_config sets, the one a results file's ash_config dump
        re-inserts references from); nothing here changes what is recorded or
        its shape. The shown spelling matches the external branch above: the
        variable alone, never a written default's text."""
        from automated_security_helper.config.environment_record import (
            referenced_name,
        )

        for reference in getattr(ash_conf, "_environment_references", ()) or ():
            if getattr(reference, "key", False):
                continue
            if not ScannerStatisticsCalculator._same_recorded_path(
                tuple(getattr(reference, "path", ())), tuple(path)
            ):
                continue
            name = referenced_name(getattr(reference, "written", ""))
            if name:
                return "${" + name + "}"
        return None

    @staticmethod
    def _same_recorded_path(recorded: Tuple[Any, ...], wanted: Tuple[Any, ...]) -> bool:
        """Whether a recorded config path names *wanted*'s field.

        The scanner's section is matched as get_plugin_config matches it: the
        file can spell a built-in scanner's key with another case or with "_"
        for "-", and the load records the path as written. Read by exact
        equality, such a section's env-read threshold showed its resolved value
        with threshold_from_env False.
        """
        from automated_security_helper.config.ash_config import reduced_plugin_name

        if len(recorded) != len(wanted):
            return False
        for position, (left, right) in enumerate(zip(recorded, wanted)):
            if left == right:
                continue
            if (
                position == 1
                and wanted[0] == "scanners"
                and isinstance(left, str)
                and isinstance(right, str)
                and reduced_plugin_name(left) == reduced_plugin_name(right)
            ):
                continue
            return False
        return True

    @staticmethod
    def _unreadable_reference_shown(
        ash_conf: Any, path: Tuple[Any, ...]
    ) -> Optional[str]:
        """The bare ``${NAME}`` of the reference a read-back configuration lists
        as unreadable at *path*, or None.

        A results file's record keeps a reference where its file wrote one, and
        a field that cannot hold the text is read with its default and listed
        (``recorded_config.without_unreadable_references``, the list
        ``AshAggregatedResults.validate_ash_config`` attaches). That list is the
        only trace a read-back configuration keeps of the reference: the record
        re-validated holds no environment references of its own.
        """
        from automated_security_helper.config.environment_record import (
            referenced_name,
        )
        from automated_security_helper.config.recorded_config import (
            unreadable_references,
        )

        for field, reference in unreadable_references(ash_conf):
            recorded = tuple(str(field).split("."))
            if not ScannerStatisticsCalculator._same_recorded_path(
                recorded, tuple(path)
            ):
                continue
            name = referenced_name(str(reference))
            if name:
                return "${" + name + "}"
        return None

    @staticmethod
    def _recorded_graded_level(
        asharp_model: AshAggregatedResults, scanner_name: str
    ) -> Optional[str]:
        """The level *scanner_name*'s target reports record it was graded against.

        The executor writes the level it graded each target against on the
        report (``ScanResultsContainer.scanner_severity_threshold``). One level
        over every report of the scanner that carries one; None when none does
        (a results file from an ASH that recorded none, a report written by hand)
        or when two targets were graded against different levels, since then the
        reports carry no one answer and the record's own read stands.
        """
        reports = ScannerStatisticsCalculator.reports_for(asharp_model, scanner_name)
        if not isinstance(reports, dict):
            return None
        levels = set()
        for report in reports.values():
            if not isinstance(
                report, dict
            ) or not ScannerStatisticsCalculator._same_scanner(
                report.get("scanner_name"), scanner_name
            ):
                continue
            level = report.get("scanner_severity_threshold")
            if isinstance(level, str) and level in _RECORDED_LEVELS:
                levels.add(level)
        return levels.pop() if len(levels) == 1 else None

    @staticmethod
    def _status_info_from_report(report: Dict[str, Any]) -> Tuple[bool, bool, bool]:
        """Read (excluded, dependencies_missing, error) off one serialized container.

        ``excluded`` comes from the container's own ``excluded`` field and is never inferred
        from the status string. Those two used to be the same thing, and the inference was sound
        while it lasted: before per-target outcome tracking, ``determine_status`` had exactly
        three return sites -- ERROR, FAILED, PASSED -- so the only way a container could carry
        SKIPPED was ``for_excluded()``, where ``excluded`` genuinely held. A scanner that runs
        and evaluates nothing now also reports SKIPPED, and re-deriving ``excluded`` from that
        asserts the operator switched the scanner off, which is a different and false claim.

        The cost of the false claim is not cosmetic. ``excluded`` and the SKIPPED it produces
        both set ``ScannerMetrics.passed``, and a scanner runs against two targets, so a cdk-nag
        that evaluated no source templates and found two CRITICAL issues in the converted tree
        rendered as skipped-and-passed. No red row in the summary table, while the exit code
        still failed the build off the very findings the row was hiding.

        ``exclude_unset=True`` in the dump is what makes the field trustworthy in the other
        direction: ``for_excluded()`` is the only caller that ever assigns ``excluded``, so the
        key is absent from every report written by a scanner that actually ran, and ``.get``
        falls back to the model default of False.

        Shared by both report-shaped branches of ``get_scanner_status_info`` rather than
        duplicated into each. The two blocks were identical, which is how one of them could
        have been fixed and the other left behind.
        """
        excluded = bool(report.get("excluded", False))
        dependencies_missing = False
        error = False

        match report.get("status"):
            case "MISSING":
                dependencies_missing = True
            case "ERROR":
                error = True
            case "SKIPPED" | "FAILED" | "PASSED":
                # All three are verdicts the scanner reached about its own run, and none of
                # them says anything about configuration. SKIPPED is in this list rather than
                # setting ``excluded`` because it reports a fact about the input -- there was
                # nothing to evaluate -- and that fact travels in ``evaluated_nothing``.
                pass
            case _:
                # An unrecognized status is not a verdict this code can reason about. Treated as
                # excluded for backward compatibility, which keeps it out of the failure counts
                # rather than inventing a severity for it.
                excluded = True

        # A failure container is ERROR whatever status it carries.
        # ``ScanResultsContainer.for_failure`` writes FAILED, and the run modes'
        # handlers give it ``raw_results`` with ``status: "failed"`` (the
        # executor grades such a dict ERROR on its own path, but these containers
        # never take it). Read as its status said, a crashed scanner's report
        # under "None" was a verdict: not ERROR, and with findings it rolled up
        # FAILED ("ran and found something") instead of ERROR, and the completeness
        # gate let it through. ``exception`` is the other mark a failure leaves.
        if ScannerStatisticsCalculator._is_failure_report(report):
            error = True

        return excluded, dependencies_missing, error

    @staticmethod
    def _is_failure_report(report: Dict[str, Any]) -> bool:
        """True when one serialized container carries a failure's marks.

        Two marks, either one enough: ``raw_results`` is a dict whose ``status``
        is ``"failed"`` (the run modes' handlers write it on every failure row,
        fresh or refiled), or ``exception`` is set (``set_exception`` writes it
        on a row the handler refiles, ``for_failure`` on a fresh one, and a
        merged or hand-written file can carry it alone). The one rule for the
        three readers of a failure: ``_status_info_from_report`` grades such a
        report ERROR whatever status it carries,
        ``target_report_is_partial_loss`` refuses it (a crash's counters are
        not a partial loss's), and ``recorded_error_is_partial_loss`` refuses an
        ERROR row beside it. Spelled out in two of the three, a report with
        partial counters, no ``raw_results`` and an ``exception`` read as a
        crash when the scanner had a recorded row and as a partial loss when it
        had none, so the same reports gave two statuses.
        """
        raw_results = report.get("raw_results")
        if isinstance(raw_results, dict) and raw_results.get("status") == "failed":
            return True
        return bool(report.get("exception"))

    @staticmethod
    def reports_for(asharp_model: AshAggregatedResults, scanner_name: Any) -> Any:
        """The ``additional_reports`` entry for *scanner_name*: under its own spelling,
        or under the one spelling that folds to it.

        ``extract_scanner_statistics`` unions scanner names case-insensitively and
        keeps the first spelling met, scanner_results' before the reports', so the
        name a row is read under can differ in case from the key its reports sit
        under: "Bandit" in scanner_results, "bandit" in additional_reports (a merged
        or hand-written results file). An exact lookup then found nothing, and
        every per-target read (an ERROR or MISSING recorded only there, the dict
        counts, the durations, the target counters) was lost along with the row
        the union had dropped. The exact key wins when present; otherwise the first
        key that folds to the name. Two keys that both fold to it with neither
        exact (a merge of "Bandit" and "bandit" files) read as the first, a shape
        no ASH writer produces.

        A model with no ``additional_reports`` at all (a summary read that carries
        only the configuration, as the threshold readers are given) holds no
        reports: None, the same answer as an entry that is absent.
        """
        reports = getattr(asharp_model, "additional_reports", None)
        if not isinstance(reports, dict):
            return None
        found = reports.get(scanner_name)
        if found is not None or not isinstance(scanner_name, str):
            return found
        folded = scanner_name.lower()
        for name, value in reports.items():
            if isinstance(name, str) and name.lower() == folded:
                return value
        return None

    @staticmethod
    def _same_scanner(recorded: Any, scanner_name: Any) -> bool:
        """Whether a report's recorded ``scanner_name`` names *scanner_name*, in any
        case. Names that are not text compare as they are."""
        if isinstance(recorded, str) and isinstance(scanner_name, str):
            return recorded.lower() == scanner_name.lower()
        return recorded == scanner_name

    @staticmethod
    def _recorded_report(
        asharp_model: AshAggregatedResults, scanner_name: str, target: str
    ) -> Optional[Dict[str, Any]]:
        """The report *scanner_name* recorded for *target*, or None when there is none
        this code can read.

        A report is the container ``ScanResultProcessor`` serializes, a mapping that
        names its scanner, written under that name. A results file from another ASH
        version, or one put together by hand and given to ``ash merge``, can hold a
        mapping without ``scanner_name`` (the sample results under tests/test_data
        do), one that names another scanner, or a value that is not a mapping. None
        of them is this scanner's report: read as one, the first and last raised
        KeyError or TypeError, which ``ash merge`` let out as a traceback, and the
        second gave the other scanner's status as this one's. Treated as none
        recorded, each leaves the scanner with no recorded status, which
        ``get_scanner_status_info`` reports as an error.
        """
        reports = ScannerStatisticsCalculator.reports_for(asharp_model, scanner_name)
        if not isinstance(reports, dict):
            return None
        report = reports.get(target)
        # The scanner-level report is filed under the string "None" by the
        # processor and under the Python None by a writer that keyed the live
        # container's target directly; asked for "None", both are read.
        if report is None and target == "None":
            report = reports.get(None)
        if not isinstance(
            report, dict
        ) or not ScannerStatisticsCalculator._same_scanner(
            report.get("scanner_name"), scanner_name
        ):
            return None
        return report

    @staticmethod
    def target_report_is_partial_loss(
        report: Dict[str, Any], threshold: str | None
    ) -> bool:
        """True when one serialized ERROR report is the ERROR a partial loss earns.

        ``0 < targets_failed < targets_attempted``, both real ints. Total loss
        (``failed >= attempted``), a negative or non-int counter, and a report with no
        counters at all are not partial: a tree that is ERROR with no counters to say it
        evaluated anything is read as having evaluated nothing.

        The counters are necessary and not enough. ``ScanResultsContainer.determine_status``
        grades a partial loss ERROR only when the tree's own findings pass the gate, and
        FAILED when they fail it. The executor writes ERROR over other grades for causes of
        its own, and those trees keep partial counters: a killed tool, a ``scan()`` that
        returned nothing, a tool ASH could not stop. Counted as partial losses they would
        roll up FAILED beside a finding, and a killed tool would read as a graded partial
        audit. So the report must also be the grade its own counts give
        (``determine_status`` at *threshold* answers ERROR), and must carry neither
        a failure's marks (``_is_failure_report``: ``raw_results.status ==
        "failed"`` or an ``exception``) nor ``could_not_stop``.

        What this cannot tell apart: a tool killed on a tree whose own findings pass the
        gate. That tree's counters and counts are what a partial loss writes, and the
        report records the kill only in its error text. Telling them apart needs the
        executor to mark the ERROR's cause on the container.
        """
        attempted = report.get("targets_attempted")
        failed = report.get("targets_failed")
        if isinstance(attempted, bool) or not isinstance(attempted, int):
            return False
        if isinstance(failed, bool) or not isinstance(failed, int):
            return False
        if not (attempted > 0 and 0 < failed < attempted):
            return False

        if ScannerStatisticsCalculator._is_failure_report(report):
            return False
        if report.get("could_not_stop"):
            return False

        counts = report.get("severity_counts")
        # A ScannerSeverityCount instance is read through its own dump: a report
        # that is still a live container's dict (or a test's) can carry one, and
        # read as "not a dict" it was replaced by empty counts, so the grade below
        # ran on zeros and a partial loss whose findings fail the gate (FAILED,
        # not a partial-loss ERROR) was flagged as one. The dump re-validates, so
        # an instance mutated after construction into a shape the model refuses is
        # refused here too (a ValidationError is a ValueError).
        # warnings=False: pydantic warns (PydanticSerializationUnexpectedValue)
        # when it serializes a value a field refuses, and under a
        # warnings-as-errors filter that warning would raise here instead of
        # the validation below refusing the instance.
        if isinstance(counts, ScannerSeverityCount):
            counts = counts.model_dump(warnings=False)
        try:
            severity_counts = (
                ScannerSeverityCount.model_validate(counts)
                if isinstance(counts, dict)
                else ScannerSeverityCount()
            )
        except ValueError:
            return False
        graded = ScanResultsContainer(
            severity_counts=severity_counts,
            targets_attempted=attempted,
            targets_failed=failed,
        ).determine_status(threshold)
        return graded == ScannerStatus.ERROR

    @staticmethod
    def _is_partial_loss(
        asharp_model: AshAggregatedResults,
        scanner_name: str,
        report: Dict[str, Any],
    ) -> bool:
        """``target_report_is_partial_loss`` at the scanner's own threshold."""
        threshold, _ = ScannerStatisticsCalculator.get_scanner_threshold_info(
            asharp_model, scanner_name
        )
        return ScannerStatisticsCalculator.target_report_is_partial_loss(
            report, threshold
        )

    @staticmethod
    def recorded_error_is_partial_loss(
        asharp_model: AshAggregatedResults, scanner_name: str
    ) -> bool:
        """True when the per-target reports explain a recorded ERROR with a partial loss.

        At least one target report is ERROR and every ERROR target report is a partial
        loss (``target_report_is_partial_loss``). A recorded ERROR for which no report is
        ERROR is not explained: a run that raised leaves FAILED containers and an ERROR
        row written by the completeness check, and that row is the only record of it.
        Nor is one for which any report is a failure container (``_is_failure_report``:
        ``raw_results.status`` ``failed``, or an ``exception``): a run that raised on one
        tree beside a partial loss on another is a crash, and the partial loss does not
        explain it away. Only this scanner's own reports are read (``_own_reports``).
        """
        reports = ScannerStatisticsCalculator._own_reports(asharp_model, scanner_name)
        for report in reports.values():
            if ScannerStatisticsCalculator._is_failure_report(report):
                return False
        errored = [
            report
            for report in reports.values()
            if report.get("status") == ScannerStatus.ERROR.value
        ]
        return bool(errored) and all(
            ScannerStatisticsCalculator._is_partial_loss(
                asharp_model, scanner_name, report
            )
            for report in errored
        )

    @staticmethod
    def any_target_errored(
        asharp_model: AshAggregatedResults,
        scanner_name: str,
        *,
        include_partial_loss: bool = True,
    ) -> bool:
        """True when ANY target this scanner reported under came back ERROR.

        With ``include_partial_loss=False`` an ERROR tree that lost only some of its
        targets (``target_report_is_partial_loss``) is not counted, so True means a
        tree evaluated nothing. ``get_scanner_status_info`` asks both ways: findings
        outrank a partial loss and do not outrank total loss.

        ``ScanPhase`` gives each scanner one task carrying both the source tree and the
        converted tree, and ``ScanResultProcessor`` writes one serialized container per target
        under ``additional_reports[scanner][target_type]``. ERROR is what
        ``ScanResultsContainer.determine_status`` returns when the coverage loss is the loudest
        fact about a tree: every attempted target failed, the counters are inconsistent (a
        poisoned or negative count, a failure count beside no attempt claim, or a failure
        count exceeding the attempt claim), or a
        partial loss whose surviving findings pass the severity gate (one whose findings fail
        the gate grades FAILED instead, so the findings stay visible to consumers that gate on
        them). An ERROR here therefore means that tree's coverage cannot be trusted, whatever
        its siblings yielded. What the scanner's status does with it differs by the kind of
        loss: a tree that evaluated nothing sets ``error`` whatever the scanner found, and a
        partial loss sets it only when no tree has gate-failing findings
        (``include_partial_loss`` and ``get_scanner_status_info``).

        ``get_scanner_status_info`` used to derive its ``error`` flag from the ``"source"``
        report alone. A cdk-nag that passed on the source tree and errored on the converted one
        therefore rolled up to PASSED: the ERROR container was written to disk, serialized into
        the aggregated results, and never read. Nothing downstream could recover the fact,
        because ``error`` is the flag every rolled-up status keys on.

        "Any", not "all", and the asymmetry with the severity gate is the point. A finding count
        of zero is ambiguous, so the guards in ``determine_status`` are careful about which
        zero they are looking at. An ERROR is a hole in the scan whether or not its sibling was
        fine, and a report that averages it away against a passing sibling is asserting
        coverage it does not have. It does not always set the scanner's ``error`` flag: a tree
        that lost only some of its targets yields to gate-failing findings on any tree, so the
        scanner reads FAILED and the loss stays visible through ``incomplete_scanners``.

        Modelled on ``scanner_evaluated_nothing``, which already reads across every target for
        the same structural reason. That function existed with that quantifier and this one did
        not, and the gap between them is exactly where the defect lived.

        Only this scanner's own reports are read (``_own_reports``), as ``any_target_missing``
        and ``_recorded_report`` read them: a report filed under this name that names another
        scanner is not this scanner's ERROR.
        """
        reports = ScannerStatisticsCalculator._own_reports(asharp_model, scanner_name)

        for target_report in reports.values():
            if target_report.get("status") != ScannerStatus.ERROR.value:
                continue
            if (
                not include_partial_loss
                and ScannerStatisticsCalculator._is_partial_loss(
                    asharp_model, scanner_name, target_report
                )
            ):
                continue
            return True
        return False

    @staticmethod
    def any_target_missing(
        asharp_model: AshAggregatedResults, scanner_name: str
    ) -> bool:
        """True when ANY target this scanner reported under came back MISSING.

        The same quantifier as ``any_target_errored``, for the same reason. The scan phase
        records a dependency it checks before the scanner runs on the scanner-level report,
        but the executor records MISSING per target when ``scan()`` returns a falsy value,
        so a scanner can evaluate the source tree and find its dependencies unavailable on
        the converted one. No rule ran against that tree. Read off the source report or the
        ``scanner_results`` row alone, the scanner rolled up to PASSED, which is the "PASSED
        with an unevaluated target" contract clause 3i forbids.

        Which reports count is ``target_report_is_missing``. Only this scanner's own
        reports count, as in ``_recorded_report``: a mapping that names another
        scanner is no report of this one's.
        """
        reports = ScannerStatisticsCalculator.reports_for(asharp_model, scanner_name)
        if not isinstance(reports, dict):
            return False

        for target_report in reports.values():
            if not isinstance(
                target_report, dict
            ) or not ScannerStatisticsCalculator._same_scanner(
                target_report.get("scanner_name"), scanner_name
            ):
                continue
            if ScannerStatisticsCalculator.target_report_is_missing(target_report):
                return True
        return False

    @staticmethod
    def target_report_is_missing(report: Dict[str, Any]) -> bool:
        """True when one serialized target report says its dependencies were unavailable.

        Its status says MISSING, or it says ``dependencies_satisfied: false`` whatever
        status it reached. The second is a scanner whose ``scan()`` override recorded
        its tool absent and still returned a report: the executor copies that onto the
        container, which then grades PASSED on the nothing it found. No rule ran for
        want of the tool, so the target is as unevaluated as a MISSING one.

        The status is read directly rather than through ``_status_info_from_report``,
        which maps an unrecognized status to ``excluded=True``. A MISSING report that
        says ``dependencies_satisfied: true`` (the scan phase's filtering-raised
        record) still counts, by its status.
        """
        status = report.get("status")
        if getattr(status, "value", status) == ScannerStatus.MISSING.value:
            return True
        return report.get("dependencies_satisfied") is False

    @staticmethod
    def scanner_evaluated_nothing(
        asharp_model: AshAggregatedResults, scanner_name: str
    ) -> bool:
        """True when a target-tracking scanner reported that it attempted zero targets.

        The honest channel for "nothing was evaluated", replacing the old route where that fact
        arrived disguised as ``excluded``. It lives in
        ``ScanResultsContainer.targets_attempted``, which is tri-state: absent from a serialized
        report means the scanner does not track per-target outcomes and is making no claim
        (``exclude_none=True`` drops the None), while a present 0 means it tracked and attempted
        none. Absent must never read as zero -- bandit, checkov, semgrep, grype, syft,
        detect-secrets and opengrep are all in the no-claim state (cdk-nag, cfn-nag and
        npm-audit track targets), and reading them as tracked-zero would turn every row of a
        clean report yellow.

        Read across every target the scanner reported under, because ``ScanPhase`` gives each
        scanner a task carrying both the source and the converted tree and only one of them may
        have been empty. So: at least one target must have made a claim, and every claim must be
        zero. Consulting a single target instead would report a half-empty scan as skipped and
        discard whatever the other half found.

        Mirrors the ``targets_attempted <= 0`` guard in ``determine_status`` rather than testing
        ``== 0``, so the status a container computes for itself and the status rendered in the
        summary table cannot disagree about the same counter. A negative count does not reach
        this branch anyway: ``determine_status`` sends it to ERROR, and ``error`` is checked
        first.

        Only this scanner's own reports are read (``_own_reports``), as the other walks
        read them.
        """
        reports = ScannerStatisticsCalculator._own_reports(asharp_model, scanner_name)

        claims = []
        for target_report in reports.values():
            attempted = target_report.get("targets_attempted")
            failed = target_report.get("targets_failed")
            # A counter that is present but not a genuine int (bool is an int
            # subclass, and a True/False counter is a caller bug rather than a
            # claim about targets) poisons the scanner's accounting. SKIPPED is
            # a complete status, so answering True off the readable half of a
            # poisoned report would complete a scan whose counters cannot be
            # trusted; unified_metrics.target_counts classifies the same report
            # as untrustworthy and the incomplete-scan check lists it instead.
            for value in (attempted, failed):
                if value is not None and (
                    isinstance(value, bool) or not isinstance(value, int)
                ):
                    return False
            if isinstance(attempted, int) and not isinstance(attempted, bool):
                claims.append(attempted)

        return bool(claims) and all(attempted <= 0 for attempted in claims)

    @staticmethod
    def _has_actionable_findings(
        asharp_model: AshAggregatedResults, scanner_name: str
    ) -> bool:
        """True when the scanner's SARIF findings fail its severity threshold.

        The count ``get_scanner_status`` and ``get_unified_scanner_metrics`` rank
        against the did-not-run statuses, so the flag
        ``get_scanner_status_info`` returns is decided on the same number.
        """
        suppressed, critical, high, medium, low, info = (
            ScannerStatisticsCalculator.extract_sarif_counts_for_scanner(
                asharp_model, scanner_name
            )
        )
        threshold, _ = ScannerStatisticsCalculator.get_scanner_threshold_info(
            asharp_model, scanner_name
        )
        return (
            ScannerStatisticsCalculator.calculate_actionable_count(
                critical, high, medium, low, info, threshold
            )
            > 0
        )

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
            Tuple of (excluded, dependencies_missing, error), where:
            - excluded: True if the scanner was explicitly excluded from the scan
            - dependencies_missing: True if the scanner has missing dependencies
            - error: True if the scanner failed to run or generate results

        None of the three covers "the scanner ran and evaluated nothing". That is a fourth and
        genuinely different fact, and it is answered by ``scanner_evaluated_nothing`` rather than
        folded into ``excluded`` here -- see ``_status_info_from_report`` for what folding it in
        used to cost.

        ``error`` and ``dependencies_missing`` are read across every target rather than off a
        single report, and ``excluded`` is not. A scanner is switched off for the whole run --
        a fact about configuration, which the scanner-level report states correctly. Whether a
        rule was evaluated is a fact about one tree, and a scanner gets two: a target can come
        back ERROR, or MISSING when ``scan()`` found its dependencies unavailable there. See
        ``any_target_errored`` and ``any_target_missing`` for what reading only the source
        report cost. Widening ``excluded`` the same way would be actively wrong: one target
        carrying an unrecognized status makes ``_status_info_from_report`` return
        ``excluded=True`` for backward compatibility, which would then claim the operator had
        switched the scanner off.
        """
        excluded = False
        dependencies_missing = False
        error = False
        none_report = ScannerStatisticsCalculator._recorded_report(
            asharp_model, scanner_name, "None"
        )
        source_report = ScannerStatisticsCalculator._recorded_report(
            asharp_model, scanner_name, "source"
        )
        if none_report is not None:
            excluded, dependencies_missing, error = (
                ScannerStatisticsCalculator._status_info_from_report(none_report)
            )
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

            # ERROR has to be read off the recorded status here, and this branch is
            # the one a scanner that actually ran takes.
            #
            # Nothing else recovers it. get_unified_scanner_metrics consults this
            # flag before it tests `actionable > 0`, and only reaches the recorded
            # status in the else after both. So with error left False, a scanner
            # recorded ERROR that had written findings before it failed was reported
            # FAILED -- "ran and found something" -- and disappeared from
            # incomplete_scanners entirely. Measured on this tree, one scanner
            # recorded ERROR: with 0 SARIF findings it read ERROR and tripped the
            # gate; with 3 it read FAILED and the gate reported nothing incomplete,
            # so `ash scan` exited 2 rather than 1 for a run in which a scanner had
            # crashed.
            #
            # Only ERROR is taken from the status. excluded and dependencies_missing
            # have their own dedicated fields above, which are the authoritative
            # signals for SKIPPED and MISSING, and PASSED/FAILED must not be taken
            # from here at all: the recorded status is not authoritative about the
            # finding count, so a scanner recorded PASSED whose findings are
            # actionable at this run's threshold has to keep reading FAILED. What the
            # recorded status *is* authoritative about is whether the scanner crashed.
            status_value = getattr(
                getattr(scanner_status_info, "status", None), "value", None
            ) or getattr(scanner_status_info, "status", None)
            #
            # An ERROR row is deferred to the walk below, like the source
            # report's ERROR in the branch after this one, when the per-target
            # reports account for it with a partial loss alone
            # (``recorded_error_is_partial_loss``). This is the branch a scan
            # reaches for such a scanner: a scanner whose run returned an ERROR
            # tree is not recorded as completed, the scan phase's completeness
            # check writes it an ERROR row, and the rebuild reads that row first.
            # A rule kept only in the source-report branch never ran for it. An
            # ERROR row that no report explains (a run that raised leaves FAILED
            # containers) stays ERROR.
            if status_value == ScannerStatus.ERROR.value:
                error = not ScannerStatisticsCalculator.recorded_error_is_partial_loss(
                    asharp_model, scanner_name
                )
        else:
            # One tree's report: the source tree's first, else any other tree's
            # (a scanner recorded only under "converted", with no row, read as
            # "nothing says it ran" and ERROR while its report said PASSED). A
            # report that names no scanner gives no status, as _recorded_report
            # gives none: _own_reports keeps it for the counters and durations,
            # but a status filed under the wrong key would flip the row.
            tree_report = source_report
            if tree_report is None:
                own_reports = ScannerStatisticsCalculator._own_reports(
                    asharp_model, scanner_name
                )
                for key in sorted(own_reports, key=str):
                    if key in (None, "None"):
                        continue
                    if not ScannerStatisticsCalculator._same_scanner(
                        own_reports[key].get("scanner_name"), scanner_name
                    ):
                        continue
                    if own_reports[key].get("status"):
                        tree_report = own_reports[key]
                        break
            if tree_report is not None and tree_report.get("status"):
                excluded, dependencies_missing, error = (
                    ScannerStatisticsCalculator._status_info_from_report(tree_report)
                )
                # The report is one tree's. A partial-loss ERROR on it is judged with
                # the other trees below, like any other tree's, so it does not set
                # the flag ahead of the scanner's findings.
                if error and ScannerStatisticsCalculator._is_partial_loss(
                    asharp_model, scanner_name, tree_report
                ):
                    error = False
            else:
                # No status recorded for the scanner, so nothing says it ran.
                error = True

        # ORed in after the branches above rather than replacing them. Those branches also
        # produce ``excluded``, which stays scanner-level, and the first branch reads a report
        # keyed ``"None"`` -- a scanner that never reached a target at all -- which both walks
        # cover as well since they read every key.
        #
        # Findings outrank lost coverage except total loss, the rule
        # ``ScanResultsContainer.determine_status`` applies on one tree. A tree that
        # evaluated nothing sets ``error`` whatever its siblings found. A tree that lost
        # only SOME targets sets it only when the scanner has no gate-failing findings on
        # any tree, so 13 attempted, 4 lost and one HIGH finding reads FAILED whether the
        # loss and the finding share a tree or not. This matches the findings-outrank-MISSING
        # precedence and the exit code, which fails on the findings; the partial loss stays
        # visible through ``incomplete_scanners``, not through status precedence.
        if not error:
            if ScannerStatisticsCalculator.any_target_errored(
                asharp_model, scanner_name, include_partial_loss=False
            ):
                error = True
            elif ScannerStatisticsCalculator.any_target_errored(
                asharp_model, scanner_name
            ):
                error = not ScannerStatisticsCalculator._has_actionable_findings(
                    asharp_model, scanner_name
                )
        dependencies_missing = (
            dependencies_missing
            or ScannerStatisticsCalculator.any_target_missing(
                asharp_model, scanner_name
            )
        )

        return excluded, dependencies_missing, error

    @staticmethod
    def get_scanner_status(
        asharp_model: AshAggregatedResults, scanner_name: str
    ) -> str:
        """Determine the status of a scanner based on its findings and configuration.

        This method calculates the status of a scanner based on its findings, configuration,
        and execution status. The possible statuses are:

        - "ERROR": The scanner produced no usable results
        - "FAILED": The scanner found actionable findings (at or above the threshold)
        - "SKIPPED": The scanner was explicitly excluded, or it ran and evaluated no targets
        - "MISSING": The scanner has missing dependencies
        - "PASSED": The scanner evaluated targets and found nothing actionable

        Listed in the order the branches are checked. Findings are counted before the
        did-not-run branches, so a scanner carrying actionable findings can never come back as a
        status that reads as passing.

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

        # The same rule get_unified_scanner_metrics applies: stored target counters
        # that cannot be read (a string, a bool, a negative, a failure count with
        # no attempt count) are a coverage claim nobody can trust, and the row is
        # ERROR for it. Without it this function answered PASSED or SKIPPED where
        # the unified metrics answered ERROR for the same scanner. Imported here:
        # unified_metrics imports this module at load.
        from automated_security_helper.core.unified_metrics import (
            counters_unusable,
            target_counts,
        )

        if counters_unusable(*target_counts(asharp_model, scanner_name)):
            return "ERROR"

        # Counted before the excluded and dependencies_missing branches, matching the precedence
        # in ``unified_metrics.get_unified_scanner_metrics``. Two functions that answer "what is
        # this scanner's status" must not disagree: whichever one a caller happens to reach, a
        # scanner carrying findings has to come back FAILED rather than as a status that reads
        # as passing.
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

        if actionable > 0:
            return "FAILED"

        if excluded:
            return "SKIPPED"

        if dependencies_missing:
            return "MISSING"

        if ScannerStatisticsCalculator.scanner_evaluated_nothing(
            asharp_model, scanner_name
        ):
            return "SKIPPED"

        return "PASSED"

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
            - skipped_scanners: Number of scanners that were skipped (excluded, or
              they ran and evaluated nothing)
            - missing_scanners: Number of scanners with missing dependencies
            - error_scanners: Number of scanners that produced no usable results
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

        totals = ScannerSeverityCount()
        total_findings = 0
        total_actionable = 0
        passed_count = 0
        failed_count = 0
        skipped_count = 0
        missing_count = 0
        error_count = 0

        for scanner_name, stats in scanner_stats.items():
            totals.suppressed += stats["suppressed"]
            totals.critical += stats["critical"]
            totals.high += stats["high"]
            totals.medium += stats["medium"]
            totals.low += stats["low"]
            totals.info += stats["info"]
            total_findings += stats["total"]
            total_actionable += stats["actionable"]

            # The same order as the first five branches of unified_metrics:
            # a scanner that produced no usable results is counted as an
            # error ahead of anything else, findings outrank the did-not-run
            # statuses, and a tracking scanner that attempted nothing is
            # skipped, not passed. Two things unified_metrics reads that this
            # count does not: the per-target attempted/failed counters (an
            # unusable one grades the row ERROR there) and the recorded row's
            # own status (a recorded SKIPPED stays SKIPPED there), so such a
            # scanner is counted as passed here and shown as ERROR or SKIPPED
            # in the metrics table. Read with .get: a stats row from an older
            # writer may carry neither flag, and absence is "no claim".
            if stats.get("error", False):
                error_count += 1
            elif stats["actionable"] > 0:
                failed_count += 1
            elif stats["excluded"]:
                skipped_count += 1
            elif stats["dependencies_missing"]:
                missing_count += 1
            elif stats.get("evaluated_nothing", False):
                skipped_count += 1
            else:
                passed_count += 1

        return {
            "total_scanners": len(scanner_stats),
            "passed_scanners": passed_count,
            "failed_scanners": failed_count,
            "skipped_scanners": skipped_count,
            "missing_scanners": missing_count,
            "error_scanners": error_count,
            "total_suppressed": totals.suppressed,
            "total_critical": totals.critical,
            "total_high": totals.high,
            "total_medium": totals.medium,
            "total_low": totals.low,
            "total_info": totals.info,
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
        the sum of total and suppressed findings from the scanner statistics, less the
        findings recorded on non-SARIF (dict) target reports: those are findings the
        merged SARIF never holds, and ``extract_sarif_counts_for_scanner`` adds them to
        every row so the summary and the exit code see them. If the counts match, the
        method returns True, indicating that the statistics calculation is accurate.

        Args:
            asharp_model: The AshAggregatedResults model containing SARIF data

        Returns:
            True if the total number of findings matches the length of results in SARIF,
            False otherwise
        """
        # Count findings in SARIF
        sarif_finding_count = 0
        if asharp_model.sarif:
            sarif_finding_count = len(asharp_model.sarif.get_all_results())

        # Count findings from scanner statistics
        scanner_stats = ScannerStatisticsCalculator.extract_scanner_statistics(
            asharp_model
        )
        stats_finding_count = sum(
            stats["total"] + stats["suppressed"] for stats in scanner_stats.values()
        )

        # The dict-result counts are in every row (extract_sarif_counts_for_scanner
        # adds them, whatever the SARIF holds) and in no SARIF result, so they are
        # taken back out before the compare: a scanner that returned
        # {"severity_counts": {"high": 3}} is not a mismatch of three on a run
        # whose SARIF is complete.
        dict_finding_count = 0
        for scanner_name in scanner_stats:
            dict_counts = ScannerStatisticsCalculator._dict_result_counts(
                asharp_model, scanner_name
            )
            dict_finding_count += sum(
                getattr(dict_counts, field)
                for field in ("suppressed", "critical", "high", "medium", "low", "info")
            )

        # Compare counts
        return sarif_finding_count == stats_finding_count - dict_finding_count

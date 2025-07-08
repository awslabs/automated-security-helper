# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Metrics alignment utilities for ASH.

This module provides utilities to ensure all metrics in ASH are aligned and driven
from the same source of truth: the final SARIF data via get_unified_scanner_metrics().

The main function populate_metrics_from_unified_source() should be called after
the SARIF data is finalized to ensure that summary_stats and scanner_results
are populated consistently with the final processed findings.
"""

from datetime import datetime
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    SummaryStats,
    ScannerTargetStatusInfo,
    ScannerSeverityCount,
)
from automated_security_helper.core.unified_metrics import get_unified_scanner_metrics
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.utils.log import ASH_LOGGER


def populate_metrics_from_unified_source(
    aggregated_results: AshAggregatedResults,
) -> AshAggregatedResults:
    """Populate summary_stats and scanner_results from unified metrics.

    This function ensures that all metrics are driven from the same source of truth:
    the final SARIF data via get_unified_scanner_metrics(). It replaces any existing
    summary_stats and updates scanner_results to consolidate source/converted layers.

    This should be called after the SARIF data is finalized to ensure consistency
    across all metrics reporting.

    Args:
        aggregated_results: The AshAggregatedResults model to update
    """
    ASH_LOGGER.info(
        "Aligning all metrics using unified scanner metrics as source of truth"
    )

    # Get unified metrics from the final SARIF data
    unified_metrics = get_unified_scanner_metrics(aggregated_results)

    # 1. Populate summary_stats from unified metrics
    aggregated_results = _populate_summary_stats_from_unified_metrics(
        aggregated_results, unified_metrics
    )

    # 2. Update scanner_results to consolidate source/converted and align with unified metrics
    aggregated_results = _populate_scanner_results_from_unified_metrics(
        aggregated_results, unified_metrics
    )

    ASH_LOGGER.info("Metrics alignment completed - all sources now use unified metrics")
    return aggregated_results


def _populate_summary_stats_from_unified_metrics(
    aggregated_results: AshAggregatedResults, unified_metrics: list
) -> AshAggregatedResults:
    """Populate summary_stats from unified metrics.

    Args:
        aggregated_results: The AshAggregatedResults model to update
        unified_metrics: List of ScannerMetrics from get_unified_scanner_metrics()
    """
    # Calculate totals from unified metrics
    total_suppressed = sum(m.suppressed for m in unified_metrics)
    total_critical = sum(m.critical for m in unified_metrics)
    total_high = sum(m.high for m in unified_metrics)
    total_medium = sum(m.medium for m in unified_metrics)
    total_low = sum(m.low for m in unified_metrics)
    total_info = sum(m.info for m in unified_metrics)
    total_findings = sum(m.total for m in unified_metrics)
    total_actionable = sum(m.actionable for m in unified_metrics)

    # Count scanner statuses
    passed_count = sum(1 for m in unified_metrics if m.status == "PASSED")
    failed_count = sum(1 for m in unified_metrics if m.status == "FAILED")
    skipped_count = sum(1 for m in unified_metrics if m.status == "SKIPPED")
    missing_count = sum(1 for m in unified_metrics if m.status == "MISSING")

    # Preserve timing information if it exists
    existing_start = aggregated_results.metadata.summary_stats.start
    existing_end = aggregated_results.metadata.summary_stats.end
    existing_duration = aggregated_results.metadata.summary_stats.duration

    # Create new summary stats with unified metrics
    aggregated_results.metadata.summary_stats = SummaryStats(
        start=existing_start.isoformat(timespec="seconds")
        if isinstance(existing_start, datetime)
        else existing_start,
        end=existing_end.isoformat(timespec="seconds")
        if isinstance(existing_end, datetime)
        else existing_end,
        duration=existing_duration,
        suppressed=total_suppressed,
        critical=total_critical,
        high=total_high,
        medium=total_medium,
        low=total_low,
        info=total_info,
        total=total_findings + total_suppressed,
        actionable=total_actionable,
        passed=passed_count,
        failed=failed_count,
        missing=missing_count,
        skipped=skipped_count,  # Add the missing skipped field
    )

    ASH_LOGGER.debug(
        f"Updated summary_stats: {total_actionable} actionable findings across {len(unified_metrics)} scanners"
    )

    return aggregated_results


def _populate_scanner_results_from_unified_metrics(
    aggregated_results: AshAggregatedResults, unified_metrics: list
) -> AshAggregatedResults:
    """Update scanner_results to consolidate source/converted layers and align with unified metrics.

    This function updates the scanner_results to use consolidated metrics from the unified
    source instead of maintaining separate source/converted counts that may not align
    with the final SARIF data.

    Args:
        aggregated_results: The AshAggregatedResults model to update
        unified_metrics: List of ScannerMetrics from get_unified_scanner_metrics()
    """
    for metrics in unified_metrics:
        scanner_name = metrics.scanner_name
        total_duration = metrics.duration

        # Create consolidated severity counts from unified metrics
        consolidated_severity_counts = ScannerSeverityCount(
            suppressed=metrics.suppressed,
            critical=metrics.critical,
            high=metrics.high,
            medium=metrics.medium,
            low=metrics.low,
            info=metrics.info,
        )

        # Convert status from string to enum
        if metrics.status == "PASSED":
            status = ScannerStatus.PASSED
        elif metrics.status == "FAILED":
            status = ScannerStatus.FAILED
        elif metrics.status == "SKIPPED":
            status = ScannerStatus.SKIPPED
        elif metrics.status == "MISSING":
            status = ScannerStatus.MISSING
        else:
            status = ScannerStatus.PASSED  # Default fallback

        # Create consolidated target status info (combines source + converted)
        consolidated_target_info = ScannerTargetStatusInfo(
            severity_counts=consolidated_severity_counts,
            # Total includes suppressed
            finding_count=metrics.total,
            actionable_finding_count=metrics.actionable,
            duration=total_duration,
            status=status,
        )

        # Update scanner_results with consolidated information
        # We'll put the consolidated metrics in the 'source' field and zero out 'converted'
        # to maintain the existing structure while consolidating the data
        aggregated_results.scanner_results[scanner_name] = consolidated_target_info

    ASH_LOGGER.debug(
        f"Updated scanner_results for {len(unified_metrics)} scanners with consolidated metrics"
    )
    return aggregated_results


def verify_metrics_alignment(aggregated_results: AshAggregatedResults) -> bool:
    """Verify that all metrics sources are aligned.

    This function checks that summary_stats, scanner_results totals, and SARIF results
    all report the same counts. It's useful for validation after calling
    populate_metrics_from_unified_source().

    Args:
        aggregated_results: The AshAggregatedResults model to verify

    Returns:
        True if all metrics are aligned, False otherwise
    """
    # Get unified metrics
    unified_metrics = get_unified_scanner_metrics(aggregated_results)

    # Calculate expected totals
    expected_totals = {
        "critical": sum(m.critical for m in unified_metrics),
        "high": sum(m.high for m in unified_metrics),
        "medium": sum(m.medium for m in unified_metrics),
        "low": sum(m.low for m in unified_metrics),
        "info": sum(m.info for m in unified_metrics),
        "suppressed": sum(m.suppressed for m in unified_metrics),
        "total": sum(m.total for m in unified_metrics),
        "actionable": sum(m.actionable for m in unified_metrics),
    }

    # Check summary_stats
    summary_stats = aggregated_results.metadata.summary_stats
    summary_totals = {
        "critical": summary_stats.critical,
        "high": summary_stats.high,
        "medium": summary_stats.medium,
        "low": summary_stats.low,
        "info": summary_stats.info,
        "suppressed": summary_stats.suppressed,
        "total": summary_stats.total,
        "actionable": summary_stats.actionable,
    }

    # Check scanner_results totals
    scanner_results_totals = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
        "suppressed": 0,
        "total": 0,
        "actionable": 0,
    }

    for scanner_info in aggregated_results.scanner_results.values():
        # Since we consolidated into 'source', only count source metrics
        source_counts = scanner_info.severity_counts
        scanner_results_totals["critical"] += source_counts.critical
        scanner_results_totals["high"] += source_counts.high
        scanner_results_totals["medium"] += source_counts.medium
        scanner_results_totals["low"] += source_counts.low
        scanner_results_totals["info"] += source_counts.info
        scanner_results_totals["suppressed"] += source_counts.suppressed
        scanner_results_totals["total"] += scanner_info.finding_count or 0
        scanner_results_totals["actionable"] += scanner_info.actionable_finding_count

    # Compare all three sources
    alignment_ok = True
    for metric in expected_totals.keys():
        expected = expected_totals[metric]
        summary = summary_totals[metric]
        scanner_results = scanner_results_totals[metric]

        if not (expected == summary == scanner_results):
            ASH_LOGGER.error(
                f"Metrics alignment failed for {metric}: "
                f"unified={expected}, summary_stats={summary}, scanner_results={scanner_results}"
            )
            alignment_ok = False

    if alignment_ok:
        ASH_LOGGER.info("✅ All metrics sources are aligned")
    else:
        ASH_LOGGER.error("❌ Metrics alignment verification failed")

    return alignment_ok

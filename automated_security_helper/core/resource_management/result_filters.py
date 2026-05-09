# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Result filtering utilities for MCP scan results.

These functions filter and reshape the raw scan-result dict returned by
mcp_get_scan_results into smaller, purpose-specific views.
"""

import copy
from typing import Any, Dict, Optional


def filter_summary(results: Dict[str, Any]) -> Dict[str, Any]:
    """Filter results to return only summary information."""
    summary: Dict[str, Any] = {
        "success": True,
        "scan_id": results.get("scan_id"),
        "status": results.get("status"),
        "is_complete": results.get("is_complete"),
        "completion_time": results.get("completion_time"),
        "metadata": {},
        "findings_summary": {},
        "scanner_summary": {},
        "_filter": "summary",
    }

    raw_results = results.get("raw_results", {})
    metadata = raw_results.get("metadata", {})

    summary["metadata"] = {
        "generated_at": metadata.get("generated_at"),
        "ash_version": metadata.get("tool_version"),
        "scan_duration_seconds": metadata.get("summary_stats", {}).get("duration"),
    }

    summary_stats = results.get("summary_stats", {})
    summary["findings_summary"] = {
        "by_severity": {
            "critical": summary_stats.get("critical", 0),
            "high": summary_stats.get("high", 0),
            "medium": summary_stats.get("medium", 0),
            "low": summary_stats.get("low", 0),
            "info": summary_stats.get("info", 0),
            "suppressed": summary_stats.get("suppressed", 0),
            "total": summary_stats.get("total", 0),
            "actionable": summary_stats.get("actionable", 0),
        },
        "scan_stats": {
            "passed": summary_stats.get("passed", 0),
            "failed": summary_stats.get("failed", 0),
            "missing": summary_stats.get("missing", 0),
            "skipped": summary_stats.get("skipped", 0),
        },
    }

    scanner_results = raw_results.get("scanner_results", {})
    summary["scanner_summary"] = {
        "by_scanner": {},
        "total_scanners": len(scanner_results),
        "completed_scanners": 0,
    }

    for scanner_name, scanner_data in scanner_results.items():
        status = scanner_data.get("status", "UNKNOWN")
        severity_counts = scanner_data.get("severity_counts", {})

        scanner_info = {
            "status": status,
            "findings_count": scanner_data.get("finding_count", 0),
            "actionable_findings": scanner_data.get("actionable_finding_count", 0),
            "suppressed_findings": scanner_data.get("suppressed_finding_count", 0),
            "duration": scanner_data.get("duration", 0),
            "by_severity": {
                "critical": severity_counts.get("critical", 0),
                "high": severity_counts.get("high", 0),
                "medium": severity_counts.get("medium", 0),
                "low": severity_counts.get("low", 0),
                "info": severity_counts.get("info", 0),
                "suppressed": severity_counts.get("suppressed", 0),
            },
        }

        summary["scanner_summary"]["by_scanner"][scanner_name] = scanner_info

        if status in ["PASSED", "FAILED"]:
            summary["scanner_summary"]["completed_scanners"] += 1

    return summary


def filter_minimal(results: Dict[str, Any]) -> Dict[str, Any]:
    """Filter results to return only minimal status information."""
    return {
        "success": True,
        "scan_id": results.get("scan_id"),
        "status": results.get("status"),
        "is_complete": results.get("is_complete"),
        "completion_time": results.get("completion_time"),
        "summary_stats": results.get("summary_stats", {}),
        "_filter": "minimal",
    }


def filter_actionable_only(results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Filter results to exclude suppressed findings.

    Returns a deep copy of *results* with suppressed SARIF entries removed
    and suppressed counts zeroed out.
    """
    filtered_results = copy.deepcopy(results)

    if "raw_results" in filtered_results and "sarif" in filtered_results["raw_results"]:
        sarif = filtered_results["raw_results"]["sarif"]
        if "runs" in sarif:
            for run in sarif["runs"]:
                if "results" in run and run["results"]:
                    run["results"] = [
                        r
                        for r in run["results"]
                        if not (r.get("suppressions") and len(r.get("suppressions", [])) > 0)
                    ]

    if "summary_stats" in filtered_results:
        summary_stats = filtered_results["summary_stats"]
        summary_stats["suppressed"] = 0
        summary_stats["total"] = summary_stats.get("actionable", 0)

    if (
        "raw_results" in filtered_results
        and "scanner_results" in filtered_results["raw_results"]
    ):
        for scanner_data in filtered_results["raw_results"]["scanner_results"].values():
            if "suppressed_finding_count" in scanner_data:
                scanner_data["suppressed_finding_count"] = 0
            if (
                "severity_counts" in scanner_data
                and "suppressed" in scanner_data["severity_counts"]
            ):
                scanner_data["severity_counts"]["suppressed"] = 0

    if "_content_filters" not in filtered_results:
        filtered_results["_content_filters"] = {}
    filtered_results["_content_filters"]["actionable_only"] = True

    return filtered_results


def apply_content_filters(
    results: Dict[str, Any],
    scanners: Optional[str] = None,
    severities: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Filter results by scanner names and/or severity levels.

    Args:
        results: The full scan results.
        scanners: Comma-separated scanner names (e.g., "bandit,semgrep").
        severities: Comma-separated severity levels (e.g., "critical,high").

    Returns:
        Filtered results with only matching scanners and severities.
    """
    scanner_list = (
        [s.strip().lower() for s in scanners.split(",")] if scanners else None
    )
    severity_list = (
        [s.strip().lower() for s in severities.split(",")] if severities else None
    )

    filtered_results = copy.deepcopy(results)

    if "scanner_reports" in filtered_results and scanner_list:
        filtered_results["scanner_reports"] = {
            name: data
            for name, data in filtered_results["scanner_reports"].items()
            if name.lower() in scanner_list
        }

    if (
        "raw_results" in filtered_results
        and "scanner_results" in filtered_results["raw_results"]
    ):
        orig = filtered_results["raw_results"]["scanner_results"]
        if scanner_list:
            new_scanner_results = {}
            for name, data in orig.items():
                if name.lower() in scanner_list:
                    if severity_list and "severity_counts" in data:
                        data = data.copy()
                        data["severity_counts"] = {
                            k: v
                            for k, v in data["severity_counts"].items()
                            if k.lower() in severity_list
                        }
                    new_scanner_results[name] = data
            filtered_results["raw_results"]["scanner_results"] = new_scanner_results
        elif severity_list:
            new_scanner_results = {}
            for name, data in orig.items():
                if "severity_counts" in data:
                    data = data.copy()
                    data["severity_counts"] = {
                        k: v
                        for k, v in data["severity_counts"].items()
                        if k.lower() in severity_list
                    }
                new_scanner_results[name] = data
            filtered_results["raw_results"]["scanner_results"] = new_scanner_results

    if (
        "raw_results" in filtered_results
        and "additional_reports" in filtered_results["raw_results"]
        and scanner_list
    ):
        filtered_results["raw_results"]["additional_reports"] = {
            name: data
            for name, data in filtered_results["raw_results"]["additional_reports"].items()
            if name.lower() in scanner_list
        }

    _severity_keys = {"critical", "high", "medium", "low", "info", "suppressed"}
    if severity_list and "summary_stats" in filtered_results:
        filtered_results["summary_stats"] = {
            key: (value if key not in _severity_keys or key.lower() in severity_list else 0)
            for key, value in filtered_results["summary_stats"].items()
        }

    filter_metadata: Dict[str, Any] = {}
    if scanner_list:
        filter_metadata["scanners"] = scanner_list
    if severity_list:
        filter_metadata["severities"] = severity_list
    filtered_results["_content_filters"] = filter_metadata

    return filtered_results

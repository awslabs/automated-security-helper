from automated_security_helper.utils.meta_analysis import (
    SCANNER_NAME_MAP,
)
from automated_security_helper.utils.meta_analysis.compare_result_fields import (
    compare_result_fields,
)
from automated_security_helper.utils.meta_analysis.extract_result_summary import (
    extract_result_summary,
)
from automated_security_helper.utils.meta_analysis.find_matching_result import (
    find_matching_result,
)


from typing import Dict


def validate_sarif_aggregation(
    original_reports: Dict[str, Dict], aggregated_report: Dict
) -> Dict:
    """
    Validate that all important fields from original scanner reports
    are preserved in the aggregated report.

    Args:
        original_reports: Dict mapping scanner names to their SARIF reports
        aggregated_report: The combined ASH SARIF report

    Returns:
        Dict with validation results and statistics
    """
    validation_results = {
        "missing_fields": {},
        "match_statistics": {},
        "unmatched_results": {},
        "summary": {
            "total_findings": 0,
            "matched_findings": 0,
            "critical_missing_fields": 0,
            "important_missing_fields": 0,
            "informational_missing_fields": 0,
        },
    }

    # Extract results from aggregated report
    agg_results = []
    if (
        aggregated_report.get("runs")
        and len(aggregated_report["runs"]) > 0
        and aggregated_report["runs"][0].get("results")
    ):
        agg_results = aggregated_report["runs"][0]["results"]

    # For each scanner's report
    for scanner_name, original_report in original_reports.items():
        # Map scanner name to ASH configuration name if available
        normalized_scanner_name = SCANNER_NAME_MAP.get(scanner_name, scanner_name)

        validation_results["missing_fields"][normalized_scanner_name] = {
            "critical": [],
            "important": [],
            "informational": [],
        }
        validation_results["match_statistics"][normalized_scanner_name] = {
            "total_results": 0,
            "matched_results": 0,
            "field_preservation_rate": 0,
            "critical_fields_missing": 0,
            "important_fields_missing": 0,
            "informational_fields_missing": 0,
        }

        # Get original results
        orig_results = []
        if (
            original_report.get("runs")
            and len(original_report["runs"]) > 0
            and original_report["runs"][0].get("results")
        ):
            orig_results = original_report["runs"][0]["results"]

        # Process each result in the original report
        for orig_result in orig_results:
            validation_results["match_statistics"][normalized_scanner_name][
                "total_results"
            ] += 1
            validation_results["summary"]["total_findings"] += 1

            # Find matching result in aggregated report
            matched_result = find_matching_result(orig_result, agg_results)

            if matched_result:
                validation_results["match_statistics"][normalized_scanner_name][
                    "matched_results"
                ] += 1
                validation_results["summary"]["matched_findings"] += 1

                # Compare fields between original and matched result
                missing_fields = compare_result_fields(orig_result, matched_result)

                # Categorize missing fields by importance
                for field_info in missing_fields:
                    importance = field_info["importance"]
                    validation_results["missing_fields"][normalized_scanner_name][
                        importance
                    ].append(field_info)
                    validation_results["match_statistics"][normalized_scanner_name][
                        f"{importance}_fields_missing"
                    ] += 1
                    validation_results["summary"][f"{importance}_missing_fields"] += 1
            else:
                # Track unmatched results
                if (
                    normalized_scanner_name
                    not in validation_results["unmatched_results"]
                ):
                    validation_results["unmatched_results"][
                        normalized_scanner_name
                    ] = []
                validation_results["unmatched_results"][normalized_scanner_name].append(
                    extract_result_summary(orig_result)
                )

    # Calculate field preservation rates
    for scanner_name in validation_results["match_statistics"]:
        stats = validation_results["match_statistics"][scanner_name]
        if stats["total_results"] > 0:
            stats["field_preservation_rate"] = (
                stats["matched_results"] / stats["total_results"]
            )

    return validation_results

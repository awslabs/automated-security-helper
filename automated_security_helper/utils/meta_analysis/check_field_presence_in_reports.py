from automated_security_helper.utils.meta_analysis.get_reporter_mappings import (
    get_reporter_mappings,
)
from automated_security_helper.utils.meta_analysis.get_value_from_path import (
    get_value_from_path,
)


from typing import Any, Dict, Optional, Set


def check_field_presence_in_reports(
    field_paths: Dict[str, Dict[str, Set[str]]],
    aggregate_report: Dict,
    flat_reports: Optional[Dict[str, Dict]] = None,
) -> Dict[str, Dict[str, Any]]:
    """
    Check if fields are present in aggregate and flat reports.

    Args:
        field_paths: Dictionary of field paths from original reports
        aggregate_report: The aggregated SARIF report
        flat_reports: Optional dictionary of flat report formats (CSV, JSON)

    Returns:
        Dictionary mapping field paths to presence information
    """
    presence_info = {}

    # First, initialize the presence_info dictionary with all fields
    for path, info in field_paths.items():
        if path not in presence_info:
            presence_info[path] = {
                "type": list(info["type"]),
                "scanners": list(info["scanners"]),  # Make sure we capture all scanners
                "in_aggregate": False,
                "in_flat": {},
                "reporter_mappings": {},
            }
        else:
            # If the path already exists, merge the scanner information
            # Convert both lists to sets for proper merging
            scanners_set = set(presence_info[path]["scanners"])
            scanners_set.update(info["scanners"])  # Add all scanners from the new info
            presence_info[path]["scanners"] = list(scanners_set)

            # Do the same for types
            types_set = set(presence_info[path]["type"])
            types_set.update(info["type"])
            presence_info[path]["type"] = list(types_set)

        # Check presence in aggregate report
        if aggregate_report:
            # Use get_value_from_path to check if field exists in aggregate
            result = get_value_from_path(aggregate_report, path)
            presence_info[path]["in_aggregate"] = result[
                "exists"
            ]  # Field exists even if value is None

        # Check presence in flat reports
        if flat_reports:
            for report_type, report_data in flat_reports.items():
                presence_info[path]["in_flat"][report_type] = False

                # Get the mapping for this report type if available
                reporter_mappings = get_reporter_mappings()
                if (
                    report_type in reporter_mappings
                    and path in reporter_mappings[report_type]
                ):
                    mapped_field = reporter_mappings[report_type][path]

                    # Check if the mapped field exists in the flat report
                    if isinstance(report_data, dict):
                        # For nested fields in JSON-like formats
                        field_parts = mapped_field.split(".")
                        current = report_data
                        field_exists = True

                        for part in field_parts:
                            if part in current:
                                current = current[part]
                            else:
                                field_exists = False
                                break

                        presence_info[path]["in_flat"][report_type] = field_exists
                    elif isinstance(report_data, str):
                        # For text-based formats, check if the field name appears in the content
                        presence_info[path]["in_flat"][report_type] = (
                            mapped_field in report_data
                        )
                else:
                    # Fallback to checking if the last part of the path exists in the report
                    field_name = path.split(".")[-1]
                    if isinstance(report_data, dict) and field_name in report_data:
                        presence_info[path]["in_flat"][report_type] = True
                    elif isinstance(report_data, str) and field_name in report_data:
                        presence_info[path]["in_flat"][report_type] = True

    # Add reporter mappings if available
    reporter_mappings = get_reporter_mappings()
    for path in presence_info:
        for reporter_name, mappings in reporter_mappings.items():
            if path in mappings:
                if "reporter_mappings" not in presence_info[path]:
                    presence_info[path]["reporter_mappings"] = {}
                presence_info[path]["reporter_mappings"][reporter_name] = mappings[path]

    return presence_info

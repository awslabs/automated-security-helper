from automated_security_helper.utils.meta_analysis import EXPECTED_TRANSFORMATIONS
from automated_security_helper.utils.meta_analysis.field_mapping import (
    categorize_field_importance,
    extract_field_paths,
    get_value_from_path,
)


from typing import Dict, List


def compare_result_fields(original_result: Dict, aggregated_result: Dict) -> List[Dict]:
    """
    Compare fields between original and aggregated results.

    Args:
        original_result: Result from original scanner report
        aggregated_result: Matching result from aggregated report

    Returns:
        List of missing fields with their importance
    """
    missing_fields = []

    # Extract all field paths from both results
    orig_paths = extract_field_paths(original_result)
    agg_paths = extract_field_paths(aggregated_result)

    # Find fields in original that are missing in aggregated
    for path in orig_paths:
        # Skip known fields that might be intentionally different
        if path in ["properties", ".properties"]:
            continue

        # Check if this is an expected transformation: the entry itself, a
        # field under it ("tool.driver.name") or an item of it. extract_field_paths
        # writes a list's items as "properties.tags[0]", which neither equals
        # "properties.tags" nor starts with "properties.tags.", so every tag of a
        # consolidated tag list was reported as a missing field.
        is_expected_transformation = any(
            path == transform_path
            or path.startswith((f"{transform_path}.", f"{transform_path}["))
            for transform_path in EXPECTED_TRANSFORMATIONS
        )

        if path not in agg_paths and not is_expected_transformation:
            # Get the value from the original result
            orig_value = get_value_from_path(original_result, path)

            missing_fields.append(
                {
                    "path": path,
                    "original_value": orig_value["value"],
                    "importance": categorize_field_importance(path),
                }
            )

    return missing_fields

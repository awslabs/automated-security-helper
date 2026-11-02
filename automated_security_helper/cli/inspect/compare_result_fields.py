from automated_security_helper.utils.meta_analysis import is_expected_transformation
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

        # An expected transformation (the entry itself, a field under it such as
        # "tool.driver.name", or an item of it such as "properties.tags[0]") is
        # decided by the one predicate the meta-analysis module keeps, so this
        # loop and the module cannot read the list two different ways.
        if path not in agg_paths and not is_expected_transformation(path):
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

from automated_security_helper.utils.meta_analysis.extract_location_info import (
    extract_location_info,
)
from automated_security_helper.utils.meta_analysis.get_message_text import (
    get_message_text,
)
from automated_security_helper.utils.meta_analysis.locations_match import (
    locations_match,
)


from typing import Dict, List


def find_matching_result(original_result: Dict, aggregated_results: List[Dict]) -> Dict:
    """
    Find a matching result in the aggregated report using rule ID and location.

    Args:
        original_result: Result from original scanner report
        aggregated_results: List of results from aggregated report

    Returns:
        Matching result or None
    """
    # Extract matching criteria
    rule_id = original_result.get("ruleId")

    # Extract location info
    location_info = extract_location_info(original_result)

    # Try to find a match
    for agg_result in aggregated_results:
        # Match by rule ID first
        if agg_result.get("ruleId") == rule_id:
            # Then check location
            agg_location = extract_location_info(agg_result)

            # Compare locations, allowing for path normalization
            if locations_match(location_info, agg_location):
                return agg_result

            # If locations don't match but messages do, consider it a match
            if (
                original_result.get("message")
                and agg_result.get("message")
                and get_message_text(original_result) == get_message_text(agg_result)
            ):
                return agg_result

            # Check analysisTarget if available
            if (
                original_result.get("analysisTarget")
                and agg_result.get("analysisTarget")
                and original_result["analysisTarget"].get("uri")
                == agg_result["analysisTarget"].get("uri")
            ):
                return agg_result

    return None

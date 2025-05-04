from automated_security_helper.utils.meta_analysis.extract_location_info import (
    extract_location_info,
)
from automated_security_helper.utils.meta_analysis.get_message_text import (
    get_message_text,
)


from typing import Dict


def extract_result_summary(result: Dict) -> Dict:
    """
    Extract a summary of a result for reporting.

    Args:
        result: SARIF result object

    Returns:
        Summary dictionary
    """
    summary = {
        "ruleId": result.get("ruleId", "unknown"),
        "message": get_message_text(result),
        "location": extract_location_info(result),
    }

    return summary

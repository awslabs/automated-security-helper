from typing import Dict


def get_message_text(result: Dict) -> str:
    """
    Extract message text from a result.

    Args:
        result: SARIF result object

    Returns:
        Message text
    """
    if result.get("message"):
        if isinstance(result["message"], str):
            return result["message"]
        elif isinstance(result["message"], dict):
            if result["message"].get("text"):
                return result["message"]["text"]
            elif result["message"].get("root") and result["message"]["root"].get(
                "text"
            ):
                return result["message"]["root"]["text"]

    return ""

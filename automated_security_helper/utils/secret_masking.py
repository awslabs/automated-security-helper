"""Utility functions for masking secrets in security findings."""

import re
from typing import Optional


def mask_secret_in_text(text: str, rule_id: Optional[str] = None) -> str:
    """
    Mask secrets in text based on the rule ID and content patterns.

    Args:
        text: The text that may contain secrets
        rule_id: The rule ID that triggered the finding (e.g., 'B105')

    Returns:
        The text with secrets masked
    """
    if not text or not rule_id:
        return text

    # Handle Bandit B105/B106/B107 (hardcoded password) findings
    if rule_id in ("B105", "B106", "B107"):
        return _mask_bandit_password_secret(text)

    return text


def _mask_bandit_password_secret(text: str) -> str:
    """
    Mask secrets in Bandit B105/B106/B107 findings.

    These findings typically have messages like:
    "Possible hardcoded password: 'actual_secret_value'"

    Args:
        text: The finding description text

    Returns:
        The text with the secret value masked
    """
    # Pattern to match Bandit password messages with quoted secrets.
    # Uses a non-greedy match that handles escaped quotes and stops at
    # the matching closing delimiter (single or double quote).
    pattern = r"""(Possible hardcoded password:\s*)(["'])((?:(?!\2).)*)\2"""

    def mask_replacement(match):
        prefix = match.group(1)  # "Possible hardcoded password: "
        quote = match.group(2)   # The quote character (' or ")
        secret = match.group(3)  # The actual secret

        masked_secret = _mask_secret_value(secret)
        return f"{prefix}{quote}{masked_secret}{quote}"

    return re.sub(pattern, mask_replacement, text)


# Keep the old name as an alias for backward compatibility
_mask_bandit_b105_secret = _mask_bandit_password_secret


def _mask_secret_value(secret: str) -> str:
    """
    Mask a secret value while preserving some structure for analysis.
    At least 75% of characters are masked for any secret of length >= 4.

    Args:
        secret: The secret value to mask

    Returns:
        The masked secret value
    """
    if not secret:
        return secret

    length = len(secret)

    # For very short secrets (< 4 chars), mask completely
    if length < 4:
        return "*" * length

    # For secrets of length 4-7, show only the first character
    if length <= 7:
        return secret[0] + "*" * (length - 1)

    # For secrets of length 8-12, show first and last character
    if length <= 12:
        return secret[0] + "*" * (length - 2) + secret[-1]

    # For long secrets, show first 2 and last 1 character
    return secret[:2] + "*" * (length - 3) + secret[-1]

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
    
    # Handle Bandit B105 (hardcoded password) findings
    if rule_id == "B105":
        return _mask_bandit_b105_secret(text)
    
    # Add other rule-specific masking as needed
    # elif rule_id == "B106":  # hardcoded password funcarg
    #     return _mask_bandit_b106_secret(text)
    
    return text


def _mask_bandit_b105_secret(text: str) -> str:
    """
    Mask secrets in Bandit B105 findings.
    
    B105 findings typically have messages like:
    "Possible hardcoded password: 'actual_secret_value'"
    
    Args:
        text: The finding description text
        
    Returns:
        The text with the secret value masked
    """
    # Pattern to match Bandit B105 messages with quoted secrets
    # Matches: "Possible hardcoded password: 'secret'" or "Possible hardcoded password: \"secret\""
    pattern = r"(Possible hardcoded password:\s*['\"])([^'\"]+)(['\"])"
    
    def mask_replacement(match):
        prefix = match.group(1)  # "Possible hardcoded password: '"
        secret = match.group(2)   # The actual secret
        suffix = match.group(3)   # "'"
        
        # Mask the secret while preserving some structure for analysis
        masked_secret = _mask_secret_value(secret)
        return f"{prefix}{masked_secret}{suffix}"
    
    return re.sub(pattern, mask_replacement, text)


def _mask_secret_value(secret: str) -> str:
    """
    Mask a secret value while preserving some structure for analysis.
    
    Args:
        secret: The secret value to mask
        
    Returns:
        The masked secret value
    """
    if not secret:
        return secret
    
    # For very short secrets (< 4 chars), mask completely
    if len(secret) < 4:
        return "*" * len(secret)
    
    # For 4-character secrets, show first and last character
    if len(secret) == 4:
        return secret[0] + "**" + secret[-1]
    
    # For longer secrets, show first 2 and last 2 characters
    if len(secret) <= 8:
        return secret[:2] + "*" * (len(secret) - 4) + secret[-2:]
    
    # For very long secrets, show first 3 and last 3 characters
    return secret[:3] + "*" * (len(secret) - 6) + secret[-3:]
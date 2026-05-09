# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Utility functions for matching findings against suppression rules."""

import fnmatch
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Tuple

from automated_security_helper.models.core import AshSuppression
from automated_security_helper.utils.path_matching import _recursive_glob_match
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.utils.log import ASH_LOGGER

# Regex patterns for inline suppression comments.
# Supported formats (hash-style for Python/Ruby/YAML/Shell):
#   # ash-ignore: RULE-ID [reason]
#   # ash-ignore-next-line: RULE-ID [reason]
# Supported formats (slash-style for JS/TS/Java/C#/Go):
#   // ash-ignore: RULE-ID [reason]
#   // ash-ignore-next-line: RULE-ID [reason]
_HASH_INLINE_PATTERN = re.compile(
    r"#\s*ash-ignore:\s*(\S+)\s*(.*)?$", re.IGNORECASE
)
_HASH_NEXT_LINE_PATTERN = re.compile(
    r"#\s*ash-ignore-next-line:\s*(\S+)\s*(.*)?$", re.IGNORECASE
)
_SLASH_INLINE_PATTERN = re.compile(
    r"//\s*ash-ignore:\s*(\S+)\s*(.*)?$", re.IGNORECASE
)
_SLASH_NEXT_LINE_PATTERN = re.compile(
    r"//\s*ash-ignore-next-line:\s*(\S+)\s*(.*)?$", re.IGNORECASE
)

_INLINE_PATTERNS = [_HASH_INLINE_PATTERN, _SLASH_INLINE_PATTERN]
_NEXT_LINE_PATTERNS = [_HASH_NEXT_LINE_PATTERN, _SLASH_NEXT_LINE_PATTERN]


@dataclass(frozen=True)
class InlineSuppression:
    """A suppression directive parsed from an inline source comment."""

    line_number: int
    """The source line that the suppression applies to."""
    rule_id: str
    reason: str


def matches_suppression(
    finding: FlatVulnerability, suppression: AshSuppression
) -> bool:
    """Thin wrapper around ``AshSuppression.matches`` kept for backward compatibility.

    Prefer ``suppression.matches(finding)`` in new code.
    """
    return suppression.matches(finding)


def _rule_id_matches(finding_rule_id: Optional[str], suppression_rule_id: str) -> bool:
    """Check if the finding's rule ID matches the suppression rule ID."""
    if finding_rule_id is None:
        return False

    # Normalize to lowercase for OS-independent case-insensitive matching.
    # fnmatch.fnmatch is case-insensitive on macOS/Windows but case-sensitive
    # on Linux, so we force lowercase on both sides for consistent behavior.
    return fnmatch.fnmatch(finding_rule_id.lower(), suppression_rule_id.lower())


def file_path_matches(
    finding_file_path: Optional[str], suppression_file_path: str
) -> bool:
    """Check if the finding's file path matches the suppression file path pattern.

    Supports ``**`` as a recursive glob that matches zero or more directories,
    e.g. ``tests/**/*.py`` matches both ``tests/test_foo.py`` and
    ``tests/sub/test_bar.py``.
    """
    if finding_file_path is None:
        return False

    # Normalize to lowercase for OS-independent case-insensitive matching.
    finding_lower = finding_file_path.lower()
    suppression_lower = suppression_file_path.lower()

    if finding_lower == suppression_lower:
        return True

    # When the pattern contains "**", we need special handling because
    # fnmatch treats "*" as "anything except /" and has no concept of
    # recursive directory matching.  We split on "**" and check that
    # each segment matches in order, allowing any number of path
    # components (including zero) in place of each "**".
    if "**" in suppression_lower:
        return _recursive_glob_match(finding_lower, suppression_lower)

    return fnmatch.fnmatch(finding_lower, suppression_lower)


def _line_range_matches(
    finding: FlatVulnerability, suppression: AshSuppression
) -> bool:
    """Check if the finding's line range overlaps with the suppression line range."""
    # If suppression doesn't specify line range, it matches any line
    if suppression.line_start is None and suppression.line_end is None:
        return True

    # If finding doesn't have line information but suppression requires it, no match
    if finding.line_start is None:
        return False

    # If only start line is specified in suppression
    if suppression.line_start is not None and suppression.line_end is None:
        # Match if finding overlaps with the suppression start line:
        # either the finding starts at/after suppression start, or the
        # finding spans across the suppression start (multi-line finding).
        finding_end = (
            finding.line_end if finding.line_end is not None else finding.line_start
        )
        return finding_end >= suppression.line_start

    # If only end line is specified in suppression
    if suppression.line_start is None and suppression.line_end is not None:
        # Match if finding ends at or before the suppression end line
        finding_end = (
            finding.line_end if finding.line_end is not None else finding.line_start
        )
        return finding_end <= suppression.line_end

    # Both start and end lines are specified in suppression
    finding_start = finding.line_start
    finding_end = (
        finding.line_end if finding.line_end is not None else finding.line_start
    )

    # Check if the finding's line range overlaps with the suppression's line range
    return (finding_start <= (suppression.line_end or 0)) and (
        finding_end >= (suppression.line_start or 0)
    )


def should_suppress_finding(
    finding: FlatVulnerability, suppressions: List[AshSuppression]
) -> Tuple[bool, Optional[AshSuppression]]:
    """
    Determine if a finding should be suppressed based on the suppression rules.

    Args:
        finding: The finding to check
        suppressions: List of suppression rules to check against

    Returns:
        A tuple of (should_suppress, matching_suppression)
    """
    for suppression in suppressions:
        # Skip expired suppressions
        if suppression.expiration:
            try:
                expiration_date = datetime.strptime(
                    suppression.expiration, "%Y-%m-%d"
                ).date()
                if expiration_date <= datetime.now().date():
                    ASH_LOGGER.debug(
                        f"Suppression for rule {suppression.rule_id} has expired on {suppression.expiration}"
                    )
                    continue
            except ValueError:
                ASH_LOGGER.warning(
                    f"Invalid expiration date format for suppression: {suppression.expiration}"
                )
                continue

        if matches_suppression(finding, suppression):
            return True, suppression

    return False, None


def check_for_expiring_suppressions(
    suppressions: List[AshSuppression], days_threshold: int = 30
) -> List[AshSuppression]:
    """
    Check for suppressions that will expire within the specified number of days.

    Args:
        suppressions: List of suppression rules to check
        days_threshold: Number of days threshold for warning

    Returns:
        List of suppressions that will expire within the threshold
    """
    expiring_suppressions = []
    today = datetime.now().date()

    for suppression in suppressions:
        if suppression.expiration:
            try:
                expiration_date = datetime.strptime(
                    suppression.expiration, "%Y-%m-%d"
                ).date()
                days_until_expiration = (expiration_date - today).days

                if 0 <= days_until_expiration <= days_threshold:
                    expiring_suppressions.append(suppression)
            except ValueError:
                ASH_LOGGER.warning(
                    f"Invalid expiration date format for suppression: {suppression.expiration}"
                )

    return expiring_suppressions


def find_inline_suppressions(file_path: Path) -> List[InlineSuppression]:
    """Scan a source file for inline suppression comments.

    Recognised directives (both ``#`` and ``//`` comment styles):

    * ``# ash-ignore: <rule-id> [reason]``  --  suppresses same line.
    * ``# ash-ignore-next-line: <rule-id> [reason]``  --  suppresses next line.
    * ``// ash-ignore: <rule-id> [reason]``  --  same (JS/TS/Java/C#/Go).
    * ``// ash-ignore-next-line: <rule-id> [reason]``  --  same.

    Args:
        file_path: Path to the source file to scan.

    Returns:
        List of ``InlineSuppression`` instances, one per directive found.
    """
    suppressions: List[InlineSuppression] = []
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeDecodeError) as exc:
        ASH_LOGGER.debug(f"Could not read {file_path} for inline suppressions: {exc}")
        return suppressions

    for line_num_0, line in enumerate(text.splitlines()):
        line_num = line_num_0 + 1  # 1-based

        matched = False
        for pattern in _INLINE_PATTERNS:
            match = pattern.search(line)
            if match:
                rule_id = match.group(1)
                reason = (match.group(2) or "").strip()
                suppressions.append(
                    InlineSuppression(
                        line_number=line_num,
                        rule_id=rule_id,
                        reason=reason or "Inline suppression",
                    )
                )
                matched = True
                break
        if matched:
            continue

        for pattern in _NEXT_LINE_PATTERNS:
            match = pattern.search(line)
            if match:
                rule_id = match.group(1)
                reason = (match.group(2) or "").strip()
                suppressions.append(
                    InlineSuppression(
                        line_number=line_num + 1,
                        rule_id=rule_id,
                        reason=reason or "Inline suppression (next-line)",
                    )
                )
                break

    return suppressions

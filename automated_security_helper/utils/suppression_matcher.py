# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Utility functions for matching findings against suppression rules."""

import fnmatch
from datetime import datetime
from typing import List, Optional, Tuple

from automated_security_helper.models.core import AshSuppression
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.utils.log import ASH_LOGGER


def matches_suppression(
    finding: FlatVulnerability, suppression: AshSuppression
) -> bool:
    """
    Determine if a finding matches a suppression rule.

    Args:
        finding: The finding to check
        suppression: The suppression rule to match against

    Returns:
        True if the finding matches the suppression rule, False otherwise
    """
    # Check if rule ID matches
    if suppression.rule_id and not _rule_id_matches(
        finding.rule_id, suppression.rule_id
    ):
        return False

    # Check if file path matches
    if not _file_path_matches(finding.file_path, suppression.path):
        return False

    # Check if line range matches (if specified)
    if not _line_range_matches(finding, suppression):
        return False

    return True


def _rule_id_matches(finding_rule_id: Optional[str], suppression_rule_id: str) -> bool:
    """Check if the finding's rule ID matches the suppression rule ID."""
    if finding_rule_id is None:
        return False

    # Normalize to lowercase for OS-independent case-insensitive matching.
    # fnmatch.fnmatch is case-insensitive on macOS/Windows but case-sensitive
    # on Linux, so we force lowercase on both sides for consistent behavior.
    return fnmatch.fnmatch(finding_rule_id.lower(), suppression_rule_id.lower())


def _file_path_matches(
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


def _recursive_glob_match(path: str, pattern: str) -> bool:
    """Match *path* against *pattern* treating ``**`` as zero-or-more directories.

    The algorithm splits the pattern on ``**`` separators, then verifies that
    each resulting segment appears in the correct order inside *path* using
    ``fnmatch`` for each segment.
    """
    # Normalise separators
    path = path.replace("\\", "/")
    pattern = pattern.replace("\\", "/")

    # Split pattern on "**" (possibly surrounded by slashes)
    import re

    segments = re.split(r"/?\*\*/?", pattern)

    # Handle trailing ** (e.g. "tests/**") — means match anything under prefix
    has_trailing_star = pattern.rstrip("/").endswith("**")
    # Handle leading ** (e.g. "**/*.py") — means match from any depth
    has_leading_star = pattern.lstrip("/").startswith("**")

    # Remove empty segments but track their positions
    segments = [s for s in segments if s]

    # Pattern is just "**" — matches everything
    if not segments:
        return True

    # Single segment with both leading and trailing ** — match anywhere in path
    if len(segments) == 1 and has_leading_star and has_trailing_star:
        middle = segments[0]
        parts = path.split("/")
        seg_parts = middle.split("/")
        seg_len = len(seg_parts)
        for j in range(len(parts) - seg_len + 1):
            candidate = "/".join(parts[j : j + seg_len])
            if fnmatch.fnmatch(candidate, middle):
                return True
        return False

    # Single segment with trailing ** — prefix match
    if len(segments) == 1 and has_trailing_star and not has_leading_star:
        prefix = segments[0]
        parts = path.split("/")
        seg_parts = prefix.split("/")
        seg_len = len(seg_parts)
        if len(parts) < seg_len:
            return False
        candidate = "/".join(parts[:seg_len])
        return fnmatch.fnmatch(candidate, prefix)

    # Single segment with leading ** — suffix match
    if len(segments) == 1 and has_leading_star and not has_trailing_star:
        suffix = segments[0]
        parts = path.split("/")
        seg_parts = suffix.split("/")
        seg_len = len(seg_parts)
        if len(parts) < seg_len:
            return fnmatch.fnmatch(path, suffix)
        candidate = "/".join(parts[-seg_len:])
        return fnmatch.fnmatch(candidate, suffix)

    # Multiple segments — match in order
    remaining = path
    for i, segment in enumerate(segments):
        if not segment:
            continue

        is_first = i == 0
        is_last = i == len(segments) - 1

        if is_first and is_last:
            return fnmatch.fnmatch(remaining, segment)

        if is_first:
            parts = remaining.split("/")
            seg_parts = segment.split("/")
            seg_len = len(seg_parts)
            prefix = "/".join(parts[:seg_len])
            if not fnmatch.fnmatch(prefix, segment):
                return False
            remaining = "/".join(parts[seg_len:])
        elif is_last:
            parts = remaining.split("/")
            seg_parts = segment.split("/")
            seg_len = len(seg_parts)
            suffix = "/".join(parts[-seg_len:]) if seg_len <= len(parts) else remaining
            return fnmatch.fnmatch(suffix, segment)
        else:
            parts = remaining.split("/")
            seg_parts = segment.split("/")
            seg_len = len(seg_parts)
            found = False
            for j in range(len(parts) - seg_len + 1):
                candidate = "/".join(parts[j : j + seg_len])
                if fnmatch.fnmatch(candidate, segment):
                    remaining = "/".join(parts[j + seg_len :])
                    found = True
                    break
            if not found:
                return False

    return True


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

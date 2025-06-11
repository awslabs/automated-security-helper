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

    # Allow glob pattern matching for rule IDs
    return fnmatch.fnmatch(finding_rule_id, suppression_rule_id)


def _file_path_matches(
    finding_file_path: Optional[str], suppression_file_path: str
) -> bool:
    """Check if the finding's file path matches the suppression file path pattern."""
    if finding_file_path is None:
        return False

    # Use glob pattern matching for file paths
    return fnmatch.fnmatch(finding_file_path, suppression_file_path)


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
        # Match if finding starts at or after the suppression start line
        return finding.line_start >= suppression.line_start

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
    return (finding_start <= suppression.line_end) and (
        finding_end >= suppression.line_start
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
                if expiration_date < datetime.now().date():
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

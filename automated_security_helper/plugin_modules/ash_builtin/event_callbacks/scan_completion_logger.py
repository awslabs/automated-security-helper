# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Event subscriber for scan completion logging."""

from automated_security_helper.utils.log import ASH_LOGGER


def handle_scan_completion_logging(**kwargs) -> bool:
    """
    Event subscriber that handles logging remaining scanners when a scanner completes.

    This subscriber receives SCAN_COMPLETE events and logs information about
    remaining scanners. The main completion message is still logged by the scan phase.

    Args:
        **kwargs: Event data including:
            - scanner: Name of the completed scanner
            - completed_count: Number of scanners completed so far
            - total_count: Total number of scanners
            - remaining_count: Number of scanners still running
            - remaining_scanners: List of remaining scanner names
            - message: Human-readable summary message

    Returns:
        bool: True to indicate successful handling of the event
    """
    remaining_count = kwargs.get("remaining_count", 0)
    remaining_scanners = kwargs.get("remaining_scanners", [])

    # Log information about remaining scanners
    if remaining_count > 0:
        remaining_list = ", ".join(remaining_scanners)
        ASH_LOGGER.info(f"Remaining scanners ({remaining_count}): {remaining_list}")
    else:
        ASH_LOGGER.info("All scanners completed!")

    return True

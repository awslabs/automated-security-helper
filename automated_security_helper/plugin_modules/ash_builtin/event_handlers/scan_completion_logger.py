# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Event subscriber for scan completion logging."""

from automated_security_helper.utils.log import ASH_LOGGER


def handle_scan_completion_logging(*args, **kwargs) -> bool:
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
            - succeeded: Whether the completed scanner's turn succeeded. An
              emitter that passes False for the last turn gets the all-done
              line naming the failure; absent, the line is unchanged.

    Returns:
        bool: True to indicate successful handling of the event
    """
    remaining_count = kwargs.get("remaining_count", 0)
    # The default message is built only when the emitter gave none: built
    # eagerly as the default argument of kwargs.get, its join ran on every
    # event, so a None or non-list remaining_scanners raised TypeError although
    # the emitter had supplied a message the join never reached.
    message = kwargs.get("message")
    if not isinstance(message, str):
        remaining_scanners = kwargs.get("remaining_scanners") or []
        if isinstance(remaining_scanners, (str, bytes)):
            remaining_scanners = [str(remaining_scanners)]
        names = ",".join(str(name) for name in remaining_scanners)
        message = f"Remaining scanners ({remaining_count}): {names}"
    # Log information about remaining scanners
    if isinstance(remaining_count, (int, float)) and remaining_count > 0:
        ASH_LOGGER.info(message)
    elif kwargs.get("succeeded") is False:
        # SCAN_COMPLETE is announced for every recorded turn, a recorded turn
        # whose scanner_succeeded is False included, so the last event of a
        # scan can be a failed scanner's. "All scanners completed!" read as
        # "all succeeded" then; the line names the failure when the emitter
        # says so.
        scanner = kwargs.get("scanner")
        who = f"the last, {scanner}," if scanner else "the last"
        ASH_LOGGER.info(f"All scanners completed; {who} ended with a failure.")
    else:
        ASH_LOGGER.info("All scanners completed!")

    return True

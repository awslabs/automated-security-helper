# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Event subscriber for checking suppression expiration at execution start."""

from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.suppression_matcher import (
    check_for_expiring_suppressions,
)


def handle_suppression_expiration_check(*args, **kwargs) -> bool:
    """
    Event subscriber that checks for expiring suppressions at execution start.

    This subscriber receives EXECUTION_START events and checks if any suppressions
    in the configuration are approaching their expiration date. This ensures the
    check is performed only once per execution rather than multiple times during
    SARIF processing.

    Args:
        **kwargs: Event data including:
            - plugin_context: PluginContext with configuration
            - phases: List of phases to be executed
            - source_dir: Source directory path
            - output_dir: Output directory path
            - message: Human-readable summary message

    Returns:
        bool: True to indicate successful handling of the event
    """
    plugin_context = kwargs.get("plugin_context")

    if not plugin_context or not plugin_context.config:
        ASH_LOGGER.debug(
            "No plugin context or config available for suppression expiration check"
        )
        return True

    # Get suppressions from global settings
    suppressions = plugin_context.config.global_settings.suppressions or []

    if not suppressions:
        ASH_LOGGER.debug("No suppressions configured, skipping expiration check")
        return True

    # Check if ignore_suppressions flag is set
    if (
        hasattr(plugin_context, "ignore_suppressions")
        and plugin_context.ignore_suppressions
    ):
        ASH_LOGGER.debug("Suppressions are being ignored, skipping expiration check")
        return True

    ASH_LOGGER.debug(f"Checking {len(suppressions)} suppressions for expiration")

    # Check for expiring suppressions
    expiring_suppressions = check_for_expiring_suppressions(suppressions)

    if expiring_suppressions:
        ASH_LOGGER.warning("The following suppressions will expire within 30 days:")
        for suppression in expiring_suppressions:
            expiration_date = suppression.expiration
            rule_id = suppression.rule_id
            file_path = suppression.path
            reason = suppression.reason or "No reason provided"
            ASH_LOGGER.warning(
                f"  - Rule '{rule_id}' for '{file_path}' expires on {expiration_date}. Reason: {reason}"
            )

        # Add a helpful message about how to update suppressions
        ASH_LOGGER.info(
            "To update suppression expiration dates, modify your ASH configuration file"
        )
    else:
        ASH_LOGGER.debug("No suppressions are expiring within 30 days")

    return True

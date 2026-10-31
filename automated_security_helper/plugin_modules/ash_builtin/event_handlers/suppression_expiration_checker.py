# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Event subscriber for checking suppression expiration at execution start."""

from typing import Any

from automated_security_helper.models.core import (
    IGNORE_PATH_LISTS,
    IGNORE_PATH_LISTS_LIFTED_BY_IGNORE_SUPPRESSIONS,
    expiration_has_passed,
    value_at,
)
from automated_security_helper.utils.log import ASH_LOGGER, NO_MARKUP
from automated_security_helper.utils.suppression_matcher import (
    check_for_expiring_ignore_paths,
    check_for_expiring_suppressions,
    recorded_ignore_paths,
    recorded_suppressions,
)


def handle_suppression_expiration_check(*args, **kwargs) -> bool:
    """
    Event subscriber that checks for expiring suppressions at execution start.

    This subscriber receives EXECUTION_START events and checks if any suppressions
    or ignore paths in the configuration are approaching their expiration date.
    This ensures the check is performed only once per execution rather than
    multiple times during SARIF processing.

    Under ``--ignore-suppressions`` the suppressions and the global ignore paths
    are not checked: the flag lifts every suppression and every global ignore path
    for the run (``models.core.ignore_paths_that_skip_scanning`` returns none under
    it, and the SARIF step applies none), so their expiry changes nothing about
    the scan, and a warning about it would describe a scan that is not running.
    Which lists the flag lifts is recorded beside ``IGNORE_PATH_LISTS``
    (``IGNORE_PATH_LISTS_LIFTED_BY_IGNORE_SUPPRESSIONS``).
    The scanner option lists that take the same entries (bandit ``excluded_paths``,
    checkov ``skip_path``, syft ``exclude``) are still checked: they are handed
    to the tool as its own arguments, which the flag does not lift.

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

    # Every list of ignore-path entries, global and the scanner options that take
    # the same entries, as ``ash config lint`` reads them.
    ignore_path_lists = [
        (subject, list(value_at(plugin_context.config, keys) or []), ".".join(keys))
        for keys, subject in IGNORE_PATH_LISTS
    ]
    # Get suppressions from global settings
    suppressions = plugin_context.config.global_settings.suppressions or []
    ignoring_suppressions = bool(getattr(plugin_context, "ignore_suppressions", False))
    # A field read from the environment is shown by its reference.
    recorded = recorded_suppressions(plugin_context.config)
    for (keys, _), (_, entries, _) in zip(IGNORE_PATH_LISTS, ignore_path_lists):
        recorded.update(recorded_ignore_paths(plugin_context.config, entries, keys))

    if ignoring_suppressions:
        # The flag lifts the suppressions and the global ignore paths. A scanner's
        # own option list (bandit ``excluded_paths``, checkov ``skip_path``, syft
        # ``exclude``) reaches the tool as its argument whether or not the flag is
        # set, so an expired entry there still changes what the tool scans, and
        # an expiring one is still worth the notice.
        scanner_lists = [
            entry
            for entry, (keys, _) in zip(ignore_path_lists, IGNORE_PATH_LISTS)
            if keys not in IGNORE_PATH_LISTS_LIFTED_BY_IGNORE_SUPPRESSIONS
        ]
        ASH_LOGGER.debug(
            "Suppressions and global ignore paths are being ignored, so none of "
            "them is checked for expiration"
        )
        _warn_about_expired_entries(scanner_lists, [], recorded)
        _warn_about_expiring_ignore_paths(scanner_lists, recorded)
        return True

    _warn_about_expired_entries(ignore_path_lists, suppressions, recorded)
    _warn_about_expiring_ignore_paths(ignore_path_lists, recorded)

    if not suppressions:
        ASH_LOGGER.debug("No suppressions configured, skipping expiration check")
        return True

    ASH_LOGGER.debug(f"Checking {len(suppressions)} suppressions for expiration")

    # Check for expiring suppressions. One that expires today has already
    # stopped applying, and is named by the expired-entries warning instead.
    expiring_suppressions = [
        s for s in check_for_expiring_suppressions(suppressions) if _expires_later(s)
    ]

    if expiring_suppressions:
        # A field read from the environment is shown by its reference:
        # ``recorded``, built once above for every entry, through the module's
        # one lookup rule.
        ASH_LOGGER.warning("The following suppressions will expire within 30 days:")
        for suppression in expiring_suppressions:
            expiration_date = _shown(suppression, "expiration", recorded)
            # A suppression with no rule covers every rule, spelled "*" as the
            # expired-entries warning and the suppression's own id spell it;
            # this line printed Rule 'None' for the same entry.
            rule_id = _shown(suppression, "rule_id", recorded) or "*"
            file_path = _shown(suppression, "path", recorded)
            reason = _shown(suppression, "reason", recorded) or "No reason provided"
            ASH_LOGGER.warning(
                f"  - Rule '{rule_id}' for '{file_path}' expires on {expiration_date}. Reason: {reason}",
                extra=NO_MARKUP,
            )

        # Add a helpful message about how to update suppressions
        ASH_LOGGER.info(
            "To update suppression expiration dates, modify your ASH configuration file"
        )
    else:
        ASH_LOGGER.debug("No suppressions are expiring within 30 days")

    return True


def _shown(entry, field: str, recorded) -> Any:
    """``entry``'s ``field`` as a warning shows it: the reference the config file
    wrote where it read the field from the environment (``recorded``, from
    ``recorded_suppressions`` and ``recorded_ignore_paths``), else the field."""
    return (recorded or {}).get(id(entry), {}).get(field, getattr(entry, field))


def _warn_about_expiring_ignore_paths(ignore_path_lists, recorded=None) -> None:
    """Name the ignore paths that expire within 30 days, as for suppressions.

    When one expires, the files it excluded are scanned again and their findings
    count, so the notice matters as much as a suppression's. ``ignore_path_lists``
    is ``(subject, entries, location)`` per list, from
    ``models.core.IGNORE_PATH_LISTS``; the location names an entry whose date
    does not parse. ``recorded`` (``_shown``) shows a field read from the
    environment by its reference.
    """
    expiring = [
        (subject, entry)
        for subject, entries, where in ignore_path_lists
        for entry in check_for_expiring_ignore_paths(entries, where=where)
        if _expires_later(entry)
    ]
    if not expiring:
        ASH_LOGGER.debug("No ignore paths are expiring within 30 days")
        return
    ASH_LOGGER.warning("The following ignore paths will expire within 30 days:")
    for subject, ignore_path in expiring:
        ASH_LOGGER.warning(
            f"  - {subject} '{_shown(ignore_path, 'path', recorded)}' expires on "
            f"{_shown(ignore_path, 'expiration', recorded)}. "
            f"Reason: {_shown(ignore_path, 'reason', recorded)}",
            extra=NO_MARKUP,
        )
    ASH_LOGGER.info(
        "To update ignore path expiration dates, modify your ASH configuration file"
    )


def _expires_later(entry) -> bool:
    """Whether ``entry`` still applies today, i.e. expires on a later day."""
    days = entry.days_until_expiry
    return days is not None and days > 0


def _warn_about_expired_entries(ignore_path_lists, suppressions, recorded=None) -> None:
    """One warning naming every entry that has already expired.

    An expired entry changes what the scan reports: the files an ignore path
    excluded are scanned again, and a suppression's findings count again, so a
    scan whose exit code changed overnight says why. One message for the scan,
    rather than one per finding or per scanner. Suppressions are left out under
    ``--ignore-suppressions``, where none of them applies anyway. ``recorded``
    (``_shown``) shows a field read from the environment by its reference.
    """
    lines = []
    for subject, entries, _ in ignore_path_lists:
        for ignore_path in entries:
            when = _expired_since(ignore_path, recorded)
            if when:
                lines.append(
                    f"  - {subject} '{_shown(ignore_path, 'path', recorded)}' "
                    f"{when}. Reason: {_shown(ignore_path, 'reason', recorded)}"
                )
    for suppression in suppressions:
        when = _expired_since(suppression, recorded)
        if when:
            lines.append(
                "  - Suppression of rule "
                f"'{_shown(suppression, 'rule_id', recorded) or '*'}' for "
                f"'{_shown(suppression, 'path', recorded)}' {when}. "
                f"Reason: {_shown(suppression, 'reason', recorded)}"
            )
    if not lines:
        return
    header = (
        "The following ignore paths and suppressions have expired and no longer apply:"
    )
    footer = (
        "Remove them, or move their expiration dates, in your ASH configuration file."
    )
    ASH_LOGGER.warning("\n".join([header, *lines, footer]), extra=NO_MARKUP)


def _expired_since(entry, recorded=None) -> str:
    """How ``entry`` has expired, or an empty string if it still applies. The
    date is shown as ``_shown`` shows it."""
    if not entry.expiration:
        return ""
    try:
        if expiration_has_passed(entry.expiration):
            return f"expired on {_shown(entry, 'expiration', recorded)}"
    except ValueError:
        # Not the date itself: a stored configuration keeps one that does not
        # parse as written, and it can be a value read from the environment.
        return "has an expiration that is not YYYY-MM-DD"
    return ""

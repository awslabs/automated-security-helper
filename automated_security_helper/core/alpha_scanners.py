# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Deprecated shim: the shipped-scanner index moved to ``plugins.enablement``.

Registry membership is now declared in
:mod:`automated_security_helper.plugins.registries`, and the name-to-module
index plus the unloaded-name hint live beside the enablement policy in
:mod:`automated_security_helper.plugins.enablement`. The two functions below
keep the old import path working for one release
(:data:`COMMUNITY_ALIASES_DROPPED_IN`) and warn once per process; new code
calls ``enablement.shipped_module_for`` / ``enablement.shipped_scanner_modules``.

This module also keeps the community-tier alias warning from the tier rename
(the tier of the opt-in scanners ASH ships was called "community" before it
was renamed), which retires on the same release.
"""

from typing import Dict, Optional

#: The release that stops accepting the pre-rename "community" spellings -- and
#: this shim module with them. The old spellings are aliases for one release:
#: accepted, mapped to the new spelling, and warned about.
COMMUNITY_ALIASES_DROPPED_IN = "3.9.0"

_WARNED_COMMUNITY_ALIASES: set[str] = set()


def warn_community_alias(old: str, new: str) -> None:
    """Say once per process that the "community" spelling *old* is now *new*."""
    if old in _WARNED_COMMUNITY_ALIASES:
        return
    _WARNED_COMMUNITY_ALIASES.add(old)
    # Imported here: the log module is not needed to map scanners to modules.
    from automated_security_helper.utils.log import ASH_LOGGER

    ASH_LOGGER.warning(
        f"'{old}' is deprecated: the community tier is now called alpha, so use "
        f"'{new}'. The old spelling is accepted until ASH {COMMUNITY_ALIASES_DROPPED_IN}.",
        extra={"markup": False},
    )


def _warn_moved(old: str, new: str) -> None:
    from automated_security_helper.plugins.enablement import warn_renamed_spelling

    warn_renamed_spelling(
        old,
        new,
        COMMUNITY_ALIASES_DROPPED_IN,
        reason="the shipped-scanner index moved to plugins.enablement",
    )


def alpha_scanner_modules() -> Dict[str, str]:
    """Deprecated alias of ``plugins.enablement.shipped_scanner_modules``."""
    from automated_security_helper.plugins.enablement import shipped_scanner_modules

    _warn_moved(
        "core.alpha_scanners.alpha_scanner_modules",
        "plugins.enablement.shipped_scanner_modules",
    )
    return shipped_scanner_modules()


def alpha_module_for(scanner_name: str) -> Optional[str]:
    """Deprecated alias of ``plugins.enablement.shipped_module_for``."""
    from automated_security_helper.plugins.enablement import shipped_module_for

    _warn_moved(
        "core.alpha_scanners.alpha_module_for",
        "plugins.enablement.shipped_module_for",
    )
    return shipped_module_for(scanner_name)

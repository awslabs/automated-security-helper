# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The archive extraction limits a config file in the scanned tree may set.

``converters.archive.options`` holds four limits on what extracting an archive in
the scanned tree may write: ``max_members``, ``max_member_bytes``,
``max_total_bytes`` and ``max_compression_ratio``. A limit the scanned repository
could raise for itself would bound nothing, so when the config was built from a
file the repository wrote (``config/sandbox_grants.py`` decides that: a file inside
the scanned tree, a workspace project's own config, or a config an MCP client
uploaded), each limit is held to the trusted base's value: the defaults,
``ASH_CONFIG``'s file, or the operator's config outside the tree, with
``--config-overrides`` replayed onto it. A value at or below the trusted one is
kept, so such a file can still lower a limit. A higher one is replaced by the
trusted value, with a warning naming each option and where its value came from:
the file, when it set the option, or the default, when it left the option out.

A config file in the tree replaces ``ASH_CONFIG`` the way any selected config file
does (config sources are selected, not merged), so a limit the file leaves out is
the default, capped by the trusted value like any other. To scan a repository with
its own config under higher limits, raise them with ``--config-overrides`` or a
config file outside the tree.

Validation already refuses a null, zero or negative limit (each is a
``PositiveInt``), so no spelling of "no limit" reaches this module. A limit written
with hyphens (``max-member-bytes``) is not an option at all; it stays in the
options' extras, unread, and the declared option keeps the value capped here.
MCP runtime overrides of these four are refused: they are in ``ALWAYS_DENIED_PATHS``
(config/ash_config.py), which every ``global_settings.mcp.runtime_overrides.denied_paths``
keeps, a profile's own list included.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, List, Optional, Sequence

from automated_security_helper.config.config_sources import describe_config_path
from automated_security_helper.config.confinement_remedy import KEEP_A_SETTING
from automated_security_helper.plugin_modules.ash_builtin.converters.archive_converter import (
    EXTRACTION_LIMIT_OPTIONS,
    ArchiveConverterConfigOptions,
)
from automated_security_helper.utils.log import ASH_LOGGER

if TYPE_CHECKING:
    from automated_security_helper.config.ash_config import AshConfig

_LIMITS_SECTION = ("converters", "archive", "options")


def _sets_a_limit(override: str) -> bool:
    """Whether a ``--config-overrides`` entry can set one of the extraction limits.

    True for an entry at one of the four options and for one at a section holding
    them (``converters.archive.options``, ``converters.archive``, ``converters``),
    with either separator spelling, the way ``_apply_config_override`` reads keys.
    """
    key = override.partition("=")[0].removesuffix("+").strip()
    parts = [part.strip().replace("-", "_") for part in key.split(".")]
    depth = min(len(parts), len(_LIMITS_SECTION))
    if parts[:depth] != list(_LIMITS_SECTION[:depth]):
        return False
    return len(parts) <= len(_LIMITS_SECTION) or parts[3] in EXTRACTION_LIMIT_OPTIONS


def confine_archive_limits(
    config: "AshConfig",
    trusted_config: "AshConfig",
    config_overrides: Optional[Sequence[str]],
    in_tree: Sequence[Path],
) -> None:
    """Cap each archive extraction limit in ``config`` at the trusted base's value.

    Args:
        config: The resolved AshConfig, changed in place.
        trusted_config: The trusted base ``resolve_config`` built for the sandbox
            settings: the defaults, ``ASH_CONFIG``'s file, or the operator's config
            outside the tree.
        config_overrides: ``--config-overrides``. Those that can set a limit are
            replayed onto ``trusted_config`` to get the trusted values, the same
            way the sandbox overrides are, so an override sets a limit whatever
            the in-tree file says.
        in_tree: The config files the repository wrote, named in the warning.
    """
    from automated_security_helper.config.resolve_config import (
        apply_config_overrides,
    )

    limit_overrides = [
        override for override in config_overrides or [] if _sets_a_limit(override)
    ]
    if limit_overrides:
        trusted_config = apply_config_overrides(trusted_config, limit_overrides)
    options = config.converters.archive.options
    trusted = trusted_config.converters.archive.options
    defaults = ArchiveConverterConfigOptions()
    # Split by where the capped value came from, so the warning names its source: a
    # value equal to the default is the default, which the file took by leaving the
    # option out (it replaces ASH_CONFIG as any selected config does); any other
    # value was written by the file. An override cannot be either, because the
    # overrides are replayed onto the trusted base as well.
    set_by_file: List[str] = []
    defaulted: List[str] = []
    for name in EXTRACTION_LIMIT_OPTIONS:
        value = getattr(options, name)
        cap = getattr(trusted, name)
        if value <= cap:
            continue
        entry = f"converters.archive.options.{name} ({value} above {cap})"
        if value == getattr(defaults, name):
            defaulted.append(entry)
        else:
            set_by_file.append(entry)
        setattr(options, name, cap)
    files = ", ".join(describe_config_path(path) for path in in_tree)
    remedy = KEEP_A_SETTING
    if set_by_file:
        ASH_LOGGER.warning(
            f"Ignoring {', '.join(set_by_file)}, set by {files}: the scanned "
            "repository or an MCP client wrote that file, so it can lower an archive "
            f"extraction limit but not raise it. {remedy}"
        )
    if defaulted:
        ASH_LOGGER.warning(
            f"Capping {', '.join(defaulted)}, the default: {files} leaves the option "
            "out and replaces ASH_CONFIG as any selected config file does, so the "
            "default applied, and the trusted config sets a lower limit. Set the "
            f"option in that file to lower it further. {remedy}"
        )

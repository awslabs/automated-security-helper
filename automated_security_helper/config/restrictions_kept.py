# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What an operator file in another git checkout still sets for the trusted base.

Why this exists
---------------
A config file inside any git checkout, not only the scanned one, cannot grant
(``config/sandbox_grants.py``). An ``ASH_CONFIG`` or ``trusted_config_path`` file
that sits in a checkout other than the scanned one is therefore not the trusted
base the scanned repository's config is held to; ``resolve_config`` builds that
base from the defaults instead (``trusted_base_config``). Taking the whole file
out of the base also took out what the file sets to restrict. An operator who
keeps ``ASH_CONFIG`` in a dotfiles checkout and lowers an archive extraction
limit there found the repository's config capped at the default, not at the
operator's value.

What is kept
------------
``keep_restrictions`` narrows the base with the settings of the file that only
restrict, and nothing else. They are the settings the confinement steps already
let a file the repository wrote set, because they cannot widen anything:
- each archive extraction limit (``config/archive_limits.py``), at the lower of
  the file's value and the base's;
- a scanner option set to a value that only narrows what the tool does
  (``TIGHTENING_VALUES``: semgrep and opengrep ``metrics: off``, trivy
  ``disable_telemetry: true``), when the file wrote it;
- a ``network_scanners`` list, as a limit (``SandboxConfig.network_limit``): a
  scanner outside it gets no network. The list is not kept as a list, because a
  list replaces the scanners' declared needs and so can add network.
Every other setting of the file falls to the defaults with its grants.

What is not done here
---------------------
A file an MCP client delivered keeps nothing: its base is the defaults, so the
caller does not call this for it. A file outside every checkout is the
operator's own and is the base whole. The file's sandbox mode is carried by
``trusted_base_config`` on its own, as it was.

``honor_ignore_files`` is not kept in either direction. ``false`` makes the scan
read the paths a repository's ``.gitignore`` and ``.ignore`` files leave out
(``node_modules/``, ``.venv/``, ``.env``), so it widens what a scan reads and
what the operator's reporters can send off the host; the confinement step
(``confine_honor_ignore_files``) therefore takes it from the base, and a file
in another checkout sets it only through ``--no-honor-ignore-files`` or
``--config-overrides``.

Limits
------
- No warning names a setting that fell to the defaults; the base is built before
  any file is compared with it.
- The limit from a ``network_scanners`` list is read off the base by
  ``resolve_config`` right after ``trusted_base_config`` returns and handed to
  ``confine_sandbox_grants``, because the later rebuilds of the trusted sandbox
  settings (the file's own sandbox section, the operator's overrides) do not
  carry a private attribute. An operator override of ``network_scanners``
  replaces the limit, as an override replaces the other base values.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from automated_security_helper.config.tool_config_trust import (
    TIGHTENING_VALUES,
    _get,
    _options_of,
    _set,
    _wrote,
)
from automated_security_helper.plugin_modules.ash_builtin.converters.archive_converter import (
    EXTRACTION_LIMIT_OPTIONS,
)

if TYPE_CHECKING:
    from automated_security_helper.config.ash_config import AshConfig


def keep_restrictions(base: "AshConfig", source: "AshConfig") -> None:
    """Narrow *base*, changed in place, with what *source* sets that only restricts.

    Args:
        base: A trusted base that is not *source*: the defaults, or a config
            copied for the purpose. It is changed; *source* is not.
        source: The operator's config from a file in another git checkout.
    """
    _keep_archive_limits(base, source)
    _keep_tightening_values(base, source)
    _keep_network_limit(base, source)


def _keep_archive_limits(base: "AshConfig", source: "AshConfig") -> None:
    held = base.converters.archive.options
    given = source.converters.archive.options
    for name in EXTRACTION_LIMIT_OPTIONS:
        setattr(held, name, min(getattr(held, name), getattr(given, name)))


def _keep_tightening_values(base: "AshConfig", source: "AshConfig") -> None:
    from automated_security_helper.config.client_scanner_exclusions import (
        _scanner_sections,
    )

    for (scanner, name), values in TIGHTENING_VALUES.items():
        for _key, section in _scanner_sections(source, scanner):
            options = _options_of(section)
            written = _get(options, name)
            if not _wrote(options, name, written) or written not in values:
                continue
            for _held_key, held_section in _scanner_sections(base, scanner):
                held = _options_of(held_section)
                if held is not None:
                    _set(held, name, written, None)


def _keep_network_limit(base: "AshConfig", source: "AshConfig") -> None:
    listed = source.sandbox.network_scanners
    if listed is None:
        return
    held = base.sandbox.network_limit
    base.sandbox.network_limit = (
        list(listed) if held is None else [name for name in held if name in listed]
    )

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Whether an opt-in scanner is part of a run.

A scanner class that sets ``OPT_IN = True`` (see
:attr:`automated_security_helper.base.scanner_plugin.ScannerPluginBase.OPT_IN`)
is left out of a run entirely unless the operator enabled it. This module is the
one place that decides "enabled", so the scan phase, its expected-scanner roster
and anything else that has to agree with it read the same rule.

The rule
--------
An opt-in scanner is enabled when either of these holds:

1. Its name is in the scanner selection -- ``--scanners``, the ``scanners``
   argument of the MCP ``run_ash_workspace_scan`` tool, or the Python
   ``run_ash_scan(scanners=...)``. All three arrive in the scan phase as the same
   ``enabled_scanners`` list. (The single-project MCP ``run_ash_scan`` tool takes
   no scanner selection; enable through its ``config_path`` instead.)
2. Its resolved config says ``enabled: true``. That covers the project config
   file, ``--config-overrides 'scanners.<name>.enabled=true'`` and a workspace
   policy's ``additional_scanners``, which all write the same field.

Otherwise it is omitted: not constructed, not recorded, not counted.

Precedence against ``enabled: false``
------------------------------------
Naming an opt-in scanner in the selection runs it even when its config says
``enabled: false``. This is the one place opt-in scanners differ from the
others, where the selection only narrows and a config-disabled scanner named in
``--scanners`` is recorded SKIPPED.

This is a choice, made so that ``--scanners gitleaks`` always runs gitleaks.
``enabled: false`` is an opt-in scanner's default, so letting the config win
would mean naming a scanner did nothing unless the config also enabled it.
The alternative -- honoring only an ``enabled: false`` the operator wrote -- was
rejected: the typed ``AshConfig`` does record which fields were set
(``model_fields_set``), but the scan phase receives the config through
``get_plugin_config``, which returns a ``model_dump`` dict where the written
value and the default are the same, and config merging and overrides would
each have to preserve the distinction for it to be reliable. A config cannot
forbid an opt-in scanner that someone names on the command line; to keep one
off, do not name it.

``--exclude-scanners`` still wins over both, as it does for every scanner: the
execution engine removes excluded names from the selection before the scan
phase runs, and an opt-in scanner enabled by config and then excluded is
recorded SKIPPED like any other excluded scanner.
"""

from __future__ import annotations

import typing
from typing import Any, Iterable, Optional


def is_opt_in(plugin: Any) -> bool:
    """Whether *plugin* (a scanner class or instance) declares ``OPT_IN = True``.

    Compared with ``is True`` rather than truthiness, so a MagicMock-based plugin
    double -- whose every attribute is truthy -- is not mistaken for an opt-in
    scanner and dropped from a run.
    """
    return getattr(plugin, "OPT_IN", False) is True


def _declared_config_class(plugin_class: type) -> Optional[type]:
    """The concrete config class *plugin_class* declares on its ``config`` field."""
    field = (getattr(plugin_class, "model_fields", None) or {}).get("config")
    if field is None:
        return None
    annotation = field.annotation
    candidates = [a for a in typing.get_args(annotation) if a is not type(None)]
    for candidate in candidates or [annotation]:
        name_field = (getattr(candidate, "model_fields", None) or {}).get("name")
        if isinstance(getattr(name_field, "default", None), str):
            return candidate
    return None


def _config_value(plugin_config: Any, key: str) -> Any:
    if plugin_config is None:
        return None
    if isinstance(plugin_config, dict):
        return plugin_config.get(key)
    return getattr(plugin_config, key, None)


def opt_in_scanner_name(plugin_class: type, plugin_config: Any = None) -> str:
    """The name an opt-in scanner is selected and reported by.

    The same precedence the scan phase uses for a constructed scanner: the
    resolved config's ``name``, then the name the config class declares, then
    the lowercased class name.
    """
    name = _config_value(plugin_config, "name")
    if isinstance(name, str) and name:
        return name
    config_class = _declared_config_class(plugin_class)
    if config_class is not None:
        default = config_class.model_fields["name"].default
        if default:
            return default
    return getattr(plugin_class, "__name__", "unknown").lower()


def named_in_selection(name: str, enabled_scanners: Optional[Iterable[str]]) -> bool:
    """Whether *name* is in the scanner selection, matched the way the scan phase matches."""
    key = str(name).lower().strip()
    return any(key == str(s).lower().strip() for s in (enabled_scanners or []))


def _config_enabled(plugin_class: type, plugin_config: Any) -> bool:
    """The ``enabled`` value *plugin_config* resolves to for *plugin_class*.

    When no config was resolved, or the resolved one does not set enabled,
    the scanner will get its config class's default, so that default is the
    answer. A class that declares no config
    class at all answers False: an opt-in scanner is off until something says
    it is on.
    """
    enabled = _config_value(plugin_config, "enabled")
    if enabled is None:
        config_class = _declared_config_class(plugin_class)
        field = (getattr(config_class, "model_fields", None) or {}).get("enabled")
        enabled = getattr(field, "default", None)
    return enabled is True


def opt_in_scanner_enabled(
    plugin_class: type,
    plugin_config: Any,
    enabled_scanners: Optional[Iterable[str]] = None,
) -> bool:
    """Whether *plugin_class* takes part in a run.

    Always True for a scanner that is not opt-in, so a caller can apply it to
    every scanner class without checking first.

    Args:
        plugin_class: The scanner class.
        plugin_config: The config resolved for it -- what
            ``AshConfig.get_plugin_config`` returns (a dict or None), or a config
            model.
        enabled_scanners: The scanner selection for the run; empty or None means
            no selection.
    """
    if not is_opt_in(plugin_class):
        return True
    if named_in_selection(
        opt_in_scanner_name(plugin_class, plugin_config), enabled_scanners
    ):
        return True
    return _config_enabled(plugin_class, plugin_config)

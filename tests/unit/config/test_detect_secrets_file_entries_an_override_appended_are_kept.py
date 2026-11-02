# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A ``file://`` entry an operator's override appended is not the file's.

detect-secrets loads a filter or plugin named ``file://<path>`` from that file, so
the confinement drops one the trusted base does not name. An override that
appends one (``scan_settings.filters_used+=[...]``) and that the trusted base
cannot take lands on the resolved config alone, and the entry it added is the
operator's: the confinement leaves it, as it leaves any value such an override
set. The step looked for a landing only at ``scan_settings``, so an entry appended
to a list below it was dropped and the warning named the repository's file for it.

The config is built in memory, with the override applied to the defaults, and the
landing is the one ``landings_of`` gives for an override the base could not take.
"""

from __future__ import annotations

import json

import pytest

from automated_security_helper.config import resolve_config as resolve_module
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.client_scanner_exclusions import (
    _scanner_sections,
)
from automated_security_helper.config.tool_config_trust import (
    Landing,
    _confine_settings_files,
)

pytestmark = pytest.mark.unit

ENTRY = {"path": "file:///ops/filters.py::check"}
OVERRIDE = "scanners.detect-secrets.options.scan_settings.filters_used+=" + json.dumps(
    [ENTRY]
)


def _filter_paths(config: AshConfig) -> list:
    section = _scanner_sections(config, "detect-secrets")[0][1]
    filters = section.options.scan_settings.filters_used
    return [entry.path for entry in filters]


def _landing(config: AshConfig) -> Landing:
    key = _scanner_sections(config, "detect-secrets")[0][0]
    return Landing(
        "scanners",
        frozenset({key}),
        ("options", "scan_settings", "filters_used"),
        True,
        [ENTRY],
    )


def test_an_entry_an_override_appended_to_the_list_is_kept():
    config = resolve_module.apply_config_overrides(AshConfig(), [OVERRIDE])
    assert _filter_paths(config) == [ENTRY["path"]]

    ignored = _confine_settings_files(config, AshConfig(), [_landing(config)])

    assert ignored == []
    assert _filter_paths(config) == [ENTRY["path"]]


def test_control_the_same_entry_with_no_override_behind_it_is_dropped():
    config = resolve_module.apply_config_overrides(AshConfig(), [OVERRIDE])

    ignored = _confine_settings_files(config, AshConfig(), [])

    assert len(ignored) == 1 and ignored[0].endswith("filters_used[].path"), ignored
    assert _filter_paths(config) == []

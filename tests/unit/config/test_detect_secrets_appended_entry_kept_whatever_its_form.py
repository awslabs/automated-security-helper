# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An appended ``file://`` entry is kept whatever form the resolved list holds.

The landing records the entry as the operator typed it, a raw mapping, while the
resolved configuration holds it validated into the list's entry model, which
coerces values (``min_level`` typed as ``"2"`` becomes the int ``2``) and dumps
in the model's own form. The confinement judges the entry by its path alone: an
operator-approved path is approved whatever the other fields are, so the entry
is kept even when its raw and validated forms differ.

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

#: ``min_level`` is typed as a string: the entry model's ``int | None`` slot
#: coerces it, so the validated entry and the raw appended mapping hold the
#: same entry in two forms.
ENTRY = {"path": "file:///ops/filters.py::check", "min_level": "2"}
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


def test_an_appended_entry_the_model_coerced_is_kept():
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

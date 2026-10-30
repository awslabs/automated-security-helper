# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``replace_plugin_module_list`` leaves the config as it was when the move refuses.

The function assigns the new ``ash_plugin_modules`` list and then moves the
references with ``move_plugin_module_references``, which checks that each
moved reference still describes the entry at its new position and raises
ValueError when the list was edited after the references were recorded. The
raise used to leave the new list beside the references at their old indices.
The previous list is put back before the error propagates.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.unit.config._plugin_module_helpers import (
    INSTALLED,
    SEC_ONE,
    entries_file as _entries_file,
    plant_site_and_environment,
    resolved_config as _resolved_config,
)

pytestmark = pytest.mark.unit

_LISTS = (
    "_environment_references",
    "_displayed_environment_references",
    "_written_references",
)


@pytest.fixture
def root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    return plant_site_and_environment(tmp_path, monkeypatch)


def test_a_refused_move_puts_the_previous_list_back(root: Path):
    from automated_security_helper.config.plugin_module_trust import (
        replace_plugin_module_list,
    )

    config = _resolved_config(
        _entries_file(root / "read.yaml", [INSTALLED, "${ASH_RECV_ONE}"])
    )
    assert list(config.ash_plugin_modules) == [INSTALLED, SEC_ONE]
    # The list is edited after its references were recorded: the entry the
    # read recorded at index 1 is no longer there.
    edited = [INSTALLED, "tampered_ash_plugins"]
    config.ash_plugin_modules = list(edited)
    before = {
        attribute: tuple(getattr(config, attribute, ()) or ()) for attribute in _LISTS
    }

    with pytest.raises(ValueError, match="does not hold the entry"):
        replace_plugin_module_list(config, [1, 0], ["added_ash_plugins"])

    assert list(config.ash_plugin_modules) == edited, config.ash_plugin_modules
    after = {
        attribute: tuple(getattr(config, attribute, ()) or ()) for attribute in _LISTS
    }
    assert after == before

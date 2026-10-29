# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A validate_config denial names a plugin module read from the environment as
``<value>``.

The denial for ``ash_plugin_modules`` entries a delivered config may not add
lists the modules it refuses. A module the config read from the environment is
not the config's own text, so the denial shows it as the placeholder, while a
module the file wrote is still named.
"""

from types import SimpleNamespace

import pytest

from automated_security_helper.cli.mcp_tools import (
    _plugin_modules_shown,
    _with_modules_shown,
)

pytestmark = pytest.mark.unit

READ = "probemodulefromenv"
WRITTEN = "probemodulewritten"


def _check(resolved, shown):
    return SimpleNamespace(resolved_data=resolved, shown_resolved=shown)


def test_a_module_read_from_the_environment_is_shown_as_the_placeholder():
    check = _check(
        {"ash_plugin_modules": [READ, WRITTEN]},
        {"ash_plugin_modules": ["<value>", WRITTEN]},
    )

    reason = _with_modules_shown(
        f"adds {READ!r} (not importable), {WRITTEN!r} (not importable)",
        _plugin_modules_shown(check),
    )

    assert READ not in reason, reason
    assert "'<value>' (not importable)" in reason, reason
    assert f"{WRITTEN!r} (not importable)" in reason, reason


def test_both_pieces_of_a_comma_joined_entry_are_shown_as_the_placeholder():
    check = _check(
        {"ash_plugin_modules": [f"{READ},{WRITTEN}"]},
        {"ash_plugin_modules": ["<value>"]},
    )

    reason = _with_modules_shown(
        f"adds {READ!r} (x), {WRITTEN!r} (x)", _plugin_modules_shown(check)
    )

    assert READ not in reason and WRITTEN not in reason, reason


def test_a_check_with_no_shown_copy_changes_nothing():
    check = _check(None, None)

    assert _plugin_modules_shown(check) == {}
    assert _with_modules_shown(f"adds {WRITTEN!r}", {}) == f"adds {WRITTEN!r}"

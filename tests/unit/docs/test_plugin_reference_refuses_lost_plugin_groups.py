# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The plugin reference generators refuse a package that lost a plugin group.

``ash_builtin`` isolates each plugin group's import and records a failure in
``ASH_PLUGIN_LOAD_ERRORS`` instead of raising, so the package imports with a
shorter ``ASH_SCANNERS``, ``ASH_REPORTERS`` or ``ASH_CONVERTERS``. The reference
pages are built from those lists, and ``discover`` read them without reading the
errors, so a page built while a group was lost published the survivors as the
whole set with nothing on it to say so. ``discover`` now retries the lost groups
the way ``plugins/loader.py`` does and raises for what still fails.
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = REPO_ROOT / "scripts"
REPORTERS = "automated_security_helper.plugin_modules.ash_builtin.reporters"


def _plugin_reference():
    sys.path.insert(0, str(SCRIPTS))
    try:
        return importlib.import_module("_plugin_reference")
    finally:
        sys.path.remove(str(SCRIPTS))


@pytest.fixture
def builtin_only(monkeypatch):
    """``discover`` over the built-in package alone, with its groups as planted."""
    import automated_security_helper.plugin_modules.ash_builtin as ash_builtin

    reference = _plugin_reference()
    monkeypatch.setattr(
        reference, "plugin_packages", lambda: [reference.BUILTIN_PACKAGE]
    )
    return reference, ash_builtin


def test_a_group_that_still_fails_to_import_fails_the_reference(
    builtin_only, monkeypatch
):
    reference, ash_builtin = builtin_only
    still_lost = {REPORTERS: "ImportError: an optional dependency is absent"}
    monkeypatch.setattr(ash_builtin, "ASH_PLUGIN_LOAD_ERRORS", dict(still_lost))
    # The retry fails again, as it does for a group missing a dependency.
    monkeypatch.setattr(
        ash_builtin,
        "retry_failed_plugin_groups",
        lambda: dict(ash_builtin.ASH_PLUGIN_LOAD_ERRORS),
    )

    with pytest.raises(ImportError) as caught:
        reference.discover("reporter")

    message = str(caught.value)
    assert REPORTERS in message
    assert "an optional dependency is absent" in message
    assert "smaller set" in message


def test_control_a_group_recovered_on_retry_is_listed(builtin_only, monkeypatch):
    reference, ash_builtin = builtin_only
    monkeypatch.setattr(
        ash_builtin, "ASH_PLUGIN_LOAD_ERRORS", {REPORTERS: "ImportError: partial"}
    )

    def recovered():
        ash_builtin.ASH_PLUGIN_LOAD_ERRORS = {}
        return {}

    monkeypatch.setattr(ash_builtin, "retry_failed_plugin_groups", recovered)

    plugins = reference.discover("reporter")

    assert plugins, "the built-in package declares reporters"
    assert ash_builtin.ASH_PLUGIN_LOAD_ERRORS == {}


def test_control_a_healthy_package_lists_its_plugins(builtin_only, monkeypatch):
    reference, ash_builtin = builtin_only
    monkeypatch.setattr(ash_builtin, "ASH_PLUGIN_LOAD_ERRORS", {})

    plugins = reference.discover("scanner")

    assert plugins
    assert all(plugin.builtin for plugin in plugins)

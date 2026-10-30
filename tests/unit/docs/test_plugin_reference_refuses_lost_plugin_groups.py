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


def test_the_record_is_read_from_the_module_not_from_what_the_retry_returns(
    builtin_only, monkeypatch
):
    """A retry that answers nothing useful does not hide a group the module still records."""
    reference, ash_builtin = builtin_only
    still_lost = {REPORTERS: "ImportError: an optional dependency is absent"}
    monkeypatch.setattr(ash_builtin, "ASH_PLUGIN_LOAD_ERRORS", dict(still_lost))
    monkeypatch.setattr(ash_builtin, "retry_failed_plugin_groups", lambda: None)

    with pytest.raises(ImportError) as caught:
        reference.discover("reporter")

    assert REPORTERS in str(caught.value)


def test_a_group_that_the_real_retry_cannot_import_fails_the_reference(
    builtin_only, monkeypatch
):
    """The real retry runs; the reporters group fails to import again; the page refuses.

    ``retry_failed_plugin_groups`` rebinds the module's lists and its error
    record, so each is restored by the same monkeypatch that planted the
    failure.
    """
    reference, ash_builtin = builtin_only
    for name in (
        "ASH_CONVERTERS",
        "ASH_SCANNERS",
        "ASH_REPORTERS",
        "ASH_EVENT_HANDLERS",
    ):
        monkeypatch.setattr(ash_builtin, name, getattr(ash_builtin, name))
    monkeypatch.setattr(
        ash_builtin, "ASH_PLUGIN_LOAD_ERRORS", {REPORTERS: "ImportError: earlier"}
    )
    real_load_module = ash_builtin._load_module

    def failing_reporters(module_path):
        if module_path == REPORTERS:
            raise ImportError("No module named 'an_optional_dependency'")
        return real_load_module(module_path)

    monkeypatch.setattr(ash_builtin, "_load_module", failing_reporters)

    with pytest.raises(ImportError) as caught:
        reference.discover("reporter")

    message = str(caught.value)
    assert REPORTERS in message
    assert "an_optional_dependency" in message
    assert ash_builtin.ASH_PLUGIN_LOAD_ERRORS == {
        REPORTERS: "ImportError: No module named 'an_optional_dependency'"
    }


def test_a_record_that_is_not_a_mapping_is_refused_as_unreadable(
    builtin_only, monkeypatch
):
    reference, ash_builtin = builtin_only
    monkeypatch.setattr(ash_builtin, "ASH_PLUGIN_LOAD_ERRORS", ["reporters"])
    monkeypatch.setattr(ash_builtin, "retry_failed_plugin_groups", dict)

    with pytest.raises(ImportError) as caught:
        reference.discover("reporter")

    assert "not a mapping" in str(caught.value)


@pytest.mark.parametrize("record", [[], "", 0, ()], ids=["list", "str", "int", "tuple"])
def test_a_falsy_record_that_is_not_a_mapping_is_refused_too(
    builtin_only, monkeypatch, record
):
    """An empty list or string is as unreadable as a non-empty one.

    The record is read as "nothing failed" only when it is absent or an empty
    mapping; a falsy value of another type says nothing about the groups and
    must not pass as a clean load.
    """
    reference, ash_builtin = builtin_only
    monkeypatch.setattr(ash_builtin, "ASH_PLUGIN_LOAD_ERRORS", record)
    monkeypatch.setattr(ash_builtin, "retry_failed_plugin_groups", dict)

    with pytest.raises(ImportError) as caught:
        reference.discover("reporter")

    assert "not a mapping" in str(caught.value)


def test_control_an_absent_record_reads_as_a_clean_load(builtin_only, monkeypatch):
    reference, ash_builtin = builtin_only
    monkeypatch.delattr(ash_builtin, "ASH_PLUGIN_LOAD_ERRORS", raising=False)
    monkeypatch.setattr(ash_builtin, "retry_failed_plugin_groups", dict)

    plugins = reference.discover("reporter")

    assert plugins


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

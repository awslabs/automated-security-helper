# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The scanner inventory survives broken metadata and honors the operator's config.

``_discover_external_scanner_plugin_packages`` reads each installed
distribution's name with str methods; a distribution whose metadata carries no
readable Name appears as None, and one such install raised AttributeError
outside the try that makes discovery non-fatal, failing the whole inventory.
``describe_scanner`` reported an unconstructable scanner's enabled flag from the
default its config class declares, ignoring the operator's default configuration
that a constructed scanner honors.
"""

from __future__ import annotations

import pytest

from automated_security_helper.core import scanner_inventory
from automated_security_helper.core.scanner_inventory import (
    _discover_external_scanner_plugin_packages,
    describe_scanner,
)

pytestmark = pytest.mark.unit


def test_a_distribution_with_no_readable_name_does_not_fail_discovery(monkeypatch):
    """Red before the fix: AttributeError on None.startswith.

    Patched on the backport, which the discovery reads (the standard library's
    reader is its fallback only; see the test below)."""
    import importlib_metadata

    def packages_distributions():
        return {
            "broken_top_level": [None],
            "ash_demo_plugins": ["ash_demo_plugins"],
        }

    monkeypatch.setattr(
        importlib_metadata, "packages_distributions", packages_distributions
    )

    found = _discover_external_scanner_plugin_packages()

    assert found == ["automated_security_helper.plugin_modules.ash_demo_plugins"]


def test_discovery_reads_the_metadata_backport_not_the_standard_library(monkeypatch):
    """Red before the fix: the standard library's packages_distributions was
    read, which on Python 3.10 reads only top_level.txt and so sees no
    hatchling-built plugin distribution; the backport reads RECORD everywhere."""
    import importlib.metadata

    import importlib_metadata

    monkeypatch.setattr(
        importlib_metadata,
        "packages_distributions",
        lambda: {"hatched_ash_plugins": ["ash_hatched_plugins"]},
    )
    monkeypatch.setattr(importlib.metadata, "packages_distributions", dict)

    found = _discover_external_scanner_plugin_packages()

    assert found == ["automated_security_helper.plugin_modules.hatched_ash_plugins"]


class _SwitchedOffConfig:
    """What the operator's default configuration says about the scanner."""

    def __init__(self, enabled):
        self.enabled = enabled


class _DefaultConfig:
    def __init__(self, enabled):
        self._enabled = enabled
        self.asked = []

    def get_plugin_config(self, plugin_type, plugin_name):
        self.asked.append((plugin_type, plugin_name))
        return _SwitchedOffConfig(self._enabled)


class _DeclaredScannerConfig:
    """The class-level default: enabled."""

    enabled = True


class _ConfigField:
    annotation = type("U", (), {"__args__": (_DeclaredScannerConfig, type(None))})


class _UnconstructableScanner:
    offline_strategy = None
    model_fields = {"config": _ConfigField()}

    def __init__(self, context=None):
        raise RuntimeError("stub refuses to be constructed")


def test_an_unconstructed_scanner_reports_the_operators_enabled_value():
    """Red before the fix: the class's declared True stood over the operator's False."""
    default_config = _DefaultConfig(enabled=False)

    entry = describe_scanner(
        _UnconstructableScanner, context=object(), default_config=default_config
    )

    assert entry["dependencies_satisfied"] is None
    assert entry["enabled"] is False
    assert default_config.asked == [("scanner", entry["name"])]


class _UnbuildableScannerConfig:
    enabled = True

    def __init__(self):
        raise RuntimeError("config class refuses to be built")


class _UnbuildableConfigField:
    annotation = type("U", (), {"__args__": (_UnbuildableScannerConfig, type(None))})


class _ScannerWithUnbuildableConfig(_UnconstructableScanner):
    model_fields = {"config": _UnbuildableConfigField()}


class _ScannerDeclaringNoConfig(_UnconstructableScanner):
    model_fields: dict = {}


@pytest.mark.parametrize(
    "scanner_class", [_ScannerWithUnbuildableConfig, _ScannerDeclaringNoConfig]
)
def test_an_unconstructed_scanner_whose_declaration_cannot_be_read_still_honors_the_operator(
    scanner_class,
):
    """Red before the fix: both paths returned the optimistic True untouched."""
    default_config = _DefaultConfig(enabled=False)

    entry = describe_scanner(
        scanner_class, context=object(), default_config=default_config
    )

    assert entry["enabled"] is False
    assert default_config.asked == [("scanner", entry["name"])]


def test_an_unconstructed_scanner_with_no_operator_section_keeps_the_declared_value():
    """Control: no operator section, the class's declaration stands."""

    class _NoSection:
        def get_plugin_config(self, plugin_type, plugin_name):
            return None

    entry = describe_scanner(
        _UnconstructableScanner, context=object(), default_config=_NoSection()
    )

    assert entry["enabled"] is True


def test_the_declared_config_class_is_still_the_one_read():
    """Control for the stub shape: the helper finds the declared config class."""
    assert (
        scanner_inventory._declared_config_class(_UnconstructableScanner)
        is _DeclaredScannerConfig
    )

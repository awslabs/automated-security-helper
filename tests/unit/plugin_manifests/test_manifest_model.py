# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The manifest model refuses what a kernel could not act on.

Each refusal here is a shape a declaration could take by mistake: a deprecated
scanner with no target, a retirement pointing at itself, an entry point outside
the plugin's own module, a path that escapes the repository. The model is
fail-closed, so every one must raise rather than default.
"""

from __future__ import annotations

import copy
from typing import Any

import pytest
from pydantic import ValidationError

from automated_security_helper.base.plugin_manifest import (
    MANIFEST_SCHEMA_VERSION,
    ManifestSchemaError,
    PluginTier,
    ScannerManifest,
    parse_scanner_manifest,
)

pytestmark = pytest.mark.unit

_PKG = "automated_security_helper.plugin_modules.ash_demo_plugins"

GOOD: dict[str, Any] = {
    "schema_version": MANIFEST_SCHEMA_VERSION,
    "name": "demo-scan",
    "version": "bundled",
    "aliases": ["demo"],
    "tier": "alpha",
    "default_enabled": False,
    "plugin_module": _PKG,
    "superseded_by": None,
    "entry_points": {"scanner": f"{_PKG}.demo_scanner:DemoScanner"},
    "options_model": f"{_PKG}.demo_scanner:DemoScannerConfigOptions",
    "file_ownership": [
        "automated_security_helper/plugin_modules/ash_demo_plugins",
    ],
}


def _with(**changes: Any) -> dict[str, Any]:
    data = copy.deepcopy(GOOD)
    data.update(changes)
    return data


def test_the_control_manifest_is_accepted() -> None:
    """Planted control: the refusals below fail on their one change, not on GOOD."""
    manifest = parse_scanner_manifest(GOOD)
    assert manifest.tier is PluginTier.ALPHA
    assert manifest.default_enabled is False
    assert manifest.aliases == ("demo",)


@pytest.mark.parametrize(
    "changes",
    [
        {"name": "Demo_Scan"},
        {"name": ""},
        {"version": "latest"},
        {"aliases": ["demo", "demo"]},
        {"aliases": ["demo-scan"]},
        {"aliases": ["Demo"]},
        {"tier": "beta"},
        {"tier": "deprecated"},
        {"superseded_by": "other"},
        {"tier": "deprecated", "superseded_by": "demo-scan"},
        {"plugin_module": "not a module"},
        {"entry_points": {"scanner": "no_colon_here"}},
        {"entry_points": {"scanner": "other.package.mod:Cls"}},
        {"entry_points": {"scanner": f"{_PKG}.m:C", "reporters": ["bad ref"]}},
        {"options_model": "other.package.mod:Options"},
        {"file_ownership": []},
        {"file_ownership": ["/etc/passwd"]},
        {"file_ownership": ["a/../b"]},
        {"file_ownership": ["a", "a"]},
        {"schema_version": 0},
        {"default_enabled": "maybe"},
    ],
    ids=lambda changes: ",".join(sorted(changes)) + "=" + str(list(changes.values())),
)
def test_a_bad_declaration_is_refused(changes: dict[str, Any]) -> None:
    with pytest.raises((ValidationError, ManifestSchemaError)):
        parse_scanner_manifest(_with(**changes))


def test_a_missing_kernel_field_is_refused_not_defaulted() -> None:
    for field in (
        "schema_version",
        "name",
        "version",
        "aliases",
        "tier",
        "default_enabled",
        "plugin_module",
        "entry_points",
        "options_model",
        "file_ownership",
    ):
        data = copy.deepcopy(GOOD)
        del data[field]
        with pytest.raises(ValidationError):
            parse_scanner_manifest(data)


def test_an_unknown_field_is_refused() -> None:
    with pytest.raises(ValidationError):
        parse_scanner_manifest(_with(license="Apache-2.0"))


def test_a_deprecated_manifest_names_its_target() -> None:
    manifest = parse_scanner_manifest(
        _with(tier="deprecated", superseded_by="demo-next")
    )
    assert manifest.tier is PluginTier.DEPRECATED
    assert manifest.superseded_by == "demo-next"


def test_a_newer_schema_is_refused_in_prose_not_guessed() -> None:
    newer = _with(schema_version=MANIFEST_SCHEMA_VERSION + 1, brand_new_field=True)
    with pytest.raises(ManifestSchemaError) as raised:
        parse_scanner_manifest(newer)
    message = str(raised.value)
    assert "demo-scan" in message
    assert f"schema_version {MANIFEST_SCHEMA_VERSION + 1}" in message
    assert f"reads schema_version {MANIFEST_SCHEMA_VERSION}" in message
    assert "upgrade ASH" in message


def test_a_manifest_is_immutable() -> None:
    manifest = parse_scanner_manifest(GOOD)
    with pytest.raises(ValidationError):
        manifest.tier = PluginTier.SUPPORTED  # type: ignore[misc]
    assert isinstance(manifest, ScannerManifest)

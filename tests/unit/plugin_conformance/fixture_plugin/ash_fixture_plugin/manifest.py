# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The fixture plugin's manifest, as data (see ``base/plugin_manifest.py``)."""

from automated_security_helper.base.plugin_manifest import (
    BUNDLED_VERSION,
    MANIFEST_SCHEMA_VERSION,
    EntryPoints,
    PluginTier,
    ScannerManifest,
)

_PLUGIN = "ash_fixture_plugin"

MANIFEST = ScannerManifest(
    schema_version=MANIFEST_SCHEMA_VERSION,
    name="fixture-lint",
    version=BUNDLED_VERSION,
    aliases=(),
    tier=PluginTier.ALPHA,
    default_enabled=False,
    plugin_module=_PLUGIN,
    entry_points=EntryPoints(scanner=f"{_PLUGIN}.scanner:FixtureScanner"),
    options_model=f"{_PLUGIN}.scanner:FixtureOptions",
    file_ownership=("tests/unit/plugin_conformance/fixture_plugin/ash_fixture_plugin",),
)

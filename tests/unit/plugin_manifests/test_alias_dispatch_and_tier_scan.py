# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Alias dispatch and the manifest tier scan.

Design decisions 5 and 7. The semgrep retirement is manifest DATA: opengrep
declares ``aliases: ["semgrep"]`` and semgrep's manifest is ``deprecated`` and
``superseded_by`` opengrep, and these rows prove the data dispatches. They also
prove the declaration changes no run: semgrep stays a manifest of its own, still
default-enabled, until the retirement is decided and wired separately (#981).

The registry-consistency rows drive ``_check`` on hand-built manifests, so the
refusals are proven on inputs that the shipped data never contains.
"""

from __future__ import annotations

from typing import Any

import pytest

from automated_security_helper.base.plugin_manifest import (
    MANIFEST_SCHEMA_VERSION,
    EntryPoints,
    PluginTier,
    ScannerManifest,
)
from automated_security_helper.plugin_manifests import (
    ManifestRegistryError,
    _check,
    dispatch_target,
    manifest_for,
    opt_in_module_for,
    opt_in_scanner_modules,
    scanner_manifests,
)

pytestmark = pytest.mark.unit

_PKG = "automated_security_helper.plugin_modules.ash_demo_plugins"


# --------------------------------------------------------------------------- #
# The semgrep retirement shape, as shipped
# --------------------------------------------------------------------------- #


def test_semgrep_dispatches_to_opengrep() -> None:
    assert dispatch_target("semgrep") == "opengrep"
    assert dispatch_target("  SEMGREP ") == "opengrep"


def test_opengrep_dispatches_to_itself() -> None:
    assert dispatch_target("opengrep") == "opengrep"


def test_a_name_with_no_manifest_and_no_alias_dispatches_nowhere() -> None:
    assert dispatch_target("no-such-scanner") is None


def test_the_retirement_is_declared_on_both_manifests() -> None:
    semgrep = manifest_for("semgrep")
    opengrep = manifest_for("opengrep")
    assert semgrep.tier is PluginTier.DEPRECATED
    assert semgrep.superseded_by == "opengrep"
    assert "semgrep" in opengrep.aliases
    assert opengrep.tier is PluginTier.SUPPORTED


def test_declaring_the_retirement_changes_no_run() -> None:
    """semgrep is still a builtin that loads by default; only data was added."""
    semgrep = manifest_for("semgrep")
    assert semgrep.default_enabled is True
    assert semgrep.plugin_module.endswith(".ash_builtin")
    assert semgrep.entry_points.scanner.endswith(":SemgrepScanner")


def test_only_one_scanner_is_deprecated_and_only_one_alias_exists() -> None:
    """Planted control for the dispatch rows: the shipped data is exactly this."""
    deprecated = [
        m.name for m in scanner_manifests() if m.tier is PluginTier.DEPRECATED
    ]
    aliases = {a: m.name for m in scanner_manifests() for a in m.aliases}
    assert deprecated == ["semgrep"]
    assert aliases == {"semgrep": "opengrep"}


# --------------------------------------------------------------------------- #
# The manifest tier scan
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "scanner,package",
    [
        ("betterleaks", "ash_betterleaks_plugins"),
        ("ferret-scan", "ash_ferret_plugins"),
        ("guarddog", "ash_guarddog_plugins"),
        ("hadolint", "ash_hadolint_plugins"),
        ("snyk-code", "ash_snyk_plugins"),
        ("trivy-repo", "ash_trivy_plugins"),
    ],
)
def test_each_alpha_scanner_maps_to_its_plugin_module(scanner, package) -> None:
    expected = f"automated_security_helper.plugin_modules.{package}"
    assert opt_in_module_for(scanner) == expected
    assert opt_in_module_for(f"  {scanner.upper()} ") == expected


def test_the_opt_in_scan_lists_exactly_the_scanners_that_do_not_load_by_default() -> (
    None
):
    assert set(opt_in_scanner_modules()) == {
        m.name for m in scanner_manifests() if not m.default_enabled
    }
    assert len(opt_in_scanner_modules()) == 7
    # Today the opt-in scanners are the alpha ones; that is the data, not the
    # rule (test_a_promoted_optin_scanner_keeps_its_hint covers the difference).
    assert {m.name for m in scanner_manifests() if m.tier is PluginTier.ALPHA} == set(
        opt_in_scanner_modules()
    )


@pytest.mark.parametrize("builtin", ["bandit", "semgrep", "opengrep", "trivy", "grype"])
def test_builtin_scanners_are_not_opt_in_scanners(builtin) -> None:
    assert opt_in_module_for(builtin) is None


# --------------------------------------------------------------------------- #
# The registry's own consistency rules, on inputs the shipped data never has
# --------------------------------------------------------------------------- #


def _manifest(name: str, **changes: Any) -> ScannerManifest:
    data: dict[str, Any] = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "name": name,
        "version": "bundled",
        "aliases": (),
        "tier": PluginTier.SUPPORTED,
        "default_enabled": True,
        "plugin_module": _PKG,
        "superseded_by": None,
        "entry_points": EntryPoints(scanner=f"{_PKG}.m:{name.title()}Scanner"),
        "options_model": f"{_PKG}.m:{name.title()}Options",
        "file_ownership": (f"automated_security_helper/plugin_modules/{name}",),
    }
    data.update(changes)
    return ScannerManifest(**data)


def test_the_control_registry_is_accepted() -> None:
    _check(
        (
            _manifest("new", aliases=("old",)),
            _manifest("old", tier=PluginTier.DEPRECATED, superseded_by="new"),
        )
    )


@pytest.mark.parametrize(
    "manifests,fragment",
    [
        ((_manifest("a"), _manifest("a")), "two manifests are named"),
        (
            (_manifest("a", aliases=("x",)), _manifest("b", aliases=("x",))),
            "declared by both",
        ),
        (
            (_manifest("a", aliases=("b",)), _manifest("b")),
            "is a scanner of its own",
        ),
        (
            (_manifest("a", tier=PluginTier.DEPRECATED, superseded_by="gone"),),
            "has no manifest",
        ),
        (
            (
                _manifest("a", tier=PluginTier.DEPRECATED, superseded_by="b"),
                _manifest("b"),
            ),
            "does not list",
        ),
    ],
    ids=[
        "duplicate-name",
        "duplicate-alias",
        "alias-shadows-a-live-scanner",
        "target-missing",
        "target-does-not-list-the-alias",
    ],
)
def test_the_registry_refuses_a_contradiction(manifests, fragment) -> None:
    with pytest.raises(ManifestRegistryError, match=fragment):
        _check(manifests)

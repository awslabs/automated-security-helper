# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Default enablement, read from the manifests: invariants, uniform mechanics, flips.

The one behavioral meaning a manifest's ``default_enabled`` has is whether the
plugin's module loads without being named (``plugins.enablement``). These tests
pin the derived sets against the shipped package directories, the uniform-surface
property (an opt-in shipped plugin's mechanics are a custom SDK plugin's
mechanics, and nothing on the record says which is which), and the flip
differential (changing a manifest's ``default_enabled`` changes enablement and
nothing on the record).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper import plugin_manifests
from automated_security_helper.plugins import enablement
from automated_security_helper.plugins.loader import scan_plugin_filter
from automated_security_helper.plugins.plugin_manager import AshPluginRegistration

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[3]
PLUGIN_MODULES_DIR = REPO_ROOT / "automated_security_helper" / "plugin_modules"
PLUGIN_MODULES_PACKAGE = "automated_security_helper.plugin_modules"


# ---------------------------------------------------------------------------
# The derived sets
# ---------------------------------------------------------------------------


def test_the_two_sets_are_non_empty_disjoint_and_sorted() -> None:
    unnamed = enablement.modules_loading_unnamed()
    needing = enablement.modules_needing_naming()
    assert unnamed and needing
    assert not set(unnamed) & set(needing), (
        "a module in both sets has two enablement defaults at once"
    )
    assert list(unnamed) == sorted(set(unnamed))
    assert list(needing) == sorted(set(needing))


def test_the_sets_are_the_manifests_plugin_modules_split_on_default_enabled() -> None:
    manifests = plugin_manifests.scanner_manifests()
    assert set(enablement.modules_loading_unnamed()) == {
        m.plugin_module for m in manifests if m.default_enabled
    }
    assert set(enablement.modules_needing_naming()) == {
        m.plugin_module for m in manifests if not m.default_enabled
    }


def test_the_shipped_sets_match_the_package_directory_census() -> None:
    """Every shipped scanner package is in exactly one set, and no set names a
    package that is not shipped: a package added to or removed from
    ``plugin_modules/`` without its manifest fails here, in whichever direction
    it drifted."""
    census = {
        f"{PLUGIN_MODULES_PACKAGE}.{package.name}"
        for package in PLUGIN_MODULES_DIR.glob("ash_*")
        if (package / "__init__.py").is_file()
        and "ASH_SCANNERS" in (package / "__init__.py").read_text(encoding="utf-8")
    }
    declared = set(enablement.modules_loading_unnamed()) | set(
        enablement.modules_needing_naming()
    )
    assert declared == census, (
        "the manifests and the shipped scanner packages disagree; "
        f"manifest-only: {sorted(declared - census)}, "
        f"directory-only: {sorted(census - declared)}"
    )
    # The AWS delivery reporters are shipped, load only when named, and have no
    # scanner manifest: enablement is not maturity, and it is not in either set.
    aws = f"{PLUGIN_MODULES_PACKAGE}.ash_aws_plugins"
    assert not enablement.loads_unnamed(aws)
    assert aws not in enablement.modules_needing_naming()


def test_loads_unnamed_covers_a_module_its_submodules_and_nothing_else() -> None:
    (root,) = enablement.modules_loading_unnamed()
    assert enablement.loads_unnamed(root)
    assert enablement.loads_unnamed(f"{root}.scanners.bandit_scanner")
    # A name that only shares a prefix is nobody's submodule.
    assert not enablement.loads_unnamed(f"{root}_extra")
    assert not enablement.loads_unnamed("custom_ash_plugins")
    for module in enablement.modules_needing_naming():
        assert not enablement.loads_unnamed(module)
        assert not enablement.loads_unnamed(f"{module}.some_module")


def test_the_internal_plugin_package_is_derived_not_declared() -> None:
    from automated_security_helper.plugins import loader

    assert (loader.INTERNAL_PLUGIN_PACKAGE,) == enablement.modules_loading_unnamed()


# ---------------------------------------------------------------------------
# The unloaded-module hint and refusal
# ---------------------------------------------------------------------------


def test_the_unloaded_hint_names_the_module_and_no_tier_word() -> None:
    hint = enablement.unloaded_opt_in_hint(
        {"snyk-code": f"{PLUGIN_MODULES_PACKAGE}.ash_snyk_plugins"}
    )
    assert "snyk-code" in hint
    assert "ash_snyk_plugins" in hint
    assert "ash_plugin_modules" in hint
    assert "--ash-plugin-modules" in hint
    assert "alpha" not in hint.lower(), "the refusal describes loading, never maturity"
    assert enablement.unloaded_opt_in_hint({}) == ""


def test_the_refusal_keeps_the_misspelling_clause_and_no_tier_word() -> None:
    scanner_cls = type(
        "FakeScanner",
        (),
        {"__module__": f"{enablement.modules_loading_unnamed()[0]}.x"},
    )
    refusal = enablement.unloaded_opt_in_refusal(
        ["snyk-code", "bandittt"], ["bandit"], [scanner_cls]
    )
    assert "ash_snyk_plugins" in refusal
    assert "bandittt" in refusal and "check the spelling" in refusal
    assert "alpha" not in refusal.lower()
    # A selection where any name resolves is not this refusal's case.
    assert (
        enablement.unloaded_opt_in_refusal(
            ["bandit", "snyk-code"], ["bandit"], [scanner_cls]
        )
        == ""
    )
    # Nothing registered: nothing to judge the names against.
    assert enablement.unloaded_opt_in_refusal(["snyk-code"], [], []) == ""


def test_a_module_that_supplied_other_scanners_is_not_reported_unloaded() -> None:
    from_snyk_module = type(
        "FromSnyk", (), {"__module__": f"{PLUGIN_MODULES_PACKAGE}.ash_snyk_plugins.x"}
    )
    assert (
        enablement.unloaded_opt_in_scanners(["snyk-code"], [], [from_snyk_module]) == {}
    )


# ---------------------------------------------------------------------------
# The uniform-surface differential: nothing downstream can tell an opt-in
# shipped plugin from a custom SDK plugin.
# ---------------------------------------------------------------------------


def _defined_in(module: str, name: str = "Plugin") -> type:
    return type(name, (), {"__module__": module})


def test_the_registration_record_carries_no_origin_field() -> None:
    suspicious = ("tier", "origin", "registry", "maturity", "extern")
    for field_name in AshPluginRegistration.model_fields:
        assert not any(word in field_name.lower() for word in suspicious), (
            f"the plugin record grew an origin-revealing field: {field_name}"
        )
    shipped_module = enablement.modules_needing_naming()[0]
    shipped = AshPluginRegistration(name="X", plugin_module_path=shipped_module)
    custom = AshPluginRegistration(name="X", plugin_module_path="custom_ash_plugins")
    shipped_dump, custom_dump = shipped.model_dump(), custom.model_dump()
    assert set(shipped_dump) == set(custom_dump)
    del shipped_dump["plugin_module_path"], custom_dump["plugin_module_path"]
    assert shipped_dump == custom_dump


def test_selection_treats_a_shipped_opt_in_and_a_custom_identically() -> None:
    opt_in = enablement.modules_needing_naming()[0]
    opt_in_cls = _defined_in(opt_in, "OptInShipped")
    custom_cls = _defined_in("custom_ash_plugins", "Custom")
    core_cls = _defined_in(f"{enablement.modules_loading_unnamed()[0]}.scanners.x")

    named_both = scan_plugin_filter([opt_in, "custom_ash_plugins"])
    assert named_both(opt_in_cls) and named_both(custom_cls) and named_both(core_cls)

    named_neither = scan_plugin_filter([])
    assert not named_neither(opt_in_cls)
    assert not named_neither(custom_cls), (
        "a custom plugin and a shipped opt-in plugin share one enablement rule"
    )
    assert named_neither(core_cls), "default-enabled modules load unnamed"

    # The loader's submodule rule is one rule for both: a class defined only in
    # a submodule of a named package is not selected through the package, and
    # that answer does not depend on whether the package ships with ASH.
    opt_in_sub = _defined_in(f"{opt_in}.scanner", "OptInSub")
    custom_sub = _defined_in("custom_ash_plugins.scanner", "CustomSub")
    assert named_both(opt_in_sub) == named_both(custom_sub)
    assert not named_both(opt_in_sub)


# ---------------------------------------------------------------------------
# The flip differential: one manifest field moves a module between the sets, and
# nothing on the record.
# ---------------------------------------------------------------------------


def test_flipping_default_enabled_moves_a_module_between_the_sets(monkeypatch) -> None:
    mover = f"{PLUGIN_MODULES_PACKAGE}.ash_hadolint_plugins"
    flipped = tuple(
        m.model_copy(update={"default_enabled": True})
        if m.plugin_module == mover
        else m
        for m in plugin_manifests.scanner_manifests()
    )
    assert not enablement.loads_unnamed(mover)
    monkeypatch.setattr(enablement, "scanner_manifests", lambda: flipped)

    assert enablement.loads_unnamed(mover)
    assert mover in enablement.modules_loading_unnamed()
    assert mover not in enablement.modules_needing_naming()
    record = AshPluginRegistration(name="X", plugin_module_path=mover)
    assert set(record.model_dump()) == set(AshPluginRegistration.model_fields)

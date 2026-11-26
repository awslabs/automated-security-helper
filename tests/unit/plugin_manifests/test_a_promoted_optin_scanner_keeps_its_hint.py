# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Promoting an opt-in scanner to ``supported`` must not change how it loads.

The opt-in scan answers "which shipped scanners are not loaded unless their module
is named". That is a LOADING fact (``default_enabled``), not a maturity fact
(``tier``): a maintained integration that stays opt-in is ``supported`` and still
needs naming. Keyed on ``tier is ALPHA`` the scan silently dropped such a scanner
at the first promotion, so the "add this module" hint, the ``dependencies
install`` hint and the MCP inventory's shipped-module list lost it while the
plugin still loaded only when named.
"""

from __future__ import annotations

import pytest

from automated_security_helper import plugin_manifests
from automated_security_helper.base.plugin_manifest import PluginTier
from automated_security_helper.plugins import enablement

pytestmark = pytest.mark.unit

_SNYK = "automated_security_helper.plugin_modules.ash_snyk_plugins"


@pytest.fixture
def snyk_code_promoted(monkeypatch):
    """The shipped manifests with ``snyk-code`` promoted to ``supported``.

    The promotion is the one-line ``tier`` edit in the manifest data; it changes
    nothing about whether the plugin loads by default.
    """
    shipped = plugin_manifests.scanner_manifests()
    promoted = tuple(
        m.model_copy(update={"tier": PluginTier.SUPPORTED})
        if m.name == "snyk-code"
        else m
        for m in shipped
    )
    snyk = next(m for m in promoted if m.name == "snyk-code")
    assert snyk.tier is PluginTier.SUPPORTED and snyk.default_enabled is False
    monkeypatch.setattr(plugin_manifests, "scanner_manifests", lambda: promoted)
    monkeypatch.setattr(enablement, "scanner_manifests", lambda: promoted)
    plugin_manifests.opt_in_scanner_modules.cache_clear()
    yield
    monkeypatch.undo()
    plugin_manifests.opt_in_scanner_modules.cache_clear()


def test_a_promoted_scanner_that_is_still_opt_in_keeps_the_add_this_module_hint(
    snyk_code_promoted,
) -> None:
    assert plugin_manifests.opt_in_module_for("snyk-code") == _SNYK
    assert plugin_manifests.opt_in_module_for("  SNYK-CODE ") == _SNYK
    hint = enablement.unloaded_opt_in_hint(
        enablement.unloaded_opt_in_scanners(["snyk-code"], ["bandit"], [])
    )
    assert _SNYK in hint and "--ash-plugin-modules" in hint


def test_a_promoted_scanner_stays_in_the_shipped_module_list_the_mcp_inventory_loads(
    snyk_code_promoted,
) -> None:
    assert _SNYK in enablement.modules_needing_naming()
    assert set(enablement.modules_needing_naming()) == set(
        plugin_manifests.opt_in_scanner_modules().values()
    )


def test_promotion_changes_no_loading_decision(snyk_code_promoted) -> None:
    assert not enablement.loads_unnamed(_SNYK)
    assert not enablement.loads_unnamed(f"{_SNYK}.snyk_code_scanner")
    assert enablement.loads_unnamed(enablement.modules_loading_unnamed()[0])
    assert _SNYK not in enablement.modules_loading_unnamed()


def test_a_default_enabled_scanner_is_never_in_the_selector(snyk_code_promoted) -> None:
    assert plugin_manifests.opt_in_module_for("bandit") is None

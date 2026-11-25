# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Promoting an opt-in scanner to ``supported`` must not change how it loads.

The tier scan answers "which shipped scanners are not loaded unless their module
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
from automated_security_helper.core.scanner_inventory import (
    _VENDORED_SCANNER_PLUGIN_PACKAGES,
)

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
    plugin_manifests.alpha_scanner_modules.cache_clear()
    yield
    monkeypatch.undo()
    plugin_manifests.alpha_scanner_modules.cache_clear()


def test_a_promoted_scanner_that_is_still_opt_in_keeps_the_add_this_module_hint(
    snyk_code_promoted,
) -> None:
    assert plugin_manifests.alpha_module_for("snyk-code") == _SNYK
    assert plugin_manifests.alpha_module_for("  SNYK-CODE ") == _SNYK


def test_a_promoted_scanner_stays_in_the_shipped_module_list_the_mcp_inventory_loads(
    snyk_code_promoted,
) -> None:
    assert set(_VENDORED_SCANNER_PLUGIN_PACKAGES) == set(
        plugin_manifests.alpha_scanner_modules().values()
    )


def test_a_default_enabled_scanner_is_never_in_the_selector(snyk_code_promoted) -> None:
    assert plugin_manifests.alpha_module_for("bandit") is None

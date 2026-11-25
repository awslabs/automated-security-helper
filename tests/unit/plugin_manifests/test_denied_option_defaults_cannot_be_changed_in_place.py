# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A denied option's default is one value for the process: nothing can edit it in place.

``ScannerManifest.denied_option_defaults`` holds the default of each plugin option
a client-delivered config may not change, and ``client_config_policy`` answers "is
this delivered value the default?" from it. The manifests are cached
(``scanner_manifests`` is ``lru_cache``d) and validating a ``dict[str, Any]`` keeps
the value objects it was given, so the list defaults (guarddog's ``ecosystems``,
trivy-repo's ``scanners``) were the very lists the module-level constant in
``plugin_manifests.alpha`` holds. One ``sort`` or ``append`` on any of those
objects changed the answer, for every later call in the process.

The lists stay lists (a delivered list is compared with ``==``); what changed is
that no object a reader gets is one the next reader gets too.
"""

from __future__ import annotations

import pytest

from automated_security_helper.config.client_config_policy import (
    PLUGIN_OPTION_DEFAULTS,
    _writes_plugin_default,
)
from automated_security_helper.plugin_manifests import alpha, scanner_manifests

pytestmark = pytest.mark.unit

GUARDDOG_ECOSYSTEMS = ("guarddog", "ecosystems")
TRIVY_SCANNERS = ("trivy-repo", "scanners")


def _manifest(name: str):
    return next(m for m in scanner_manifests() if m.name == name)


def test_control_the_defaults_are_the_lists_the_plugins_declare():
    """Control: the rows these cells change exist and hold list values."""
    assert PLUGIN_OPTION_DEFAULTS[GUARDDOG_ECOSYSTEMS] == [
        "pypi",
        "npm",
        "go",
        "github_action",
        "rubygems",
        "crates",
    ]
    assert PLUGIN_OPTION_DEFAULTS[TRIVY_SCANNERS] == [
        "vuln",
        "secret",
        "misconfig",
        "license",
    ]


def test_a_manifest_does_not_share_a_list_with_the_module_constant():
    """Red at the base: the manifest's list was the constant's list."""
    declared = alpha._DENIED_OPTION_DEFAULTS["guarddog"]["ecosystems"]
    held = _manifest("guarddog").denied_option_defaults["ecosystems"]

    assert held == declared
    assert held is not declared


def test_editing_the_module_constant_in_place_changes_no_manifest():
    declared = alpha._DENIED_OPTION_DEFAULTS["trivy-repo"]["scanners"]
    before = list(_manifest("trivy-repo").denied_option_defaults["scanners"])
    declared.append("sbom")
    try:
        assert _manifest("trivy-repo").denied_option_defaults["scanners"] == before
        assert PLUGIN_OPTION_DEFAULTS[TRIVY_SCANNERS] == before
    finally:
        declared.remove("sbom")


def test_editing_a_list_read_from_the_table_changes_no_later_read():
    """Red at the base: the table returned the stored list, so a sort in one
    caller reordered the default for every caller after it."""
    first = PLUGIN_OPTION_DEFAULTS[GUARDDOG_ECOSYSTEMS]
    first.sort()
    first.append("maven")

    again = PLUGIN_OPTION_DEFAULTS[GUARDDOG_ECOSYSTEMS]
    assert again == ["pypi", "npm", "go", "github_action", "rubygems", "crates"]
    assert again is not first


def test_editing_a_list_read_through_items_changes_no_later_read():
    for key, value in PLUGIN_OPTION_DEFAULTS.items():
        if key == TRIVY_SCANNERS:
            value.clear()

    assert PLUGIN_OPTION_DEFAULTS[TRIVY_SCANNERS] == [
        "vuln",
        "secret",
        "misconfig",
        "license",
    ]


def test_editing_a_manifests_list_changes_no_answer_of_the_policy():
    """The answer the table decides: with the manifest's own list edited in place,
    a delivered value equal to the default is still the default, and one equal to
    the edited list is not."""
    from automated_security_helper.config.ash_config import AshConfig

    manifest = _manifest("guarddog")
    held = manifest.denied_option_defaults["ecosystems"]
    held.append("maven")
    try:

        class Denial:
            from_patch = False
            pointer = "/scanners/guarddog/options/ecosystems"

        delivered = {
            "scanners": {
                "guarddog": {
                    "options": {
                        "ecosystems": [
                            "pypi",
                            "npm",
                            "go",
                            "github_action",
                            "rubygems",
                            "crates",
                        ]
                    }
                }
            }
        }
        base = AshConfig(project_name="p")
        assert _writes_plugin_default(delivered, Denial, base) is True
    finally:
        held.remove("maven")

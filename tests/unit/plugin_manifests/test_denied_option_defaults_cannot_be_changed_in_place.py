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


def test_a_manifests_list_cannot_be_edited_in_place():
    """Red at the base: the cached manifest's list was a live ``list``, and one
    ``append`` changed what "the default" meant for the cached manifest."""
    held = _manifest("guarddog").denied_option_defaults["ecosystems"]
    before = list(held)

    for edit in (
        lambda: held.append("maven"),
        lambda: held.extend(["maven"]),
        lambda: held.insert(0, "maven"),
        lambda: held.remove("pypi"),
        lambda: held.pop(),
        lambda: held.sort(),
        lambda: held.reverse(),
        lambda: held.clear(),
        lambda: held.__setitem__(0, "maven"),
        lambda: held.__delitem__(0),
        lambda: held.__iadd__(["maven"]),
        lambda: held.__imul__(2),
    ):
        with pytest.raises(TypeError):
            edit()

    assert list(held) == before
    assert _manifest("guarddog").denied_option_defaults["ecosystems"] == before


def test_a_manifests_table_of_defaults_cannot_be_edited_in_place():
    held = _manifest("guarddog").denied_option_defaults
    keys = set(held)

    for edit in (
        lambda: held.__setitem__("x", 1),
        lambda: held.__delitem__("ecosystems"),
        lambda: held.pop("ecosystems"),
        lambda: held.popitem(),
        lambda: held.setdefault("x", 1),
        lambda: held.update({"x": 1}),
        lambda: held.clear(),
        lambda: held.__ior__({"x": 1}),
    ):
        with pytest.raises(TypeError):
            edit()

    assert set(_manifest("guarddog").denied_option_defaults) == keys


def test_a_manifest_that_declares_none_has_a_frozen_empty_table():
    """Red at the tip it was found on: pydantic does not validate a default, so a
    manifest that passed no table (every builtin one) held a plain ``dict``."""
    builtin = [m for m in scanner_manifests() if m.default_enabled]
    assert builtin, "control: there are builtin manifests"

    for manifest in builtin:
        table = manifest.denied_option_defaults
        assert table == {}
        with pytest.raises(TypeError):
            table["x"] = 1
        with pytest.raises(TypeError):
            table.update({"x": 1})


def test_every_manifests_table_is_the_same_frozen_type():
    from automated_security_helper.base.plugin_manifest import _FrozenDict

    kinds = {type(m.denied_option_defaults) for m in scanner_manifests()}

    assert kinds == {_FrozenDict}


def test_a_nested_list_is_frozen_too():
    from automated_security_helper.base.plugin_manifest import ScannerManifest

    manifest = _manifest("guarddog")
    data = manifest.model_dump()
    data["denied_option_defaults"] = {"nested": {"inner": ["a", "b"]}}
    rebuilt = ScannerManifest.model_validate(data)

    with pytest.raises(TypeError):
        rebuilt.denied_option_defaults["nested"]["inner"].append("c")
    with pytest.raises(TypeError):
        rebuilt.denied_option_defaults["nested"]["x"] = 1


def test_a_frozen_default_dumps_validates_and_copies_as_plain_data():
    import copy

    from automated_security_helper.base.plugin_manifest import ScannerManifest

    manifest = _manifest("guarddog")
    dumped = manifest.model_dump()

    assert type(dumped["denied_option_defaults"]) is dict
    assert type(dumped["denied_option_defaults"]["ecosystems"]) is list
    assert ScannerManifest.model_validate(dumped) == manifest
    assert copy.deepcopy(manifest.denied_option_defaults) == (
        manifest.denied_option_defaults
    )


def test_the_policy_answers_from_the_table_whatever_is_attempted_on_a_manifest():
    """The answer the table decides: a delivered value equal to the default is
    still the default after every attempt to edit the manifest's own list."""
    from automated_security_helper.config.ash_config import AshConfig

    held = _manifest("guarddog").denied_option_defaults["ecosystems"]
    with pytest.raises(TypeError):
        held.append("maven")

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

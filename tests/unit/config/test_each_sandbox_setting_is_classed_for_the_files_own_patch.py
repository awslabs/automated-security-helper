# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Each ``sandbox`` setting is classed for the way a file's own patch is read.

``_own_grants_after_patch`` reads a setting the file's own ``patch`` removes or
rewrites by the setting's class:

- ``mode`` is read by ``_own_mode_after_patch``;
- ``network_scanners`` restricts, so a patch cuts the list down and never drops it;
- the four additive lists (``_ADDITIVE_SANDBOX_SETTINGS``: ``extra_read_paths``,
  ``read_path_scanners``, ``env_scanners``, ``environment``) only add access, so
  what a patch leaves of them is cut down to the entries that both the list the file
  wrote and the list the patch leaves name.

A setting in no class is dropped. That is safe for a setting that adds access, and
wrong for one that restricts (a deny list, a ``false`` for a network switch): the
trusted base's looser value would take its place. So a new field of
``SandboxConfig`` has to be put in a class here and in
``_own_grants_after_patch`` before this test passes.
"""

from __future__ import annotations

import pytest

from automated_security_helper.config.ash_config import SandboxConfig
from automated_security_helper.config.resolve_config import (
    _ADDITIVE_SANDBOX_SETTINGS,
    _NARROWED_SANDBOX_SETTING,
    _REWRITE_KEPT_SANDBOX_SETTING,
)

pytestmark = pytest.mark.unit


def test_each_sandbox_setting_is_in_one_class():
    classed = {
        _REWRITE_KEPT_SANDBOX_SETTING,
        _NARROWED_SANDBOX_SETTING,
        *_ADDITIVE_SANDBOX_SETTINGS,
    }

    assert set(SandboxConfig.model_fields) == classed, (
        "SandboxConfig has a setting that _own_grants_after_patch does not class: "
        f"{sorted(set(SandboxConfig.model_fields) ^ classed)}. Decide how a patch "
        "that rewrites it is read, then put it in a class in resolve_config.py and "
        "in this set: a setting that restricts is cut down like network_scanners, "
        "a list that only adds access joins _ADDITIVE_SANDBOX_SETTINGS, and a "
        "setting in no class is dropped, which hands a restriction the trusted "
        "base's looser value."
    )


def test_the_three_classes_do_not_overlap():
    assert _REWRITE_KEPT_SANDBOX_SETTING == "mode"
    assert _NARROWED_SANDBOX_SETTING == "network_scanners"
    assert {_REWRITE_KEPT_SANDBOX_SETTING, _NARROWED_SANDBOX_SETTING}.isdisjoint(
        _ADDITIVE_SANDBOX_SETTINGS
    )


def test_the_additive_lists_are_the_four_that_only_add_access():
    assert _ADDITIVE_SANDBOX_SETTINGS == {
        "extra_read_paths",
        "read_path_scanners",
        "env_scanners",
        "environment",
    }


def test_the_network_limit_is_not_a_setting_a_config_file_can_write():
    # A private attribute behind a property, so the settings above are all a file
    # can set. Declared as a field it would be one more setting to class, and a
    # config file could then set the limit that sandbox_grants.py alone sets.
    assert "network_limit" not in SandboxConfig.model_fields
    assert isinstance(SandboxConfig.network_limit, property)

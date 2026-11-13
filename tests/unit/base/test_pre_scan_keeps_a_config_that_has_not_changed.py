# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``_pre_scan`` swaps a scan's config in only when it differs from the plugin's.

``_pre_scan`` took the config it was handed (a model, or the dump of one), built
the plugin's config model from its dump and stored that, on every scan. Building
a model from a dump makes every nested entry a new object. An entry that carries
an identity the dump does not write (a filter entry the secrets scanners hold)
got a new identity on every scan, and the private state the first build recorded
was dropped. The swap now happens only when the config handed in differs from
the one held; an unchanged one leaves the held config, and everything nested in
it, as it was.
"""

from __future__ import annotations

import pytest

from tests.unit.base.scanner_support import build_scanner

pytestmark = pytest.mark.unit


@pytest.fixture
def target(tmp_path):
    directory = tmp_path / "target"
    directory.mkdir()
    (directory / "app.py").write_text("x = 1\n", encoding="utf-8")
    return directory


def test_a_config_that_says_the_same_is_not_swapped_in(plugin_context, target):
    scanner = build_scanner(plugin_context)
    held = scanner.config
    options = held.options

    started = scanner._pre_scan(
        target=target, target_type="source", config=held.model_dump(by_alias=True)
    )

    assert started is True
    assert scanner.config is held
    assert scanner.config.options is options


def test_the_plugins_own_config_handed_back_is_kept_too(plugin_context, target):
    scanner = build_scanner(plugin_context)
    held = scanner.config

    assert scanner._pre_scan(target=target, target_type="source", config=held)

    assert scanner.config is held


def test_a_config_that_differs_replaces_the_held_one(plugin_context, target):
    """The control: the swap still happens when the config says something else."""
    scanner = build_scanner(plugin_context)
    held = scanner.config
    changed = held.model_dump(by_alias=True)
    changed["enabled"] = not held.enabled

    assert scanner._pre_scan(target=target, target_type="source", config=changed)

    assert scanner.config is not held
    assert scanner.config.enabled is changed["enabled"]

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A key read from the environment is paired with the key it came to.

Two shapes went unrecorded, each with every environment read beneath the key:

* a plugin section key whose value is a non-declared spelling of a known plugin
  (``ASH_SCANNER=Bandit``): the resolved document was folded to the declared
  spelling before pairing, and the exact lookup of the value found no such key;
* a key the loader never resolves (a TOML key, a quoted YAML key): the lookup
  of the value found no such key either, where the key came to its own text.

Red at the base: ``environment_references`` returned nothing for both.
"""

from __future__ import annotations

import pytest

from automated_security_helper.config.environment_record import (
    environment_references,
)

pytestmark = pytest.mark.unit


def test_a_respelled_plugin_section_key_pairs_with_the_folded_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ASH_U35_SCANNER", "Bandit")
    monkeypatch.setenv("ASH_U35_V", "v")
    written = {"scanners": {"${ASH_U35_SCANNER}": {"options": {"x": "${ASH_U35_V}"}}}}
    resolved = {"scanners": {"bandit": {"options": {"x": "v"}}}}

    found = environment_references(written, resolved)

    assert [(r.path, r.written, r.value) for r in found if not r.key] == [
        (("scanners", "bandit", "options", "x"), "${ASH_U35_V}", "v")
    ]
    assert [(r.path, r.written, r.resolved) for r in found if r.key] == [
        (("scanners",), "${ASH_U35_SCANNER}", "bandit")
    ]


def test_a_key_the_loader_never_resolved_pairs_with_its_own_text(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A TOML key, or a quoted YAML key, stays its own text in both views."""
    monkeypatch.setenv("ASH_U35_K", "a")
    monkeypatch.setenv("ASH_U35_V", "v")
    written = {"${ASH_U35_K}": {"x": "${ASH_U35_V}"}}
    resolved = {"${ASH_U35_K}": {"x": "v"}}

    found = environment_references(written, resolved)

    assert [(r.path, r.written, r.value, r.key) for r in found] == [
        (("${ASH_U35_K}", "x"), "${ASH_U35_V}", "v", False)
    ]


def test_a_resolved_key_still_pairs_exactly(monkeypatch: pytest.MonkeyPatch) -> None:
    """The control: a key that came to its value pairs under the value."""
    monkeypatch.setenv("ASH_U35_K", "bandit")
    monkeypatch.setenv("ASH_U35_V", "v")
    written = {"scanners": {"${ASH_U35_K}": {"options": {"x": "${ASH_U35_V}"}}}}
    resolved = {"scanners": {"bandit": {"options": {"x": "v"}}}}

    found = environment_references(written, resolved)

    assert [(r.path, r.value) for r in found if not r.key] == [
        (("scanners", "bandit", "options", "x"), "v")
    ]

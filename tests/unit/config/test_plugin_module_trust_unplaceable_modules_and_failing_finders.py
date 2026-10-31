# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""How ``plugin_module_trust`` judges a module it cannot place, or cannot look up.

* A finder that raises anything but ``ImportError`` or ``ValueError`` while a
  name is looked up means the name is not located: ``refusal_reason`` refuses it
  and ``_is_ash_own_module`` says it is not ASH's own. The exception does not
  escape into config resolution.
* A module whose spec has no file location at some level (built in, frozen, or
  served by a finder with no file) cannot be shown to sit outside the scanned
  tree. ``refusal_reason`` refuses it, and it is not ASH's own module, so the
  rootless client refusal does not let it through on an empty ``all()``.
* The rootless client refusal does not locate a name outside the plugin
  namespace: the scan never imports such a name, so asking every meta-path finder
  about it only runs their code.
"""

from __future__ import annotations

import sys
from importlib.machinery import ModuleSpec
from pathlib import Path

import pytest

from automated_security_helper.config import plugin_module_trust
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.plugin_module_trust import (
    _is_ash_own_module,
    confine_plugin_modules,
    refusal_reason,
)
from automated_security_helper.core.exceptions import ASHConfigSourceError

pytestmark = pytest.mark.unit

RAISING = "raisingfinder_ash_plugins"
UNPLACED = "unplaced_ash_plugins"
OUTSIDE = "outside_namespace_module"


class _RaisingFinder:
    """A meta-path finder that fails for one name and answers None for the rest."""

    @staticmethod
    def find_spec(name, path=None, target=None):
        if name == RAISING:
            raise RuntimeError("the finder failed")
        return None


@pytest.fixture
def raising_finder(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "meta_path", [_RaisingFinder, *sys.meta_path])


def _locate_without_a_file(monkeypatch: pytest.MonkeyPatch, origin) -> None:
    """Make every lookup answer a spec that has no file location."""
    monkeypatch.setattr(
        plugin_module_trust,
        "_spec_without_importing",
        lambda prefix, _parent: ModuleSpec(prefix, None, origin=origin),
    )


def _rootless_client_confinement(config: AshConfig) -> None:
    confine_plugin_modules(
        config,
        AshConfig(),
        [],
        None,
        [],
        no_scanned_tree=True,
        untrusted=True,
        checkout_membership=True,
        mixed_membership=False,
        given_root_membership=False,
        undecided_membership=False,
    )


@pytest.mark.usefixtures("raising_finder")
def test_a_finder_that_raises_refuses_the_name_instead_of_escaping():
    reason = refusal_reason(RAISING, None)

    assert reason is not None and "not importable" in reason, reason


@pytest.mark.usefixtures("raising_finder")
def test_a_finder_that_raises_means_the_name_is_not_ashs_own():
    assert _is_ash_own_module(RAISING) is False


@pytest.mark.parametrize("origin", [None, "frozen"])
def test_a_module_with_no_file_location_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, origin
):
    _locate_without_a_file(monkeypatch, origin)

    reason = refusal_reason(UNPLACED, tmp_path)

    assert reason is not None and "no file location" in reason, reason


def test_a_module_with_no_file_location_is_not_ashs_own(
    monkeypatch: pytest.MonkeyPatch,
):
    _locate_without_a_file(monkeypatch, None)

    assert _is_ash_own_module(UNPLACED) is False


def test_a_rootless_client_config_refuses_a_module_with_no_file_location(
    monkeypatch: pytest.MonkeyPatch,
):
    _locate_without_a_file(monkeypatch, None)
    config = AshConfig.model_validate({"ash_plugin_modules": [UNPLACED]})

    with pytest.raises(ASHConfigSourceError) as caught:
        _rootless_client_confinement(config)

    assert UNPLACED in str(caught.value), str(caught.value)


def test_a_rootless_client_config_does_not_locate_a_name_outside_the_namespace(
    monkeypatch: pytest.MonkeyPatch,
):
    located = []

    def record(prefix, _parent):
        located.append(prefix)
        return None

    monkeypatch.setattr(plugin_module_trust, "_spec_without_importing", record)
    config = AshConfig.model_validate({"ash_plugin_modules": [OUTSIDE]})

    with pytest.raises(ASHConfigSourceError) as caught:
        _rootless_client_confinement(config)

    assert OUTSIDE in str(caught.value), str(caught.value)
    assert located == [], located

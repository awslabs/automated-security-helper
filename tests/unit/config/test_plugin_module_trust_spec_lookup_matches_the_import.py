# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The spec lookup in ``plugin_module_trust`` answers as the scan's import would.

* A relative ``submodule_search_locations`` entry that names nothing on disk is
  a path hook's marker string, not a place a module file lives, so it is not
  judged as a path against the working directory.
* A child of an imported parent that is a plain module has no spec, the answer a
  parent that is not imported already gave, so the check surfaces agree with the
  scan whatever the process has imported.
* ``refusal_reason`` drops the import system's caches before it looks a module
  up, as the scan's loader does, so a module installed after a miss was cached
  is found.
* A rootless load that has no scanned tree does not say a module "resolves
  inside the scanned tree".
"""

from __future__ import annotations

import importlib.util
import sys
from importlib.machinery import ModuleSpec
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

MARKER = "__editable__.demo-1.0.finder.__path_hook__"


def test_a_path_hook_marker_is_not_a_location(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    from automated_security_helper.config.plugin_module_trust import _spec_locations

    monkeypatch.chdir(tmp_path)
    portion = tmp_path / "portion"
    portion.mkdir()
    spec = ModuleSpec("marked_ash_plugins", None, is_package=True)
    spec.submodule_search_locations = [MARKER, str(portion)]

    assert _spec_locations(spec) == [portion]


def test_a_relative_entry_that_exists_is_still_a_location(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """The control: a relative directory that is there is judged as a path."""
    from automated_security_helper.config.plugin_module_trust import _spec_locations

    monkeypatch.chdir(tmp_path)
    (tmp_path / "relative_portion").mkdir()
    spec = ModuleSpec("relative_ash_plugins", None, is_package=True)
    spec.submodule_search_locations = ["relative_portion"]

    assert _spec_locations(spec) == [Path("relative_portion")]


def test_a_child_of_an_imported_plain_module_has_no_spec(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    from automated_security_helper.config.plugin_module_trust import (
        _spec_without_importing,
    )
    from automated_security_helper.plugins.loader import _unfindable_level

    parent_name = "plainparent_ash_plugins"
    child_name = f"{parent_name}.child"
    source = tmp_path / f"{parent_name}.py"
    source.write_text("VALUE = 1\n", encoding="utf-8")
    monkeypatch.syspath_prepend(str(tmp_path))
    # The parent is imported, as an earlier scan in a long-lived process would
    # have left it, without running its body here.
    parent_spec = importlib.util.spec_from_file_location(parent_name, source)
    assert parent_spec is not None
    monkeypatch.setitem(
        sys.modules, parent_name, importlib.util.module_from_spec(parent_spec)
    )

    assert _spec_without_importing(child_name, parent_spec) is None
    assert _unfindable_level(child_name) == child_name


def test_refusal_reason_finds_a_module_installed_after_a_miss_was_cached(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    from automated_security_helper.config.plugin_module_trust import refusal_reason

    name = "latecomer_ash_plugins"
    site = tmp_path / "late-site"
    scan_root = tmp_path / "scan"
    scan_root.mkdir()
    monkeypatch.syspath_prepend(str(site))
    # The directory does not exist yet, so the import system caches that it
    # holds nothing.
    assert importlib.util.find_spec(name) is None
    site.mkdir()
    (site / f"{name}.py").write_text("VALUE = 1\n", encoding="utf-8")
    # The premise: the cached miss hides the file from a plain lookup.
    assert importlib.util.find_spec(name) is None

    assert refusal_reason(name, scan_root) is None


def test_a_rootless_decision_does_not_claim_a_scanned_tree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    from automated_security_helper.config import plugin_module_trust
    from automated_security_helper.config.plugin_module_trust import refusal_reason
    from automated_security_helper.config.sandbox_grants import WalkJudgment

    monkeypatch.setattr(
        plugin_module_trust,
        "_spec_without_importing",
        lambda _prefix, _parent: object(),
    )
    monkeypatch.setattr(
        plugin_module_trust,
        "_spec_locations",
        lambda _spec: [tmp_path / "mods" / "mod.py"],
    )
    monkeypatch.setattr(
        plugin_module_trust,
        "scanned_tree_judgment",
        lambda _location, _root: WalkJudgment(True, True),
    )

    reason = refusal_reason("their_ash_plugins", None, any_checkout=True)

    assert reason is not None and "scanned tree" not in reason, reason
    # The control: with a scanned tree the reason names it.
    assert refusal_reason("their_ash_plugins", tmp_path / "scan") == (
        "it resolves inside the scanned tree"
    )

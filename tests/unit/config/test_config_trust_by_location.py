# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A config file is judged by where it sits, not by where a symbolic link leads.

A config file inside the scanned tree was written by the repository under scan,
so the sandbox grants it makes (``extra_read_paths``, ``network_scanners``) are
dropped. The tree's own ``.ash/.ash.yaml`` can be a symbolic link to a file
outside it -- a git checkout or an MCP ``set_source_git`` delivery keeps links --
and judged by its resolved path it looked like an operator file outside the tree,
so its grants applied. The location of the name decides now, for a discovered
config, a named one, the file ``ASH_CONFIG`` names and the operator's trusted
config alike.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from automated_security_helper.config.resolve_config import resolve_config

GRANTS = "sandbox:\n  extra_read_paths: ['/']\n  network_scanners: ['bandit']\n"

pytestmark = pytest.mark.skipif(
    not hasattr(os, "symlink") or os.name == "nt",
    reason="creates symbolic links, which need privileges on Windows",
)


@pytest.fixture(autouse=True)
def _no_ash_config_variable(monkeypatch):
    monkeypatch.delenv("ASH_CONFIG", raising=False)


@pytest.fixture
def outside(tmp_path) -> Path:
    """A file that sets grants, outside the scanned tree (another checkout)."""
    path = tmp_path / "other-checkout" / "grants.yaml"
    path.parent.mkdir(parents=True)
    path.write_text(GRANTS, encoding="utf-8")
    return path


@pytest.fixture
def scanned(tmp_path) -> Path:
    path = tmp_path / "scanned"
    (path / ".ash").mkdir(parents=True)
    (path / "app.py").write_text("x = 1\n", encoding="utf-8")
    return path


def _granted(config) -> tuple:
    return list(config.sandbox.extra_read_paths), config.sandbox.network_scanners


def test_a_discovered_config_linked_out_of_the_tree_grants_nothing(scanned, outside):
    (scanned / ".ash" / ".ash.yaml").symlink_to(outside)

    assert _granted(resolve_config(source_dir=scanned)) == ([], None)


def test_a_named_config_linked_out_of_the_tree_grants_nothing(scanned, outside):
    link = scanned / ".ash" / "custom.yaml"
    link.symlink_to(outside)

    assert _granted(resolve_config(config_path=link, source_dir=scanned)) == (
        [],
        None,
    )


def test_an_ash_config_link_in_the_tree_grants_nothing(scanned, outside, monkeypatch):
    link = scanned / ".ash" / "env.yaml"
    link.symlink_to(outside)
    monkeypatch.setenv("ASH_CONFIG", str(link))

    assert _granted(resolve_config(source_dir=scanned)) == ([], None)


def test_an_ash_config_link_in_the_tree_is_not_the_trusted_base(
    scanned, outside, monkeypatch
):
    """With an in-tree config found as well, ``ASH_CONFIG`` is the trusted base."""
    (scanned / ".ash" / ".ash.yaml").write_text(GRANTS, encoding="utf-8")
    link = scanned / ".ash" / "env.yaml"
    link.symlink_to(outside)
    monkeypatch.setenv("ASH_CONFIG", str(link))

    assert _granted(resolve_config(source_dir=scanned)) == ([], None)


def test_control_an_ash_config_outside_the_tree_is_the_trusted_base(
    scanned, outside, monkeypatch
):
    (scanned / ".ash" / ".ash.yaml").write_text(GRANTS, encoding="utf-8")
    monkeypatch.setenv("ASH_CONFIG", str(outside))

    assert _granted(resolve_config(source_dir=scanned)) == (["/"], ["bandit"])


def test_an_operator_config_link_in_the_tree_is_not_the_trusted_base(scanned, outside):
    """The trusted base an in-tree config's grants are replaced from."""
    (scanned / ".ash" / ".ash.yaml").write_text(GRANTS, encoding="utf-8")
    profile = scanned / ".ash" / "profile.yaml"
    profile.symlink_to(outside)

    config = resolve_config(source_dir=scanned, trusted_config_path=profile)

    assert _granted(config) == ([], None)


def test_control_a_regular_config_in_the_tree_grants_nothing(scanned):
    (scanned / ".ash" / ".ash.yaml").write_text(GRANTS, encoding="utf-8")

    assert _granted(resolve_config(source_dir=scanned)) == ([], None)


def test_control_the_operator_file_outside_the_tree_still_grants(scanned, outside):
    config = resolve_config(config_path=outside, source_dir=scanned)

    assert _granted(config) == (["/"], ["bandit"])

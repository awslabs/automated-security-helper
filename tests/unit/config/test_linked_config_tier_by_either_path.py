# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A config reached through a link is repository-written when either path is.

A config file counts as repository-written, so the sandbox grants it makes are
dropped, when the path it was found or named by is inside a git checkout or the
scanned directory, or when the file that path resolves to is
(``sandbox_grants.untrusted_reason``, ``repository_written``). A link moves a
file without moving its name, so both paths are judged.

test_config_trust_by_location.py covers a link from the scanned directory to a
file outside it. These cases use real git checkouts (a ``.git`` directory) on
either side of the link: a name inside a checkout that links outside every
checkout, and a name outside every checkout that links into one.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from automated_security_helper.config.resolve_config import resolve_config
from tests.utils.helpers import mark_git_checkout

GRANT = "/opt/linked-grant"
GRANTS = f"project_name: linked\nsandbox:\n  extra_read_paths: ['{GRANT}']\n"

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(
        not hasattr(os, "symlink") or os.name == "nt",
        reason="creates symbolic links, which need privileges on Windows",
    ),
]


@pytest.fixture(autouse=True)
def _no_ash_config_variable(monkeypatch):
    monkeypatch.delenv("ASH_CONFIG", raising=False)


def _checkout(path: Path) -> Path:
    mark_git_checkout(path)
    return path


def _grants(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(GRANTS, encoding="utf-8")
    return path


def _granted(config) -> bool:
    return GRANT in list(config.sandbox.extra_read_paths or [])


def test_a_discovered_link_in_a_checkout_to_a_file_outside_every_checkout(tmp_path):
    repo = _checkout(tmp_path / "repo")
    (repo / ".ash").mkdir()
    (repo / ".ash" / ".ash.yaml").symlink_to(_grants(tmp_path / "outside" / "ash.yaml"))

    assert not _granted(resolve_config(source_dir=repo))


def test_a_discovered_dot_ash_link_in_a_checkout_to_a_directory_outside(tmp_path):
    repo = _checkout(tmp_path / "repo")
    _grants(tmp_path / "outside" / "dot-ash" / ".ash.yaml")
    (repo / ".ash").symlink_to(tmp_path / "outside" / "dot-ash")

    assert not _granted(resolve_config(source_dir=repo))


def test_a_discovered_link_to_a_file_in_another_checkout(tmp_path):
    """The scanned directory is in no checkout; the file the link reaches is."""
    scanned = tmp_path / "scanned"
    scanned.mkdir()
    ops = _checkout(tmp_path / "ops")
    (scanned / ".ash.yaml").symlink_to(_grants(ops / "ash.yaml"))

    assert not _granted(resolve_config(source_dir=scanned))


def test_a_named_link_in_a_checkout_to_a_file_outside_every_checkout(tmp_path):
    scanned = tmp_path / "scanned"
    scanned.mkdir()
    ops = _checkout(tmp_path / "ops")
    (ops / "ash.yaml").symlink_to(_grants(tmp_path / "outside" / "ash.yaml"))

    config = resolve_config(config_path=ops / "ash.yaml", source_dir=scanned)

    assert not _granted(config)


def test_a_named_link_outside_every_checkout_to_a_file_in_a_checkout(tmp_path):
    scanned = tmp_path / "scanned"
    scanned.mkdir()
    ops = _checkout(tmp_path / "ops")
    link = tmp_path / "outside" / "ash.yaml"
    link.parent.mkdir()
    link.symlink_to(_grants(ops / "ash.yaml"))

    assert not _granted(resolve_config(config_path=link, source_dir=scanned))


def test_an_ash_config_link_in_a_checkout_is_not_the_trusted_base(
    tmp_path, monkeypatch
):
    """The base an in-tree config's grants are replaced from."""
    repo = _checkout(tmp_path / "repo")
    _grants(repo / ".ash" / ".ash.yaml")
    ops = _checkout(tmp_path / "ops")
    (ops / "env.yaml").symlink_to(_grants(tmp_path / "outside" / "env.yaml"))
    monkeypatch.setenv("ASH_CONFIG", str(ops / "env.yaml"))

    assert not _granted(resolve_config(source_dir=repo))


def test_control_an_operator_config_outside_every_checkout_grants(tmp_path):
    scanned = tmp_path / "scanned"
    scanned.mkdir()
    operator = _grants(tmp_path / "operator" / "ash.yaml")

    assert _granted(resolve_config(config_path=operator, source_dir=scanned))


def test_control_an_operator_link_outside_every_checkout_grants(tmp_path):
    """Both paths outside every checkout: the link alone does not make it untrusted."""
    scanned = tmp_path / "scanned"
    scanned.mkdir()
    link = tmp_path / "operator" / "ash.yaml"
    link.parent.mkdir()
    link.symlink_to(_grants(tmp_path / "operator-files" / "ash.yaml"))

    assert _granted(resolve_config(config_path=link, source_dir=scanned))


def test_control_an_ash_config_outside_every_checkout_is_the_trusted_base(
    tmp_path, monkeypatch
):
    repo = _checkout(tmp_path / "repo")
    _grants(repo / ".ash" / ".ash.yaml")
    monkeypatch.setenv("ASH_CONFIG", str(_grants(tmp_path / "outside" / "env.yaml")))

    assert _granted(resolve_config(source_dir=repo))

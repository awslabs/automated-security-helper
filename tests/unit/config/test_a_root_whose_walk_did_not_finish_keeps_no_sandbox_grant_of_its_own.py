# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A root config whose directory walk did not finish keeps no sandbox grant of its own.

A config file inside a git checkout may not choose the sandbox grants, and a file
whose name walk cannot reach its end is read as inside one: no checkout was found,
but the walk could not rule one out. A root config that sits outside every checkout
and extends a base inside one keeps the sandbox section it writes itself
(``resolve_config._with_own_sandbox``); a root whose walk did not finish is not that
file, and its own section is dropped like the rest.

The walk is made undecided for real. One directory component of the file's name is
made unjudgeable for the link walk's own ``lstat`` (the permission failure a parent
that cannot be searched gives), and every other path keeps the real ``lstat``, so
the load of the file and every check around it are real.

Each case is run twice: with the file named by ``ASH_CONFIG``, where the file is the
configuration, and with the file selected as the config.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.confinement_remedy import LET_THE_WALK_FINISH
from automated_security_helper.config.resolve_config import (
    _warn_dropped_own_sandbox,
    resolve_config,
)
from automated_security_helper.config.sandbox_grants import in_any_checkout
from tests.utils.helpers import link_walk_cannot_examine, mark_git_checkout

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()

#: The grant lists a config file can write (the environment list among them, a
#: marker label and never a real library), and the one list that still restricts
#: when it comes from a file that may not grant.
GRANTS = {
    "project_name": "operator",
    "sandbox": {
        "extra_read_paths": ["/data"],
        "network_scanners": ["grype"],
        "read_path_scanners": ["zizmor"],
        "env_scanners": ["zizmor"],
        "environment": ["LD_PRELOAD=MARKER-not-a-real-library"],
    },
}


@pytest.fixture(autouse=True)
def _tmp_path_is_outside_every_checkout(tmp_path: Path, monkeypatch) -> None:
    assert not in_any_checkout(tmp_path), (
        f"{tmp_path} is inside a git checkout; run with --basetemp outside one"
    )
    monkeypatch.delenv("ASH_CONFIG", raising=False)


def _scene(tmp_path: Path):
    """A scanned checkout with its scanned directory, and the operator's file
    outside every checkout."""
    mark_git_checkout(tmp_path / "repo")
    source = tmp_path / "repo" / "app"
    source.mkdir(parents=True)
    config = tmp_path / "ops" / "gate" / "ash.yaml"
    config.parent.mkdir(parents=True)
    config.write_text(json.dumps(GRANTS), encoding="utf-8")
    assert not in_any_checkout(config)
    return source, config


def _resolved(selected: bool, monkeypatch, source: Path, config: Path):
    if selected:
        return resolve_config(config_path=config, source_dir=source)
    monkeypatch.setenv("ASH_CONFIG", str(config))
    return resolve_config(source_dir=source)


@pytest.mark.parametrize("selected", [True, False], ids=["selected", "ash-config"])
def test_a_root_whose_walk_did_not_finish_keeps_no_sandbox_grant_of_its_own(
    tmp_path, monkeypatch, selected
):
    source, config = _scene(tmp_path)
    refused = link_walk_cannot_examine(monkeypatch, config.parent)

    sandbox = _resolved(selected, monkeypatch, source, config).sandbox

    assert refused.asked > 0, "the walk never asked to look at the component"
    # The default, not the written list: the grant is taken away.
    assert sandbox.network_scanners == AshConfig().sandbox.network_scanners
    assert list(sandbox.extra_read_paths) == []
    assert list(sandbox.read_path_scanners) == []
    assert list(sandbox.env_scanners) == []
    # The environment list is taken away too, and the default list stands.
    assert list(sandbox.environment) == list(AshConfig().sandbox.environment)
    # What only restricts stays: the written list still narrows the network.
    assert sandbox.network_limit == ["grype"]


@pytest.mark.parametrize("selected", [True, False], ids=["selected", "ash-config"])
def test_a_root_whose_walk_did_not_finish_is_named_once_and_the_line_says_the_walk_stopped(
    tmp_path, monkeypatch, caplog, selected
):
    """The grants taken away are announced, and the file whose walk could not be
    decided gets one warning for it. The confinement warning already says the file
    is read as the repository's because its walk stopped and which settings it
    loses; the own-sandbox rule leaves the same file out for the same cause, so a
    second line for it only repeats that."""
    source, config = _scene(tmp_path)
    link_walk_cannot_examine(monkeypatch, config.parent)

    with caplog.at_level(logging.WARNING):
        _resolved(selected, monkeypatch, source, config)

    ignoring = [
        record.getMessage()
        for record in caplog.records
        if record.getMessage().startswith("Ignoring")
    ]
    undecided = [line for line in ignoring if "could not be decided" in line]
    assert len(undecided) == 1, caplog.text
    assert undecided[0].startswith("Ignoring sandbox."), undecided
    assert "resolving its name stopped before the walk finished" in undecided[0]
    assert not [line for line in ignoring if line.startswith("Ignoring the sandbox")]
    assert undecided[0].endswith(f"{LET_THE_WALK_FINISH}."), undecided


@pytest.mark.parametrize("selected", [True, False], ids=["selected", "ash-config"])
def test_the_one_line_for_a_root_with_an_unfinished_walk_ends_with_the_walks_remedy(
    tmp_path, monkeypatch, caplog, selected
):
    """The file sits outside every tree, so advice to move it out of the tree
    cannot help it. The one line the file gets ends with what would: letting the
    walk finish. The ending is compared whole, not counted, so a tail that still
    says the in-tree remedy is caught by what it says."""
    source, config = _scene(tmp_path)
    link_walk_cannot_examine(monkeypatch, config.parent)

    with caplog.at_level(logging.WARNING):
        _resolved(selected, monkeypatch, source, config)

    lines = [
        record.getMessage()
        for record in caplog.records
        if record.getMessage().startswith("Ignoring sandbox.")
        and config.name in record.getMessage()
    ]
    assert len(lines) == 1, caplog.text
    assert lines[0].endswith(f"{LET_THE_WALK_FINISH}."), lines
    assert "--config-overrides" in lines[0], lines
    assert "outside the tree" not in lines[0], lines
    assert "outside every git checkout" not in lines[0], lines


def test_the_remedy_names_each_way_a_walk_ends_without_an_answer(tmp_path, caplog):
    """A walk ends undecided at a directory it cannot search, at a link it cannot
    read, or at the bound on the links it follows. The first two are cured by
    making the path searchable and readable; the third only by naming the file
    through fewer links, and the line says so."""
    root = tmp_path / "ops" / "gate" / "operator-base.yaml"
    root.parent.mkdir(parents=True)
    root.write_text(json.dumps(GRANTS), encoding="utf-8")

    with caplog.at_level(logging.WARNING):
        _warn_dropped_own_sandbox(root, [tmp_path / "repo"], None, undecided=True)

    lines = [
        record.getMessage()
        for record in caplog.records
        if record.getMessage().startswith("Ignoring the sandbox settings")
        and root.name in record.getMessage()
    ]
    assert len(lines) == 1, caplog.text
    assert "searchable" in lines[0], lines
    assert "readable" in lines[0], lines
    assert "through fewer links" in lines[0], lines


@pytest.mark.parametrize("selected", [True, False], ids=["selected", "ash-config"])
def test_control_the_same_root_with_its_walk_finished_keeps_its_grants(
    tmp_path, monkeypatch, selected
):
    source, config = _scene(tmp_path)

    sandbox = _resolved(selected, monkeypatch, source, config).sandbox

    assert sandbox.network_scanners == ["grype"]
    assert list(sandbox.extra_read_paths) == ["/data"]
    assert list(sandbox.read_path_scanners) == ["zizmor"]
    assert list(sandbox.env_scanners) == ["zizmor"]
    assert list(sandbox.environment) == ["LD_PRELOAD=MARKER-not-a-real-library"]

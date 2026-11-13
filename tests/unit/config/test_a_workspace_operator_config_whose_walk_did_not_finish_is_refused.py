# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A workspace's operator config whose name walk did not finish is refused.

The operator config of a workspace is layered over each project's own config, so
every file it is built from has to be the operator's. A file is the repository's
when a scanned tree holds it or it is reached through a link inside one.
``sandbox_grants.tree_holding`` answers None both for a file no tree holds and
for one whose name walk stopped before the end without finding a tree, and the
refusal read only that answer, so a file the walk could not place was accepted as
the operator's while every other check of the load reads it as the repository's.
The refusal now names such a file and says to let the walk finish.

The walk is made unfinished for real: one directory component of the name is made
unjudgeable for the link walk's own ``lstat`` (the failure a parent that cannot be
searched gives), and every other path keeps the real ``lstat``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.confinement_remedy import LET_THE_WALK_FINISH
from automated_security_helper.config.resolve_config import check_operator_config
from automated_security_helper.config.sandbox_grants import (
    forget_unverifiable_warnings,
    in_any_checkout,
)
from automated_security_helper.core.exceptions import ASHConfigValidationError
from tests.utils.helpers import link_walk_cannot_examine, mark_git_checkout

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()


@pytest.fixture(autouse=True)
def _fresh_scene(tmp_path: Path, monkeypatch) -> None:
    assert not in_any_checkout(tmp_path), (
        f"{tmp_path} is inside a git checkout; run with --basetemp outside one"
    )
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    forget_unverifiable_warnings()
    yield
    forget_unverifiable_warnings()


def _scene(tmp_path: Path):
    """A workspace inside a checkout, and an operator config outside every
    checkout whose parent directory is the component the walk will not examine."""
    mark_git_checkout(tmp_path / "repo")
    workspace = tmp_path / "repo" / "app"
    workspace.mkdir(parents=True)
    config = tmp_path / "ops" / "gate" / "ash.yaml"
    config.parent.mkdir(parents=True)
    config.write_text("project_name: ops\n", encoding="utf-8")
    assert not in_any_checkout(config)
    return workspace, config


def test_an_operator_config_whose_walk_did_not_finish_is_refused(tmp_path, monkeypatch):
    workspace, config = _scene(tmp_path)
    refused = link_walk_cannot_examine(monkeypatch, config.parent)

    with pytest.raises(ASHConfigValidationError) as raised:
        check_operator_config(config, workspace)

    assert refused.asked > 0, "the walk never asked to look at the component"
    message = " ".join(str(raised.value).split())
    assert "could not be placed" in message, message
    assert LET_THE_WALK_FINISH in message, message


def test_control_an_operator_config_whose_walk_finished_is_accepted(tmp_path):
    workspace, config = _scene(tmp_path)

    check_operator_config(config, workspace)

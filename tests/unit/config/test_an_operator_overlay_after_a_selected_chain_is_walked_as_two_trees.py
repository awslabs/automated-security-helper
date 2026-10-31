# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A chain made of a selected config's chain and the operator's overlay chain
holds two ``extends`` trees, and the operator-chain walkers are told so.

``_resolve_config`` lays the overlay's files after the selected config's, each
chain one tree. ``_operator_chain_occurrences`` rebuilt the chain as one tree,
read the two roots as a chain that does not rebuild, warned that no file of it
is the operator's own, and the operator views (the sandbox-mode floor, the
reporters and scanners the operator's own files wrote) took nothing, the
overlay's own writes included. The walkers now take the count of roots from
the caller and walk each tree from its own root.

Red at the base: the two-root walk answered [] with the rebuild warning, and a
load with an overlay over a project config logged that warning.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest
import yaml

from automated_security_helper.config.resolve_config import (
    _operator_chain_occurrences,
    _owned_sandbox_mode,
    resolve_config,
)

pytestmark = pytest.mark.unit

_NOT_REBUILT = "could not be rebuilt"


@pytest.fixture(autouse=True)
def _no_ash_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.delenv("ASH_MCP_WORKSPACE_ROOT", raising=False)


def _two_root_chain(tmp_path: Path):
    """A selected config's one-file chain followed by an overlay's one-file
    chain, with each file's own document, as the load leaves them."""
    project = tmp_path / "repo" / ".ash" / ".ash.yaml"
    operator = tmp_path / "operator" / "ash.yaml"
    for file in (project, operator):
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text("project_name: x\n", encoding="utf-8")
    reads = {
        project.resolve(): {"project_name": "project"},
        operator.resolve(): {
            "project_name": "operator",
            "sandbox": {"mode": "firejail"},
        },
    }
    return project, operator, reads


def test_two_roots_named_are_walked_from_each_root(tmp_path, caplog) -> None:
    project, operator, reads = _two_root_chain(tmp_path)

    with caplog.at_level(logging.WARNING):
        taken = _operator_chain_occurrences(
            [project, operator], [project], reads, set(), roots=2
        )

    assert taken == [operator]
    assert not any(_NOT_REBUILT in r.getMessage() for r in caplog.records), caplog.text


def test_two_roots_read_as_one_tree_still_take_nothing_and_say_so(
    tmp_path, caplog
) -> None:
    """The control: a caller that names one root for a two-root chain keeps the
    rebuild refusal, which is what guards against a drifted walk."""
    project, operator, reads = _two_root_chain(tmp_path)

    with caplog.at_level(logging.WARNING):
        taken = _operator_chain_occurrences(
            [project, operator], [project], reads, set()
        )

    assert taken == []
    assert any(_NOT_REBUILT in r.getMessage() for r in caplog.records), caplog.text


def test_the_floor_reads_the_overlay_roots_own_mode(tmp_path) -> None:
    project, operator, reads = _two_root_chain(tmp_path)

    mode = _owned_sandbox_mode([project, operator], [project], reads, set(), roots=2)

    assert mode == "firejail"


def test_a_load_with_an_overlay_over_a_project_config_logs_no_rebuild_warning(
    tmp_path, caplog
) -> None:
    project = tmp_path / "repo" / ".ash" / ".ash.yaml"
    operator = tmp_path / "operator" / "ash.yaml"
    project.parent.mkdir(parents=True)
    operator.parent.mkdir(parents=True)
    project.write_text(yaml.safe_dump({"fail_on_findings": False}), encoding="utf-8")
    operator.write_text(yaml.safe_dump({"fail_on_findings": True}), encoding="utf-8")

    with caplog.at_level(logging.WARNING):
        config = resolve_config(
            config_path=project,
            source_dir=tmp_path / "repo",
            trusted_config_path=operator,
            overlay_config_path=operator,
        )

    assert config.fail_on_findings is True, "the premise: the overlay is final"
    assert not any(_NOT_REBUILT in r.getMessage() for r in caplog.records), caplog.text

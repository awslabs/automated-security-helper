# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A named config with a search_dir is judged for that target's tree.

``search_dir`` names the directory the caller's scan will target, and the
answer refuses exactly what a scan of that target refuses. A scan of the
target resolves a named config with the target as its source directory, so a
config inside the target may extend a base anywhere in the target
(``default_confinement_root``). The answer must apply the same root: judging
the file by its own directory instead would refuse an in-target base the
scan loads.

A named config outside the target keeps its own root, for the answer and for
the scan alike, so an extends past that root stays refused either way.
"""

import pytest

from automated_security_helper.cli import mcp_tools
from automated_security_helper.config.resolve_config import resolve_config


@pytest.fixture
def no_ambient_config(monkeypatch):
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.delenv("ASH_MCP_ALLOWED_ROOTS", raising=False)
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)


def _target_with_a_config_extending_its_root(tmp_path):
    target = tmp_path / "target"
    (target / "configs").mkdir(parents=True)
    (target / "base.yaml").write_text(
        "project_name: base-in-target\n", encoding="utf-8"
    )
    config = target / "configs" / "alt.yaml"
    config.write_text("extends: ../base.yaml\n", encoding="utf-8")
    return target, config


def test_a_named_file_extending_a_base_in_the_target_answers(
    tmp_path, no_ambient_config
):
    """The reviewer's divergence: a scan of the target loads this file, so
    the answer may not refuse it."""
    target, config = _target_with_a_config_extending_its_root(tmp_path)

    answer = mcp_tools.mcp_get_config(config_path=str(config), search_dir=str(target))

    assert answer.get("success") is not False, answer
    assert "error_type" not in answer, answer
    assert answer.get("project_name") == "base-in-target", answer


def test_the_scan_side_loads_the_same_chain(tmp_path, no_ambient_config):
    """Parity control: the scan's own resolution (named config, the target as
    its source directory) accepts the chain the answer must accept."""
    target, config = _target_with_a_config_extending_its_root(tmp_path)

    resolved = resolve_config(config_path=config, source_dir=target)

    assert resolved.project_name == "base-in-target"


def test_a_named_file_outside_the_target_keeps_its_own_root(
    tmp_path, no_ambient_config
):
    """Control: for a config outside the target the root stays the config's
    own directory, so an extends past it is refused with or without the
    target named -- as a scan with that named config refuses it."""
    target = tmp_path / "target"
    target.mkdir()
    outside = tmp_path / "configs-elsewhere"
    outside.mkdir()
    (tmp_path / "beyond.yaml").write_text(
        "project_name: beyond-the-root\n", encoding="utf-8"
    )
    config = outside / "cfg.yaml"
    config.write_text("extends: ../beyond.yaml\n", encoding="utf-8")

    answer = mcp_tools.mcp_get_config(config_path=str(config), search_dir=str(target))

    assert answer.get("success") is False, answer
    assert answer.get("error_type") == "config_input_not_permitted", answer
    assert "beyond-the-root" not in str(answer), answer


def test_without_a_search_dir_the_named_file_keeps_its_own_root(
    tmp_path, no_ambient_config
):
    """Control: the pre-existing named-file shape is unchanged -- no target
    named, so the file is judged by its own confinement root."""
    target, config = _target_with_a_config_extending_its_root(tmp_path)

    answer = mcp_tools.mcp_get_config(config_path=str(config))

    assert answer.get("success") is False, answer
    assert answer.get("error_type") == "config_input_not_permitted", answer

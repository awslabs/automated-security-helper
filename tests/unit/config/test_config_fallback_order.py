# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The config a scan uses when none is named, in the order the MCP reference gives.

``run_ash_scan``'s ``config_path`` note in ``scripts/generate_mcp_tool_reference.py``
says: the profile the session bound with ``select_profile``, else the config ASH
discovers in the source directory, else the file ``ASH_CONFIG`` names, else the
built-in defaults. The first step is the MCP tool's
(``test_profile_binding_takes_effect.py``); these pin the other three, which are
``resolve_config``'s.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.config.resolve_config import resolve_config

pytestmark = pytest.mark.unit


@pytest.fixture
def source(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    source = tmp_path / "source"
    source.mkdir()
    operator = tmp_path / "operator" / "ash.yaml"
    operator.parent.mkdir()
    operator.write_text("project_name: from-ash-config\n", encoding="utf-8")
    monkeypatch.setenv("ASH_CONFIG", str(operator))
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "workspaces"))
    return source


def test_a_discovered_config_comes_before_ash_config(source: Path) -> None:
    (source / ".ash").mkdir()
    (source / ".ash" / ".ash.yaml").write_text(
        "project_name: discovered\n", encoding="utf-8"
    )

    assert resolve_config(source_dir=source).project_name == "discovered"


def test_ash_config_comes_before_the_defaults(source: Path) -> None:
    assert resolve_config(source_dir=source).project_name == "from-ash-config"


def test_the_defaults_come_last(source: Path, monkeypatch) -> None:
    """Discovery reads the source directory only, never a parent's config."""
    from automated_security_helper.config.ash_config import AshConfig

    monkeypatch.delenv("ASH_CONFIG")
    (source.parent / ".ash").mkdir()
    (source.parent / ".ash" / ".ash.yaml").write_text(
        "project_name: parent\n", encoding="utf-8"
    )

    assert resolve_config(source_dir=source).project_name == AshConfig().project_name

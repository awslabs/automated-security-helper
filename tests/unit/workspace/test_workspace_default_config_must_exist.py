# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A workspace's default config (``--config``, an MCP profile) must exist when named.

It is the config of a project that declares none, and the trusted base the sandbox
grants of every project's in-tree config come from, so a missing one is refused
even when every project has its own config. ``ash scan --workspace`` passes
``--config`` to planning, so the refusal is exit 3 at planning, ``--dry-run``
included.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.core.exceptions import ASHConfigValidationError
from automated_security_helper.workspace.resolver import resolve_workspace


@pytest.fixture(autouse=True)
def _no_ash_config_variable(monkeypatch):
    monkeypatch.delenv("ASH_CONFIG", raising=False)


def _workspace(root: Path, *keys: str, with_own_config: bool = False) -> Path:
    for key in keys:
        (root / key).mkdir(parents=True, exist_ok=True)
        if with_own_config:
            (root / key / ".ash.yaml").write_text(
                f"project_name: {key}\n", encoding="utf-8"
            )
    path = root / "team.code-workspace"
    path.write_text(
        json.dumps({"folders": [{"path": key} for key in keys]}), encoding="utf-8"
    )
    return path


def test_a_missing_default_config_is_refused_when_every_project_has_its_own(
    tmp_path,
):
    workspace = _workspace(tmp_path, "api", "web", with_own_config=True)

    with pytest.raises(ASHConfigValidationError, match="profile.yaml"):
        resolve_workspace(workspace, default_config=tmp_path / "profile.yaml")


def test_control_an_existing_default_config_is_accepted(tmp_path):
    # The operator's default config outside the workspace root: one inside it is
    # not the operator's, and is refused for that.
    workspace = _workspace(tmp_path / "ws", "api", with_own_config=True)
    profile = tmp_path / "ops" / "profile.yaml"
    profile.parent.mkdir()
    profile.write_text("project_name: profile\n", encoding="utf-8")

    plan = resolve_workspace(workspace, default_config=profile)

    assert [p.key for p in plan.projects] == ["api"]


@pytest.mark.parametrize(
    "config",
    [pytest.param("missing.yaml", id="missing"), pytest.param("", id="empty")],
)
def test_dry_run_refuses_a_config_option_that_does_not_name_a_file(
    tmp_path, monkeypatch, config
):
    monkeypatch.chdir(tmp_path)
    _workspace(tmp_path, "api", with_own_config=True)

    result = CliRunner().invoke(
        app,
        [
            "scan",
            "--no-progress",
            "--workspace",
            str(tmp_path / "team.code-workspace"),
            "--output-dir",
            str(tmp_path / "out"),
            "--config",
            config,
            "--dry-run",
        ],
    )

    assert result.exit_code == 3, result.output[-2000:]

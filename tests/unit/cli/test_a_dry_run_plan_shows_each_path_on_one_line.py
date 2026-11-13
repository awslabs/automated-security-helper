# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The plan ``ash scan --workspace ... --dry-run`` prints keeps each path on one line.

The plan's lines name the workspace file, its root, its policy file, each
project's folder and the config file each project is scanned with. Each is the
caller's text, or the tree's, so each line of the plan is shown on one line, a
newline in a path written as ``\\x0a``.
"""

from __future__ import annotations

import json
import sys

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(
        sys.platform == "win32", reason="Windows file names hold no newline"
    ),
]


@pytest.fixture(autouse=True)
def _here(tmp_path, monkeypatch):
    for name in ("ASH_SOURCE_DIR", "ASH_OUTPUT_DIR", "ASH_CONFIG", "ASH_WORKSPACE"):
        monkeypatch.delenv(name, raising=False)
    # A console this wide wraps no line of the plan, so a line that starts with
    # a path's rest started there because of the newline.
    monkeypatch.setenv("COLUMNS", "400")
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.chdir(tmp_path)


def _workspace(root) -> str:
    (root / "api").mkdir(parents=True)
    workspace = root / "dev.code-workspace"
    workspace.write_text(json.dumps({"folders": [{"path": "api"}]}), encoding="utf-8")
    return str(workspace)


def _assert_kept_whole(output: str, tails) -> None:
    starts = [line for line in output.splitlines() if line.startswith(tuple(tails))]
    assert starts == [], f"a path's rest began a line of its own:\n{output}"
    assert "\\\\x0a" not in output, f"a newline was shown twice:\n{output}"


def test_a_config_with_a_newline_in_its_name_is_named_on_one_line(tmp_path):
    """The config of a project that declares none, from --config: the plan's
    "config:" line."""
    shared = tmp_path / "b\nshared.yaml"
    shared.write_text("project_name: t\n", encoding="utf-8")

    result = CliRunner().invoke(
        app,
        [
            "scan",
            "--workspace",
            _workspace(tmp_path / "ws"),
            "--config",
            str(shared),
            "--dry-run",
        ],
    )

    assert result.exit_code == 0, result.output
    _assert_kept_whole(result.output, ["shared.yaml"])
    config_lines = [
        line
        for line in result.output.splitlines()
        if line.lstrip().startswith("config:")
    ]
    assert len(config_lines) == 1, result.output
    assert config_lines[0].endswith("\\x0ashared.yaml"), config_lines


def test_a_root_with_a_newline_in_its_name_is_named_on_one_line(tmp_path):
    """The workspace file, the root, the policy file, the project's folder and
    its config all name the root."""
    root = tmp_path / "a\nroot"
    workspace = _workspace(root)
    (root / "api" / ".ash").mkdir()
    (root / "api" / ".ash" / ".ash.yaml").write_text(
        "project_name: api\n", encoding="utf-8"
    )
    (root / "ash-workspace.yaml").write_text(
        "workspace:\n  max_severity_threshold: HIGH\n", encoding="utf-8"
    )

    result = CliRunner().invoke(app, ["scan", "--workspace", workspace, "--dry-run"])

    assert result.exit_code == 0, result.output
    _assert_kept_whole(result.output, ["root"])
    shown = [
        line.split()[0]
        for line in result.output.splitlines()
        if "\\x0aroot" in line and line.strip()
    ]
    assert {"file:", "root:", "policy:", "path:", "config:"} <= set(shown), (
        result.output
    )

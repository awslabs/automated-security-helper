# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A container that exits 2 without a results file is reported as a usage error.

The scan inside the container is the ASH CLI. It exits 2 for findings only after it
has written its results file, and for a usage error (Click's code) without one. An
image built from an older ASH than the host's gives that usage error for an option
the host's ASH passes it, such as ``--config-from-scanned-repository``, which the
host adds for a config elsewhere in the scanned checkout. The host then refuses with
exit 3 and says to rebuild the image from this ASH, rather than ending at "Results
file not found" with exit 1.
"""

from __future__ import annotations

from typing import Any, Dict

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.interactions import run_ash_container as rac
from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.subprocess_utils import create_completed_process

FLAG = rac.CONFIG_FROM_SCANNED_REPOSITORY_FLAG


@pytest.fixture(autouse=True)
def _no_real_runner(monkeypatch):
    def refuse(cmd_list, check=True, debug=False, shell=False, env=None):
        raise AssertionError(f"a real runner command was attempted: {cmd_list}")

    monkeypatch.setattr(rac, "run_cmd_direct", refuse)


@pytest.fixture
def container(monkeypatch, tmp_path) -> Dict[str, Any]:
    """The scan inside exits with ``seen['returncode']`` and writes nothing."""
    monkeypatch.chdir(tmp_path)
    seen: Dict[str, Any] = {"returncode": 2, "runs": []}

    monkeypatch.setattr(subprocess_utils, "get_host_uid", lambda: 1000)
    monkeypatch.setattr(subprocess_utils, "get_host_gid", lambda: 1000)
    monkeypatch.setattr(
        rac, "_find_runner", lambda _name: "/nonexistent/ash-test/docker"
    )

    def fake_execute(cmd, debug=False):
        seen["runs"].append(list(cmd))
        return create_completed_process(
            args=list(cmd), returncode=seen["returncode"], stderr="Usage: ash ...\n"
        )

    monkeypatch.setattr(rac, "_execute_container", fake_execute)
    for name in ("CI", "IsCI", "ISCI", "CODEBUILD_BUILD_ID", "ASH_IMAGE_NAME"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    return seen


def _scan(*args: str):
    return CliRunner().invoke(
        app, ["scan", "--mode", "container", "--no-build", "--no-progress", *args]
    )


def test_the_mark_an_older_image_does_not_know(container, tmp_path):
    checkout = tmp_path / "repo"
    (checkout / ".git").mkdir(parents=True)
    (checkout / "svc").mkdir()
    (checkout / "ci").mkdir()
    config = checkout / "ci" / "ash.yaml"
    config.write_text("project_name: p\n", encoding="utf-8")

    result = _scan(
        "--source-dir",
        str(checkout / "svc"),
        "--output-dir",
        str(tmp_path / "out"),
        "--config",
        str(config),
    )

    [run] = container["runs"]
    assert FLAG in run
    assert result.exit_code == 3, result.output
    assert "Rebuild the image from this ASH" in result.output
    assert FLAG in result.output
    assert "Results file not found" not in result.output


def test_any_other_usage_error_inside(container, tmp_path):
    (tmp_path / "src").mkdir()

    result = _scan("--source-dir", "src", "--output-dir", str(tmp_path / "out"))

    assert result.exit_code == 3, result.output
    assert "Rebuild the image from this ASH" in result.output
    assert "Results file not found" not in result.output


def test_success_without_results_is_unchanged(container, tmp_path):
    """Control: exit 0 with no results file is still the missing-results error."""
    container["returncode"] = 0
    (tmp_path / "src").mkdir()

    result = _scan("--source-dir", "src", "--output-dir", str(tmp_path / "out"))

    assert result.exit_code == 1, result.output
    assert "Results file not found" in result.output

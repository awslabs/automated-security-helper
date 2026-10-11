# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""In a container scan, a chain file of the scanned checkout extends only files in it.

An operator's config kept outside the source directory may extend a file elsewhere
in the scanned checkout (a shared ``ci/ash.yaml``, say); the scan inside is then
told the merged config is the repository's (``--config-from-scanned-repository``).
That base may extend other files of the checkout. One whose ``extends`` entry
leads out of the checkout refuses the run with exit 3 before anything is built or
run, and the message names the base and the file it extends. A base inside the
source directory itself is refused whatever it extends
(test_container_config_chain_base_in_the_source.py).
"""

from __future__ import annotations

from pathlib import Path
from typing import List

import pytest

from automated_security_helper.interactions import run_ash_container as rac
from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.subprocess_utils import create_completed_process


@pytest.fixture(autouse=True)
def _no_real_runner(monkeypatch):
    def refuse(cmd_list, check=True, debug=False, shell=False):
        raise AssertionError(f"a real runner command was attempted: {cmd_list}")

    monkeypatch.setattr(rac, "run_cmd_direct", refuse)


@pytest.fixture
def commands(monkeypatch) -> List[List[str]]:
    seen: List[List[str]] = []

    def record(cmd_list, check=True, debug=False, shell=False):
        cmd = [str(item) for item in cmd_list if item is not None]
        seen.append(cmd)
        return create_completed_process(args=cmd, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(subprocess_utils, "get_host_uid", lambda: 1000)
    monkeypatch.setattr(subprocess_utils, "get_host_gid", lambda: 1000)
    monkeypatch.setattr(
        rac, "_find_runner", lambda _name: "/nonexistent/ash-test/docker"
    )
    monkeypatch.setattr(rac, "_runner_supports_buildx", lambda _runner: False)
    monkeypatch.setattr(rac, "run_cmd_direct", record)
    for name in ("CI", "ASH_IMAGE_NAME", "ASH_CONFIG", "OCI_RUNNER_WRAPPER"):
        monkeypatch.delenv(name, raising=False)
    return seen


@pytest.fixture
def layout(tmp_path, monkeypatch):
    """An operator directory holding a checkout whose scan root is ``repo/src``."""
    operator = tmp_path / "operator"
    repo = operator / "repo"
    (repo / ".git").mkdir(parents=True)
    (repo / "src").mkdir(parents=True)
    (repo / "ci").mkdir()
    (operator / "settings").mkdir()
    (operator / "settings" / "shared.yaml").write_text(
        "project_name: p\n", encoding="utf-8"
    )
    config = operator / "ash.yaml"
    config.write_text("extends: repo/ci/ash.yaml\n", encoding="utf-8")
    monkeypatch.chdir(operator)
    return {"operator": operator, "repo": repo, "config": config}


def _run(config: Path):
    return rac.run_ash_container(
        source_dir="repo/src", output_dir="out", config=str(config), build=False
    )


def test_a_repository_base_extending_a_file_outside_the_tree_is_refused(
    layout, commands
):
    base = layout["repo"] / "ci" / "ash.yaml"
    base.write_text("extends: ../../settings/shared.yaml\n", encoding="utf-8")

    result = _run(layout["config"])

    assert commands == [], f"a runner command was started: {commands}"
    assert result.returncode == 3
    assert not rac.container_was_started(result)
    assert str(base.resolve()) in result.stderr
    assert str((layout["operator"] / "settings" / "shared.yaml").resolve()) in (
        result.stderr
    )


def test_a_repository_base_extending_a_file_in_the_tree_still_runs(layout, commands):
    """Control: the repository's files may extend each other."""
    (layout["repo"] / "ci" / "common.yaml").write_text(
        "project_name: p\n", encoding="utf-8"
    )
    (layout["repo"] / "ci" / "ash.yaml").write_text(
        "extends: common.yaml\n", encoding="utf-8"
    )

    result = _run(layout["config"])

    assert result.returncode == 0, result.stderr
    [run] = commands
    assert rac.CONFIG_FROM_SCANNED_REPOSITORY_FLAG in run


def test_an_operator_base_may_extend_another_operator_file(layout, commands):
    """Control: only files the repository wrote are held to its tree."""
    (layout["operator"] / "common.yaml").write_text(
        "project_name: p\n", encoding="utf-8"
    )
    (layout["operator"] / "team.yaml").write_text(
        "extends: common.yaml\n", encoding="utf-8"
    )
    layout["config"].write_text("extends: team.yaml\n", encoding="utf-8")

    result = _run(layout["config"])

    assert result.returncode == 0, result.stderr

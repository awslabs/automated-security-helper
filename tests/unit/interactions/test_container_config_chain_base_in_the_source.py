# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A container scan refuses a config kept outside the source directory that extends a
file inside it.

Container mode mounts each file of a config's ``extends`` chain, read-only, where
the scan inside looks for it. A config kept outside the source directory has its
chain mounted from under that config's own directory
(``config_sources.default_confinement_root``); a config inside the source directory
has its chain read through ``/src``. A chain that starts outside the source
directory and has a base inside it is refused with exit 3 before anything is built
or run, and the message names the base.
"""

from __future__ import annotations

from pathlib import Path
from typing import List

import pytest

from automated_security_helper.interactions import run_ash_container as rac
from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.subprocess_utils import create_completed_process
from tests.utils.helpers import mark_git_checkout


@pytest.fixture(autouse=True)
def _no_real_runner(monkeypatch):
    def refuse(cmd_list, check=True, debug=False, shell=False):
        raise AssertionError(f"a real runner command was attempted: {cmd_list}")

    monkeypatch.setattr(rac, "run_cmd_direct", refuse)


@pytest.fixture
def commands(monkeypatch, tmp_path) -> List[List[str]]:
    seen: List[List[str]] = []

    def record(cmd_list, check=True, debug=False, shell=False, env=None):
        cmd = [str(item) for item in cmd_list if item is not None]
        seen.append(cmd)
        return create_completed_process(args=cmd, returncode=0, stdout="", stderr="")

    assets = tmp_path / "assets"
    assets.mkdir()
    (assets / "Dockerfile").write_text("FROM scratch AS non-root\n", encoding="utf-8")
    monkeypatch.setattr(rac, "ASH_ASSETS_DIR", assets)
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
    mark_git_checkout(repo)
    (repo / "src" / ".ash").mkdir(parents=True)
    (operator / "operator-only.yaml").write_text("project_name: p\n", encoding="utf-8")
    monkeypatch.chdir(operator)
    return {"operator": operator, "repo": repo, "source": repo / "src"}


def _run(config: Path, build: bool):
    return rac.run_ash_container(
        source_dir="repo/src",
        output_dir="out",
        config=str(config),
        ash_revision_to_install="v3.7.0",
        build=build,
        run=True,
    )


def _refused(result, commands, base: Path) -> None:
    assert commands == [], f"a runner command was started: {commands}"
    assert result.returncode == 3
    assert not rac.container_was_started(result)
    assert str(base.resolve()) in result.stderr


@pytest.mark.parametrize("build", [True, False], ids=["build", "no-build"])
def test_a_base_inside_the_source_directory_is_refused(build, layout, commands):
    base = layout["source"] / ".ash" / "base.yaml"
    base.write_text("extends: ../../../operator-only.yaml\n", encoding="utf-8")
    config = layout["operator"] / "ash.yaml"
    config.write_text("extends: repo/src/.ash/base.yaml\n", encoding="utf-8")

    result = _run(config, build=build)

    _refused(result, commands, base)


def test_a_base_inside_the_source_directory_further_down_is_refused(layout, commands):
    base = layout["source"] / "base.yaml"
    base.write_text("project_name: p\n", encoding="utf-8")
    (layout["operator"] / "team.yaml").write_text(
        "extends: repo/src/base.yaml\n", encoding="utf-8"
    )
    config = layout["operator"] / "ash.yaml"
    config.write_text("extends: team.yaml\n", encoding="utf-8")

    result = _run(config, build=False)

    _refused(result, commands, base)


def test_the_library_entry_point_refuses_it_too(layout):
    """``_assemble_run_command`` is what ``run_ash_container`` builds the run with."""
    base = layout["source"] / "base.yaml"
    base.write_text("project_name: p\n", encoding="utf-8")
    config = layout["operator"] / "ash.yaml"
    config.write_text("extends: repo/src/base.yaml\n", encoding="utf-8")

    with pytest.raises(rac.ContainerInputError, match="base.yaml"):
        rac._host_file_in_container(
            str(config),
            layout["source"].resolve(),
            rac.CONTAINER_CONFIG_ROOT,
            follow_extends=True,
        )


def test_an_operator_chain_outside_the_source_still_runs(layout, commands):
    """Control: every file of the chain is the operator's."""
    (layout["operator"] / "base.yaml").write_text("project_name: p\n", encoding="utf-8")
    config = layout["operator"] / "ash.yaml"
    config.write_text("extends: base.yaml\n", encoding="utf-8")

    result = _run(config, build=False)

    assert result.returncode == 0, result.stderr
    assert [cmd[1] for cmd in commands] == ["run"]


def test_a_config_inside_the_source_extending_a_base_there_still_runs(layout, commands):
    """Control: the chain is read through /src and nothing else is mounted."""
    (layout["source"] / ".ash" / "base.yaml").write_text(
        "project_name: p\n", encoding="utf-8"
    )
    config = layout["source"] / ".ash" / "ash.yaml"
    config.write_text("extends: base.yaml\n", encoding="utf-8")

    result = _run(config, build=False)

    assert result.returncode == 0, result.stderr
    run = commands[0]
    assert run[run.index("--config") + 1] == "/src/.ash/ash.yaml"

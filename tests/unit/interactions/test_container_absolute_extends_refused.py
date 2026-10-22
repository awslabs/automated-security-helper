# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An absolute ``extends`` path in a container scan's config refuses the run with exit 3.

The files of a config's ``extends`` chain are mounted into the container at their
place relative to the config, so a relative base resolves inside as it does on the
host. An absolute base names a host path, and inside the container that path is
either missing, which fails the scan there with an error about a file the operator
can see, or, worse, another file that happens to be at the same path in the image.
So the host refuses it before anything is built or run, naming the file and the
entry, wherever the config is.
"""

from __future__ import annotations

from typing import List

import pytest

from automated_security_helper.interactions import run_ash_container as rac
from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.subprocess_utils import create_completed_process


@pytest.fixture(autouse=True)
def _no_real_runner(monkeypatch):
    def refuse(cmd_list, check=True, debug=False, shell=False, env=None):
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
    (tmp_path / "src" / ".ash").mkdir(parents=True)
    (tmp_path / "operator").mkdir()
    monkeypatch.chdir(tmp_path)
    return seen


def _run(config, build: bool = True):
    return rac.run_ash_container(
        source_dir="src",
        output_dir="out",
        config=str(config),
        ash_revision_to_install="v3.7.0",
        build=build,
        run=True,
    )


@pytest.mark.parametrize("where", ["operator", "src/.ash"])
@pytest.mark.parametrize("build", [True, False], ids=["build", "no-build"])
def test_an_absolute_base_is_refused_before_anything_runs(
    where, build, commands, tmp_path
):
    base = (tmp_path / where / "base.yaml").resolve()
    base.write_text("project_name: p\n", encoding="utf-8")
    config = tmp_path / where / "ash.yaml"
    config.write_text(f"extends: {base}\n", encoding="utf-8")

    result = _run(config, build=build)

    assert commands == [], f"a runner command was started: {commands}"
    assert result.returncode == 3
    assert not rac.container_was_started(result)
    assert str(base) in result.stderr
    assert "extends" in result.stderr


def test_an_absolute_base_further_down_the_chain_is_refused(commands, tmp_path):
    operator = tmp_path / "operator"
    common = (operator / "common.yaml").resolve()
    common.write_text("project_name: p\n", encoding="utf-8")
    (operator / "team.yaml").write_text(f"extends: [{common}]\n", encoding="utf-8")
    config = operator / "ash.yaml"
    config.write_text("extends: team.yaml\n", encoding="utf-8")

    result = _run(config)

    assert commands == []
    assert result.returncode == 3
    assert "team.yaml" in result.stderr


def test_a_relative_chain_still_runs(commands, tmp_path):
    """Control."""
    operator = tmp_path / "operator"
    (operator / "base.yaml").write_text("project_name: p\n", encoding="utf-8")
    config = operator / "ash.yaml"
    config.write_text("extends: base.yaml\n", encoding="utf-8")

    result = _run(config, build=False)

    assert result.returncode == 0
    assert [cmd[1] for cmd in commands] == ["run"]

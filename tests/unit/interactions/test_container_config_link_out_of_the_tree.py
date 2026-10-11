# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A ``--config`` the scanned repository points out of its tree is never mounted.

A run that names a config inside the repository (``--config .ash/x.yaml``, as CI
jobs do) trusts the repository to say what that path is. If the repository made it
a symbolic link -- the file itself, or a directory on the way to it -- to a file
outside the scanned tree, resolving the link and mounting its target puts that
host file, say ``~/.docker/config.json`` with a registry token, inside a container
that runs the repository's own code. So a config path that is inside the scanned
tree as named but outside it once resolved refuses the run with exit 3, before
anything is built or run, and so does a config file ASH itself cannot read: the
runner mounts with its own rights, which can be wider.
"""

from __future__ import annotations

import os
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
def commands(monkeypatch, tmp_path) -> List[List[str]]:
    seen: List[List[str]] = []

    def record(cmd_list, check=True, debug=False, shell=False):
        cmd = [str(item) for item in cmd_list if item is not None]
        seen.append(cmd)
        return create_completed_process(args=cmd, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(subprocess_utils, "get_host_uid", lambda: 1000)
    monkeypatch.setattr(subprocess_utils, "get_host_gid", lambda: 1000)
    monkeypatch.setattr(rac, "_find_runner", lambda _name: "/usr/bin/docker")
    monkeypatch.setattr(rac, "_runner_supports_buildx", lambda _runner: False)
    monkeypatch.setattr(rac, "run_cmd_direct", record)
    for name in ("CI", "ASH_IMAGE_NAME", "ASH_CONFIG", "OCI_RUNNER_WRAPPER"):
        monkeypatch.delenv(name, raising=False)
    return seen


@pytest.fixture
def layout(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    (repo / ".ash").mkdir()
    (repo / "src").mkdir()
    secret = tmp_path / "home" / ".docker" / "config.json"
    secret.parent.mkdir(parents=True)
    secret.write_text('{"auths": {"registry.example": {"auth": "dXNlcjp0b2tlbg=="}}}')
    monkeypatch.chdir(repo)
    return {"repo": repo, "secret": secret}


def _run(source: str, config: str):
    return rac.run_ash_container(
        source_dir=source, output_dir="out", config=config, build=False, run=True
    )


def _refused(result, commands) -> None:
    assert commands == [], f"a runner command was started: {commands}"
    assert result.returncode == 3
    assert not rac.container_was_started(result)


@pytest.mark.parametrize("source", [".", "src"], ids=["source-is-repo", "subdir"])
def test_a_config_linked_out_of_the_tree_is_refused(source, layout, commands):
    (layout["repo"] / ".ash" / ".ash.yaml").symlink_to(layout["secret"])

    result = _run(source, ".ash/.ash.yaml")

    _refused(result, commands)
    assert "link" in result.stderr


def test_a_directory_linked_out_of_the_tree_is_refused(layout, commands):
    (layout["repo"] / "conf").symlink_to(
        layout["secret"].parent, target_is_directory=True
    )

    result = _run(".", "conf/config.json")

    _refused(result, commands)


def test_a_link_inside_the_tree_to_a_file_inside_it_still_runs(layout, commands):
    """Control: both ends are the repository's."""
    (layout["repo"] / ".ash" / "real.yaml").write_text("project_name: p\n")
    (layout["repo"] / ".ash" / ".ash.yaml").symlink_to("real.yaml")

    result = _run(".", ".ash/.ash.yaml")

    assert result.returncode == 0
    run = commands[0]
    assert run[run.index("--config") + 1] == "/src/.ash/real.yaml"


def test_an_operator_link_outside_the_tree_still_runs(layout, commands, tmp_path):
    """Control: a link the operator made, outside the tree, is followed."""
    real = tmp_path / "etc-ash" / "ash.yaml"
    real.parent.mkdir()
    real.write_text("project_name: p\n")
    link = tmp_path / "ash.yaml"
    link.symlink_to(real)

    result = _run(".", str(link))

    assert result.returncode == 0


@pytest.mark.skipif(
    os.name == "nt" or os.geteuid() == 0,
    reason="POSIX file modes that root ignores: the test needs a file it cannot read",
)
def test_a_config_ash_cannot_read_is_refused(layout, commands, tmp_path):
    unreadable = tmp_path / "operator.yaml"
    unreadable.write_text("project_name: p\n")
    unreadable.chmod(0)
    try:
        result = _run(".", str(unreadable))
    finally:
        unreadable.chmod(0o600)

    _refused(result, commands)
    assert "read" in result.stderr

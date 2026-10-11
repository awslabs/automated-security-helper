# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A path the runner's ``--mount`` syntax cannot carry refuses the run with exit 3.

``--mount type=bind,source=<path>,destination=<path>,readonly`` is a list of
comma-separated ``key=value`` fields, read as CSV. A comma in a host path ends its
field early and starts another, so a source directory named ``a,b`` is read as
``a`` and a field ``b``. A double quote starts CSV quoting, and a line break ends
the argument for runners that read it a line at a time. So every path that
becomes a mount -- the source directory, the output directory, the config file
and its ``extends`` chain, and a workspace policy -- is checked first, and one
holding a comma, a double quote, a carriage return or a line feed is refused with
exit 3 before anything is built or run.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

import pytest

from automated_security_helper.core.enums import ExecutionPhase, ExecutionStrategy
from automated_security_helper.interactions import run_ash_container as rac
from automated_security_helper.interactions.run_ash_container import (
    _assemble_run_command,
)
from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.subprocess_utils import create_completed_process

#: Each character the mount syntax cannot carry, in a directory name.
UNREPRESENTABLE = [
    pytest.param("a,b", id="comma"),
    pytest.param('x"y', id="double-quote"),
    pytest.param("x\ny", id="line-feed"),
    pytest.param("x\ry", id="carriage-return"),
]


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
    monkeypatch.chdir(tmp_path)
    return seen


def _refused(result) -> None:
    assert result.returncode == 3
    assert not rac.container_was_started(result)
    assert "--mount" in result.stderr


@pytest.mark.parametrize("name", UNREPRESENTABLE)
@pytest.mark.parametrize("build", [True, False], ids=["build", "no-build"])
def test_a_source_directory_the_mount_cannot_carry_is_refused(
    name, build, commands, tmp_path
):
    source = tmp_path / name
    source.mkdir()

    result = rac.run_ash_container(
        source_dir=str(source),
        output_dir=str(tmp_path / "out"),
        ash_revision_to_install="v3.7.0",
        build=build,
        run=True,
    )

    assert commands == [], f"a runner command was started: {commands}"
    _refused(result)


@pytest.mark.parametrize("name", UNREPRESENTABLE)
def test_an_output_directory_the_mount_cannot_carry_is_refused(
    name, commands, tmp_path
):
    (tmp_path / "src").mkdir()

    result = rac.run_ash_container(
        source_dir="src", output_dir=str(tmp_path / name), build=False, run=True
    )

    assert commands == []
    _refused(result)


@pytest.mark.parametrize("name", UNREPRESENTABLE)
def test_a_config_file_the_mount_cannot_carry_is_refused(name, commands, tmp_path):
    (tmp_path / "src").mkdir()
    holder = tmp_path / name
    holder.mkdir()
    config = holder / "ash.yaml"
    config.write_text("project_name: p\n", encoding="utf-8")

    result = rac.run_ash_container(
        source_dir="src",
        output_dir="out",
        config=str(config),
        build=False,
        run=True,
    )

    assert commands == []
    _refused(result)


def test_a_base_in_the_config_chain_the_mount_cannot_carry_is_refused(
    commands, tmp_path
):
    (tmp_path / "src").mkdir()
    operator = tmp_path / "operator"
    (operator / "a,b").mkdir(parents=True)
    (operator / "a,b" / "base.yaml").write_text("project_name: p\n", encoding="utf-8")
    config = operator / "ash.yaml"
    config.write_text("extends: a,b/base.yaml\n", encoding="utf-8")

    result = rac.run_ash_container(
        source_dir="src", output_dir="out", config=str(config), build=False, run=True
    )

    assert commands == []
    _refused(result)


def test_ordinary_paths_still_run(commands, tmp_path):
    """Control: spaces and other punctuation are carried as they are."""
    source = tmp_path / "with space; and (parens) & 'single quotes'"
    source.mkdir()

    result = rac.run_ash_container(
        source_dir=str(source), output_dir=str(tmp_path / "out"), build=False, run=True
    )

    assert result.returncode == 0
    assert [cmd[1] for cmd in commands] == ["run"]


def _assemble(source_dir: Path, output_dir: Path, **overrides: Any) -> List[str]:
    kwargs: Dict[str, Any] = {
        "oci_command_prefix": [],
        "resolved_oci_runner": "/usr/bin/docker",
        "image_name": "automated-security-helper:non-root",
        "source_dir": source_dir,
        "output_dir": output_dir,
        "offline": False,
        "debug": False,
        "color": False,
        "quiet": True,
        "progress": False,
        "verbose": False,
        "simple": True,
        "python_based_plugins_only": False,
        "cleanup": False,
        "inspect": False,
        "fail_on_findings": None,
        "phases": [ExecutionPhase.SCAN],
        "scanners": [],
        "exclude_scanners": [],
        "output_formats": [],
        "config": None,
        "config_overrides": [],
        "existing_results": None,
        "ash_plugin_modules": [],
        "strategy": ExecutionStrategy.PARALLEL,
        "ctx": None,
    }
    kwargs.update(overrides)
    return _assemble_run_command(**kwargs)


@pytest.mark.parametrize("name", UNREPRESENTABLE)
def test_the_command_builder_itself_refuses_such_a_path(name, tmp_path):
    """Defense in depth for callers that build the command directly."""
    with pytest.raises(ValueError, match="--mount"):
        _assemble(tmp_path / name, tmp_path / "out")

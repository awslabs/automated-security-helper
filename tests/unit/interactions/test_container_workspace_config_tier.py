# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A workspace scan in container mode refuses a config it cannot mark.

A one-directory container scan mounts a config from outside ``--source-dir`` at
``/ash-config`` and, when a local scan would count it as repository-written (it is
in a git checkout, or reached through the scanned tree), passes
``--config-from-scanned-repository`` so the scan inside limits it. A workspace scan
inside the container refuses that flag: it applies only to a single-directory scan.
So in workspace mode the host had no way to hand the verdict over, and passed the
config unmarked. The scan inside, which sees ``/ash-config`` in no checkout, then
gave it the operator's grants (``sandbox.extra_read_paths`` and the rest).

Container mode now refuses such a config in workspace mode with exit 3, before
anything is built, mounted or cleared: exactly the configs a one-directory scan
would mark, judged by the files it would mount (a file it extends stays inside the
config's own directory, so none of its bases can be in a checkout the config is
not in; ``config_sources.default_confinement_root``). A config inside the
workspace root is read through ``/src`` and judged by the scan inside, as before,
and one outside every checkout is the operator's.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import List

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.interactions import run_ash_container as rac
from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.subprocess_utils import create_completed_process

GRANT = "project_name: tier\nsandbox:\n  extra_read_paths:\n    - /opt/tier-grant\n"
FIX = "Keep --config outside the checkout, or inside the workspace"


@pytest.fixture
def commands(monkeypatch, tmp_path) -> List[List[str]]:
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
    monkeypatch.chdir(tmp_path)
    return seen


@pytest.fixture
def checkout(tmp_path) -> Path:
    """A git checkout whose ``ws`` directory is a workspace with one project."""
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    project = repo / "ws" / "proj"
    project.mkdir(parents=True)
    (project / "a.py").write_text("x = 1\n", encoding="utf-8")
    (repo / "ws" / "ash.code-workspace").write_text(
        json.dumps({"folders": [{"path": "proj"}]}), encoding="utf-8"
    )
    return repo


def _config(path: Path, text: str = GRANT) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _workspace_run(checkout: Path, config: Path, tmp_path: Path, **kwargs):
    return rac.run_ash_container(
        source_dir=str(checkout / "ws"),
        output_dir=str(tmp_path / "out"),
        config=str(config),
        workspace_relative_file="ash.code-workspace",
        build=False,
        run=True,
        **kwargs,
    )


def _run_command(commands: List[List[str]]) -> List[str]:
    (run,) = [cmd for cmd in commands if cmd[1] == "run"]
    return run


@pytest.mark.parametrize(
    "where",
    [
        "the-config-in-the-checkout-outside-the-workspace",
        "the-config-in-another-checkout",
        "a-link-outside-the-checkout-to-a-config-in-it",
    ],
)
def test_a_config_the_repository_could_have_written_is_refused(
    where, checkout, commands, tmp_path
):
    if where == "the-config-in-the-checkout-outside-the-workspace":
        config = _config(checkout / "other" / "ash-config.yaml")
    elif where == "the-config-in-another-checkout":
        (tmp_path / "elsewhere" / ".git").mkdir(parents=True)
        config = _config(tmp_path / "elsewhere" / "ash-config.yaml")
    else:
        # Named outside every checkout, but the file it names is in one, and that
        # file is what is mounted.
        target = _config(checkout / "other" / "ash-config.yaml")
        config = tmp_path / "operator" / "ash-config.yaml"
        config.parent.mkdir()
        config.symlink_to(target)

    result = _workspace_run(checkout, config, tmp_path)

    assert result.returncode == 3, result.stderr
    assert not rac.container_was_started(result)
    assert commands == []
    assert str(config) in result.stderr
    assert FIX in result.stderr


def test_a_config_inside_the_workspace_is_read_through_src(
    checkout, commands, tmp_path
):
    """Control: the scan inside sees it in its own tree and judges it there."""
    config = _config(checkout / "ws" / "ws-config.yaml")

    result = _workspace_run(checkout, config, tmp_path)

    assert result.returncode != 3, result.stderr
    run = _run_command(commands)
    assert run[run.index("--config") + 1] == "/src/ws-config.yaml"
    assert rac.CONFIG_FROM_SCANNED_REPOSITORY_FLAG not in run


def test_a_config_outside_every_checkout_is_the_operators(checkout, commands, tmp_path):
    """Control: mounted at /ash-config, unmarked, as before."""
    config = _config(tmp_path / "operator" / "ash-config.yaml")

    result = _workspace_run(checkout, config, tmp_path)

    assert result.returncode != 3, result.stderr
    run = _run_command(commands)
    assert run[run.index("--config") + 1] == "/ash-config/ash-config.yaml"
    assert rac.CONFIG_FROM_SCANNED_REPOSITORY_FLAG not in run


def test_a_one_directory_scan_still_marks_it(checkout, commands, tmp_path):
    """Control: the one-directory rule is unchanged."""
    config = _config(checkout / "other" / "ash-config.yaml")

    result = rac.run_ash_container(
        source_dir=str(checkout / "ws" / "proj"),
        output_dir=str(tmp_path / "out"),
        config=str(config),
        build=False,
        run=True,
    )

    assert result.returncode != 3, result.stderr
    assert rac.CONFIG_FROM_SCANNED_REPOSITORY_FLAG in _run_command(commands)


def test_the_assembled_command_refuses_it_on_its_own(checkout, tmp_path):
    """The check holds wherever it is called from: command assembly applies it
    too, whatever order a caller's checks run in."""
    config = _config(checkout / "other" / "ash-config.yaml")
    (tmp_path / "out").mkdir()

    with pytest.raises(rac.ContainerInputError, match=FIX):
        rac._assemble_run_command(
            oci_command_prefix=[],
            resolved_oci_runner="docker",
            image_name="ash:test",
            source_dir=(checkout / "ws").resolve(),
            output_dir=(tmp_path / "out").resolve(),
            offline=False,
            debug=False,
            color=False,
            quiet=True,
            progress=False,
            verbose=False,
            simple=True,
            python_based_plugins_only=False,
            cleanup=False,
            inspect=False,
            fail_on_findings=None,
            phases=[],
            scanners=[],
            exclude_scanners=[],
            output_formats=[],
            config=str(config),
            config_overrides=[],
            existing_results=None,
            ash_plugin_modules=[],
            strategy=None,
            ctx=None,
            workspace_relative_file="ash.code-workspace",
        )


def test_the_scan_cli_refuses_it_before_clearing_the_output(
    checkout, commands, tmp_path
):
    config = _config(checkout / "other" / "ash-config.yaml")
    output = tmp_path / "out"
    (output / "reports").mkdir(parents=True)
    (output / "reports" / "previous.txt").write_text("kept\n", encoding="utf-8")

    result = CliRunner().invoke(
        app,
        [
            "scan",
            "--mode",
            "container",
            "--no-build",
            "--no-progress",
            "--workspace",
            str(checkout / "ws" / "ash.code-workspace"),
            "--config",
            str(config),
            "--output-dir",
            str(output),
        ],
    )

    assert result.exit_code == 3, result.output
    assert commands == []
    assert (output / "reports" / "previous.txt").read_text(encoding="utf-8") == "kept\n"
    assert FIX in " ".join(result.output.split())

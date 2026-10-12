# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A workspace scan in container mode marks or refuses a config the repository
could have written.

A one-directory container scan mounts a config from outside ``--source-dir`` at
``/ash-config`` and, when a local scan would count it as repository-written (it is
in a git checkout, or reached through the scanned tree), passes
``--config-from-scanned-repository`` so the scan inside limits it. A workspace scan
inside the container refused that flag, so in workspace mode the host passed the
config unmarked, and the scan inside, which sees ``/ash-config`` in no checkout,
gave it the operator's grants (``sandbox.extra_read_paths`` and the rest).

In workspace mode the host now marks a config from another git checkout, and the
workspace scan inside accepts the mark and limits that config, and the files it
extends, for every project (``sandbox_grants.marked_repository_written``; the
settings that come out are compared with a local workspace scan's in
test_container_workspace_config_parity.py). A config in the checkout around the
workspace root, or reached through a link there, is refused with exit 3 before
anything is built, mounted or cleared, judged by the files it would mount (a file
it extends stays inside the config's own directory;
``config_sources.default_confinement_root``). The scan CLI refuses it before that,
as a local workspace scan refuses an operator config inside the workspace's tree
(``resolve_config.check_operator_config``). A config inside the workspace root is
read through ``/src``, and one outside every checkout is the operator's.
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
from tests.utils.config_link_layouts import config_through_links

GRANT = "project_name: tier\nsandbox:\n  extra_read_paths:\n    - /opt/tier-grant\n"
FIX = "Keep --config, and every file it extends, outside every git checkout"


@pytest.fixture
def commands(monkeypatch, tmp_path) -> List[List[str]]:
    seen: List[List[str]] = []

    def record(cmd_list, check=True, debug=False, shell=False, env=None):
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
        "a-link-outside-the-checkout-to-a-config-in-it",
        "a-link-in-the-checkout-on-the-way-to-a-config-outside-it",
    ],
)
def test_a_config_in_the_workspaces_own_checkout_is_refused(
    where, checkout, commands, tmp_path
):
    if where == "the-config-in-the-checkout-outside-the-workspace":
        config = _config(checkout / "other" / "ash-config.yaml")
    elif where == "a-link-in-the-checkout-on-the-way-to-a-config-outside-it":
        (checkout / "ci").mkdir()
        config = config_through_links(
            "file-link-in-the-scanned-checkout", checkout, tmp_path
        )
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


@pytest.mark.parametrize(
    "where",
    [
        "the-config-in-another-checkout",
        "a-config-extending-a-base-in-another-checkout",
        "a-link-in-another-checkout-to-a-config-outside-every-checkout",
    ],
)
def test_a_config_in_another_checkout_is_marked_for_the_scan_inside(
    where, checkout, commands, tmp_path
):
    """Not the workspace's own checkout: mounted at /ash-config and marked, so the
    scan inside limits it as a local workspace scan does."""
    elsewhere = tmp_path / "elsewhere"
    (elsewhere / ".git").mkdir(parents=True)
    if where == "the-config-in-another-checkout":
        config = _config(elsewhere / "ash-config.yaml")
    elif where == "a-config-extending-a-base-in-another-checkout":
        _config(elsewhere / "base.yaml")
        config = _config(
            elsewhere / "ash-config.yaml", "project_name: tier\nextends: base.yaml\n"
        )
    else:
        target = _config(tmp_path / "operator" / "ash-config.yaml")
        config = elsewhere / "ash-config.yaml"
        config.symlink_to(target)

    result = _workspace_run(checkout, config, tmp_path)

    assert result.returncode != 3, result.stderr
    run = _run_command(commands)
    assert run[run.index("--config") + 1] == "/ash-config/ash-config.yaml"
    assert rac.CONFIG_FROM_SCANNED_REPOSITORY_FLAG in run


def test_the_inner_workspace_scan_accepts_the_mark(monkeypatch, tmp_path):
    """The scan inside the container treats the marked --config, and every file
    it extends, as repository-written while it runs, and only those files."""
    from automated_security_helper.cli import scan as scan_cli
    from automated_security_helper.config.sandbox_grants import repository_written

    workspace = tmp_path / "src"
    (workspace / "proj").mkdir(parents=True)
    (workspace / "proj" / "a.py").write_text("x = 1\n", encoding="utf-8")
    (workspace / "ash.code-workspace").write_text(
        json.dumps({"folders": [{"path": "proj"}]}), encoding="utf-8"
    )
    mounted = tmp_path / "ash-config"
    base = _config(mounted / "base.yaml")
    config = _config(
        mounted / "ash-config.yaml", "project_name: t\nextends: base.yaml\n"
    )
    beside = _config(mounted / "not-in-the-chain.yaml")
    seen = {}

    def run(**kwargs):
        seen["kwargs"] = kwargs
        seen["written"] = repository_written(
            [base.resolve(), config.resolve()], workspace
        )
        seen["beside"] = repository_written([beside.resolve()], workspace)
        seen["project"] = repository_written(
            [(workspace / "proj" / "a.py").resolve()], tmp_path / "unrelated"
        )

    monkeypatch.setattr(scan_cli, "run_ash_scan", run)
    monkeypatch.chdir(workspace)

    result = CliRunner().invoke(
        app,
        [
            "scan",
            "--workspace",
            str(workspace / "ash.code-workspace"),
            "--config",
            str(config),
            rac.CONFIG_FROM_SCANNED_REPOSITORY_FLAG,
        ],
    )

    assert result.exit_code == 0, result.output
    assert seen["written"] == [base.resolve(), config.resolve()]
    assert seen["beside"] == []
    assert seen["project"] == []
    # Applied by the mark, not by untrusted_config, which is for an MCP client's file.
    assert seen["kwargs"].get("untrusted_config", False) is False
    # Only while the scan runs.
    assert repository_written([config.resolve()], workspace) == []


def test_the_inner_workspace_scan_needs_a_config_for_the_mark(monkeypatch, tmp_path):
    from automated_security_helper.cli import scan as scan_cli

    workspace = tmp_path / "src"
    (workspace / "proj").mkdir(parents=True)
    (workspace / "ash.code-workspace").write_text(
        json.dumps({"folders": [{"path": "proj"}]}), encoding="utf-8"
    )
    monkeypatch.setattr(scan_cli, "run_ash_scan", lambda **kw: None)
    monkeypatch.chdir(workspace)

    result = CliRunner().invoke(
        app,
        [
            "scan",
            "--workspace",
            str(workspace / "ash.code-workspace"),
            rac.CONFIG_FROM_SCANNED_REPOSITORY_FLAG,
        ],
    )

    assert result.exit_code == 3, result.output
    assert rac.CONFIG_FROM_SCANNED_REPOSITORY_FLAG in result.output


def test_a_config_inside_the_workspace_is_read_through_src(
    checkout, commands, tmp_path
):
    """Control: read through /src, in the scan's own tree inside, and not marked."""
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
    """The CLI's own workspace check comes first, with its message: the operator's
    config is layered over every project, so none of its files may be the
    workspace's."""
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
    message = " ".join(result.output.split())
    assert "ash-config.yaml" in message, message
    assert "is inside the checkout" in message, message

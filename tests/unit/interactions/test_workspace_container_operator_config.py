# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Workspace mode in a container keeps the operator's --config final.

The container mounts only the workspace root (``/src``) and the output
directory, and an operator ``--config`` inside the workspace is refused, so the
operator's file is never at a path the in-container run can read. It is mounted
read-only at ``/ash-operator-config``, with each base it extends at the same
place relative to it, and the in-container run is given that path.

The host reads fail_on_findings and fail_on_incomplete_scanners from a config
before it builds the container's command. In workspace mode the in-container
run layers the operator's file and judges each project itself, so the host
forwards only the values the operator gave on the command line: a value it
read would beat every project's own config inside the container.

No container is started: these tests read the command ASH would run.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest
import yaml

from automated_security_helper.interactions.run_ash_container import (
    OPERATOR_CONFIG_MOUNT,
    _assemble_run_command,
)
from automated_security_helper.interactions.run_ash_scan import (
    ScanOptions,
    _run_container_mode,
)
from automated_security_helper.utils.subprocess_utils import create_completed_process
from automated_security_helper.workspace.plan import ProjectPlan, WorkspacePlan


def _write(path: Path, document: Any) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    return path


def _command(tmp_path: Path, **overrides: Any) -> List[str]:
    kwargs: Dict[str, Any] = {
        "oci_command_prefix": [],
        "resolved_oci_runner": "docker",
        "image_name": "ash:test",
        "source_dir": tmp_path / "work",
        "output_dir": tmp_path / "out",
        "offline": False,
        "debug": False,
        "color": False,
        "quiet": False,
        "progress": False,
        "verbose": False,
        "simple": False,
        "python_based_plugins_only": False,
        "cleanup": False,
        "inspect": False,
        "fail_on_findings": None,
        "phases": [],
        "scanners": [],
        "exclude_scanners": [],
        "output_formats": [],
        "config": None,
        "config_overrides": [],
        "existing_results": None,
        "ash_plugin_modules": [],
        "strategy": None,
        "ctx": None,
        "workspace_relative_file": "dev.code-workspace",
    }
    kwargs.update(overrides)
    return _assemble_run_command(**kwargs)


def _mounts(command: List[str]) -> List[str]:
    return [command[i + 1] for i, arg in enumerate(command) if arg == "--mount"]


def test_the_operators_config_is_mounted_read_only_and_named_inside(tmp_path):
    operator = _write(tmp_path / "ops" / "ash.yaml", {"fail_on_findings": True})

    command = _command(tmp_path, config=str(operator))

    inside = f"{OPERATOR_CONFIG_MOUNT}/ash.yaml"
    assert command[command.index("--config") + 1] == inside
    assert (
        f"type=bind,source={operator.resolve()},destination={inside},readonly"
        in _mounts(command)
    )
    # The host path is never handed to the in-container run.
    assert str(operator) not in command[command.index("ash:test") :]


def test_the_bases_it_extends_are_mounted_where_it_names_them(tmp_path):
    base = _write(tmp_path / "ops" / "shared" / "base.yaml", {"fail_on_findings": True})
    operator = _write(tmp_path / "ops" / "ash.yaml", {"extends": "shared/base.yaml"})

    mounts = _mounts(_command(tmp_path, config=str(operator)))

    assert (
        f"type=bind,source={base.resolve()},"
        f"destination={OPERATOR_CONFIG_MOUNT}/shared/base.yaml,readonly"
    ) in mounts
    # Only the files the config is built from, never the directory they are in.
    assert not any(
        f"source={(tmp_path / 'ops').resolve()}," in mount for mount in mounts
    )


def test_a_single_directory_scan_passes_its_config_as_before(tmp_path):
    command = _command(tmp_path, config="ash.yaml", workspace_relative_file=None)

    assert command[command.index("--config") + 1] == "ash.yaml"
    assert not any(OPERATOR_CONFIG_MOUNT in mount for mount in _mounts(command))


def _plan(root: Path) -> WorkspacePlan:
    return WorkspacePlan(
        workspace_file=(root / "dev.code-workspace").as_posix(),
        workspace_root=root.as_posix(),
        projects=[
            ProjectPlan(
                key="api",
                relative_path="api",
                path=(root / "api").as_posix(),
                label="api",
                display_label="api",
            )
        ],
    )


def _forwarded(tmp_path: Path, **opts: Any) -> Dict[str, Any]:
    captured: Dict[str, Any] = {}

    def run(**kwargs):
        captured.update(kwargs)
        return create_completed_process(args=[], returncode=1, stdout="", stderr="")

    options = ScanOptions(
        source_dir=tmp_path / "work", output_dir=tmp_path / "out", **opts
    )
    with (
        patch(
            "automated_security_helper.interactions.run_ash_scan.run_ash_container",
            side_effect=run,
        ),
        pytest.raises(SystemExit),
    ):
        _run_container_mode(
            options,
            MagicMock(),
            resolved_fail_on_findings=False,
            resolved_fail_on_incomplete_scanners=False,
        )
    return captured


def test_workspace_mode_forwards_no_fail_on_value_the_host_read(tmp_path):
    forwarded = _forwarded(tmp_path, workspace_plan=_plan(tmp_path / "work"))

    assert forwarded["fail_on_findings"] is None
    assert forwarded["fail_on_incomplete_scanners"] is None


def test_workspace_mode_forwards_the_values_given_on_the_command_line(tmp_path):
    forwarded = _forwarded(
        tmp_path,
        workspace_plan=_plan(tmp_path / "work"),
        fail_on_findings=True,
        fail_on_incomplete_scanners=True,
    )

    assert forwarded["fail_on_findings"] is True
    assert forwarded["fail_on_incomplete_scanners"] is True


def test_a_single_directory_scan_still_forwards_what_the_host_read(tmp_path):
    forwarded = _forwarded(tmp_path)

    assert forwarded["fail_on_findings"] is False
    assert forwarded["fail_on_incomplete_scanners"] is False

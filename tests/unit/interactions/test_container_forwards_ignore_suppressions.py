# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Container mode hands ``--ignore-suppressions`` to the scan inside the container.

The scan inside the container decides which files its scanners read. Under
``--ignore-suppressions`` every scanner reads the files under ignore paths, so the
flag has to reach that scan. The host still recomputes the verdict from the
results it reads back, but a finding a scanner never produced is not in those
results to count. Before, the flag stayed on the host, so a container scan with
it reported findings under an ignore path only from scanners that read them
anyway.

No container is built or run: each step is called with its collaborators
replaced, and what is asserted is the argument each step hands the next.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.core.enums import ExecutionPhase, ExecutionStrategy
from automated_security_helper.interactions import run_ash_container as rac
from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.subprocess_utils import create_completed_process


def _run_command(tmp_path: Path, **overrides: Any) -> List[str]:
    kwargs: Dict[str, Any] = {
        "oci_command_prefix": [],
        "resolved_oci_runner": "docker",
        "image_name": "ash:test",
        "source_dir": tmp_path / "src",
        "output_dir": tmp_path / "out",
        "offline": False,
        "debug": False,
        "color": False,
        "quiet": False,
        "progress": True,
        "verbose": False,
        "simple": False,
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
    return rac._assemble_run_command(**kwargs)


class TestTheContainerCommand:
    def test_the_flag_is_passed_to_the_inner_ash(self, tmp_path):
        cmd = _run_command(tmp_path, ignore_suppressions=True)

        assert "--ignore-suppressions" in cmd
        assert cmd.index("--ignore-suppressions") > cmd.index("ash:test")

    def test_without_the_flag_nothing_is_passed(self, tmp_path):
        assert "--ignore-suppressions" not in _run_command(tmp_path)


@pytest.fixture
def container_stubs(monkeypatch, tmp_path):
    """Every collaborator that would reach an OCI runtime, replaced by a recorder."""
    recorded: Dict[str, Any] = {"run_command": []}
    dockerfile = tmp_path / "assets" / "Dockerfile"
    dockerfile.parent.mkdir(parents=True)
    dockerfile.write_text("FROM scratch\n", encoding="utf-8")

    monkeypatch.setattr(subprocess_utils, "get_host_uid", lambda: 4242)
    monkeypatch.setattr(subprocess_utils, "get_host_gid", lambda: 4343)
    monkeypatch.setattr(rac, "_resolve_oci_runner", lambda oci_runner: "docker")
    monkeypatch.setattr(rac, "get_ash_revision", lambda quiet=False: "LOCAL")
    monkeypatch.setattr(rac, "_find_dockerfile", lambda revision: dockerfile)

    def fake_assemble(**kwargs):
        recorded["run_command"].append(kwargs)
        return ["docker", "run", "--rm", kwargs["image_name"]]

    monkeypatch.setattr(rac, "_assemble_run_command", fake_assemble)
    monkeypatch.setattr(
        rac,
        "_execute_container",
        lambda cmd, debug=False, env=None: create_completed_process(
            args=cmd, returncode=0
        ),
    )
    for name in ("CI", "IsCI", "ISCI", "CODEBUILD_BUILD_ID", "ASH_IMAGE_NAME"):
        monkeypatch.delenv(name, raising=False)
    return recorded


@pytest.mark.parametrize("flag", [False, True])
def test_run_ash_container_hands_the_flag_to_the_command(
    container_stubs, tmp_path, flag
):
    source = tmp_path / "src"
    source.mkdir()

    rac.run_ash_container(
        source_dir=source,
        output_dir=tmp_path / "out",
        build=False,
        run=True,
        ignore_suppressions=flag,
    )

    (kwargs,) = container_stubs["run_command"]
    assert kwargs["ignore_suppressions"] is flag


class _Stop(Exception):
    """Raised by the stand-in container so the read-back does not run."""


@pytest.mark.parametrize("flag", [False, True])
def test_container_mode_hands_the_flag_to_the_container(tmp_path, flag):
    from automated_security_helper.interactions.run_ash_scan import (
        ScanOptions,
        _run_container_mode,
    )

    opts = ScanOptions(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        ignore_suppressions=flag,
    )
    captured: Dict[str, Any] = {}

    def fake_run_ash_container(**kwargs):
        captured.update(kwargs)
        raise _Stop

    with patch(
        "automated_security_helper.interactions.run_ash_scan.run_ash_container",
        side_effect=fake_run_ash_container,
    ):
        with pytest.raises(_Stop):
            _run_container_mode(opts, MagicMock())

    assert captured["ignore_suppressions"] is flag

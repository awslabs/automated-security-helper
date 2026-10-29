# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The switch that stops ASH honoring ignore files reaches the scan inside a container.

``ash scan --mode container`` runs the same CLI inside the image, so a host flag that is
not forwarded is silently dropped: the in-container scan honors the repository's
``.gitignore`` / ``.ignore`` files although the operator asked it not to. The flag may be
forwarded as itself or as the ``--config-overrides`` entry it stands for; either
reaches the inner scan. Nothing is built or started: the run command is recorded.

``--no-honor-ignore-files`` and ``honor_ignore_files`` are proposed names, spelled only
in the constants below.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List

import pytest
from typer.testing import CliRunner

from automated_security_helper.interactions import run_ash_container as rac
from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.subprocess_utils import create_completed_process

pytestmark = pytest.mark.unit

SWITCH_OFF_FLAG = "--no-honor-ignore-files"
CONFIG_KEY = "honor_ignore_files"


@pytest.fixture
def recorded(monkeypatch, tmp_path) -> Dict[str, Any]:
    """Recorders in place of the image build and the container run."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("print('hello')\n")
    seen: Dict[str, Any] = {"commands": []}

    def fake_execute(cmd, debug=False, env=None):
        seen["commands"].append(list(cmd))
        return create_completed_process(args=list(cmd), returncode=0)

    monkeypatch.setattr(subprocess_utils, "get_host_uid", lambda: 1000)
    monkeypatch.setattr(subprocess_utils, "get_host_gid", lambda: 1000)
    monkeypatch.setattr(rac, "_find_runner", lambda _name: "/usr/bin/docker")
    monkeypatch.setattr(rac, "get_ash_revision", lambda quiet=False: "LOCAL")
    monkeypatch.setattr(rac, "_build_image", lambda **_kwargs: None)
    monkeypatch.setattr(rac, "_execute_container", fake_execute)
    for name in (
        "CI",
        "IsCI",
        "ISCI",
        "CODEBUILD_BUILD_ID",
        "ASH_IMAGE_NAME",
        "ASH_CONFIG",
        "AWS_PROFILE",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_DEFAULT_PROFILE",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("AWS_CONFIG_FILE", os.devnull)
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", os.devnull)
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    monkeypatch.setenv("AWS_ENDPOINT_URL", "http://127.0.0.1:9")
    return seen


def _container_scan(tmp_path, *args: str):
    from automated_security_helper.cli.main import app

    return CliRunner().invoke(
        app,
        [
            "scan",
            "--mode",
            "container",
            "--no-build",
            "--source-dir",
            str(tmp_path / "src"),
            "--output-dir",
            str(tmp_path / "out"),
            "--no-progress",
            *args,
        ],
    )


def _run_command(seen: Dict[str, Any], result) -> List[str]:
    assert seen["commands"], (
        "the container was never run, so nothing was recorded; CLI output: "
        f"{result.output[-3000:]}"
    )
    return seen["commands"][-1]


def _carries_switch_off(argv: List[str]) -> bool:
    if SWITCH_OFF_FLAG in argv:
        return True
    overrides = [
        argv[i + 1] for i, arg in enumerate(argv[:-1]) if arg == "--config-overrides"
    ]
    return any(
        o.replace("-", "_").replace(" ", "").lower() == f"{CONFIG_KEY}=false"
        for o in overrides
    )


def test_the_flag_is_forwarded_into_the_container(recorded, tmp_path):
    result = _container_scan(tmp_path, SWITCH_OFF_FLAG)
    argv = _run_command(recorded, result)
    assert _carries_switch_off(argv), (
        f"{SWITCH_OFF_FLAG} did not reach the in-container scan; run command: {argv}"
    )


def test_control_the_config_override_is_forwarded_verbatim(recorded, tmp_path):
    """Passes today: the run command is recorded and overrides travel with it."""
    result = _container_scan(tmp_path, "--config-overrides", f"{CONFIG_KEY}=false")
    argv = _run_command(recorded, result)
    assert _carries_switch_off(argv), argv


def test_control_without_the_switch_nothing_is_forwarded(recorded, tmp_path):
    result = _container_scan(tmp_path)
    argv = _run_command(recorded, result)
    assert not _carries_switch_off(argv), argv

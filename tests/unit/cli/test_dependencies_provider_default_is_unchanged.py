# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""With none of the new flags, ``ash dependencies install`` runs what plugins declared.

The provider layer sits between a plugin's declared install commands and the runner.
Its no-regression anchor is that, without ``--providers`` and without a virtualenv,
every declared command reaches the runner byte for byte, with its shell flag, in the
order declared: each command is built by the provider it was declared for.
"""

from __future__ import annotations

import sys

import pytest

from automated_security_helper.base.plugin_base import CustomCommand
from automated_security_helper.utils.download_utils import (
    create_pinned_tool_install_command,
)
from tests.unit.cli.dependencies_install_support import (
    CHECKOV_COMMAND,
    build_scene,
    run_install,
)

pytestmark = pytest.mark.unit


def test_default_run_emits_todays_commands_byte_for_byte(tmp_path, monkeypatch):
    pinned = create_pinned_tool_install_command(
        "grype", "linux", "amd64", str(tmp_path / "bin")
    )
    declared = [
        list(CHECKOV_COMMAND),
        [sys.executable, "-m", "pip", "install", "ash[sarif]"],
        ["gem", "install", "cfn-nag", "--user-install"],
        ["apt-get", "install", "-y", "jq=1.7"],
        CustomCommand(args=["echo $HOME"], shell=True),  # nosec B604
        pinned,
        ["npm", "install", "-g", "left-pad@1"],
    ]
    scene = build_scene(
        monkeypatch,
        tmp_path,
        declared=declared,
        find_on_path=lambda cmd: f"/usr/bin/{cmd}",
    )

    run_install(scene, monkeypatch, tmp_path)

    expected = [
        (list(CHECKOV_COMMAND), False),
        ([sys.executable, "-m", "pip", "install", "ash[sarif]"], False),
        (["gem", "install", "cfn-nag", "--user-install"], False),
        (["apt-get", "install", "-y", "jq=1.7"], False),
        (["echo $HOME"], True),
        (list(pinned.args), False),
        (["npm", "install", "-g", "left-pad@1"], False),
    ]
    assert scene.calls == expected, (scene.calls, scene.text)
    assert scene.result.exit_code == 0, scene.text
    assert "Skipped provider" not in scene.text, scene.text


def test_inherit_default_counts_a_path_tool_as_present(tmp_path, monkeypatch):
    """The measured default: a tool found on PATH satisfies the dependency, so a
    run whose uv listing knows nothing of the tool still passes."""
    scene = build_scene(
        monkeypatch,
        tmp_path,
        find_on_path=lambda cmd: f"/usr/local/global-bin/{cmd}",
    )

    run_install(scene, monkeypatch, tmp_path)

    assert scene.result.exit_code == 0, scene.text
    assert "/usr/local/global-bin/checkov" in scene.text, scene.text

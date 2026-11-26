# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``--no-inherit-system-tools`` reaches the pinned install's CHILD, not only the parent.

The pinned install runs in a child python whose ``install_pinned_tool`` re-checks
for an already-present copy before downloading. The parent's pre-check was already
flag-aware; the declared command is retold with the no-inherit script so the
child's re-check is too. Without the rewrite, a byte-identical PATH copy (the ASH
container image's /usr/local/bin syft, grype and trivy -- the case the skip was
built for) made the child log "already present" and install nothing, and the
post-install sweep, which counts only managed copies under the flag, failed the
very run the operator asked for.
"""

from __future__ import annotations

import pytest

from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.download_utils import (
    _PINNED_TOOL_INSTALL_SCRIPT,
    _PINNED_TOOL_INSTALL_SCRIPT_NO_INHERIT,
    create_pinned_tool_install_command,
)
from tests.unit.cli.dependencies_install_support import build_scene, run_install

pytestmark = pytest.mark.unit


def _scene(monkeypatch, tmp_path, declared):
    scene = build_scene(
        monkeypatch,
        tmp_path,
        name="grype",
        command="grype",
        declared=declared,
        uv_listing=lambda cmd: f"/uv/tools/{cmd}",
    )
    # No copy of the tool anywhere, so the parent's pre-check never skips and the
    # declared command is what runs; the lookup is the real one otherwise.
    monkeypatch.setattr(subprocess_utils, "find_executable", lambda *_a, **_k: None)
    return scene


def _declared(tmp_path):
    return [
        list(
            create_pinned_tool_install_command(
                "grype", "linux", "amd64", str(tmp_path / "bin")
            ).args
        )
    ]


def test_no_inherit_retells_the_pinned_command_for_the_child(tmp_path, monkeypatch):
    declared = _declared(tmp_path)
    scene = _scene(monkeypatch, tmp_path, [list(declared[0])])

    run_install(scene, monkeypatch, tmp_path, "--no-inherit-system-tools")

    assert len(scene.argvs) == 1, scene.argvs
    ran = scene.argvs[0]
    assert ran[2] == _PINNED_TOOL_INSTALL_SCRIPT_NO_INHERIT, ran[2]
    assert ran[3:] == declared[0][3:], ran


def test_the_default_runs_the_declared_pinned_command_byte_for_byte(
    tmp_path, monkeypatch
):
    declared = _declared(tmp_path)
    scene = _scene(monkeypatch, tmp_path, [list(declared[0])])

    run_install(scene, monkeypatch, tmp_path)

    assert scene.argvs == declared, scene.argvs
    assert scene.argvs[0][2] == _PINNED_TOOL_INSTALL_SCRIPT

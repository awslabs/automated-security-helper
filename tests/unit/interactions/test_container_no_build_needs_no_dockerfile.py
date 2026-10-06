# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Regression tests: ``--no-build`` runs the image without looking for a Dockerfile.

``run_ash_container`` resolved the Dockerfile before deciding whether to build.
Outside an ASH checkout (revision LOCAL and no Dockerfile in or above the working
directory) ``ashx scan --mode container --no-build`` refused with "Dockerfile not
found" although nothing was going to be built. The lookup now happens only for a
build, so ``--no-build`` runs an image that is already present wherever it is
invoked from.
"""

from __future__ import annotations

from typing import Any, Dict

import pytest

from automated_security_helper.interactions import run_ash_container as rac
from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.subprocess_utils import create_completed_process


@pytest.fixture
def runtime(monkeypatch, tmp_path) -> Dict[str, Any]:
    """No Dockerfile anywhere, and recorders in place of the build and the run."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "src").mkdir()
    seen: Dict[str, Any] = {"build": 0, "executed": 0}

    def missing(_rev):
        raise FileNotFoundError(f"Dockerfile not found at {tmp_path / 'Dockerfile'}")

    def fake_build(**_kwargs):
        seen["build"] += 1

    def fake_execute(cmd, debug=False):
        seen["executed"] += 1
        return create_completed_process(args=list(cmd), returncode=0)

    monkeypatch.setattr(subprocess_utils, "get_host_uid", lambda: 1000)
    monkeypatch.setattr(subprocess_utils, "get_host_gid", lambda: 1000)
    monkeypatch.setattr(rac, "_find_runner", lambda _name: "/usr/bin/docker")
    monkeypatch.setattr(rac, "get_ash_revision", lambda: "LOCAL")
    monkeypatch.setattr(rac, "_find_dockerfile", missing)
    monkeypatch.setattr(rac, "_build_image", fake_build)
    monkeypatch.setattr(rac, "_execute_container", fake_execute)
    for name in ("CI", "IsCI", "ISCI", "CODEBUILD_BUILD_ID", "ASH_IMAGE_NAME"):
        monkeypatch.delenv(name, raising=False)
    return seen


def test_no_build_outside_a_checkout_runs_the_image(runtime):
    result = rac.run_ash_container(source_dir="src", build=False, run=True)

    assert runtime["executed"] == 1
    assert runtime["build"] == 0
    assert result.returncode == 0
    assert rac.container_was_started(result)


def test_a_build_still_needs_one(runtime):
    result = rac.run_ash_container(source_dir="src", build=True, run=True)

    assert result.returncode == 1
    assert "Dockerfile not found" in result.stderr
    assert runtime["executed"] == 0
    assert not rac.container_was_started(result)

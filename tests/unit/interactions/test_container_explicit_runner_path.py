# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An explicit runner path is the runner that runs; a bare name resolves on PATH.

``ash --mode container --oci-runner`` (and ``run_ash_container(oci_runner=...)``)
resolves the runner with ``find_executable``, which hands a value holding a
directory to ``shutil.which`` as that path. Pinned here with two runners named
``docker``, one at the given path and one first on PATH, each recording its own
path, because the PowerShell wrapper used to keep only the name and run the one on
PATH instead. No real runner is reachable: both stand-ins come first.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from automated_security_helper.interactions import run_ash_container as rac
from automated_security_helper.utils import subprocess_utils

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.name == "nt", reason="the stand-in runners are POSIX shell scripts"
    ),
]


def _self_recording_runner(directory: Path, log: Path) -> Path:
    """A ``docker`` that appends its own path and its first argument to *log*."""
    directory.mkdir(parents=True)
    runner = directory / "docker"
    runner.write_text(
        f"#!/bin/sh\nprintf '%s %s\\n' \"$0\" \"$1\" >> '{log}'\nexit 0\n",
        encoding="utf-8",
    )
    runner.chmod(0o755)
    return runner


@pytest.mark.parametrize("given", ["a-path", "a-name"])
def test_an_explicit_runner_path_runs_that_path(given, monkeypatch, tmp_path):
    source = tmp_path / "src"
    source.mkdir()
    log = tmp_path / "runner-calls.txt"
    explicit = _self_recording_runner(tmp_path / "given dir", log)
    on_path = _self_recording_runner(tmp_path / "path-bin", log)
    monkeypatch.setenv(
        "PATH", os.pathsep.join([str(on_path.parent), os.environ.get("PATH", "")])
    )
    # Resolutions are cached per name; another test's "docker" must not answer here.
    monkeypatch.setattr(subprocess_utils, "_find_executable_cache", {})
    monkeypatch.setattr(subprocess_utils, "get_host_uid", lambda: 1000)
    monkeypatch.setattr(subprocess_utils, "get_host_gid", lambda: 1000)
    for name in ("CI", "ASH_IMAGE_NAME", "ASH_CONFIG", "OCI_RUNNER_WRAPPER"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.chdir(tmp_path)

    rac.run_ash_container(
        source_dir=str(source),
        output_dir=str(tmp_path / "out"),
        oci_runner=str(explicit) if given == "a-path" else "docker",
        build=False,
        run=True,
    )

    expected = explicit if given == "a-path" else on_path
    assert log.read_text(encoding="utf-8").splitlines() == [f"{expected} run"]

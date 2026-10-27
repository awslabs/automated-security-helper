# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The ``ash-full-scan`` pre-commit hook runs a container scan with ``/src`` read-only.

The hook (.pre-commit-hooks.yaml) runs ``ashv3 --mode=container --simple`` in the
repository being committed to, with no ``--output-dir``, so the output is the
default ``.ash/ash_output`` inside the source directory, on its own mount. This
drives the hook's own command line through the CLI the ``ashv3`` script runs, with
the runner recorded instead of started, and checks the mounts.
"""

from __future__ import annotations

import shlex
from pathlib import Path
from typing import List

import pytest
import yaml
from typer.testing import CliRunner

from automated_security_helper.interactions import run_ash_container as rac
from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.subprocess_utils import create_completed_process
from automated_security_helper.utils.version_management import _load_toml

REPO_ROOT = Path(__file__).resolve().parents[2]


def _hook(hook_id: str) -> dict:
    hooks = yaml.safe_load((REPO_ROOT / ".pre-commit-hooks.yaml").read_text())
    return next(hook for hook in hooks if hook["id"] == hook_id)


def test_the_hook_runs_the_cli_entry_point():
    """Guards the premise: ``ashv3`` is the same CLI the rest of this file drives."""
    entry = shlex.split(_hook("ash-full-scan")["entry"])
    scripts = _load_toml(REPO_ROOT / "pyproject.toml")["project"]["scripts"]

    assert entry[0] == "ashv3"
    assert (
        scripts["ashv3"]
        == scripts["ash"]
        == "automated_security_helper.cli.entrypoint:main"
    )
    assert "--mode=container" in entry


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
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "app.py").write_text("print('hello')\n")
    monkeypatch.chdir(repository)
    return seen


@pytest.mark.parametrize(
    "extra",
    [
        pytest.param([], id="as-installed"),
        # The same with an image already built, which isolates the mount from the
        # Dockerfile lookup the build step also needs.
        pytest.param(["--no-build"], id="image-already-built"),
    ],
)
def test_the_hook_mounts_the_source_read_only(extra, commands):
    from automated_security_helper.cli.main import app

    hook = _hook("ash-full-scan")
    argv = [*shlex.split(hook["entry"])[1:], *hook.get("args", []), *extra]

    CliRunner().invoke(app, argv)

    runs = [cmd for cmd in commands if cmd[1] == "run"]
    assert len(runs) == 1, commands
    mounts = [runs[0][i + 1] for i, arg in enumerate(runs[0]) if arg == "--mount"]
    source = [mount for mount in mounts if "destination=/src" in mount.split(",")]
    output = [mount for mount in mounts if "destination=/out" in mount.split(",")]
    assert len(source) == 1 and "readonly" in source[0].split(","), mounts
    # The output is the default inside the source directory, on its own mount. The
    # source side is a host path, so its separators are the host's.
    assert len(output) == 1
    assert output[0].replace("\\", "/").endswith(".ash/ash_output,destination=/out")

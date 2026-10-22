# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A container scan refused for its inputs leaves the previous run's output alone.

Before it starts the container, ``_run_container_mode`` clears what an earlier run
left in the output directory (``_discard_prior_run_artifacts``), so a results file
found afterwards is this run's. The inputs are checked before that: a ``--config``
that does not exist, an ``extends`` entry the container cannot resolve, or an
output path ``--mount`` cannot carry refuses the scan with exit 3 and leaves the
output directory as it was. So do the build inputs: a ``--container-uid`` or
``--container-gid`` that is not a number and a ``non-root`` build as UID or GID 0
(exit 3), and an ``--ash-revision-to-install`` the build cannot take (exit 1).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.interactions import run_ash_container as rac
from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.subprocess_utils import create_completed_process

PRIOR = ("ash_aggregated_results.json", "reports/ash.sarif")


@pytest.fixture(autouse=True)
def _no_real_runner(monkeypatch):
    def refuse(cmd_list, check=True, debug=False, shell=False, env=None):
        raise AssertionError(f"a real runner command was attempted: {cmd_list}")

    monkeypatch.setattr(rac, "run_cmd_direct", refuse)


@pytest.fixture
def runtime(monkeypatch, tmp_path) -> Dict[str, Any]:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "src").mkdir()
    seen: Dict[str, Any] = {"executed": 0}

    monkeypatch.setattr(subprocess_utils, "get_host_uid", lambda: 1000)
    monkeypatch.setattr(subprocess_utils, "get_host_gid", lambda: 1000)
    monkeypatch.setattr(
        rac, "_find_runner", lambda _name: "/nonexistent/ash-test/docker"
    )

    def fake_execute(cmd, debug=False):
        seen["executed"] += 1
        return create_completed_process(args=list(cmd), returncode=0)

    monkeypatch.setattr(rac, "_execute_container", fake_execute)
    for name in ("CI", "IsCI", "ISCI", "CODEBUILD_BUILD_ID", "ASH_IMAGE_NAME"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    return seen


def _prior_run(output: Path) -> None:
    for name in PRIOR:
        (output / name).parent.mkdir(parents=True, exist_ok=True)
        (output / name).write_text("from the previous run\n", encoding="utf-8")


def _scan(output: Path, *extra: str):
    return CliRunner().invoke(
        app,
        [
            "scan",
            "--mode",
            "container",
            "--no-build",
            "--no-progress",
            "--source-dir",
            "src",
            "--output-dir",
            str(output),
            *extra,
        ],
    )


def _kept(output: Path) -> None:
    for name in PRIOR:
        assert (output / name).read_text(encoding="utf-8") == "from the previous run\n"


def test_a_config_that_is_not_there(runtime, tmp_path):
    output = tmp_path / "out"
    _prior_run(output)

    result = _scan(output, "--config", "missing.yaml")

    assert result.exit_code == 3, result.output
    assert runtime["executed"] == 0
    _kept(output)


def test_a_config_whose_chain_the_container_cannot_resolve(runtime, tmp_path):
    output = tmp_path / "out"
    _prior_run(output)
    base = (tmp_path / "base.yaml").resolve()
    base.write_text("project_name: p\n", encoding="utf-8")
    config = tmp_path / "ash.yaml"
    config.write_text(f"extends: {base}\n", encoding="utf-8")

    result = _scan(output, "--config", str(config))

    assert result.exit_code == 3, result.output
    assert runtime["executed"] == 0
    _kept(output)


def test_an_output_path_the_mount_cannot_carry(runtime, tmp_path):
    output = tmp_path / "out,b"
    _prior_run(output)

    result = _scan(output)

    assert result.exit_code == 3, result.output
    assert runtime["executed"] == 0
    _kept(output)


def _scan_building(output: Path, *extra: str):
    """The same scan, building the image first."""
    return CliRunner().invoke(
        app,
        [
            "scan",
            "--mode",
            "container",
            "--no-progress",
            "--source-dir",
            "src",
            "--output-dir",
            str(output),
            *extra,
        ],
    )


@pytest.mark.parametrize(
    ("extra", "code"),
    [
        pytest.param(["--container-uid", "x1"], 3, id="uid-not-a-number"),
        pytest.param(["--container-gid", "x1"], 3, id="gid-not-a-number"),
        pytest.param(["--ash-revision-to-install", "v1;x"], 1, id="unsafe-revision"),
    ],
)
def test_a_build_input_the_image_cannot_take(extra, code, runtime, tmp_path):
    output = tmp_path / "out"
    _prior_run(output)

    result = _scan_building(output, *extra)

    assert result.exit_code == code, result.output
    assert runtime["executed"] == 0
    _kept(output)


@pytest.mark.parametrize(
    "extra",
    [
        pytest.param([], id="host-runs-as-root"),
        pytest.param(["--build-target", "non-root"], id="explicit-non-root"),
    ],
)
def test_a_non_root_build_as_root(extra, runtime, monkeypatch, tmp_path):
    """The default outcome on a root host that does not pass --build-target ci."""
    monkeypatch.setattr(subprocess_utils, "get_host_uid", lambda: 0)
    monkeypatch.setattr(subprocess_utils, "get_host_gid", lambda: 0)
    output = tmp_path / "out"
    _prior_run(output)

    result = _scan_building(output, *extra)

    assert result.exit_code == 3, result.output
    assert "--build-target ci" in result.output
    assert runtime["executed"] == 0
    _kept(output)


def test_a_scan_that_starts_still_clears_the_previous_output(runtime, tmp_path):
    """Control: the clearing itself is unchanged."""
    output = tmp_path / "out"
    _prior_run(output)

    _scan(output)

    assert runtime["executed"] == 1
    for name in PRIOR:
        assert not (output / name).exists()

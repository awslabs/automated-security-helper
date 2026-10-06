# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Regression tests: a container-mode refusal ends the scan.

``run_ash_container`` reports every refusal (no OCI runner, a non-numeric UID, an
unsafe revision, a failed build, a missing Dockerfile) as a result with status 1.
1 is also a verdict the in-container CLI reaches from a results file, so
``_run_container_mode`` went on to read one back, found nothing, and added
"Results file not found at .../ash_aggregated_results.json" under the refusal: a
message about a report no scan could have written, which sends the operator looking
for the wrong problem. A refusal is now marked as such and the scan exits right
after it, with the refusal's status.
"""

from __future__ import annotations

from subprocess import CalledProcessError
from typing import Any, Dict

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.interactions import run_ash_container as rac
from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.subprocess_utils import create_completed_process

SCAN = [
    "scan",
    "--mode",
    "container",
    "--no-progress",
    "--source-dir",
    "src",
    "--output-dir",
    "out",
]

NOT_FOUND = "Results file not found"


@pytest.fixture
def runtime(monkeypatch, tmp_path) -> Dict[str, Any]:
    """Every collaborator that would reach an OCI runtime, replaced by a recorder."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "src").mkdir()
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM scratch\n", encoding="utf-8")

    seen: Dict[str, Any] = {"build": 0, "executed": 0}

    monkeypatch.setattr(subprocess_utils, "get_host_uid", lambda: 1000)
    monkeypatch.setattr(subprocess_utils, "get_host_gid", lambda: 1000)
    monkeypatch.setattr(rac, "_find_runner", lambda _name: "/usr/bin/docker")
    monkeypatch.setattr(rac, "get_ash_revision", lambda: "LOCAL")
    monkeypatch.setattr(rac, "_find_dockerfile", lambda _rev: dockerfile)

    def fake_build(**_kwargs):
        seen["build"] += 1

    def fake_execute(cmd, debug=False):
        seen["executed"] += 1
        return create_completed_process(args=list(cmd), returncode=0)

    monkeypatch.setattr(rac, "_build_image", fake_build)
    monkeypatch.setattr(rac, "_execute_container", fake_execute)
    for name in ("CI", "IsCI", "ISCI", "CODEBUILD_BUILD_ID", "ASH_IMAGE_NAME"):
        monkeypatch.delenv(name, raising=False)
    return seen


def _assert_stopped_after_refusal(result, refusal: str, exit_code: int = 1):
    assert result.exit_code == exit_code, result.output
    assert isinstance(result.exception, SystemExit), repr(result.exception)
    assert refusal in result.output
    assert NOT_FOUND not in result.output, result.output


class TestARefusalEndsTheScan:
    def test_no_runner(self, runtime, monkeypatch):
        monkeypatch.setattr(rac, "_find_runner", lambda _name: None)

        result = CliRunner().invoke(app, SCAN)

        _assert_stopped_after_refusal(result, "Unable to resolve an OCI runner")
        assert runtime["executed"] == 0

    def test_non_numeric_uid(self, runtime):
        result = CliRunner().invoke(app, [*SCAN, "--container-uid", "root"])

        _assert_stopped_after_refusal(result, "Container UID must be a numeric value")

    def test_unsafe_revision(self, runtime):
        result = CliRunner().invoke(
            app, [*SCAN, "--ash-revision-to-install", "main;touch pwned"]
        )

        _assert_stopped_after_refusal(result, "Invalid ASH revision value")

    def test_failed_build_keeps_the_build_status(self, runtime, monkeypatch):
        def explode(**_kwargs):
            raise CalledProcessError(125, ["docker", "build"])

        monkeypatch.setattr(rac, "_build_image", explode)

        result = CliRunner().invoke(app, SCAN)

        _assert_stopped_after_refusal(result, "Error building ASH image", 125)
        assert runtime["executed"] == 0

    def test_missing_dockerfile_for_a_build(self, runtime, monkeypatch, tmp_path):
        def missing(_rev):
            raise FileNotFoundError(f"Dockerfile not found at {tmp_path}")

        monkeypatch.setattr(rac, "_find_dockerfile", missing)

        result = CliRunner().invoke(app, SCAN)

        _assert_stopped_after_refusal(result, "Dockerfile not found")
        assert runtime["build"] == 0

    def test_a_container_that_ran_still_reads_its_results_back(self, runtime):
        """The other side of the mark: a run that left nothing is still reported."""
        result = CliRunner().invoke(app, SCAN)

        assert runtime["executed"] == 1
        assert result.exit_code == 1
        assert NOT_FOUND in result.output

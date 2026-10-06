# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What container mode prints before the container starts: runner selection,
argument refusals and a failed image build.

The real CLI runs in-process; only runner discovery and the runner process are
replaced (``fake_docker`` in conftest.py), so the command ASH assembles, the
messages and the exit code are all ASH's own.
"""

from __future__ import annotations

import pytest

from tests.snapshot.container.conftest import FakeStep

SCAN = ["scan", "--mode", "container", "--no-progress", "--source-dir", "src"]


@pytest.fixture(autouse=True)
def _src(in_tmp, local_checkout):
    (in_tmp / "src").mkdir()


class TestRunnerSelection:
    def test_no_runner_on_path(self, run_cli, snapshot, fake_docker, monkeypatch):
        # None of finch, docker, nerdctl or podman is installed.
        from automated_security_helper.interactions import run_ash_container

        monkeypatch.setattr(run_ash_container, "_find_runner", lambda _name: None)
        assert run_cli([*SCAN, "--output-dir", "out"]) == snapshot
        assert fake_docker.calls == []

    def test_named_runner_not_installed(self, run_cli, snapshot, fake_docker):
        assert (
            run_cli([*SCAN, "--output-dir", "out", "--oci-runner", "podman"])
            == snapshot
        )
        assert fake_docker.calls == []

    def test_build_image_without_a_runner(
        self, run_cli, snapshot, fake_docker, monkeypatch
    ):
        from automated_security_helper.interactions import run_ash_container

        monkeypatch.setattr(run_ash_container, "_find_runner", lambda _name: None)
        assert run_cli(["build-image", "--no-run"]) == snapshot


class TestRefusals:
    def test_non_numeric_container_uid(self, run_cli, snapshot, fake_docker):
        assert (
            run_cli([*SCAN, "--output-dir", "out", "--container-uid", "root"])
            == snapshot
        )
        assert fake_docker.calls == []

    def test_unsafe_revision(self, run_cli, snapshot, fake_docker):
        assert (
            run_cli(
                [
                    *SCAN,
                    "--output-dir",
                    "out",
                    "--ash-revision-to-install",
                    "main;touch pwned",
                ]
            )
            == snapshot
        )
        assert fake_docker.calls == []


class TestDockerfileLookup:
    def test_no_build_outside_a_checkout(self, run_cli, snapshot, fake_docker, in_tmp):
        # MEASURED: --no-build still resolves a Dockerfile first. With ASH installed
        # from a checkout (revision LOCAL) and the working directory outside it, the
        # scan stops there although nothing was going to be built.
        (in_tmp / "Dockerfile").unlink()
        assert run_cli([*SCAN, "--no-build", "--output-dir", "out"]) == snapshot
        assert fake_docker.calls == []


class TestBuildFailure:
    BUILD_ERROR = FakeStep(
        returncode=1,
        stderr='Error: building at STEP "RUN grype --version": exit status 127\n',
    )

    def test_scan_after_failed_build(self, run_cli, snapshot, fake_docker):
        fake_docker.build = self.BUILD_ERROR
        assert run_cli([*SCAN, "--output-dir", "out"]) == snapshot
        assert fake_docker.calls == ["build"]

    def test_build_image_no_run_after_failed_build(
        self, run_cli, snapshot, fake_docker
    ):
        fake_docker.build = self.BUILD_ERROR
        assert run_cli(["build-image", "--no-run"]) == snapshot
        assert fake_docker.calls == ["build"]

    def test_build_image_no_run_succeeds(self, run_cli, snapshot, fake_docker):
        fake_docker.build = FakeStep(stdout="Successfully tagged image\n")
        assert run_cli(["build-image", "--no-run"]) == snapshot
        assert fake_docker.calls == ["build"]

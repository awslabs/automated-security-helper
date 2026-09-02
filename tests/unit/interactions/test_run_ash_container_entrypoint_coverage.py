# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""run_ash_container's refusals, defaults, and error surfaces.

Why this file exists
--------------------
``run_ash_container`` is the one function in the module that never raises. Every
failure it can hit -- an unreadable host UID, a non-numeric container UID, no OCI
runner on PATH, a revision carrying shell metacharacters, a missing Dockerfile, a
build that fails, an unwritable output directory -- is converted into a
``CompletedProcess`` with a non-zero returncode and a message on stderr, because
its callers inspect ``returncode`` rather than catching. That contract was
entirely untested: nothing pinned which code comes back, or that a message
reaches the caller at all.

The other half of the file is the cwd-based defaults. ``source_dir`` and
``output_dir`` default to ``None`` and are resolved at call time rather than at
import, so that importing the module does not freeze the process's working
directory into the signature. The tests assert on the values
``_assemble_run_command`` is handed, which is where those defaults become
observable.

No container is built or run. Every collaborator that would touch an OCI runtime
is replaced by a recorder, so what is asserted is the decision
``run_ash_container`` made, not the runtime's behaviour.
"""

from __future__ import annotations

from pathlib import Path
from subprocess import CalledProcessError
from typing import Any, Dict, List

import pytest

from automated_security_helper.interactions import run_ash_container as rac
from automated_security_helper.interactions.run_ash_container import run_ash_container
from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.subprocess_utils import create_completed_process


@pytest.fixture
def container_stubs(monkeypatch, tmp_path):
    """Replace every collaborator that would reach an OCI runtime.

    Returns a dict the test can read after the call: ``build`` and ``custom``
    record the kwargs each build helper was handed, ``run_command`` records the
    kwargs ``_assemble_run_command`` received, and ``executed`` records the
    command list handed to ``_execute_container``.
    """
    dockerfile = tmp_path / "assets" / "Dockerfile"
    dockerfile.parent.mkdir(parents=True)
    dockerfile.write_text("FROM scratch\n", encoding="utf-8")

    recorded: Dict[str, Any] = {
        "build": [],
        "custom": [],
        "run_command": [],
        "executed": [],
        "dockerfile": dockerfile,
    }

    monkeypatch.setattr(subprocess_utils, "get_host_uid", lambda: 4242)
    monkeypatch.setattr(subprocess_utils, "get_host_gid", lambda: 4343)
    monkeypatch.setattr(rac, "_resolve_oci_runner", lambda oci_runner: "docker")
    monkeypatch.setattr(rac, "get_ash_revision", lambda: "LOCAL")
    monkeypatch.setattr(rac, "_find_dockerfile", lambda revision: dockerfile)

    def fake_build_image(**kwargs):
        recorded["build"].append(kwargs)

    def fake_build_custom_image(**kwargs):
        recorded["custom"].append(kwargs)
        return "automated-security-helper:custom"

    def fake_assemble(**kwargs):
        recorded["run_command"].append(kwargs)
        return ["docker", "run", "--rm", kwargs["image_name"]]

    def fake_execute(cmd, debug=False):
        recorded["executed"].append(list(cmd))
        return create_completed_process(args=list(cmd), returncode=0)

    monkeypatch.setattr(rac, "_build_image", fake_build_image)
    monkeypatch.setattr(rac, "_build_custom_image", fake_build_custom_image)
    monkeypatch.setattr(rac, "_assemble_run_command", fake_assemble)
    monkeypatch.setattr(rac, "_execute_container", fake_execute)

    # The build target is derived from CI markers; clear them so the tests that
    # assert on the image name do not depend on where they run.
    for name in ("CI", "IsCI", "ISCI", "CODEBUILD_BUILD_ID", "ASH_IMAGE_NAME"):
        monkeypatch.delenv(name, raising=False)

    return recorded


# ---------------------------------------------------------------------------
# cwd-based defaults
# ---------------------------------------------------------------------------


class TestCwdDefaults:
    def test_source_and_output_default_to_the_cwd_at_call_time(
        self, container_stubs, monkeypatch, tmp_path
    ):
        """Resolved per call, so importing the module cannot pin the directory."""
        workdir = tmp_path / "workdir"
        workdir.mkdir()
        monkeypatch.chdir(workdir)

        run_ash_container(source_dir=None, output_dir=None, build=False, run=True)

        kwargs = container_stubs["run_command"][0]
        assert kwargs["source_dir"] == workdir.resolve()
        assert kwargs["output_dir"] == (workdir / ".ash" / "ash_output").resolve()

    def test_an_empty_source_dir_falls_back_to_the_cwd(
        self, container_stubs, monkeypatch, tmp_path
    ):
        workdir = tmp_path / "workdir"
        workdir.mkdir()
        monkeypatch.chdir(workdir)

        run_ash_container(source_dir="", output_dir="", build=False, run=True)

        kwargs = container_stubs["run_command"][0]
        assert kwargs["source_dir"] == Path.cwd()
        assert kwargs["output_dir"] == workdir / "ash_output"
        assert (workdir / "ash_output").is_dir()

    def test_building_without_running_returns_success_without_a_run_command(
        self, container_stubs, tmp_path
    ):
        result = run_ash_container(source_dir=tmp_path, build=True, run=False)

        assert result.returncode == 0
        assert container_stubs["build"], "the build helper should still have run"
        assert container_stubs["run_command"] == []


# ---------------------------------------------------------------------------
# Refusals -- each returns a non-zero CompletedProcess rather than raising
# ---------------------------------------------------------------------------


class TestHostIdentityFailure:
    def test_an_unreadable_host_uid_returns_code_one(
        self, container_stubs, monkeypatch, tmp_path
    ):
        def explode():
            raise OSError("id -u unavailable")

        monkeypatch.setattr(subprocess_utils, "get_host_uid", explode)

        result = run_ash_container(source_dir=tmp_path, build=False, run=False)

        assert result.returncode == 1
        assert "id -u unavailable" in result.stderr
        assert container_stubs["build"] == []


class TestContainerIdValidation:
    def test_a_non_numeric_container_uid_is_refused(self, container_stubs, tmp_path):
        result = run_ash_container(
            source_dir=tmp_path, container_uid="root", build=False, run=False
        )

        assert result.returncode == 1
        assert result.stderr == "Container UID must be a numeric value"

    def test_a_non_numeric_container_gid_is_refused(self, container_stubs, tmp_path):
        result = run_ash_container(
            source_dir=tmp_path, container_gid="wheel", build=False, run=False
        )

        assert result.returncode == 1
        assert result.stderr == "Container GID must be a numeric value"

    def test_the_host_ids_are_used_when_none_are_given(self, container_stubs, tmp_path):
        run_ash_container(source_dir=tmp_path, build=True, run=False)

        kwargs = container_stubs["build"][0]
        assert kwargs["container_uid"] == "4242"
        assert kwargs["container_gid"] == "4343"

    def test_numeric_overrides_are_honoured(self, container_stubs, tmp_path):
        run_ash_container(
            source_dir=tmp_path,
            container_uid="501",
            container_gid="20",
            build=True,
            run=False,
        )

        kwargs = container_stubs["build"][0]
        assert kwargs["container_uid"] == "501"
        assert kwargs["container_gid"] == "20"


class TestRunnerResolutionFailure:
    def test_no_available_runner_returns_code_one(
        self, container_stubs, monkeypatch, tmp_path
    ):
        def explode(oci_runner):
            raise RuntimeError("Unable to resolve an OCI runner")

        monkeypatch.setattr(rac, "_resolve_oci_runner", explode)

        result = run_ash_container(source_dir=tmp_path, build=False, run=False)

        assert result.returncode == 1
        assert result.stderr == "Unable to resolve an OCI runner"


class TestRevisionValidation:
    def test_a_revision_with_shell_metacharacters_is_refused(
        self, container_stubs, tmp_path
    ):
        """The revision becomes a --build-arg, so it must not carry a command."""
        result = run_ash_container(
            source_dir=tmp_path,
            ash_revision_to_install="v1.0.0; touch pwned",
            build=True,
            run=False,
        )

        assert result.returncode == 1
        assert "Invalid ASH revision value" in result.stderr
        assert container_stubs["build"] == [], "no build should have been attempted"

    def test_a_plain_tag_is_accepted(self, container_stubs, tmp_path):
        run_ash_container(
            source_dir=tmp_path,
            ash_revision_to_install="v3.1.0",
            build=True,
            run=False,
        )

        assert container_stubs["build"][0]["resolved_revision"] == "v3.1.0"

    def test_local_bypasses_the_pattern_check(self, container_stubs, tmp_path):
        run_ash_container(
            source_dir=tmp_path,
            ash_revision_to_install="LOCAL",
            build=True,
            run=False,
        )

        assert container_stubs["build"][0]["resolved_revision"] == "LOCAL"


class TestDockerfileResolutionFailure:
    def test_a_missing_dockerfile_returns_code_one(
        self, container_stubs, monkeypatch, tmp_path
    ):
        def explode(revision):
            raise FileNotFoundError("Dockerfile not found at " + tmp_path.as_posix())

        monkeypatch.setattr(rac, "_find_dockerfile", explode)

        result = run_ash_container(source_dir=tmp_path, build=True, run=False)

        assert result.returncode == 1
        assert "Dockerfile not found at" in result.stderr
        assert container_stubs["build"] == []


# ---------------------------------------------------------------------------
# Build failures
# ---------------------------------------------------------------------------


class TestBuildFailure:
    def test_a_called_process_error_is_returned_unchanged(
        self, container_stubs, monkeypatch, tmp_path, capfd
    ):
        """The caller needs the original returncode, not a flattened 1."""
        failure = CalledProcessError(
            125, ["docker", "build"], output="build stdout", stderr="build stderr"
        )

        def explode(**kwargs):
            raise failure

        monkeypatch.setattr(rac, "_build_image", explode)

        result = run_ash_container(
            source_dir=tmp_path, build=True, run=False, debug=True
        )

        assert result is failure
        out = capfd.readouterr().out
        assert "Build stdout: build stdout" in out
        assert "Build stderr: build stderr" in out

    def test_any_other_build_error_becomes_code_one(
        self, container_stubs, monkeypatch, tmp_path
    ):
        def explode(**kwargs):
            raise RuntimeError("disk full")

        monkeypatch.setattr(rac, "_build_image", explode)

        result = run_ash_container(source_dir=tmp_path, build=True, run=False)

        assert result.returncode == 1
        assert result.stderr == "disk full"

    def test_a_build_failure_stops_before_the_run_phase(
        self, container_stubs, monkeypatch, tmp_path
    ):
        def explode(**kwargs):
            raise RuntimeError("disk full")

        monkeypatch.setattr(rac, "_build_image", explode)

        run_ash_container(source_dir=tmp_path, build=True, run=True)

        assert container_stubs["executed"] == []


class TestCustomContainerfile:
    def test_the_custom_image_replaces_the_base_image_for_the_run(
        self, container_stubs, tmp_path
    ):
        containerfile = tmp_path / "Containerfile"
        containerfile.write_text("ARG ASH_BASE_IMAGE\n", encoding="utf-8")

        run_ash_container(
            source_dir=tmp_path,
            custom_containerfile=containerfile.as_posix(),
            build=True,
            run=True,
        )

        assert container_stubs["custom"][0]["custom_containerfile"] == (
            containerfile.as_posix()
        )
        # A custom containerfile forces the `ci` target, so the base handed to
        # the custom build is the ci image, and the run uses the custom tag.
        assert container_stubs["custom"][0]["base_image_name"] == (
            "automated-security-helper:ci"
        )
        assert container_stubs["run_command"][0]["image_name"] == (
            "automated-security-helper:custom"
        )

    def test_without_a_custom_containerfile_the_base_image_is_run(
        self, container_stubs, tmp_path
    ):
        run_ash_container(source_dir=tmp_path, build=True, run=True)

        assert container_stubs["custom"] == []
        assert container_stubs["run_command"][0]["image_name"] == (
            "automated-security-helper:non-root"
        )


# ---------------------------------------------------------------------------
# Run-phase path handling
# ---------------------------------------------------------------------------


class TestRunPhasePaths:
    def test_a_nonexistent_source_dir_returns_code_one(self, container_stubs, tmp_path):
        missing = tmp_path / "not-here"

        result = run_ash_container(source_dir=missing, build=False, run=True)

        assert result.returncode == 1
        assert "Path does not exist" in result.stderr
        assert container_stubs["run_command"] == []

    def test_an_uncreatable_output_dir_returns_code_one(
        self, container_stubs, tmp_path
    ):
        """A file where the parent directory should be cannot be mkdir'd through."""
        blocker = tmp_path / "blocker"
        blocker.write_text("not a directory\n", encoding="utf-8")

        result = run_ash_container(
            source_dir=tmp_path,
            output_dir=blocker / "nested",
            build=False,
            run=True,
        )

        assert result.returncode == 1
        assert result.stderr != ""
        assert container_stubs["run_command"] == []

    def test_the_output_dir_is_created_and_resolved(self, container_stubs, tmp_path):
        output_dir = tmp_path / "deep" / "output"

        run_ash_container(
            source_dir=tmp_path, output_dir=output_dir, build=False, run=True
        )

        assert output_dir.is_dir()
        assert container_stubs["run_command"][0]["output_dir"] == output_dir.resolve()

    def test_the_execute_result_is_returned_to_the_caller(
        self, container_stubs, tmp_path
    ):
        result = run_ash_container(source_dir=tmp_path, build=False, run=True)

        assert result.returncode == 0
        assert container_stubs["executed"][0][:3] == ["docker", "run", "--rm"]


# ---------------------------------------------------------------------------
# Mutable defaults
# ---------------------------------------------------------------------------


class TestMutableDefaults:
    def test_each_call_gets_its_own_collections(self, container_stubs, tmp_path):
        """A shared default list would accumulate across calls."""
        run_ash_container(source_dir=tmp_path, build=False, run=True)
        first: List[str] = container_stubs["run_command"][0]["scanners"]
        first.append("leaked")

        run_ash_container(source_dir=tmp_path, build=False, run=True)
        second = container_stubs["run_command"][1]["scanners"]

        assert second == []

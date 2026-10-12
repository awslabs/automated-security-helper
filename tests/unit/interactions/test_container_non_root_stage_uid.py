# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A ``non-root`` image build whose user would get UID 0 is refused before it starts.

The ``non-root`` stage of the Dockerfile creates its user with ``adduser --uid
<UID>``, and the UID is the host's unless ``--container-uid`` names one. UID 0 is
root, which already exists, so that build fails at ``adduser`` after the whole
``core`` stage has been built. With ``non-root`` the default everywhere, a CI job
that runs as root (AWS CodeBuild, container-based GitLab and Jenkins jobs) reaches
this on every build, so ASH refuses it up front and names the two ways forward.

``ci`` has no user to create and builds as before; ``--no-build`` builds nothing.
"""

from __future__ import annotations

from typing import List

import pytest

from automated_security_helper.core.enums import BuildTarget
from automated_security_helper.interactions import run_ash_container as rac
from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.subprocess_utils import create_completed_process


@pytest.fixture
def commands(monkeypatch, tmp_path) -> List[List[str]]:
    """Record runner commands instead of running them; the host user is root."""
    seen: List[List[str]] = []

    def record(cmd_list, check=True, debug=False, shell=False):
        cmd = [str(item) for item in cmd_list if item is not None]
        seen.append(cmd)
        return create_completed_process(args=cmd, returncode=0, stdout="", stderr="")

    assets = tmp_path / "assets"
    assets.mkdir()
    (assets / "Dockerfile").write_text("FROM scratch AS non-root\n", encoding="utf-8")
    monkeypatch.setattr(rac, "ASH_ASSETS_DIR", assets)
    monkeypatch.setattr(subprocess_utils, "get_host_uid", lambda: 0)
    monkeypatch.setattr(subprocess_utils, "get_host_gid", lambda: 0)
    monkeypatch.setattr(
        rac, "_find_runner", lambda _name: "/nonexistent/ash-test/docker"
    )
    monkeypatch.setattr(rac, "_runner_supports_buildx", lambda _runner: False)
    monkeypatch.setattr(rac, "run_cmd_direct", record)
    for name in (
        "CI",
        "IsCI",
        "ISCI",
        "CODEBUILD_BUILD_ID",
        "ASH_IMAGE_NAME",
        "OCI_RUNNER",
        "OCI_RUNNER_WRAPPER",
    ):
        monkeypatch.delenv(name, raising=False)
    (tmp_path / "src").mkdir()
    monkeypatch.chdir(tmp_path)
    return seen


@pytest.mark.parametrize(
    ("build_target", "container_uid"),
    [
        pytest.param(None, None, id="default-target-as-root"),
        pytest.param(BuildTarget.NON_ROOT, None, id="explicit-non-root-as-root"),
        # The build reads stage names in any case; a library caller may pass a string.
        pytest.param("NON-ROOT", None, id="explicit-non-root-in-capitals-as-root"),
        pytest.param(None, "0", id="container-uid-0"),
        # The build reads UID=00 as 0 as well.
        pytest.param(None, "00", id="container-uid-00"),
    ],
)
def test_a_non_root_build_as_uid_0_is_refused_before_building(
    build_target, container_uid, commands
):
    result = rac.run_ash_container(
        source_dir="src",
        output_dir="out",
        ash_revision_to_install="v3.7.0",
        build=True,
        run=True,
        build_target=build_target,
        container_uid=container_uid,
    )

    assert commands == [], f"a runner command was started: {commands}"
    assert result.returncode == 1
    assert not rac.container_was_started(result)
    assert "--build-target ci" in result.stderr
    assert "--container-uid" in result.stderr


def test_the_ci_stage_builds_as_root(commands):
    """Control: ``ci`` creates no user, so UID 0 is no obstacle."""
    result = rac.run_ash_container(
        source_dir="src",
        output_dir="out",
        ash_revision_to_install="v3.7.0",
        build=True,
        run=False,
        build_target=BuildTarget.CI,
    )

    assert result.returncode == 0
    assert [cmd[1] for cmd in commands] == ["build"]


def test_a_non_root_build_with_a_container_uid_builds_as_root(commands):
    """Control: an explicit non-zero --container-uid gives the user its own UID."""
    result = rac.run_ash_container(
        source_dir="src",
        output_dir="out",
        ash_revision_to_install="v3.7.0",
        build=True,
        run=False,
        container_uid="1000",
        container_gid="1000",
    )

    assert result.returncode == 0
    build = commands[0]
    assert "UID=1000" in build
    assert build[build.index("--target") + 1] == "non-root"


def test_no_build_as_root_runs_the_existing_image(commands):
    """Control: nothing is built, so there is no user to create."""
    result = rac.run_ash_container(
        source_dir="src", output_dir="out", build=False, run=True
    )

    assert result.returncode == 0
    assert [cmd[1] for cmd in commands] == ["run"]


@pytest.mark.parametrize("uid", ["²", "٠"], ids=["superscript-two", "arabic-zero"])
def test_a_uid_of_digits_other_than_0_to_9_is_not_a_number(uid, commands):
    """``str.isdigit`` accepts these; the build and ``int`` do not read them as a UID."""
    result = rac.run_ash_container(
        source_dir="src",
        output_dir="out",
        ash_revision_to_install="v3.7.0",
        build=True,
        run=True,
        container_uid=uid,
    )

    assert commands == []
    assert result.returncode == 1
    assert "Container UID must be a numeric value" in result.stderr


@pytest.mark.parametrize("gid", ["0", "00"])
def test_a_non_root_build_with_gid_0_is_refused_before_building(gid, commands):
    """GID 0 is root's group: the non-root user would get root's group rights."""
    result = rac.run_ash_container(
        source_dir="src",
        output_dir="out",
        ash_revision_to_install="v3.7.0",
        build=True,
        run=True,
        container_uid="1000",
        container_gid=gid,
    )

    assert commands == [], f"a runner command was started: {commands}"
    assert result.returncode == 1
    assert not rac.container_was_started(result)
    assert "GID 0" in result.stderr
    assert "--build-target ci" in result.stderr
    assert "--container-gid" in result.stderr


@pytest.mark.parametrize(
    "gid", ["²", "٠", "1x"], ids=["superscript-two", "arabic-zero", "letter"]
)
def test_a_gid_of_anything_but_0_to_9_is_not_a_number(gid, commands):
    result = rac.run_ash_container(
        source_dir="src",
        output_dir="out",
        ash_revision_to_install="v3.7.0",
        build=True,
        run=True,
        container_uid="1000",
        container_gid=gid,
    )

    assert commands == []
    assert result.returncode == 1
    assert "Container GID must be a numeric value" in result.stderr


def test_an_unprivileged_host_user_builds_non_root_as_itself(commands, monkeypatch):
    """Control: the refusal is about root; any other host user is unaffected."""
    monkeypatch.setattr(subprocess_utils, "get_host_uid", lambda: 1000)
    monkeypatch.setattr(subprocess_utils, "get_host_gid", lambda: 1000)

    result = rac.run_ash_container(
        source_dir="src",
        output_dir="out",
        ash_revision_to_install="v3.7.0",
        build=True,
        run=False,
    )

    assert result.returncode == 0, result.stderr
    [build] = commands
    assert build[build.index("--target") + 1] == "non-root"
    assert "UID=1000" in build and "GID=1000" in build


@pytest.mark.parametrize("written", ["Non-Root", "NON-ROOT", "CI"])
def test_the_stage_is_built_by_its_lower_case_name(written, commands, monkeypatch):
    monkeypatch.setattr(subprocess_utils, "get_host_uid", lambda: 1000)
    monkeypatch.setattr(subprocess_utils, "get_host_gid", lambda: 1000)

    result = rac.run_ash_container(
        source_dir="src",
        output_dir="out",
        ash_revision_to_install="v3.7.0",
        build=True,
        run=False,
        build_target=written,
    )

    assert result.returncode == 0, result.stderr
    [build] = commands
    assert build[build.index("--target") + 1] == written.lower()
    assert f"automated-security-helper:{written.lower()}" in build


@pytest.mark.parametrize(
    ("container_uid", "container_gid", "id_flag"),
    [
        pytest.param(None, None, "--container-uid", id="uid-0"),
        pytest.param("1000", "0", "--container-gid", id="gid-0"),
    ],
)
def test_the_refusal_names_ci_first_and_other_ids_only_with_a_writable_output(
    container_uid, container_gid, id_flag, commands
):
    """On a root host the output directory is root's, so another UID can scan only
    when that directory is writable by it; ``ci`` works as it is."""
    result = rac.run_ash_container(
        source_dir="src",
        output_dir="out",
        ash_revision_to_install="v3.7.0",
        container_uid=container_uid,
        container_gid=container_gid,
    )

    # The advice starts with ci; the cause before it may name the flag as given.
    advice = result.stderr[result.stderr.index("Pass --build-target ci") :]
    assert id_flag in advice
    assert "output directory is writable" in advice[advice.index(id_flag) :]


def test_the_gid_has_no_default():
    """A caller that leaves the GID out gets an error, not a GID check skipped."""
    with pytest.raises(TypeError):
        rac._non_root_stage_uid_refusal(BuildTarget.NON_ROOT.value, "1000")


def test_the_refusal_names_the_opt_in_exactly(commands):
    """The message names the flag that builds the root stage, as it is typed."""
    result = rac.run_ash_container(
        source_dir="src", output_dir="out", ash_revision_to_install="v3.7.0"
    )

    assert result.returncode == 1
    assert "Pass --build-target ci " in result.stderr

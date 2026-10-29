# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for decomposed helpers in run_ash_container."""

import os
from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.interactions.run_ash_container import (
    _assemble_run_command,
    _find_dockerfile,
    _resolve_oci_runner,
)


# ---------------------------------------------------------------------------
# _resolve_oci_runner
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_resolve_oci_runner_finch_first():
    """When multiple runners are on PATH, the first discovered wins (finch before docker)."""

    def fake_find(name):
        return {
            "finch": "/usr/local/bin/finch",
            "docker": "/usr/bin/docker",
            "nerdctl": "/usr/local/bin/nerdctl",
            "podman": "/usr/bin/podman",
        }.get(name)

    with patch(
        "automated_security_helper.interactions.run_ash_container._find_runner",
        side_effect=fake_find,
    ):
        result = _resolve_oci_runner(oci_runner=None)
    assert result == "/usr/local/bin/finch"


@pytest.mark.unit
def test_resolve_oci_runner_docker_when_no_finch():
    """Falls back to docker when finch is not available."""

    def fake_find(name):
        return {
            "docker": "/usr/bin/docker",
        }.get(name)

    with patch(
        "automated_security_helper.interactions.run_ash_container._find_runner",
        side_effect=fake_find,
    ):
        result = _resolve_oci_runner(oci_runner=None)
    assert result == "/usr/bin/docker"


@pytest.mark.unit
def test_resolve_oci_runner_raises_when_none_available():
    """Raises RuntimeError when no OCI runner is found."""
    with patch(
        "automated_security_helper.interactions.run_ash_container._find_runner",
        return_value=None,
    ):
        with pytest.raises(RuntimeError, match="Unable to resolve an OCI runner"):
            _resolve_oci_runner(oci_runner=None)


@pytest.mark.unit
def test_resolve_oci_runner_respects_explicit_arg():
    """Explicit oci_runner bypasses discovery and returns the found path."""

    def fake_find(name):
        return "/usr/bin/podman" if name == "podman" else None

    with patch(
        "automated_security_helper.interactions.run_ash_container._find_runner",
        side_effect=fake_find,
    ):
        result = _resolve_oci_runner(oci_runner="podman")
    assert result == "/usr/bin/podman"


@pytest.mark.unit
def test_resolve_oci_runner_respects_env_wrapper():
    """OCI_RUNNER_WRAPPER env var is returned as a prefix list via the helper."""

    # _resolve_oci_runner returns just the runner path; the wrapper is read
    # separately via _get_oci_wrapper_prefix. Verify _resolve_oci_runner itself
    # still returns just the resolved runner path even when the env var is set.
    def fake_find(name):
        return "/usr/bin/docker" if name == "docker" else None

    with patch.dict(os.environ, {"OCI_RUNNER_WRAPPER": "sudo"}):
        with patch(
            "automated_security_helper.interactions.run_ash_container._find_runner",
            side_effect=fake_find,
        ):
            result = _resolve_oci_runner(oci_runner=None)
    assert result == "/usr/bin/docker"


# ---------------------------------------------------------------------------
# _find_dockerfile
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_find_dockerfile_uses_repo_dockerfile(tmp_path):
    """Returns the bundled Dockerfile from ASH_ASSETS_DIR when not in a repo dir."""
    fake_dockerfile = tmp_path / "Dockerfile"
    fake_dockerfile.write_text("FROM scratch\n")

    # Patch both ASH_ASSETS_DIR and Path.cwd so the cwd-check path doesn't find
    # a stray pyproject.toml + Dockerfile in the actual working directory.
    empty_dir = tmp_path / "notarepo"
    empty_dir.mkdir()

    with (
        patch(
            "automated_security_helper.interactions.run_ash_container.ASH_ASSETS_DIR",
            tmp_path,
        ),
        patch(
            "automated_security_helper.interactions.run_ash_container.Path.cwd",
            return_value=empty_dir,
        ),
    ):
        result = _find_dockerfile(resolved_revision="abc123")
    assert result == fake_dockerfile


# ---------------------------------------------------------------------------
# _assemble_run_command
# ---------------------------------------------------------------------------


def _base_assemble_kwargs(**overrides):
    base = {
        "oci_command_prefix": [],
        "resolved_oci_runner": "/usr/bin/docker",
        "image_name": "automated-security-helper:non-root",
        "source_dir": Path("/src/code"),
        "output_dir": Path("/src/code/ash_output"),
        "offline": False,
        "debug": False,
        "color": True,
        "quiet": False,
        "progress": True,
        "verbose": False,
        "simple": False,
        "python_based_plugins_only": False,
        "cleanup": False,
        "inspect": False,
        "fail_on_findings": None,
        "phases": [],
        "scanners": [],
        "exclude_scanners": [],
        "output_formats": [],
        "config": None,
        "config_overrides": [],
        "existing_results": None,
        "ash_plugin_modules": [],
        "strategy": None,
        "ctx": None,
    }
    base.update(overrides)
    return base


@pytest.mark.unit
def test_assemble_run_command_mounts():
    """--mount flags for source and output dirs are present and correct."""
    kwargs = _base_assemble_kwargs()
    cmd = _assemble_run_command(**kwargs)
    mount_args = [cmd[i + 1] for i, a in enumerate(cmd) if a == "--mount"]
    # The mount string is built with an f-string over the Path, so the host side
    # is str(Path) and uses the host separator: "\\src\\code" on Windows,
    # "/src/code" elsewhere. Derive the expectation from the same object rather
    # than hardcoding forward slashes.
    expected_source = str(kwargs["source_dir"])
    assert any(expected_source in m and "destination=/src" in m for m in mount_args), (
        mount_args
    )
    assert any("destination=/out" in m for m in mount_args), mount_args


@pytest.mark.unit
def test_assemble_run_command_env_vars():
    """ASH_ACTUAL_SOURCE_DIR and ASH_ACTUAL_OUTPUT_DIR are set correctly."""
    kwargs = _base_assemble_kwargs()
    cmd = _assemble_run_command(**kwargs)
    env_values = [cmd[i + 1] for i, a in enumerate(cmd) if a == "-e"]
    assert any(v.startswith("ASH_ACTUAL_SOURCE_DIR=") for v in env_values)
    assert any(v.startswith("ASH_ACTUAL_OUTPUT_DIR=") for v in env_values)
    src_val = next(v for v in env_values if v.startswith("ASH_ACTUAL_SOURCE_DIR="))
    out_val = next(v for v in env_values if v.startswith("ASH_ACTUAL_OUTPUT_DIR="))
    # Host paths, so separator-dependent - compare against str(Path) as above.
    assert str(kwargs["source_dir"]) in src_val, src_val
    assert "ash_output" in out_val, out_val


@pytest.mark.unit
def test_assemble_run_command_carries_ash_config_as_a_mount_not_the_variable(tmp_path):
    """The assembled command never passes ASH_CONFIG as an environment
    variable: the value is a host path, meaningless inside the container. The
    file it names is mounted read-only instead and its container path is
    passed with --ash-config-from-host, so the scan inside reads the same base
    a local scan reads, from a path that exists there."""
    config = tmp_path / "operator" / "ash.yaml"
    config.parent.mkdir()
    config.write_text("project_name: operator\n", encoding="utf-8")
    kwargs = _base_assemble_kwargs()
    with patch.dict(os.environ, {"ASH_CONFIG": str(config)}):
        cmd = _assemble_run_command(**kwargs)
    env_args = [cmd[i + 1] for i, a in enumerate(cmd) if a == "-e"]
    carried = [v for v in env_args if v == "ASH_CONFIG" or v.startswith("ASH_CONFIG=")]
    assert carried == [], carried
    # The control: the same read finds the env arguments the command does set.
    assert any(v.startswith("ASH_ACTUAL_SOURCE_DIR=") for v in env_args), env_args
    # The file rides as a read-only mount under /ash-env-config instead, and
    # the inner scan is told its path there.
    inner = cmd[cmd.index("--ash-config-from-host") + 1]
    assert inner.startswith("/ash-env-config/"), inner
    mounts = [cmd[i + 1] for i, a in enumerate(cmd) if a == "--mount"]
    expected = (
        f"type=bind,source={os.path.realpath(config)},destination={inner},readonly"
    )
    assert expected in mounts, mounts


def _git_repo(root: Path) -> Path:
    import subprocess

    root.mkdir(parents=True)
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    return root


def _scan_source_env(cmd):
    env_values = [cmd[i + 1] for i, a in enumerate(cmd) if a == "-e"]
    return [v for v in env_values if v.startswith("ASH_SCAN_SOURCE=")]


@pytest.mark.integration
def test_the_container_scan_is_told_the_scanned_directory_within_its_repository(
    tmp_path, _git_stops_at_tmp
):
    """Inside the container the source is always /src, and git there cannot see
    the repository when only a subdirectory is mounted. The host can, so the
    label is worked out here and passed in; without it container scans of
    services/api and services/web both recorded "/src" and shared one scope."""
    source = _git_repo(tmp_path / "repo") / "services" / "api"
    source.mkdir(parents=True)

    cmd = _assemble_run_command(
        **_base_assemble_kwargs(source_dir=source, output_dir=tmp_path / "out")
    )

    assert _scan_source_env(cmd) == ["ASH_SCAN_SOURCE=services/api"]


@pytest.fixture
def _git_stops_at_tmp(tmp_path, monkeypatch):
    """tmp_path, with git and the nesting check kept from looking above it.

    tmp_path is made an empty repository that excludes everything, with
    GIT_CEILING_DIRECTORIES there (tests/utils/git_isolation.py): git does not
    move up into it, and the repository it hides holds nothing below it, so the
    nesting check honors it too. So a tmp_path inside some other work tree (a
    basetemp under a worktree, a CI workspace) changes nothing here. No git runs
    in tmp_path itself.
    """
    from tests.utils.git_isolation import isolate_git_at

    isolate_git_at(tmp_path, monkeypatch)


@pytest.mark.integration
def test_an_empty_label_is_passed_for_a_directory_outside_a_repository(
    tmp_path, _git_stops_at_tmp
):
    """Empty, not absent: the scan in the container then records no scan_source
    and archives nothing, instead of asking git there, which sees only the
    mount."""
    source = tmp_path / "not-a-repo"
    source.mkdir()

    cmd = _assemble_run_command(
        **_base_assemble_kwargs(source_dir=source, output_dir=tmp_path / "out")
    )

    assert _scan_source_env(cmd) == ["ASH_SCAN_SOURCE="]


@pytest.mark.integration
def test_an_empty_label_is_passed_for_a_clone_nested_in_another_repository(
    tmp_path, _git_stops_at_tmp
):
    """The host sees the outer repository. Git in the container would see only
    the mount, a repository with nothing above it, and call it "."."""
    outer = _git_repo(tmp_path / "outer")
    nested = _git_repo(outer / "third_party" / "x")

    cmd = _assemble_run_command(
        **_base_assemble_kwargs(source_dir=nested, output_dir=tmp_path / "out")
    )

    assert _scan_source_env(cmd) == ["ASH_SCAN_SOURCE="]


@pytest.mark.integration
def test_workspace_mode_passes_the_mounts_own_label(tmp_path, _git_stops_at_tmp):
    """The label names the workspace mount. Projects in the container use git's
    view only when it is ".", the mount being a repository's root."""
    source = _git_repo(tmp_path / "repo") / "services"
    source.mkdir(parents=True)

    cmd = _assemble_run_command(
        **_base_assemble_kwargs(
            source_dir=source,
            output_dir=tmp_path / "out",
            workspace_relative_file="fixture.code-workspace",
        )
    )

    assert _scan_source_env(cmd) == ["ASH_SCAN_SOURCE=services"]


@pytest.mark.integration
def test_an_empty_label_is_passed_for_a_submodule(tmp_path, _git_stops_at_tmp):
    """A submodule's root is "." to git, as the superproject's root is; the two
    must not share a scope, so the label is empty and nothing is archived."""
    import subprocess

    def git(*args, cwd):
        subprocess.run(
            [
                "git",
                "-c",
                "user.name=fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "-c",
                "protocol.file.allow=always",
                *args,
            ],
            cwd=cwd,
            check=True,
            capture_output=True,
        )

    library = _git_repo(tmp_path / "library")
    (library / "README.md").write_text("library\n", encoding="utf-8")
    git("add", "README.md", cwd=library)
    git("commit", "-qm", "library", cwd=library)
    root = _git_repo(tmp_path / "super")
    (root / "README.md").write_text("super\n", encoding="utf-8")
    git("add", "README.md", cwd=root)
    git("commit", "-qm", "super", cwd=root)
    git("submodule", "add", "-q", library.as_uri(), "vendor/lib", cwd=root)

    cmd = _assemble_run_command(
        **_base_assemble_kwargs(
            source_dir=root / "vendor" / "lib", output_dir=tmp_path / "out"
        )
    )

    assert _scan_source_env(cmd) == ["ASH_SCAN_SOURCE="]


@pytest.mark.unit
def test_assemble_run_command_image_argument_position():
    """Image name appears before the 'ash' subcommand."""
    image = "automated-security-helper:non-root"
    cmd = _assemble_run_command(**_base_assemble_kwargs(image_name=image))
    img_idx = cmd.index(image)
    ash_idx = cmd.index("ash")
    assert img_idx < ash_idx


@pytest.mark.unit
def test_assemble_run_command_names_the_outer_run_id_without_its_value():
    """The in-container run writes it into its results file.

    By name only: the runner reads the value from its own environment
    (``_run_environment``), so it is not in the command line other processes on
    the host can read, nor in the command ``--debug`` prints.
    """
    run_id = "0123456789abcdef0123456789abcdef"
    cmd = _assemble_run_command(**_base_assemble_kwargs(outer_run_id=run_id))
    index = cmd.index("ASH_OUTER_RUN_ID")
    assert cmd[index - 1] == "-e"
    assert index < cmd.index("automated-security-helper:non-root")
    assert not any(run_id in arg for arg in cmd), cmd


@pytest.mark.unit
def test_assemble_run_command_passes_the_outer_run_id_through_a_wrapper():
    """OCI_RUNNER_WRAPPER (sudo, for one) need not pass the environment on."""
    run_id = "0123456789abcdef0123456789abcdef"
    cmd = _assemble_run_command(
        **_base_assemble_kwargs(outer_run_id=run_id, oci_command_prefix=["sudo"])
    )
    index = cmd.index(f"ASH_OUTER_RUN_ID={run_id}")
    assert cmd[index - 1] == "-e"


@pytest.mark.unit
def test_the_run_environment_carries_the_outer_run_id(monkeypatch):
    from automated_security_helper.interactions.run_ash_container import (
        _run_environment,
    )

    monkeypatch.setenv("ASH_TEST_INHERITED", "kept")
    run_id = "0123456789abcdef0123456789abcdef"

    environment = _run_environment(run_id)

    assert environment["ASH_OUTER_RUN_ID"] == run_id
    assert environment["ASH_TEST_INHERITED"] == "kept"
    assert _run_environment(None) is None


@pytest.mark.unit
def test_assemble_run_command_offline_uses_network_none():
    """--network=none is added when offline=True."""
    cmd = _assemble_run_command(**_base_assemble_kwargs(offline=True))
    assert "--network=none" in cmd


@pytest.mark.unit
def test_assemble_run_command_online_no_network_flag():
    """--network=none is NOT present when offline=False."""
    cmd = _assemble_run_command(**_base_assemble_kwargs(offline=False))
    assert "--network=none" not in cmd


@pytest.mark.unit
class TestTheInTreeToolOptInReachesTheContainer:
    """The container's ASH makes the same in-tree decision as the host's."""

    def env_values(self):
        cmd = _assemble_run_command(**_base_assemble_kwargs())
        return [cmd[i + 1] for i, a in enumerate(cmd) if a == "-e"]

    def test_forwarded_when_the_scan_allows_it(self, monkeypatch, tmp_path):
        from automated_security_helper.utils.subprocess_utils import scanning_tree

        monkeypatch.setenv("ASH_ALLOW_IN_TREE_TOOLS", "1")
        with scanning_tree(tmp_path):
            assert "ASH_ALLOW_IN_TREE_TOOLS=1" in self.env_values()

    def test_not_forwarded_otherwise(self, monkeypatch, tmp_path):
        from automated_security_helper.utils.subprocess_utils import scanning_tree

        monkeypatch.delenv("ASH_ALLOW_IN_TREE_TOOLS", raising=False)
        with scanning_tree(tmp_path):
            assert not [v for v in self.env_values() if "IN_TREE" in v]

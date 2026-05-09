# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for decomposed helpers in run_ash_container."""

import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.interactions.run_ash_container import (
    _assemble_run_command,
    _find_dockerfile,
    _resolve_oci_runner,
)


# ---------------------------------------------------------------------------
# _resolve_oci_runner
# ---------------------------------------------------------------------------


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


def test_resolve_oci_runner_raises_when_none_available():
    """Raises RuntimeError when no OCI runner is found."""
    with patch(
        "automated_security_helper.interactions.run_ash_container._find_runner",
        return_value=None,
    ):
        with pytest.raises(RuntimeError, match="Unable to resolve an OCI runner"):
            _resolve_oci_runner(oci_runner=None)


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


def test_find_dockerfile_uses_repo_dockerfile(tmp_path):
    """Returns the bundled Dockerfile from ASH_ASSETS_DIR when not in a repo dir."""
    fake_dockerfile = tmp_path / "Dockerfile"
    fake_dockerfile.write_text("FROM scratch\n")

    # Patch both ASH_ASSETS_DIR and Path.cwd so the cwd-check path doesn't find
    # a stray pyproject.toml + Dockerfile in the actual working directory.
    empty_dir = tmp_path / "notarepo"
    empty_dir.mkdir()

    with patch(
        "automated_security_helper.interactions.run_ash_container.ASH_ASSETS_DIR",
        tmp_path,
    ), patch(
        "automated_security_helper.interactions.run_ash_container.Path.cwd",
        return_value=empty_dir,
    ):
        result = _find_dockerfile(resolved_revision="abc123")
    assert result == fake_dockerfile


# ---------------------------------------------------------------------------
# _assemble_run_command
# ---------------------------------------------------------------------------


def _base_assemble_kwargs(**overrides):
    base = dict(
        oci_command_prefix=[],
        resolved_oci_runner="/usr/bin/docker",
        image_name="automated-security-helper:non-root",
        source_dir=Path("/src/code"),
        output_dir=Path("/src/code/ash_output"),
        offline=False,
        debug=False,
        color=True,
        quiet=False,
        progress=True,
        verbose=False,
        simple=False,
        python_based_plugins_only=False,
        cleanup=False,
        inspect=False,
        fail_on_findings=None,
        phases=[],
        scanners=[],
        exclude_scanners=[],
        output_formats=[],
        config=None,
        config_overrides=[],
        existing_results=None,
        ash_plugin_modules=[],
        strategy=None,
        ctx=None,
    )
    base.update(overrides)
    return base


def test_assemble_run_command_mounts():
    """--mount flags for source and output dirs are present and correct."""
    cmd = _assemble_run_command(**_base_assemble_kwargs())
    mount_args = [cmd[i + 1] for i, a in enumerate(cmd) if a == "--mount"]
    assert any("/src/code" in m and "destination=/src" in m for m in mount_args)
    assert any("destination=/out" in m for m in mount_args)


def test_assemble_run_command_env_vars():
    """ASH_ACTUAL_SOURCE_DIR and ASH_ACTUAL_OUTPUT_DIR are set correctly."""
    cmd = _assemble_run_command(**_base_assemble_kwargs())
    env_values = [cmd[i + 1] for i, a in enumerate(cmd) if a == "-e"]
    assert any(v.startswith("ASH_ACTUAL_SOURCE_DIR=") for v in env_values)
    assert any(v.startswith("ASH_ACTUAL_OUTPUT_DIR=") for v in env_values)
    src_val = next(v for v in env_values if v.startswith("ASH_ACTUAL_SOURCE_DIR="))
    out_val = next(v for v in env_values if v.startswith("ASH_ACTUAL_OUTPUT_DIR="))
    assert "/src/code" in src_val
    assert "ash_output" in out_val


def test_assemble_run_command_image_argument_position():
    """Image name appears before the 'ash' subcommand."""
    image = "automated-security-helper:non-root"
    cmd = _assemble_run_command(**_base_assemble_kwargs(image_name=image))
    img_idx = cmd.index(image)
    ash_idx = cmd.index("ash")
    assert img_idx < ash_idx


def test_assemble_run_command_offline_uses_network_none():
    """--network=none is added when offline=True."""
    cmd = _assemble_run_command(**_base_assemble_kwargs(offline=True))
    assert "--network=none" in cmd


def test_assemble_run_command_online_no_network_flag():
    """--network=none is NOT present when offline=False."""
    cmd = _assemble_run_command(**_base_assemble_kwargs(offline=False))
    assert "--network=none" not in cmd

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.cli.image import build_ash_image_cli_command
from automated_security_helper.core.enums import AshLogLevel, BuildTarget, RunMode
from automated_security_helper.interactions.run_ash_container import (
    _assemble_run_command,
    _get_oci_wrapper_prefix,
    _resolve_oci_runner,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_ctx(resilient_parsing=False, invoked_subcommand=None):
    ctx = MagicMock()
    ctx.resilient_parsing = resilient_parsing
    ctx.invoked_subcommand = invoked_subcommand
    ctx.args = []
    return ctx


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
        container_network="bridge",
    )
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# --no-build skips image build
# ---------------------------------------------------------------------------


def _invoke_build_image_cli(mock_run_ash_scan, **overrides):
    """Helper to invoke build_ash_image_cli_command with sensible defaults."""
    defaults = dict(
        ctx=_make_ctx(),
        no_build=False,
        no_run=False,
        force=False,
        oci_runner=None,
        build_target=BuildTarget.NON_ROOT,
        offline_semgrep_rulesets="p/ci",
        container_uid=None,
        container_gid=None,
        ash_revision_to_install=None,
        custom_containerfile=None,
        custom_build_arg=None,
        config_overrides=None,
        offline=False,
        quiet=False,
        log_level=AshLogLevel.INFO,
        config=None,
        verbose=False,
        debug=False,
        color=True,
        container_network="bridge",
    )
    defaults.update(overrides)
    build_ash_image_cli_command(**defaults)
    return mock_run_ash_scan.call_args[1]


def test_no_build_skips_image_build():
    """--no-build passes build=False to run_ash_scan so no build subprocess fires."""
    with patch("automated_security_helper.cli.image.run_ash_scan") as mock_run_ash_scan:
        call_kwargs = _invoke_build_image_cli(mock_run_ash_scan, no_build=True)
    assert call_kwargs["build"] is False


def test_no_run_skips_container_run():
    """--no-run passes run=False; default no_build=False means build still fires."""
    with patch("automated_security_helper.cli.image.run_ash_scan") as mock_run_ash_scan:
        call_kwargs = _invoke_build_image_cli(mock_run_ash_scan, no_run=True)
    assert call_kwargs["run"] is False
    assert call_kwargs["build"] is True


def test_default_no_flags_build_true_run_true():
    """With no flags, build=True and run=True (no_run defaults to False)."""
    with patch("automated_security_helper.cli.image.run_ash_scan") as mock_run_ash_scan:
        call_kwargs = _invoke_build_image_cli(mock_run_ash_scan)
    assert call_kwargs["build"] is True
    assert call_kwargs["run"] is True


# ---------------------------------------------------------------------------
# OCI runner discovery order
# ---------------------------------------------------------------------------


def test_oci_runner_discovery_order():
    """finch is preferred over docker, nerdctl, and podman when all are on PATH."""

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


def test_oci_runner_discovery_order_docker_when_no_finch():
    """docker is selected when finch is absent."""

    def fake_find(name):
        return {
            "docker": "/usr/bin/docker",
            "nerdctl": "/usr/local/bin/nerdctl",
            "podman": "/usr/bin/podman",
        }.get(name)

    with patch(
        "automated_security_helper.interactions.run_ash_container._find_runner",
        side_effect=fake_find,
    ):
        result = _resolve_oci_runner(oci_runner=None)
    assert result == "/usr/bin/docker"


def test_oci_runner_discovery_order_nerdctl_fallback():
    """nerdctl is selected when finch and docker are absent."""

    def fake_find(name):
        return {
            "nerdctl": "/usr/local/bin/nerdctl",
            "podman": "/usr/bin/podman",
        }.get(name)

    with patch(
        "automated_security_helper.interactions.run_ash_container._find_runner",
        side_effect=fake_find,
    ):
        result = _resolve_oci_runner(oci_runner=None)
    assert result == "/usr/local/bin/nerdctl"


def test_oci_runner_discovery_order_podman_last():
    """podman is selected only when finch, docker, and nerdctl are absent."""

    def fake_find(name):
        return "/usr/bin/podman" if name == "podman" else None

    with patch(
        "automated_security_helper.interactions.run_ash_container._find_runner",
        side_effect=fake_find,
    ):
        result = _resolve_oci_runner(oci_runner=None)
    assert result == "/usr/bin/podman"


# ---------------------------------------------------------------------------
# --container-network flag
# ---------------------------------------------------------------------------


def test_container_network_flag_none_adds_network_none():
    """Passing container_network='none' puts --network=none in docker run argv."""
    cmd = _assemble_run_command(**_base_assemble_kwargs(container_network="none"))
    assert "--network=none" in cmd


def test_container_network_flag_bridge_no_network_arg():
    """Default container_network='bridge' does NOT add a --network flag."""
    cmd = _assemble_run_command(**_base_assemble_kwargs(container_network="bridge"))
    assert "--network=none" not in cmd
    assert "--network=bridge" not in cmd


def test_container_network_independent_of_offline():
    """--network=none from offline and from container_network are both honoured."""
    # offline alone already sets --network=none
    cmd_offline = _assemble_run_command(
        **_base_assemble_kwargs(offline=True, container_network="bridge")
    )
    assert "--network=none" in cmd_offline

    # container_network=none without offline also sets --network=none
    cmd_network = _assemble_run_command(
        **_base_assemble_kwargs(offline=False, container_network="none")
    )
    assert "--network=none" in cmd_network


# ---------------------------------------------------------------------------
# OCI_RUNNER_WRAPPER env var
# ---------------------------------------------------------------------------


def test_oci_runner_wrapper_env_var_sudo():
    """OCI_RUNNER_WRAPPER=sudo causes the wrapper to be returned as a prefix."""
    with patch.dict(os.environ, {"OCI_RUNNER_WRAPPER": "sudo"}):
        prefix = _get_oci_wrapper_prefix()
    assert prefix == ["sudo"]


def test_oci_runner_wrapper_env_var_sudo_finch():
    """OCI_RUNNER_WRAPPER='sudo finch' is split correctly."""
    with patch.dict(os.environ, {"OCI_RUNNER_WRAPPER": "sudo finch"}):
        prefix = _get_oci_wrapper_prefix()
    assert prefix == ["sudo", "finch"]


def test_oci_runner_wrapper_env_var_empty():
    """Empty OCI_RUNNER_WRAPPER returns an empty prefix list."""
    with patch.dict(os.environ, {"OCI_RUNNER_WRAPPER": ""}):
        prefix = _get_oci_wrapper_prefix()
    assert prefix == []


def test_oci_runner_wrapper_prepended_in_assemble():
    """The wrapper prefix appears before the runner binary in the assembled command."""
    cmd = _assemble_run_command(
        **_base_assemble_kwargs(
            oci_command_prefix=["sudo"],
            resolved_oci_runner="/usr/bin/docker",
        )
    )
    # sudo must appear before /usr/bin/docker
    assert "sudo" in cmd
    sudo_idx = cmd.index("sudo")
    docker_idx = cmd.index("/usr/bin/docker")
    assert sudo_idx < docker_idx


# ---------------------------------------------------------------------------
# TTY heuristic
# ---------------------------------------------------------------------------


def test_tty_heuristic_adds_t_flag_when_tty():
    """-t appears in docker run args when stdout is a TTY and color is enabled."""
    with patch("sys.stdout") as mock_stdout:
        mock_stdout.isatty.return_value = True
        cmd = _assemble_run_command(**_base_assemble_kwargs(color=True))
    assert "-t" in cmd


def test_tty_heuristic_no_t_flag_when_not_tty():
    """-t is absent when stdout is not a TTY."""
    with patch("sys.stdout") as mock_stdout:
        mock_stdout.isatty.return_value = False
        cmd = _assemble_run_command(**_base_assemble_kwargs(color=True))
    assert "-t" not in cmd


def test_tty_heuristic_no_t_flag_when_color_off():
    """-t is absent when color output is disabled, even if stdout is a TTY."""
    with patch("sys.stdout") as mock_stdout:
        mock_stdout.isatty.return_value = True
        cmd = _assemble_run_command(**_base_assemble_kwargs(color=False))
    assert "-t" not in cmd


# ---------------------------------------------------------------------------
# COLUMNS/LINES passthrough
# ---------------------------------------------------------------------------


def test_columns_lines_passthrough_when_tty():
    """COLUMNS and LINES env vars are injected from terminal size when stdout is a TTY."""
    import shutil as _shutil

    fake_size = _shutil.os.terminal_size((160, 50))
    with patch("sys.stdout") as mock_stdout, patch(
        "automated_security_helper.interactions.run_ash_container.shutil.get_terminal_size",
        return_value=fake_size,
    ):
        mock_stdout.isatty.return_value = True
        cmd = _assemble_run_command(**_base_assemble_kwargs(color=True))

    env_values = [cmd[i + 1] for i, a in enumerate(cmd) if a == "-e"]
    assert "COLUMNS=160" in env_values
    assert "LINES=50" in env_values


def test_columns_lines_passthrough_when_not_tty():
    """COLUMNS/LINES are still passed even when not a TTY (shutil always works)."""
    import shutil as _shutil

    fake_size = _shutil.os.terminal_size((80, 24))
    with patch(
        "automated_security_helper.interactions.run_ash_container.shutil.get_terminal_size",
        return_value=fake_size,
    ):
        cmd = _assemble_run_command(**_base_assemble_kwargs())

    env_values = [cmd[i + 1] for i, a in enumerate(cmd) if a == "-e"]
    assert "COLUMNS=80" in env_values
    assert "LINES=24" in env_values

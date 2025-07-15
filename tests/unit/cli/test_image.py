"""Unit tests for the image CLI module."""

import platform
from unittest.mock import patch, MagicMock

from automated_security_helper.cli.image import build_ash_image_cli_command
from automated_security_helper.core.enums import AshLogLevel, BuildTarget, RunMode


@patch("automated_security_helper.cli.image.run_ash_scan")
def test_build_ash_image_cli_command_basic(mock_run_ash_scan):
    """Test the basic functionality of build_ash_image_cli_command."""
    # Create a mock context
    ctx = MagicMock()
    ctx.resilient_parsing = False
    ctx.invoked_subcommand = None

    # Call the function with minimal parameters
    build_ash_image_cli_command(
        ctx,
        force=True,
        oci_runner=None,
        build_target=BuildTarget.CI
        if platform.system().lower().startswith("win")
        else BuildTarget.NON_ROOT,
        offline_semgrep_rulesets="p/ci",
        container_uid=None,
        container_gid=None,
        ash_revision_to_install=None,
        custom_containerfile=None,
        custom_build_arg=[],
        config_overrides=[],
        offline=False,
        quiet=False,
        log_level=AshLogLevel.INFO,
        config=None,
        verbose=False,
        debug=False,
        color=True,
    )

    # Verify run_ash_scan was called with the correct parameters
    mock_run_ash_scan.assert_called_once_with(
        build=True,
        run=False,
        force=True,
        oci_runner=None,
        build_target=BuildTarget.CI
        if platform.system().lower().startswith("win")
        else BuildTarget.NON_ROOT,
        offline_semgrep_rulesets="p/ci",
        container_uid=None,
        container_gid=None,
        ash_revision_to_install=None,
        custom_containerfile=None,
        custom_build_arg=[],
        show_summary=False,
        config=None,
        config_overrides=[],
        offline=False,
        progress=False,
        log_level=AshLogLevel.INFO,
        quiet=False,
        verbose=False,
        debug=False,
        color=True,
        mode=RunMode.container,
    )


@patch("automated_security_helper.cli.image.run_ash_scan")
def test_build_ash_image_cli_command_with_custom_options(mock_run_ash_scan):
    """Test build_ash_image_cli_command with custom options."""
    # Create a mock context
    ctx = MagicMock()
    ctx.resilient_parsing = False
    ctx.invoked_subcommand = None

    # Call the function with custom parameters
    build_ash_image_cli_command(
        ctx,
        force=True,
        oci_runner="podman",
        build_target=BuildTarget.CI,
        offline_semgrep_rulesets="p/custom",
        container_uid="1000",
        container_gid="1000",
        ash_revision_to_install="main",
        custom_containerfile="./Dockerfile.custom",
        custom_build_arg=["ARG1=value1", "ARG2=value2"],
        config_overrides=["reporters.html.enabled=true"],
        offline=True,
        quiet=True,
        log_level=AshLogLevel.DEBUG,
        config="custom_config.yaml",
        verbose=True,
        debug=True,
        color=False,
    )

    # Verify run_ash_scan was called with the correct parameters
    mock_run_ash_scan.assert_called_once_with(
        build=True,
        run=False,
        force=True,
        oci_runner="podman",
        build_target=BuildTarget.CI,
        offline_semgrep_rulesets="p/custom",
        container_uid="1000",
        container_gid="1000",
        ash_revision_to_install="main",
        custom_containerfile="./Dockerfile.custom",
        custom_build_arg=["ARG1=value1", "ARG2=value2"],
        show_summary=False,
        config="custom_config.yaml",
        config_overrides=["reporters.html.enabled=true"],
        offline=True,
        progress=False,
        log_level=AshLogLevel.DEBUG,
        quiet=True,
        verbose=True,
        debug=True,
        color=False,
        mode=RunMode.container,
    )


@patch("automated_security_helper.cli.image.run_ash_scan")
def test_build_ash_image_cli_command_resilient_parsing(mock_run_ash_scan):
    """Test build_ash_image_cli_command with resilient parsing."""
    # Create a mock context with resilient_parsing=True
    ctx = MagicMock()
    ctx.resilient_parsing = True

    # Call the function
    build_ash_image_cli_command(ctx)

    # Verify run_ash_scan was not called
    mock_run_ash_scan.assert_not_called()


@patch("automated_security_helper.cli.image.run_ash_scan")
def test_build_ash_image_cli_command_with_subcommand(mock_run_ash_scan):
    """Test build_ash_image_cli_command with a subcommand."""
    # Create a mock context with a subcommand
    ctx = MagicMock()
    ctx.resilient_parsing = False
    ctx.invoked_subcommand = "some_subcommand"

    # Call the function
    build_ash_image_cli_command(ctx)

    # Verify run_ash_scan was not called
    mock_run_ash_scan.assert_not_called()

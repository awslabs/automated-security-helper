"""Extended unit tests for the CLI image module."""

import pytest
from unittest.mock import patch, MagicMock

from automated_security_helper.cli.image import build_ash_image_cli_command
from automated_security_helper.core.enums import AshLogLevel, BuildTarget, RunMode


@pytest.fixture
def mock_typer_context():
    """Create a mock Typer context."""
    context = MagicMock()
    context.resilient_parsing = False
    context.invoked_subcommand = None
    return context


@patch("automated_security_helper.cli.image.run_ash_scan")
def test_build_ash_image_cli_command_with_all_options(
    mock_run_ash_scan, mock_typer_context
):
    """Test build_ash_image_cli_command with all options."""
    # Call the function with all options
    build_ash_image_cli_command(
        mock_typer_context,
        force=True,
        oci_runner="podman",
        build_target=BuildTarget.CI,
        offline_semgrep_rulesets="p/custom",
        container_uid="1000",
        container_gid="1000",
        ash_revision_to_install="main",
        custom_containerfile="custom/Dockerfile",
        custom_build_arg=["ARG1=value1", "ARG2=value2"],
        config_overrides=["reporters.html.enabled=true"],
        offline=True,
        quiet=True,
        log_level=AshLogLevel.DEBUG,
        config="custom-config.yaml",
        verbose=True,
        debug=True,
        color=False,
    )

    # Verify run_ash_scan was called with the correct parameters
    mock_run_ash_scan.assert_called_once()
    call_args = mock_run_ash_scan.call_args[1]

    assert call_args["build"] is True
    assert call_args["run"] is False
    assert call_args["force"] is True
    assert call_args["oci_runner"] == "podman"
    assert call_args["build_target"] == BuildTarget.CI
    assert call_args["offline_semgrep_rulesets"] == "p/custom"
    assert call_args["container_uid"] == "1000"
    assert call_args["container_gid"] == "1000"
    assert call_args["ash_revision_to_install"] == "main"
    assert call_args["custom_containerfile"] == "custom/Dockerfile"
    assert call_args["custom_build_arg"] == ["ARG1=value1", "ARG2=value2"]
    assert call_args["config_overrides"] == ["reporters.html.enabled=true"]
    assert call_args["offline"] is True
    assert call_args["log_level"] == AshLogLevel.DEBUG
    assert call_args["config"] == "custom-config.yaml"
    assert call_args["verbose"] is True
    assert call_args["debug"] is True
    assert call_args["color"] is False
    assert call_args["mode"] == RunMode.container


@patch("automated_security_helper.cli.image.run_ash_scan")
def test_build_ash_image_cli_command_with_invoked_subcommand(
    mock_run_ash_scan, mock_typer_context
):
    """Test build_ash_image_cli_command with invoked subcommand."""
    # Set invoked_subcommand to something other than None or "image"
    mock_typer_context.invoked_subcommand = "other"

    # Call the function
    build_ash_image_cli_command(mock_typer_context)

    # Verify run_ash_scan was not called
    mock_run_ash_scan.assert_not_called()


@patch("automated_security_helper.cli.image.run_ash_scan")
def test_build_ash_image_cli_command_with_resilient_parsing(
    mock_run_ash_scan, mock_typer_context
):
    """Test build_ash_image_cli_command with resilient_parsing."""
    # Set resilient_parsing to True
    mock_typer_context.resilient_parsing = True

    # Call the function
    build_ash_image_cli_command(mock_typer_context)

    # Verify run_ash_scan was not called
    mock_run_ash_scan.assert_not_called()

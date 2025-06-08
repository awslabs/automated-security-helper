"""Unit tests for the scan CLI module to increase coverage."""

from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.scan import run_ash_scan_cli_command
from automated_security_helper.core.enums import RunMode, Strategy, Phases


@pytest.fixture
def cli_runner():
    """Create a CLI runner for testing."""
    return CliRunner()


@patch("automated_security_helper.cli.scan.run_ash_scan")
def test_run_ash_scan_cli_command_with_all_options(mock_run_ash_scan):
    """Test run_ash_scan_cli_command with all options."""
    # Setup mock
    mock_run_ash_scan.return_value = None

    # Create a mock context
    mock_context = MagicMock()
    mock_context.resilient_parsing = False
    mock_context.invoked_subcommand = None

    # Call the function with all options
    run_ash_scan_cli_command(
        mock_context,
        source_dir="./source",
        output_dir="./output",
        config_overrides=["key1=value1", "key2=value2"],
        offline=True,
        strategy=Strategy.sequential,
        scanners=["bandit", "checkov"],
        exclude_scanners=["semgrep"],
        progress=False,
        output_formats=["sarif", "html"],
        phases=[Phases.convert, Phases.scan],
        python_based_plugins_only=True,
        debug=True,
        color=False,
        fail_on_findings=True,
        ignore_suppressions=True,
        mode=RunMode.container,
        show_summary=False,
        build=False,
        run=False,
        force=True,
        oci_runner="podman",
        build_target="non-root",
        offline_semgrep_rulesets="p/custom",
        container_uid="1000",
        container_gid="1000",
        ash_revision_to_install="main",
        custom_containerfile="./Dockerfile",
        custom_build_arg=["ARG1=val1", "ARG2=val2"],
        ash_plugin_modules=["module1", "module2"],
        config="./config.yml",
        cleanup=True,
        inspect=True,
        quiet=True,
        verbose=True,
    )

    # Verify run_ash_scan was called with expected parameters
    mock_run_ash_scan.assert_called_once()
    args, kwargs = mock_run_ash_scan.call_args

    # Check that all parameters were passed correctly
    assert kwargs["source_dir"] == "./source"
    assert kwargs["output_dir"] == "./output"
    assert kwargs["config_overrides"] == ["key1=value1", "key2=value2"]
    assert kwargs["offline"] is True
    assert kwargs["strategy"] == Strategy.sequential
    assert kwargs["scanners"] == ["bandit", "checkov"]
    assert kwargs["exclude_scanners"] == ["semgrep"]
    assert kwargs["progress"] is False
    assert kwargs["output_formats"] == ["sarif", "html"]
    assert kwargs["cleanup"] is True
    assert kwargs["phases"] == [Phases.convert, Phases.scan]
    assert kwargs["inspect"] is True
    assert kwargs["python_based_plugins_only"] is True
    assert kwargs["quiet"] is True
    assert kwargs["verbose"] is True
    assert kwargs["debug"] is True
    assert kwargs["color"] is False
    assert kwargs["fail_on_findings"] is True
    assert kwargs["ignore_suppressions"] is True
    assert kwargs["mode"] == RunMode.container
    assert kwargs["show_summary"] is False
    assert kwargs["build"] is False
    assert kwargs["run"] is False
    assert kwargs["force"] is True
    assert kwargs["oci_runner"] == "podman"
    assert kwargs["build_target"] == "non-root"
    assert kwargs["offline_semgrep_rulesets"] == "p/custom"
    assert kwargs["container_uid"] == "1000"
    assert kwargs["container_gid"] == "1000"
    assert kwargs["ash_revision_to_install"] == "main"
    assert kwargs["custom_containerfile"] == "./Dockerfile"
    assert kwargs["custom_build_arg"] == ["ARG1=val1", "ARG2=val2"]
    assert kwargs["ash_plugin_modules"] == ["module1", "module2"]


@patch("automated_security_helper.cli.scan.run_ash_scan")
def test_run_ash_scan_cli_command_with_use_existing(
    mock_run_ash_scan, test_output_dir, test_source_dir
):
    """Test run_ash_scan_cli_command with use_existing option."""
    # Setup mock
    mock_run_ash_scan.return_value = None

    # Create a mock context
    mock_context = MagicMock()
    mock_context.resilient_parsing = False
    mock_context.invoked_subcommand = None

    # Create the output directory and mock file
    Path(test_output_dir).mkdir(parents=True, exist_ok=True)
    Path(test_output_dir).joinpath("ash_aggregated_results.json").touch()

    # Call the function with use_existing=True
    run_ash_scan_cli_command(
        mock_context,
        source_dir=test_source_dir,
        output_dir=test_output_dir,
        use_existing=True,
    )

    # Verify run_ash_scan was called with expected parameters
    mock_run_ash_scan.assert_called_once()
    args, kwargs = mock_run_ash_scan.call_args

    # Check that existing_results was set correctly
    assert kwargs["existing_results"] == str(
        Path(f"{test_output_dir}/ash_aggregated_results.json")
    )


@patch("automated_security_helper.cli.scan.run_ash_scan")
def test_run_ash_scan_cli_command_with_precommit_mode(
    mock_run_ash_scan, test_output_dir, test_source_dir
):
    """Test run_ash_scan_cli_command with precommit mode."""
    # Setup mock
    mock_run_ash_scan.return_value = None

    # Create a mock context
    mock_context = MagicMock()
    mock_context.resilient_parsing = False
    mock_context.invoked_subcommand = None

    # Call the function with mode=RunMode.precommit
    run_ash_scan_cli_command(
        mock_context,
        source_dir=test_source_dir,
        output_dir=test_output_dir,
        mode=RunMode.precommit,
    )

    # Verify run_ash_scan was called with expected parameters
    mock_run_ash_scan.assert_called_once()
    args, kwargs = mock_run_ash_scan.call_args

    # Check that mode was set correctly
    assert kwargs["mode"] == RunMode.precommit
    # Precommit mode should set simple to True
    assert kwargs["simple"] is True

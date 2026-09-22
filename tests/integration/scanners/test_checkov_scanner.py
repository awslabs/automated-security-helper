"""Tests for Checkov scanner."""

import pytest
from pathlib import Path
from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
    CheckovScanner,
    CheckovScannerConfig,
    CheckovScannerConfigOptions,
)
from automated_security_helper.models.core import IgnorePathWithReason


@pytest.fixture
def test_checkov_scanner(test_plugin_context):
    """Create a test Checkov scanner."""
    return CheckovScanner(
        context=test_plugin_context,
        config=CheckovScannerConfig(),
    )


def test_checkov_scanner_init(test_plugin_context):
    """Test CheckovScanner initialization."""
    scanner = CheckovScanner(
        context=test_plugin_context,
        config=CheckovScannerConfig(),
    )
    assert scanner.config.name == "checkov"
    assert scanner.command == "checkov"
    assert scanner.tool_type == "IAC"
    assert scanner.use_uv_tool is True  # Verify UV tool is enabled


def test_checkov_scanner_validate(test_checkov_scanner):
    """Test CheckovScanner validation."""
    assert test_checkov_scanner.validate_plugin_dependencies() is True


def test_checkov_scanner_uv_tool_integration(test_plugin_context):
    """Test CheckovScanner UV tool integration."""
    import unittest.mock

    scanner = CheckovScanner(
        context=test_plugin_context,
        config=CheckovScannerConfig(),
    )

    # Verify UV tool is enabled
    assert scanner.use_uv_tool is True
    assert scanner.command == "checkov"

    # Test UV tool version detection
    with unittest.mock.patch(
        "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"
    ) as mock_runner:
        mock_runner_instance = unittest.mock.MagicMock()
        mock_runner.return_value = mock_runner_instance
        mock_runner_instance.is_uv_available.return_value = True
        mock_runner_instance.get_tool_version.return_value = "3.2.0"

        # Test version detection
        version = scanner._get_uv_tool_version("checkov")
        assert version == "3.2.0"
        # Asserted against the scanner's own ``--from`` spec rather than a
        # literal, so a version-constraint bump does not break this test while
        # still pinning the property #426 and #549 added: the probe must run under
        # the same ``--from`` environment the scan will use. ``uv tool run checkov``
        # and ``uv tool run --from '<spec>' checkov`` resolve to different
        # environments, and stevedore's entry-point cache is keyed on
        # ``sys.executable``/``sys.prefix``, so probing the wrong one leaves the
        # scan's cache cold. The bare-name assertion this replaces could not tell
        # those two invocations apart.
        mock_runner_instance.get_tool_version.assert_called_with(
            "checkov", scanner._uv_from_spec()
        )

    # Test validation with UV tool available
    with unittest.mock.patch(
        "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"
    ) as mock_runner:
        mock_runner_instance = unittest.mock.MagicMock()
        mock_runner.return_value = mock_runner_instance
        mock_runner_instance.is_uv_available.return_value = True

        assert scanner.validate_plugin_dependencies() is True

    # Test validation with UV tool unavailable AND no direct binary.
    #
    # Both halves are required. When UV is missing the scanner defers to
    # ``get_uv_tool_command`` for a directly installed binary and returns True if it
    # finds one, so "UV unavailable" alone does not mean validation fails -- this
    # assertion passed only on a host with no checkov on PATH, and failed wherever
    # checkov was installed. ``get_uv_tool_command`` is patched in the scanner's own
    # module because checkov_scanner binds the name at import time; patching
    # ``uv_tool_runner.get_uv_tool_command`` would not affect that binding.
    with (
        unittest.mock.patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"
        ) as mock_runner,
        unittest.mock.patch(
            "automated_security_helper.plugin_modules.ash_builtin.scanners."
            "checkov_scanner.get_uv_tool_command",
            return_value=None,
        ),
    ):
        mock_runner_instance = unittest.mock.MagicMock()
        mock_runner.return_value = mock_runner_instance
        mock_runner_instance.is_uv_available.return_value = False

        assert scanner.validate_plugin_dependencies() is False

    # And the fallback itself: UV unavailable but a direct binary present means
    # validation passes with use_uv_tool switched off. Without this case the branch
    # above could be satisfied by the scanner never consulting the resolver at all.
    with (
        unittest.mock.patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"
        ) as mock_runner,
        unittest.mock.patch(
            "automated_security_helper.plugin_modules.ash_builtin.scanners."
            "checkov_scanner.get_uv_tool_command",
            return_value="/usr/local/bin/checkov",
        ),
    ):
        mock_runner_instance = unittest.mock.MagicMock()
        mock_runner.return_value = mock_runner_instance
        mock_runner_instance.is_uv_available.return_value = False

        assert scanner.validate_plugin_dependencies() is True
        assert scanner.use_uv_tool is False
        scanner.use_uv_tool = True  # restore for any later assertion


def test_checkov_scanner_configure(test_plugin_context):
    """Test CheckovScanner configuration."""
    scanner = CheckovScanner(
        context=test_plugin_context,
        config=CheckovScannerConfig(
            options=CheckovScannerConfigOptions(
                config_file=".checkov.yaml",
                skip_path=[IgnorePathWithReason(path="tests/*", reason="Test files")],
                frameworks=["terraform", "cloudformation"],
                skip_frameworks=["secrets"],
                additional_formats=["json", "junitxml"],
            )
        ),
    )
    assert scanner.config.options.config_file == ".checkov.yaml"
    assert len(scanner.config.options.skip_path) == 1
    assert scanner.config.options.skip_path[0].path == "tests/*"
    assert "terraform" in scanner.config.options.frameworks
    assert "secrets" in scanner.config.options.skip_frameworks
    assert "json" in scanner.config.options.additional_formats


@pytest.mark.parametrize(
    "config_file",
    [
        ".checkov.yaml",
        ".checkov.yml",
        "custom_checkov.yaml",
    ],
)
def test_process_config_options_with_config_files(
    config_file, test_source_dir, test_plugin_context
):
    """Test processing of different config file types."""
    config_path = test_source_dir.joinpath(config_file)
    config_path.touch()

    scanner = CheckovScanner(
        context=test_plugin_context,
        config=CheckovScannerConfig(
            options=CheckovScannerConfigOptions(
                config_file=config_path.as_posix(),
            )
        ),
    )
    scanner._process_config_options()

    # Check that the config file argument was added
    config_args = [arg.key for arg in scanner.args.extra_args]
    assert "--config-file" in config_args


def test_process_config_options_frameworks(test_plugin_context):
    """Test processing of framework options."""
    scanner = CheckovScanner(
        context=test_plugin_context,
        config=CheckovScannerConfig(
            options=CheckovScannerConfigOptions(
                frameworks=["terraform", "cloudformation"],
                skip_frameworks=["secrets"],
            )
        ),
    )
    scanner._process_config_options()

    # Check that framework arguments were added
    framework_args = [arg.key for arg in scanner.args.extra_args]
    assert "--framework" in framework_args
    assert "--skip-framework" in framework_args


def test_process_config_options_skip_paths(test_plugin_context):
    """Test processing of skip path options."""
    scanner = CheckovScanner(
        context=test_plugin_context,
        config=CheckovScannerConfig(
            options=CheckovScannerConfigOptions(
                skip_path=[
                    IgnorePathWithReason(path="tests/*", reason="Test files"),
                    IgnorePathWithReason(path="examples/*", reason="Example files"),
                ]
            )
        ),
    )
    scanner._process_config_options()

    # checkov takes the value joined to the flag, so the arg is
    # ``--skip-path=tests/*`` and the bare string ``--skip-path`` is never a
    # member. Asserting on the configured paths instead of on the flag name is
    # what this test was for: a flag present with the wrong paths, or with none,
    # used to pass.
    skip_args = [arg.key for arg in scanner.args.extra_args]
    assert any(a.startswith("--skip-path=") for a in skip_args), (
        f"no --skip-path argument was emitted at all: {skip_args}"
    )
    for configured in ("tests/*", "examples/*"):
        assert f"--skip-path={configured}" in skip_args, (
            f"configured skip path {configured!r} did not reach checkov: {skip_args}"
        )


def test_checkov_scanner_scan(test_checkov_scanner, test_data_dir):
    """Test CheckovScanner scan method."""
    # Mock the scan to avoid actual execution
    import unittest.mock

    with (
        unittest.mock.patch.object(test_checkov_scanner, "_run_subprocess"),
        unittest.mock.patch("builtins.open", unittest.mock.mock_open(read_data="{}")),
        unittest.mock.patch("json.load", return_value={}),
    ):
        # Run the scan
        results = test_checkov_scanner.scan(test_data_dir, target_type="source")

    # Check that results were returned
    assert results is not None


def test_checkov_scanner_scan_error(test_checkov_scanner):
    """Test CheckovScanner scan method with error."""
    # Try to scan a non-existent directory
    resp = test_checkov_scanner.scan(Path("nonexistent"), target_type="source")
    assert resp is not None
    assert resp is True
    assert (
        "(checkov) Target directory nonexistent is empty or doesn't exist. Skipping scan."
        in test_checkov_scanner.errors
    )


def test_checkov_scanner_additional_formats(test_plugin_context):
    """Test CheckovScanner with additional output formats."""
    scanner = CheckovScanner(
        context=test_plugin_context,
        config=CheckovScannerConfig(
            options=CheckovScannerConfigOptions(
                additional_formats=["sarif", "json"],
            )
        ),
    )
    scanner._process_config_options()

    # Check that additional format arguments were added
    format_args = [arg.key for arg in scanner.args.extra_args]
    assert "--output" in format_args

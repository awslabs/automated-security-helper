# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for FerretScanScanner plugin."""

import json
import pytest
from unittest.mock import patch, MagicMock, mock_open

from automated_security_helper.plugin_modules.ash_ferret_plugins.ferret_scanner import (
    FerretScanScanner,
    FerretScannerConfig,
    FerretScannerConfigOptions,
    UNSUPPORTED_FERRET_OPTIONS,
)
from automated_security_helper.core.exceptions import ScannerError


@pytest.mark.unit
class TestFerretScannerConfig:
    """Test configuration handling for FerretScanScanner."""

    def test_default_config_initialization(self):
        """Test default configuration values."""
        config = FerretScannerConfig()

        assert config.name == "ferret-scan"
        assert config.enabled is True
        assert isinstance(config.options, FerretScannerConfigOptions)

        # Test default options
        options = config.options
        assert options.confidence_levels == "all"
        assert options.checks == "all"
        assert options.recursive is True
        assert options.config_file is None
        assert options.profile is None
        assert options.exclude_patterns == []
        assert options.show_match is False
        assert options.enable_preprocessors is True

    def test_custom_config_initialization(self, custom_ferret_config):
        """Test custom configuration values."""
        config = custom_ferret_config

        assert config.name == "ferret-scan"
        assert config.enabled is True

        options = config.options
        assert options.confidence_levels == "high,medium"
        assert options.checks == "CREDIT_CARD,SECRETS,SSN"
        assert options.recursive is True
        assert options.profile == "security-audit"

    def test_scanner_initialization_with_default_config(self, mock_plugin_context):
        """Test scanner initialization with default configuration."""
        scanner = FerretScanScanner(context=mock_plugin_context)

        assert scanner.config is not None
        assert isinstance(scanner.config, FerretScannerConfig)
        assert scanner.command == "ferret-scan"
        assert scanner.tool_type == "Secrets"

    def test_scanner_initialization_with_custom_config(self, mock_plugin_context, custom_ferret_config):
        """Test scanner initialization with custom configuration."""
        scanner = FerretScanScanner(context=mock_plugin_context, config=custom_ferret_config)

        assert scanner.config == custom_ferret_config
        assert scanner.config.options.confidence_levels == "high,medium"
        assert scanner.config.options.checks == "CREDIT_CARD,SECRETS,SSN"


@pytest.mark.unit
class TestFerretScanScannerUnsupportedOptions:
    """Test validation of unsupported options."""

    def test_unsupported_option_format_raises_error(self):
        """Test that using 'format' option raises an error."""
        with pytest.raises(ValueError) as exc_info:
            FerretScannerConfigOptions(format="json")
        
        assert "Unsupported option 'format'" in str(exc_info.value)
        assert "ASH requires SARIF format" in str(exc_info.value)

    def test_unsupported_option_debug_raises_error(self):
        """Test that using 'debug' option raises an error."""
        with pytest.raises(ValueError) as exc_info:
            FerretScannerConfigOptions(debug=True)
        
        assert "Unsupported option 'debug'" in str(exc_info.value)
        assert "not applicable in ASH integration" in str(exc_info.value)

    def test_unsupported_option_verbose_raises_error(self):
        """Test that using 'verbose' option raises an error."""
        with pytest.raises(ValueError) as exc_info:
            FerretScannerConfigOptions(verbose=True)
        
        assert "Unsupported option 'verbose'" in str(exc_info.value)
        assert "not applicable in ASH integration" in str(exc_info.value)

    def test_unsupported_option_web_raises_error(self):
        """Test that using 'web' option raises an error."""
        with pytest.raises(ValueError) as exc_info:
            FerretScannerConfigOptions(web=True)
        
        assert "Unsupported option 'web'" in str(exc_info.value)
        assert "Web server mode is not supported" in str(exc_info.value)

    def test_unsupported_option_port_raises_error(self):
        """Test that using 'port' option raises an error."""
        with pytest.raises(ValueError) as exc_info:
            FerretScannerConfigOptions(port=8080)
        
        assert "Unsupported option 'port'" in str(exc_info.value)

    def test_unsupported_option_enable_redaction_raises_error(self):
        """Test that using 'enable_redaction' option raises an error."""
        with pytest.raises(ValueError) as exc_info:
            FerretScannerConfigOptions(enable_redaction=True)
        
        assert "Unsupported option 'enable_redaction'" in str(exc_info.value)
        assert "Redaction is not supported" in str(exc_info.value)

    def test_unsupported_option_generate_suppressions_raises_error(self):
        """Test that using 'generate_suppressions' option raises an error."""
        with pytest.raises(ValueError) as exc_info:
            FerretScannerConfigOptions(generate_suppressions=True)
        
        assert "Unsupported option 'generate_suppressions'" in str(exc_info.value)
        assert "ASH manages suppressions centrally" in str(exc_info.value)

    def test_unsupported_option_show_suppressed_raises_error(self):
        """Test that using 'show_suppressed' option raises an error."""
        with pytest.raises(ValueError) as exc_info:
            FerretScannerConfigOptions(show_suppressed=True)
        
        assert "Unsupported option 'show_suppressed'" in str(exc_info.value)

    def test_unsupported_option_extract_text_raises_error(self):
        """Test that using 'extract_text' option raises an error."""
        with pytest.raises(ValueError) as exc_info:
            FerretScannerConfigOptions(extract_text=True)
        
        assert "Unsupported option 'extract_text'" in str(exc_info.value)
        assert "Text extraction mode is not supported" in str(exc_info.value)

    def test_all_unsupported_options_documented(self):
        """Test that all unsupported options have documentation."""
        for option, message in UNSUPPORTED_FERRET_OPTIONS.items():
            assert isinstance(message, str)
            assert len(message) > 10  # Meaningful error message

    def test_unsupported_option_rejected_from_raw_dict_config(self, mock_plugin_context):
        """Regression test for Bug 3: unsupported options must be rejected even when
        config arrives as a raw dict (the get_plugin_config code path for community plugins)."""
        raw_config = {
            "name": "ferret-scan",
            "enabled": True,
            "options": {"debug": True},
        }
        with pytest.raises(Exception, match="Unsupported option.*debug"):
            FerretScanScanner(config=raw_config, context=mock_plugin_context)

    def test_valid_options_accepted_from_raw_dict_config(self, mock_plugin_context):
        """Verify that valid custom options work when config is a raw dict."""
        raw_config = {
            "name": "ferret-scan",
            "enabled": True,
            "options": {"confidence_levels": "high", "profile": "ci"},
        }
        scanner = FerretScanScanner(config=raw_config, context=mock_plugin_context)
        assert scanner.config.options.confidence_levels == "high"
        assert scanner.config.options.profile == "ci"


@pytest.mark.unit
class TestFerretScannerConfigProcessing:
    """Test configuration option processing."""

    def test_process_config_options_default(self, mock_plugin_context, default_ferret_config):
        """Test processing of default configuration options."""
        scanner = FerretScanScanner(context=mock_plugin_context, config=default_ferret_config)
        scanner._process_config_options()

        extra_args = scanner.args.extra_args

        # Should have recursive flag
        recursive_arg = next((arg for arg in extra_args if arg.key == "--recursive"), None)
        assert recursive_arg is not None

        # Should have no-color flag (always added for ASH compatibility)
        no_color_arg = next((arg for arg in extra_args if arg.key == "--no-color"), None)
        assert no_color_arg is not None

        # Should have enable-preprocessors flag (default is True)
        preprocessors_arg = next((arg for arg in extra_args if arg.key == "--enable-preprocessors"), None)
        assert preprocessors_arg is not None

        # Should NOT have confidence arg (default is "all")
        confidence_arg = next((arg for arg in extra_args if arg.key == "--confidence"), None)
        assert confidence_arg is None

        # Should NOT have checks arg (default is "all")
        checks_arg = next((arg for arg in extra_args if arg.key == "--checks"), None)
        assert checks_arg is None

    def test_process_config_options_custom(self, mock_plugin_context, custom_ferret_config):
        """Test processing of custom configuration options."""
        scanner = FerretScanScanner(context=mock_plugin_context, config=custom_ferret_config)
        scanner._process_config_options()

        extra_args = scanner.args.extra_args

        # Should have custom confidence levels
        confidence_arg = next((arg for arg in extra_args if arg.key == "--confidence"), None)
        assert confidence_arg is not None
        assert confidence_arg.value == "high,medium"

        # Should have custom checks
        checks_arg = next((arg for arg in extra_args if arg.key == "--checks"), None)
        assert checks_arg is not None
        assert checks_arg.value == "CREDIT_CARD,SECRETS,SSN"

        # Should have profile
        profile_arg = next((arg for arg in extra_args if arg.key == "--profile"), None)
        assert profile_arg is not None
        assert profile_arg.value == "security-audit"

    def test_process_exclude_patterns(self, mock_plugin_context):
        """Test exclude patterns processing."""
        config = FerretScannerConfig(
            options=FerretScannerConfigOptions(
                exclude_patterns=["*.log", "node_modules/**", "vendor/**"]
            )
        )

        scanner = FerretScanScanner(context=mock_plugin_context, config=config)
        scanner._process_config_options()

        extra_args = scanner.args.extra_args
        exclude_args = [arg for arg in extra_args if arg.key == "--exclude"]

        # Should have at least 3 exclude patterns
        assert len(exclude_args) >= 3
        exclude_values = [arg.value for arg in exclude_args]
        assert "*.log" in exclude_values
        assert "node_modules/**" in exclude_values
        assert "vendor/**" in exclude_values

    def test_process_show_match_option(self, mock_plugin_context):
        """Test show_match option processing."""
        config = FerretScannerConfig(
            options=FerretScannerConfigOptions(show_match=True)
        )

        scanner = FerretScanScanner(context=mock_plugin_context, config=config)
        scanner._process_config_options()

        extra_args = scanner.args.extra_args
        show_match_arg = next((arg for arg in extra_args if arg.key == "--show-match"), None)
        assert show_match_arg is not None

    def test_process_enable_preprocessors_disabled(self, mock_plugin_context):
        """Test enable_preprocessors option when disabled."""
        config = FerretScannerConfig(
            options=FerretScannerConfigOptions(enable_preprocessors=False)
        )

        scanner = FerretScanScanner(context=mock_plugin_context, config=config)
        scanner._process_config_options()

        extra_args = scanner.args.extra_args
        preprocessors_arg = next((arg for arg in extra_args if arg.key == "--enable-preprocessors"), None)
        assert preprocessors_arg is None

    def test_process_config_options_no_duplication_on_repeated_calls(self, mock_plugin_context, default_ferret_config):
        """Test that calling _process_config_options multiple times does not duplicate arguments."""
        scanner = FerretScanScanner(context=mock_plugin_context, config=default_ferret_config)

        # Call multiple times
        scanner._process_config_options()
        scanner._process_config_options()
        scanner._process_config_options()

        extra_args = scanner.args.extra_args

        # Each flag should appear exactly once
        recursive_args = [arg for arg in extra_args if arg.key == "--recursive"]
        assert len(recursive_args) == 1

        no_color_args = [arg for arg in extra_args if arg.key == "--no-color"]
        assert len(no_color_args) == 1

        preprocessor_args = [arg for arg in extra_args if arg.key == "--enable-preprocessors"]
        assert len(preprocessor_args) == 1


@pytest.mark.unit
class TestFerretScanScannerASHConventions:
    """Test ASH convention compliance."""

    def test_always_uses_sarif_format(self, mock_plugin_context):
        """Test that SARIF format is always used."""
        scanner = FerretScanScanner(context=mock_plugin_context)
        
        assert scanner.args.format_arg == "--format"
        assert scanner.args.format_arg_value == "sarif"

    def test_always_adds_no_color_flag(self, mock_plugin_context):
        """Test that --no-color is always added."""
        scanner = FerretScanScanner(context=mock_plugin_context)
        scanner._process_config_options()

        extra_args = scanner.args.extra_args
        no_color_arg = next((arg for arg in extra_args if arg.key == "--no-color"), None)
        assert no_color_arg is not None

    def test_never_passes_debug_or_verbose_to_ferret_scan(self, mock_plugin_context):
        """Test that --debug and --verbose are never passed to ferret-scan.
        
        ASH manages its own logging independently. Passing debug/verbose to the
        underlying tool is unreliable because ASH_LOGGER.level doesn't reflect
        the user's intended verbosity (it's always set to TRACE at the root).
        This is consistent with Semgrep, Checkov, Grype, and detect-secrets.
        """
        scanner = FerretScanScanner(context=mock_plugin_context)
        scanner._process_config_options()

        extra_args = scanner.args.extra_args
        debug_arg = next((arg for arg in extra_args if arg.key == "--debug"), None)
        verbose_arg = next((arg for arg in extra_args if arg.key == "--verbose"), None)
        
        assert debug_arg is None
        assert verbose_arg is None


@pytest.mark.unit
class TestFerretScannerConfigFileDiscovery:
    """Test configuration file discovery."""

    def test_find_config_file_explicit(self, mock_plugin_context, mock_ferret_config_file):
        """Test finding explicitly specified config file."""
        scanner = FerretScanScanner(context=mock_plugin_context)

        result = scanner._find_config_file(mock_ferret_config_file)
        assert result == mock_ferret_config_file

    def test_find_config_file_auto_discovery(self, mock_plugin_context, mock_ferret_config_file):
        """Test auto-discovery of config file."""
        scanner = FerretScanScanner(context=mock_plugin_context)

        # Should find ferret.yaml in source directory
        result = scanner._find_config_file(None)
        assert result == mock_ferret_config_file

    def test_find_config_file_not_found(self, mock_plugin_context):
        """Test when no config file is found in source dir, falls back to default."""
        scanner = FerretScanScanner(context=mock_plugin_context)

        result = scanner._find_config_file(None)
        # Should return the default config bundled with the plugin
        assert result is not None
        assert "ferret-config.yaml" in str(result)

    def test_find_config_file_disabled_default(self, mock_plugin_context):
        """Test when default config is disabled and no source config exists."""
        config = FerretScannerConfig(
            options=FerretScannerConfigOptions(use_default_config=False)
        )
        scanner = FerretScanScanner(context=mock_plugin_context, config=config)

        result = scanner._find_config_file(None)
        assert result is None

    def test_find_config_file_nonexistent_explicit(self, mock_plugin_context):
        """Test when explicitly specified config file doesn't exist."""
        scanner = FerretScanScanner(context=mock_plugin_context)

        result = scanner._find_config_file("nonexistent.yaml")
        assert result is None


@pytest.mark.unit
class TestFerretScanScannerDependencies:
    """Test dependency validation for FerretScanScanner."""

    @patch("automated_security_helper.plugin_modules.ash_ferret_plugins.ferret_scanner.find_executable")
    def test_validate_dependencies_success(self, mock_find_executable, mock_plugin_context):
        """Test successful dependency validation when ferret-scan is available."""
        mock_find_executable.return_value = "/usr/local/bin/ferret-scan"

        scanner = FerretScanScanner(context=mock_plugin_context)
        result = scanner.validate_plugin_dependencies()

        assert result is True
        assert scanner.dependencies_satisfied is True
        # find_executable is called twice: once for validation, once for version check
        assert mock_find_executable.call_count >= 1

    @patch("automated_security_helper.plugin_modules.ash_ferret_plugins.ferret_scanner.find_executable")
    def test_validate_dependencies_failure_not_found(self, mock_find_executable, mock_plugin_context):
        """Test dependency validation failure when ferret-scan is not found."""
        mock_find_executable.return_value = None

        scanner = FerretScanScanner(context=mock_plugin_context)
        result = scanner.validate_plugin_dependencies()

        assert result is False
        mock_find_executable.assert_called_once_with("ferret-scan")

    @patch("automated_security_helper.plugin_modules.ash_ferret_plugins.ferret_scanner.find_executable")
    def test_validate_dependencies_failure_empty_string(self, mock_find_executable, mock_plugin_context):
        """Test dependency validation failure when find_executable returns empty string."""
        mock_find_executable.return_value = ""

        scanner = FerretScanScanner(context=mock_plugin_context)
        result = scanner.validate_plugin_dependencies()

        assert result is False
        mock_find_executable.assert_called_once_with("ferret-scan")


@pytest.mark.unit
class TestFerretScanScannerArgumentResolution:
    """Test argument resolution for FerretScanScanner."""

    def test_resolve_arguments_default(self, mock_plugin_context, mock_target_directory):
        """Test argument resolution with default config."""
        scanner = FerretScanScanner(context=mock_plugin_context)

        args = scanner._resolve_arguments(target=mock_target_directory)

        assert args[0] == "ferret-scan"
        assert "--format" in args
        assert "sarif" in args
        assert "--file" in args
        assert str(mock_target_directory) in args[-1]

    def test_resolve_arguments_with_options(self, mock_plugin_context, mock_target_directory, custom_ferret_config):
        """Test argument resolution with custom options."""
        scanner = FerretScanScanner(context=mock_plugin_context, config=custom_ferret_config)

        args = scanner._resolve_arguments(target=mock_target_directory)

        assert "ferret-scan" in args
        assert "--confidence" in args
        assert "high,medium" in args
        assert "--checks" in args
        assert "--profile" in args
        assert "security-audit" in args

    def test_resolve_arguments_always_includes_sarif(self, mock_plugin_context, mock_target_directory):
        """Test that SARIF format is always included in arguments."""
        scanner = FerretScanScanner(context=mock_plugin_context)

        args = scanner._resolve_arguments(target=mock_target_directory)

        format_index = args.index("--format")
        assert args[format_index + 1] == "sarif"


@pytest.mark.unit
class TestFerretScanScannerScanning:
    """Test scanning workflow for FerretScanScanner."""

    @patch("automated_security_helper.plugin_modules.ash_ferret_plugins.ferret_scanner.find_executable")
    def test_scan_successful_execution(self, mock_find_executable, mock_plugin_context,
                                       mock_target_directory, mock_sarif_response, mock_results_directory):
        """Test successful scan execution with valid target."""
        mock_find_executable.return_value = "/usr/local/bin/ferret-scan"
        results_dir, source_dir = mock_results_directory

        scanner = FerretScanScanner(context=mock_plugin_context)
        scanner.results_dir = results_dir
        scanner.dependencies_satisfied = True

        with patch.object(scanner, '_pre_scan', return_value=True), \
             patch.object(scanner, '_post_scan'), \
             patch.object(scanner, '_run_subprocess') as mock_subprocess, \
             patch.object(scanner, '_plugin_log'), \
             patch("builtins.open", mock_open(read_data=json.dumps(mock_sarif_response))), \
             patch("pathlib.Path.exists", return_value=True):

            mock_subprocess.return_value = {"stdout": "", "stderr": ""}

            result = scanner.scan(target=mock_target_directory, target_type="source")

            assert result is not None
            mock_subprocess.assert_called_once()

    @patch("automated_security_helper.plugin_modules.ash_ferret_plugins.ferret_scanner.find_executable")
    def test_scan_with_config_override(self, mock_find_executable, mock_plugin_context,
                                       mock_target_directory, mock_sarif_response, mock_results_directory):
        """Test scan() with a runtime config parameter triggers _pre_scan re-validation."""
        mock_find_executable.return_value = "/usr/local/bin/ferret-scan"
        results_dir, source_dir = mock_results_directory

        scanner = FerretScanScanner(context=mock_plugin_context)
        scanner.results_dir = results_dir
        scanner.dependencies_satisfied = True

        override_config = FerretScannerConfig(
            options=FerretScannerConfigOptions(confidence_levels="high")
        )

        with patch.object(scanner, '_pre_scan', return_value=True) as mock_pre_scan, \
             patch.object(scanner, '_post_scan'), \
             patch.object(scanner, '_run_subprocess'), \
             patch.object(scanner, '_plugin_log'), \
             patch("builtins.open", mock_open(read_data=json.dumps(mock_sarif_response))), \
             patch("pathlib.Path.exists", return_value=True):

            result = scanner.scan(
                target=mock_target_directory, target_type="source", config=override_config
            )

            assert result is not None
            # Verify _pre_scan received the override config
            mock_pre_scan.assert_called_once_with(
                target=mock_target_directory, target_type="source", config=override_config
            )

    @patch("automated_security_helper.plugin_modules.ash_ferret_plugins.ferret_scanner.find_executable")
    def test_scan_pre_scan_failure(self, mock_find_executable, mock_plugin_context, mock_target_directory):
        """Test scan behavior when pre-scan validation fails."""
        mock_find_executable.return_value = "/usr/local/bin/ferret-scan"

        scanner = FerretScanScanner(context=mock_plugin_context)

        with patch.object(scanner, '_pre_scan', return_value=False), \
             patch.object(scanner, '_post_scan') as mock_post_scan:

            result = scanner.scan(target=mock_target_directory, target_type="source")

            assert result is False
            mock_post_scan.assert_called_once()

    @patch("automated_security_helper.plugin_modules.ash_ferret_plugins.ferret_scanner.find_executable")
    def test_scan_dependencies_not_satisfied(self, mock_find_executable, mock_plugin_context, mock_target_directory):
        """Test scan behavior when dependencies are not satisfied."""
        mock_find_executable.return_value = None

        scanner = FerretScanScanner(context=mock_plugin_context)
        scanner.dependencies_satisfied = False

        with patch.object(scanner, '_pre_scan', return_value=True), \
             patch.object(scanner, '_post_scan') as mock_post_scan:

            result = scanner.scan(target=mock_target_directory, target_type="source")

            assert result is False
            mock_post_scan.assert_called_once()

    def test_scan_scanner_error_propagation(self, mock_plugin_context, mock_target_directory):
        """Test that ScannerError exceptions are properly propagated."""
        scanner = FerretScanScanner(context=mock_plugin_context)

        with patch.object(scanner, '_pre_scan', side_effect=ScannerError("Test error")):

            with pytest.raises(ScannerError, match="Test error"):
                scanner.scan(target=mock_target_directory, target_type="source")


@pytest.mark.unit
class TestFerretScanScannerTargetValidation:
    """Test target validation for FerretScanScanner."""

    def test_scan_empty_directory(self, mock_plugin_context, mock_empty_directory):
        """Test scan behavior with empty target directory."""
        scanner = FerretScanScanner(context=mock_plugin_context)

        with patch.object(scanner, '_plugin_log') as mock_log, \
             patch.object(scanner, '_post_scan') as mock_post_scan:

            result = scanner.scan(target=mock_empty_directory, target_type="source")

            assert result is True  # Empty directory returns True (skip)
            mock_post_scan.assert_called_once()

            # Verify appropriate logging
            mock_log.assert_called()
            log_message = mock_log.call_args[0][0]
            assert "empty or doesn't exist" in log_message

    def test_scan_nonexistent_directory(self, mock_plugin_context, tmp_path):
        """Test scan behavior with non-existent target directory."""
        nonexistent_dir = tmp_path / "does_not_exist"

        scanner = FerretScanScanner(context=mock_plugin_context)

        with patch.object(scanner, '_plugin_log') as mock_log, \
             patch.object(scanner, '_post_scan') as mock_post_scan:

            result = scanner.scan(target=nonexistent_dir, target_type="source")

            assert result is True  # Non-existent directory returns True (skip)
            mock_post_scan.assert_called_once()


@pytest.mark.unit
class TestFerretScanScannerErrorHandling:
    """Test comprehensive error handling for FerretScanScanner."""

    @patch("automated_security_helper.plugin_modules.ash_ferret_plugins.ferret_scanner.find_executable")
    def test_json_parse_error(self, mock_find_executable, mock_plugin_context,
                              mock_target_directory, mock_results_directory):
        """Test handling of JSON parse errors from ferret-scan output.
        
        Convention: returns None (implicit) so scan_phase marks container as failed.
        """
        mock_find_executable.return_value = "/usr/local/bin/ferret-scan"
        results_dir, source_dir = mock_results_directory

        scanner = FerretScanScanner(context=mock_plugin_context)
        scanner.results_dir = results_dir
        scanner.dependencies_satisfied = True

        with patch.object(scanner, '_pre_scan', return_value=True), \
             patch.object(scanner, '_post_scan'), \
             patch.object(scanner, '_run_subprocess') as mock_subprocess, \
             patch.object(scanner, '_plugin_log'), \
             patch("builtins.open", mock_open(read_data="not valid json")), \
             patch("pathlib.Path.exists", return_value=True):

            mock_subprocess.return_value = {"stdout": "", "stderr": ""}

            result = scanner.scan(target=mock_target_directory, target_type="source")

            # Convention: return None so scan_phase correctly marks as failed
            assert result is None

    @patch("automated_security_helper.plugin_modules.ash_ferret_plugins.ferret_scanner.find_executable")
    def test_missing_output_file(self, mock_find_executable, mock_plugin_context,
                                   mock_target_directory, mock_results_directory):
        """Test handling when output file is not created.
        
        Convention: returns None (implicit) so scan_phase marks container as failed.
        """
        mock_find_executable.return_value = "/usr/local/bin/ferret-scan"
        results_dir, source_dir = mock_results_directory

        scanner = FerretScanScanner(context=mock_plugin_context)
        scanner.results_dir = results_dir
        scanner.dependencies_satisfied = True

        with patch.object(scanner, '_pre_scan', return_value=True), \
             patch.object(scanner, '_post_scan'), \
             patch.object(scanner, '_run_subprocess') as mock_subprocess, \
             patch.object(scanner, '_plugin_log'):

            mock_subprocess.return_value = {"stdout": "", "stderr": ""}

            result = scanner.scan(target=mock_target_directory, target_type="source")

            # Convention: return None so scan_phase correctly marks as failed
            assert result is None

    @patch("automated_security_helper.plugin_modules.ash_ferret_plugins.ferret_scanner.find_executable")
    def test_general_exception_handling(self, mock_find_executable, mock_plugin_context,
                                        mock_target_directory, mock_results_directory):
        """Test handling of general exceptions during scan."""
        mock_find_executable.return_value = "/usr/local/bin/ferret-scan"
        results_dir, source_dir = mock_results_directory

        scanner = FerretScanScanner(context=mock_plugin_context)
        scanner.results_dir = results_dir
        scanner.dependencies_satisfied = True

        with patch.object(scanner, '_pre_scan', return_value=True), \
             patch.object(scanner, '_resolve_arguments', side_effect=Exception("Test error")):

            with pytest.raises(ScannerError) as exc_info:
                scanner.scan(target=mock_target_directory, target_type="source")

            assert "Ferret scan failed: Test error" in str(exc_info.value)


@pytest.mark.unit
class TestFerretScanScannerVersionSupport:
    """Test version compatibility support for FerretScanScanner."""

    def test_version_constants_defined(self):
        """Test that version constants are properly defined."""
        from automated_security_helper.plugin_modules.ash_ferret_plugins.ferret_scanner import (
            MIN_SUPPORTED_VERSION,
            MAX_SUPPORTED_VERSION,
            DEFAULT_VERSION_CONSTRAINT,
            RECOMMENDED_VERSION,
        )
        
        assert MIN_SUPPORTED_VERSION is not None
        assert MAX_SUPPORTED_VERSION is not None
        assert DEFAULT_VERSION_CONSTRAINT is not None
        assert RECOMMENDED_VERSION is not None
        
        # Verify format
        assert "." in MIN_SUPPORTED_VERSION
        assert "." in MAX_SUPPORTED_VERSION
        assert ">=" in DEFAULT_VERSION_CONSTRAINT or "==" in DEFAULT_VERSION_CONSTRAINT

    def test_parse_version_simple(self):
        """Test parsing simple version strings."""
        from automated_security_helper.plugin_modules.ash_ferret_plugins.ferret_scanner import parse_version
        
        assert parse_version("1.0.0") == (1, 0, 0)
        assert parse_version("2.3.4") == (2, 3, 4)
        assert parse_version("10.20.30") == (10, 20, 30)

    def test_parse_version_with_prerelease(self):
        """Test parsing version strings with pre-release suffixes."""
        from automated_security_helper.plugin_modules.ash_ferret_plugins.ferret_scanner import parse_version
        
        assert parse_version("1.0.0-beta") == (1, 0, 0)
        assert parse_version("2.0.0-rc1") == (2, 0, 0)
        assert parse_version("1.2.3-alpha.1") == (1, 2, 3)
        assert parse_version("1.0.0+build123") == (1, 0, 0)

    def test_compare_versions(self):
        """Test version comparison."""
        from automated_security_helper.plugin_modules.ash_ferret_plugins.ferret_scanner import compare_versions
        
        # Equal versions
        assert compare_versions("1.0.0", "1.0.0") == 0
        assert compare_versions("2.3.4", "2.3.4") == 0
        
        # Less than
        assert compare_versions("1.0.0", "2.0.0") == -1
        assert compare_versions("1.0.0", "1.1.0") == -1
        assert compare_versions("1.0.0", "1.0.1") == -1
        
        # Greater than
        assert compare_versions("2.0.0", "1.0.0") == 1
        assert compare_versions("1.1.0", "1.0.0") == 1
        assert compare_versions("1.0.1", "1.0.0") == 1

    def test_compare_versions_different_lengths(self):
        """Test version comparison with different version lengths."""
        from automated_security_helper.plugin_modules.ash_ferret_plugins.ferret_scanner import compare_versions
        
        assert compare_versions("1.0", "1.0.0") == 0
        assert compare_versions("1.0.0", "1.0") == 0
        assert compare_versions("1.0", "1.0.1") == -1
        assert compare_versions("1.0.1", "1.0") == 1

    def test_is_version_compatible(self):
        """Test version compatibility checking."""
        from automated_security_helper.plugin_modules.ash_ferret_plugins.ferret_scanner import is_version_compatible
        
        # Within range
        assert is_version_compatible("1.0.0", "0.1.0", "2.0.0") is True
        assert is_version_compatible("1.5.0", "1.0.0", "2.0.0") is True
        assert is_version_compatible("1.9.9", "1.0.0", "2.0.0") is True
        
        # At minimum boundary (inclusive)
        assert is_version_compatible("1.0.0", "1.0.0", "2.0.0") is True
        
        # At maximum boundary (exclusive)
        assert is_version_compatible("2.0.0", "1.0.0", "2.0.0") is False
        
        # Below minimum
        assert is_version_compatible("0.9.0", "1.0.0", "2.0.0") is False
        
        # Above maximum
        assert is_version_compatible("2.1.0", "1.0.0", "2.0.0") is False

    def test_tool_version_option_in_config(self):
        """Test that tool_version option is available in config."""
        config = FerretScannerConfig(
            options=FerretScannerConfigOptions(
                tool_version=">=1.0.0,<1.5.0"
            )
        )
        
        assert config.options.tool_version == ">=1.0.0,<1.5.0"

    def test_skip_version_check_option_in_config(self):
        """Test that skip_version_check option is available in config."""
        config = FerretScannerConfig(
            options=FerretScannerConfigOptions(
                skip_version_check=True
            )
        )
        
        assert config.options.skip_version_check is True

    def test_get_tool_version_constraint_default(self, mock_plugin_context):
        """Test _get_tool_version_constraint returns default when not configured."""
        from automated_security_helper.plugin_modules.ash_ferret_plugins.ferret_scanner import DEFAULT_VERSION_CONSTRAINT
        
        scanner = FerretScanScanner(context=mock_plugin_context)
        
        constraint = scanner._get_tool_version_constraint()
        assert constraint == DEFAULT_VERSION_CONSTRAINT

    def test_get_tool_version_constraint_custom(self, mock_plugin_context):
        """Test _get_tool_version_constraint returns custom value when configured."""
        config = FerretScannerConfig(
            options=FerretScannerConfigOptions(
                tool_version="==1.2.3"
            )
        )
        
        scanner = FerretScanScanner(context=mock_plugin_context, config=config)
        
        constraint = scanner._get_tool_version_constraint()
        assert constraint == "==1.2.3"

    @patch("automated_security_helper.plugin_modules.ash_ferret_plugins.ferret_scanner.find_executable")
    def test_get_installed_version_success(self, mock_find_executable, mock_plugin_context):
        """Test _get_installed_version returns version when available."""
        mock_find_executable.return_value = "/usr/local/bin/ferret-scan"
        
        scanner = FerretScanScanner(context=mock_plugin_context)
        
        # Mock subprocess.run to return a version
        with patch("automated_security_helper.plugin_modules.ash_ferret_plugins.ferret_scanner.subprocess") as mock_subprocess:
            mock_subprocess.run.return_value = MagicMock(
                returncode=0,
                stdout="ferret-scan version 1.2.3"
            )
            
            version = scanner._get_installed_version()
        
        assert version == "1.2.3"

    @patch("automated_security_helper.plugin_modules.ash_ferret_plugins.ferret_scanner.find_executable")
    def test_get_installed_version_not_found(self, mock_find_executable, mock_plugin_context):
        """Test _get_installed_version returns None when not installed."""
        mock_find_executable.return_value = None
        
        scanner = FerretScanScanner(context=mock_plugin_context)
        version = scanner._get_installed_version()
        
        assert version is None

    @patch("automated_security_helper.plugin_modules.ash_ferret_plugins.ferret_scanner.find_executable")
    def test_get_installed_version_parse_error(self, mock_find_executable, mock_plugin_context):
        """Test _get_installed_version handles parse errors gracefully."""
        mock_find_executable.return_value = "/usr/local/bin/ferret-scan"
        
        scanner = FerretScanScanner(context=mock_plugin_context)
        
        # Mock subprocess.run to raise an exception
        with patch("automated_security_helper.plugin_modules.ash_ferret_plugins.ferret_scanner.subprocess") as mock_subprocess:
            mock_subprocess.run.side_effect = OSError("Command failed")
            mock_subprocess.TimeoutExpired = TimeoutError
            mock_subprocess.SubprocessError = Exception
            
            version = scanner._get_installed_version()
        
        assert version is None

    @patch("automated_security_helper.plugin_modules.ash_ferret_plugins.ferret_scanner.find_executable")
    def test_check_version_compatibility_compatible(self, mock_find_executable, mock_plugin_context):
        """Test _check_version_compatibility with compatible version."""
        mock_find_executable.return_value = "/usr/local/bin/ferret-scan"
        
        scanner = FerretScanScanner(context=mock_plugin_context)
        
        with patch.object(scanner, '_get_installed_version', return_value="1.0.0"):
            is_compatible, version, warning = scanner._check_version_compatibility()
            
            assert is_compatible is True
            assert version == "1.0.0"
            assert warning is None

    @patch("automated_security_helper.plugin_modules.ash_ferret_plugins.ferret_scanner.find_executable")
    def test_check_version_compatibility_too_old(self, mock_find_executable, mock_plugin_context):
        """Test _check_version_compatibility with version too old."""
        mock_find_executable.return_value = "/usr/local/bin/ferret-scan"
        
        scanner = FerretScanScanner(context=mock_plugin_context)
        
        with patch.object(scanner, '_get_installed_version', return_value="0.0.1"):
            is_compatible, version, warning = scanner._check_version_compatibility()
            
            assert is_compatible is False
            assert version == "0.0.1"
            assert warning is not None
            assert "older than the minimum" in warning

    @patch("automated_security_helper.plugin_modules.ash_ferret_plugins.ferret_scanner.find_executable")
    def test_check_version_compatibility_too_new(self, mock_find_executable, mock_plugin_context):
        """Test _check_version_compatibility with version too new."""
        mock_find_executable.return_value = "/usr/local/bin/ferret-scan"
        
        scanner = FerretScanScanner(context=mock_plugin_context)
        
        with patch.object(scanner, '_get_installed_version', return_value="99.0.0"):
            is_compatible, version, warning = scanner._check_version_compatibility()
            
            assert is_compatible is False
            assert version == "99.0.0"
            assert warning is not None
            assert "newer than the maximum" in warning

    @patch("automated_security_helper.plugin_modules.ash_ferret_plugins.ferret_scanner.find_executable")
    def test_validate_dependencies_with_version_check(self, mock_find_executable, mock_plugin_context):
        """Test validate_plugin_dependencies performs version check."""
        mock_find_executable.return_value = "/usr/local/bin/ferret-scan"
        
        scanner = FerretScanScanner(context=mock_plugin_context)
        
        with patch.object(scanner, '_check_version_compatibility', return_value=(True, "1.0.0", None)) as mock_check:
            result = scanner.validate_plugin_dependencies()
            
            assert result is True
            mock_check.assert_called_once()

    @patch("automated_security_helper.plugin_modules.ash_ferret_plugins.ferret_scanner.find_executable")
    def test_validate_dependencies_skip_version_check(self, mock_find_executable, mock_plugin_context):
        """Test validate_plugin_dependencies respects skip_version_check."""
        mock_find_executable.return_value = "/usr/local/bin/ferret-scan"
        
        config = FerretScannerConfig(
            options=FerretScannerConfigOptions(skip_version_check=True)
        )
        scanner = FerretScanScanner(context=mock_plugin_context, config=config)
        
        with patch.object(scanner, '_check_version_compatibility', return_value=(False, "99.0.0", "Version too new")), \
             patch.object(scanner, '_plugin_log') as mock_log:
            
            result = scanner.validate_plugin_dependencies()
            
            # Should still pass because skip_version_check is True
            assert result is True
            
            # Should log warning about skipping
            log_calls = [str(call) for call in mock_log.call_args_list]
            assert any("skip_version_check=true" in call for call in log_calls)

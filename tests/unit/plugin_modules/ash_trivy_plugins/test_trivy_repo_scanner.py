# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for TrivyRepoScanner plugin."""

import json
import pytest
from unittest.mock import patch, mock_open

from automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_repo_scanner import (
    TrivyRepoScanner,
    TrivyRepoScannerConfig,
    TrivyRepoScannerConfigOptions,
)
from automated_security_helper.core.exceptions import ScannerError


@pytest.mark.unit
class TestTrivyRepoScannerConfig:
    """Test configuration handling for TrivyRepoScanner."""

    def test_default_config_initialization(self):
        """Test default configuration values."""
        config = TrivyRepoScannerConfig()
        
        assert config.name == "trivy-repo"
        assert config.enabled is True
        assert isinstance(config.options, TrivyRepoScannerConfigOptions)
        
        # Test default options
        options = config.options
        assert options.scanners == ["vuln", "secret", "misconfig", "license"]
        assert options.license_full is True
        assert options.ignore_unfixed is True
        assert options.disable_telemetry is True

    def test_custom_config_initialization(self, custom_trivy_config):
        """Test custom configuration values."""
        config = custom_trivy_config
        
        assert config.name == "trivy-repo"
        assert config.enabled is True
        
        options = config.options
        assert options.scanners == ["vuln", "secret"]
        assert options.license_full is False
        assert options.ignore_unfixed is False
        assert options.disable_telemetry is True

    def test_config_options_validation(self):
        """Test configuration options validation."""
        # Test valid scanner types
        config = TrivyRepoScannerConfig(
            options=TrivyRepoScannerConfigOptions(
                scanners=["vuln", "misconfig"]
            )
        )
        assert config.options.scanners == ["vuln", "misconfig"]

    def test_scanner_initialization_with_default_config(self, mock_plugin_context):
        """Test scanner initialization with default configuration."""
        scanner = TrivyRepoScanner(context=mock_plugin_context)
        
        assert scanner.config is not None
        assert isinstance(scanner.config, TrivyRepoScannerConfig)
        assert scanner.command == "trivy"
        assert scanner.subcommands == ["repository"]
        assert scanner.tool_type == "SAST"

    def test_scanner_initialization_with_custom_config(self, mock_plugin_context, custom_trivy_config):
        """Test scanner initialization with custom configuration."""
        scanner = TrivyRepoScanner(context=mock_plugin_context, config=custom_trivy_config)
        
        assert scanner.config == custom_trivy_config
        assert scanner.config.options.scanners == ["vuln", "secret"]
        assert scanner.config.options.license_full is False


@pytest.mark.unit
class TestTrivyRepoScannerConfigProcessing:
    """Test configuration option processing."""

    def test_process_config_options_default(self, mock_plugin_context, default_trivy_config):
        """Test processing of default configuration options."""
        scanner = TrivyRepoScanner(context=mock_plugin_context, config=default_trivy_config)
        scanner._process_config_options()
        
        # Check that extra args are properly set
        extra_args = scanner.args.extra_args
        
        # Should have scanners arg
        scanners_arg = next((arg for arg in extra_args if arg.key == "--scanners"), None)
        assert scanners_arg is not None
        assert scanners_arg.value == "vuln,secret,misconfig,license"
        
        # Should have license-full flag
        license_arg = next((arg for arg in extra_args if arg.key == "--license-full"), None)
        assert license_arg is not None
        assert license_arg.value is None
        
        # Should have ignore-unfixed flag
        ignore_arg = next((arg for arg in extra_args if arg.key == "--ignore-unfixed"), None)
        assert ignore_arg is not None
        assert ignore_arg.value is None
        
        # Should have disable-telemetry flag
        telemetry_arg = next((arg for arg in extra_args if arg.key == "--disable-telemetry"), None)
        assert telemetry_arg is not None
        assert telemetry_arg.value is None

    def test_process_config_options_custom(self, mock_plugin_context, custom_trivy_config):
        """Test processing of custom configuration options."""
        scanner = TrivyRepoScanner(context=mock_plugin_context, config=custom_trivy_config)
        scanner._process_config_options()
        
        extra_args = scanner.args.extra_args
        
        # Should have custom scanners
        scanners_arg = next((arg for arg in extra_args if arg.key == "--scanners"), None)
        assert scanners_arg is not None
        assert scanners_arg.value == "vuln,secret"
        
        # Should NOT have license-full flag (disabled)
        license_arg = next((arg for arg in extra_args if arg.key == "--license-full"), None)
        assert license_arg is None
        
        # Should NOT have ignore-unfixed flag (disabled)
        ignore_arg = next((arg for arg in extra_args if arg.key == "--ignore-unfixed"), None)
        assert ignore_arg is None

    def test_process_severity_threshold(self, mock_plugin_context):
        """Test severity threshold processing."""
        # Test with HIGH severity
        config = TrivyRepoScannerConfig(
            options=TrivyRepoScannerConfigOptions()
        )
        config.options.severity_threshold = "HIGH"
        
        scanner = TrivyRepoScanner(context=mock_plugin_context, config=config)
        scanner._process_config_options()
        
        extra_args = scanner.args.extra_args
        severity_arg = next((arg for arg in extra_args if arg.key == "--severity-threshold"), None)
        assert severity_arg is not None
        assert severity_arg.value == "high"

    def test_process_critical_severity_threshold(self, mock_plugin_context):
        """Test CRITICAL severity threshold maps to 'high'."""
        config = TrivyRepoScannerConfig(
            options=TrivyRepoScannerConfigOptions()
        )
        config.options.severity_threshold = "CRITICAL"
        
        scanner = TrivyRepoScanner(context=mock_plugin_context, config=config)
        scanner._process_config_options()
        
        extra_args = scanner.args.extra_args
        severity_arg = next((arg for arg in extra_args if arg.key == "--severity-threshold"), None)
        assert severity_arg is not None
        assert severity_arg.value == "high"

    def test_process_all_severity_threshold(self, mock_plugin_context):
        """Test ALL severity threshold is not added as argument."""
        config = TrivyRepoScannerConfig(
            options=TrivyRepoScannerConfigOptions()
        )
        config.options.severity_threshold = "ALL"
        
        scanner = TrivyRepoScanner(context=mock_plugin_context, config=config)
        scanner._process_config_options()
        
        extra_args = scanner.args.extra_args
        severity_arg = next((arg for arg in extra_args if arg.key == "--severity-threshold"), None)
        assert severity_arg is None

    def test_process_empty_scanners_list(self, mock_plugin_context):
        """Test processing with empty scanners list."""
        config = TrivyRepoScannerConfig(
            options=TrivyRepoScannerConfigOptions(scanners=[])
        )
        
        scanner = TrivyRepoScanner(context=mock_plugin_context, config=config)
        scanner._process_config_options()
        
        extra_args = scanner.args.extra_args
        scanners_arg = next((arg for arg in extra_args if arg.key == "--scanners"), None)
        assert scanners_arg is None


@pytest.mark.unit
class TestTrivyRepoScannerDependencies:
    """Test dependency validation for TrivyRepoScanner."""

    @patch("automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_repo_scanner.find_executable")
    def test_validate_dependencies_success(self, mock_find_executable, mock_plugin_context):
        """Test successful dependency validation when Trivy is available."""
        # Mock Trivy CLI found
        mock_find_executable.return_value = "/usr/local/bin/trivy"
        
        scanner = TrivyRepoScanner(context=mock_plugin_context)
        result = scanner.validate_plugin_dependencies()
        
        assert result is True
        mock_find_executable.assert_called_once_with("trivy")

    @patch("automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_repo_scanner.find_executable")
    def test_validate_dependencies_failure_not_found(self, mock_find_executable, mock_plugin_context):
        """Test dependency validation failure when Trivy is not found."""
        # Mock Trivy CLI not found
        mock_find_executable.return_value = None
        
        scanner = TrivyRepoScanner(context=mock_plugin_context)
        result = scanner.validate_plugin_dependencies()
        
        assert result is False
        mock_find_executable.assert_called_once_with("trivy")

    @patch("automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_repo_scanner.find_executable")
    def test_validate_dependencies_failure_empty_string(self, mock_find_executable, mock_plugin_context):
        """Test dependency validation failure when find_executable returns empty string."""
        # Mock Trivy CLI returns empty string
        mock_find_executable.return_value = ""
        
        scanner = TrivyRepoScanner(context=mock_plugin_context)
        result = scanner.validate_plugin_dependencies()
        
        assert result is False
        mock_find_executable.assert_called_once_with("trivy")

    @patch("automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_repo_scanner.find_executable")
    def test_dependencies_satisfied_flag(self, mock_find_executable, mock_plugin_context):
        """Test that dependencies_satisfied flag is properly set."""
        # Test successful case
        mock_find_executable.return_value = "/usr/local/bin/trivy"
        
        scanner = TrivyRepoScanner(context=mock_plugin_context)
        
        # Initially should be None or False before validation
        assert not hasattr(scanner, 'dependencies_satisfied') or not scanner.dependencies_satisfied
        
        result = scanner.validate_plugin_dependencies()
        assert result is True
        
        # Test failed case
        mock_find_executable.return_value = None
        scanner2 = TrivyRepoScanner(context=mock_plugin_context)
        result2 = scanner2.validate_plugin_dependencies()
        assert result2 is False


@pytest.mark.unit
class TestTrivyRepoScannerScanning:
    """Test scanning workflow for TrivyRepoScanner."""

    @patch("automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_repo_scanner.find_executable")
    def test_scan_successful_execution(self, mock_find_executable, mock_plugin_context, 
                                     mock_target_directory, mock_sarif_response, mock_results_directory):
        """Test successful scan execution with valid target."""
        # Setup mocks
        mock_find_executable.return_value = "/usr/local/bin/trivy"
        results_dir, source_dir = mock_results_directory
        
        scanner = TrivyRepoScanner(context=mock_plugin_context)
        scanner.results_dir = results_dir
        scanner.dependencies_satisfied = True
        
        # Mock the subprocess execution and file operations
        with patch.object(scanner, '_pre_scan', return_value=True), \
             patch.object(scanner, '_post_scan'), \
             patch.object(scanner, '_resolve_arguments') as mock_resolve, \
             patch.object(scanner, '_run_subprocess') as mock_subprocess, \
             patch.object(scanner, '_plugin_log'), \
             patch("builtins.open", mock_open(read_data=json.dumps(mock_sarif_response))), \
             patch("pathlib.Path.exists", return_value=True):
            
            # Setup mock arguments
            mock_resolve.return_value = ["trivy", "repository", "--format", "sarif", "--output", "results.sarif", str(mock_target_directory)]
            
            result = scanner.scan(target=mock_target_directory, target_type="source")
            
            # Verify the scan was executed
            assert result is not None
            mock_resolve.assert_called_once()
            mock_subprocess.assert_called_once()

    @patch("automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_repo_scanner.find_executable")
    def test_scan_pre_scan_failure(self, mock_find_executable, mock_plugin_context, mock_target_directory):
        """Test scan behavior when pre-scan validation fails."""
        mock_find_executable.return_value = "/usr/local/bin/trivy"
        
        scanner = TrivyRepoScanner(context=mock_plugin_context)
        
        with patch.object(scanner, '_pre_scan', return_value=False), \
             patch.object(scanner, '_post_scan') as mock_post_scan:
            
            result = scanner.scan(target=mock_target_directory, target_type="source")
            
            assert result is False
            mock_post_scan.assert_called_once()

    @patch("automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_repo_scanner.find_executable")
    def test_scan_dependencies_not_satisfied(self, mock_find_executable, mock_plugin_context, mock_target_directory):
        """Test scan behavior when dependencies are not satisfied."""
        mock_find_executable.return_value = None
        
        scanner = TrivyRepoScanner(context=mock_plugin_context)
        scanner.dependencies_satisfied = False
        
        with patch.object(scanner, '_pre_scan', return_value=True), \
             patch.object(scanner, '_post_scan') as mock_post_scan:
            
            result = scanner.scan(target=mock_target_directory, target_type="source")
            
            assert result is False
            mock_post_scan.assert_called_once()

    def test_scan_scanner_error_propagation(self, mock_plugin_context, mock_target_directory):
        """Test that ScannerError exceptions are properly propagated."""
        scanner = TrivyRepoScanner(context=mock_plugin_context)
        
        with patch.object(scanner, '_pre_scan', side_effect=ScannerError("Test error")):
            
            with pytest.raises(ScannerError, match="Test error"):
                scanner.scan(target=mock_target_directory, target_type="source")


@pytest.mark.unit
class TestTrivyRepoScannerTargetValidation:
    """Test target validation for TrivyRepoScanner."""

    def test_scan_empty_directory(self, mock_plugin_context, mock_empty_directory):
        """Test scan behavior with empty target directory."""
        scanner = TrivyRepoScanner(context=mock_plugin_context)
        
        with patch.object(scanner, '_plugin_log') as mock_log, \
             patch.object(scanner, '_post_scan') as mock_post_scan:
            
            result = scanner.scan(target=mock_empty_directory, target_type="source")
            
            assert result is True  # Empty directory returns True (skip)
            mock_post_scan.assert_called_once()
            
            # Verify appropriate logging
            mock_log.assert_called()
            log_message = mock_log.call_args[0][0]
            assert "empty or doesn't exist" in log_message
            assert "Skipping scan" in log_message

    def test_scan_nonexistent_directory(self, mock_plugin_context, tmp_path):
        """Test scan behavior with non-existent target directory."""
        nonexistent_dir = tmp_path / "does_not_exist"
        
        scanner = TrivyRepoScanner(context=mock_plugin_context)
        
        with patch.object(scanner, '_plugin_log') as mock_log, \
             patch.object(scanner, '_post_scan') as mock_post_scan:
            
            result = scanner.scan(target=nonexistent_dir, target_type="source")
            
            assert result is True  # Non-existent directory returns True (skip)
            mock_post_scan.assert_called_once()
            
            # Verify appropriate logging
            mock_log.assert_called()
            log_message = mock_log.call_args[0][0]
            assert "empty or doesn't exist" in log_message


@pytest.mark.unit
class TestTrivyRepoScannerErrorHandling:
    """Test comprehensive error handling for TrivyRepoScanner."""

    @patch("automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_repo_scanner.find_executable")
    def test_subprocess_execution_failure(self, mock_find_executable, mock_plugin_context, 
                                        mock_target_directory, mock_results_directory):
        """Test handling of subprocess execution failures."""
        mock_find_executable.return_value = "/usr/local/bin/trivy"
        results_dir, source_dir = mock_results_directory
        
        scanner = TrivyRepoScanner(context=mock_plugin_context)
        scanner.results_dir = results_dir
        scanner.dependencies_satisfied = True
        
        with patch.object(scanner, '_pre_scan', return_value=True), \
             patch.object(scanner, '_run_subprocess', side_effect=ScannerError("Subprocess failed")):
            
            with pytest.raises(ScannerError, match="Subprocess failed"):
                scanner.scan(target=mock_target_directory, target_type="source")

    @patch("automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_repo_scanner.find_executable")
    def test_general_exception_handling(self, mock_find_executable, mock_plugin_context, 
                                      mock_target_directory, mock_results_directory):
        """Test handling of general exceptions during scan."""
        mock_find_executable.return_value = "/usr/local/bin/trivy"
        results_dir, source_dir = mock_results_directory
        
        scanner = TrivyRepoScanner(context=mock_plugin_context)
        scanner.results_dir = results_dir
        scanner.dependencies_satisfied = True
        
        with patch.object(scanner, '_pre_scan', return_value=True), \
             patch.object(scanner, '_resolve_arguments', side_effect=Exception("Test error message")):
            
            with pytest.raises(ScannerError) as exc_info:
                scanner.scan(target=mock_target_directory, target_type="source")
            
            assert "Trivy scan failed: Test error message" in str(exc_info.value)

    @patch("automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_repo_scanner.find_executable")
    def test_directory_creation_error(self, mock_find_executable, mock_plugin_context, 
                                    mock_target_directory):
        """Test handling of directory creation errors."""
        mock_find_executable.return_value = "/usr/local/bin/trivy"
        
        scanner = TrivyRepoScanner(context=mock_plugin_context)
        scanner.dependencies_satisfied = True
        
        with patch.object(scanner, '_pre_scan', return_value=True), \
             patch('pathlib.Path.mkdir', side_effect=OSError("Permission denied")):
            
            with pytest.raises(ScannerError) as exc_info:
                scanner.scan(target=mock_target_directory, target_type="source")

    @patch("automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_repo_scanner.find_executable")
    def test_argument_resolution_error(self, mock_find_executable, mock_plugin_context, 
                                     mock_target_directory, mock_results_directory):
        """Test handling of argument resolution errors."""
        mock_find_executable.return_value = "/usr/local/bin/trivy"
        results_dir, source_dir = mock_results_directory
        
        scanner = TrivyRepoScanner(context=mock_plugin_context)
        scanner.results_dir = results_dir
        scanner.dependencies_satisfied = True
        
        with patch.object(scanner, '_pre_scan', return_value=True), \
             patch.object(scanner, '_resolve_arguments', side_effect=ValueError("Invalid argument")):
            
            with pytest.raises(ScannerError) as exc_info:
                scanner.scan(target=mock_target_directory, target_type="source")
            
            assert "Trivy scan failed: Invalid argument" in str(exc_info.value)

    def test_pre_scan_scanner_error_propagation(self, mock_plugin_context, mock_target_directory):
        """Test that ScannerError from pre_scan is properly propagated."""
        scanner = TrivyRepoScanner(context=mock_plugin_context)
        
        with patch.object(scanner, '_pre_scan', side_effect=ScannerError("Pre-scan failed")):
            
            with pytest.raises(ScannerError, match="Pre-scan failed"):
                scanner.scan(target=mock_target_directory, target_type="source")


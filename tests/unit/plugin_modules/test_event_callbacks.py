"""Tests for ASH built-in event handlers."""

from datetime import datetime, timedelta
from unittest.mock import Mock, patch

from automated_security_helper.plugin_modules.ash_builtin.event_handlers.suppression_expiration_checker import (
    handle_suppression_expiration_check,
)
from automated_security_helper.plugin_modules.ash_builtin.event_handlers.scan_completion_logger import (
    handle_scan_completion_logging,
)
from automated_security_helper.models.core import AshSuppression
from automated_security_helper.config.ash_config import (
    AshConfig,
    AshConfigGlobalSettingsSection,
)


class TestSuppressionExpirationChecker:
    """Test the suppression expiration checker event callback."""

    def test_handle_suppression_expiration_check_no_context(self):
        """Test handling when no plugin context is provided."""
        result = handle_suppression_expiration_check()
        assert result is True

    def test_handle_suppression_expiration_check_no_config(self):
        """Test handling when plugin context has no config."""
        mock_context = Mock()
        mock_context.config = None

        result = handle_suppression_expiration_check(plugin_context=mock_context)
        assert result is True

    def test_handle_suppression_expiration_check_no_suppressions(self):
        """Test handling when no suppressions are configured."""
        mock_context = Mock()
        mock_context.config = AshConfig()
        mock_context.config.global_settings = AshConfigGlobalSettingsSection()
        mock_context.config.global_settings.suppressions = []

        result = handle_suppression_expiration_check(plugin_context=mock_context)
        assert result is True

    def test_handle_suppression_expiration_check_ignore_suppressions_flag(self):
        """Test handling when ignore_suppressions flag is set."""
        mock_context = Mock()
        mock_context.config = AshConfig()
        mock_context.config.global_settings = AshConfigGlobalSettingsSection()
        mock_context.config.global_settings.suppressions = [
            AshSuppression(
                rule_id="B101",
                path="test.py",
                expiration=(datetime.now() + timedelta(days=15)).strftime("%Y-%m-%d"),
                reason="Test suppression",
            )
        ]
        mock_context.ignore_suppressions = True

        result = handle_suppression_expiration_check(plugin_context=mock_context)
        assert result is True

    @patch(
        "automated_security_helper.plugin_modules.ash_builtin.event_handlers.suppression_expiration_checker.check_for_expiring_suppressions"
    )
    @patch(
        "automated_security_helper.plugin_modules.ash_builtin.event_handlers.suppression_expiration_checker.ASH_LOGGER"
    )
    def test_handle_suppression_expiration_check_with_expiring_suppressions(
        self, mock_logger, mock_check_expiring
    ):
        """Test handling when there are expiring suppressions."""
        # Create a suppression that expires in 15 days
        expiring_suppression = AshSuppression(
            rule_id="B101",
            path="test.py",
            expiration=(datetime.now() + timedelta(days=15)).strftime("%Y-%m-%d"),
            reason="Test suppression",
        )

        mock_context = Mock()
        mock_context.config = AshConfig()
        mock_context.config.global_settings = AshConfigGlobalSettingsSection()
        mock_context.config.global_settings.suppressions = [expiring_suppression]
        mock_context.ignore_suppressions = False

        # Mock the check function to return the expiring suppression
        mock_check_expiring.return_value = [expiring_suppression]

        result = handle_suppression_expiration_check(plugin_context=mock_context)

        assert result is True
        mock_check_expiring.assert_called_once_with([expiring_suppression])

        # Verify warning messages were logged
        mock_logger.warning.assert_called()
        warning_calls = mock_logger.warning.call_args_list
        assert (
            len(warning_calls) >= 2
        )  # At least the header and one suppression warning

        # Check that the header warning was logged
        header_call = warning_calls[0]
        assert "will expire within 30 days" in str(header_call)

        # Check that the specific suppression warning was logged
        suppression_call = warning_calls[1]
        assert "B101" in str(suppression_call)
        assert "test.py" in str(suppression_call)

    @patch(
        "automated_security_helper.plugin_modules.ash_builtin.event_handlers.suppression_expiration_checker.check_for_expiring_suppressions"
    )
    @patch(
        "automated_security_helper.plugin_modules.ash_builtin.event_handlers.suppression_expiration_checker.ASH_LOGGER"
    )
    def test_handle_suppression_expiration_check_no_expiring_suppressions(
        self, mock_logger, mock_check_expiring
    ):
        """Test handling when there are no expiring suppressions."""
        # Create a suppression that expires in 60 days (not expiring soon)
        future_suppression = AshSuppression(
            rule_id="B101",
            path="test.py",
            expiration=(datetime.now() + timedelta(days=60)).strftime("%Y-%m-%d"),
            reason="Test suppression",
        )

        mock_context = Mock()
        mock_context.config = AshConfig()
        mock_context.config.global_settings = AshConfigGlobalSettingsSection()
        mock_context.config.global_settings.suppressions = [future_suppression]
        mock_context.ignore_suppressions = False

        # Mock the check function to return no expiring suppressions
        mock_check_expiring.return_value = []

        result = handle_suppression_expiration_check(plugin_context=mock_context)

        assert result is True
        mock_check_expiring.assert_called_once_with([future_suppression])

        # Verify debug message was logged but no warnings
        mock_logger.debug.assert_called()
        mock_logger.warning.assert_not_called()


class TestScanCompletionLogger:
    """Test the scan completion logger event callback."""

    @patch(
        "automated_security_helper.plugin_modules.ash_builtin.event_handlers.scan_completion_logger.ASH_LOGGER"
    )
    def test_handle_scan_completion_logging_with_remaining_scanners(self, mock_logger):
        """Test logging when there are remaining scanners."""
        result = handle_scan_completion_logging(
            remaining_count=2, remaining_scanners=["semgrep", "checkov"]
        )

        assert result is True
        mock_logger.info.assert_called_once()
        call_args = mock_logger.info.call_args[0][0]
        assert "Remaining scanners (2): semgrep,checkov" in call_args

    @patch(
        "automated_security_helper.plugin_modules.ash_builtin.event_handlers.scan_completion_logger.ASH_LOGGER"
    )
    def test_handle_scan_completion_logging_no_remaining_scanners(self, mock_logger):
        """Test logging when there are no remaining scanners."""
        result = handle_scan_completion_logging(
            remaining_count=0, remaining_scanners=[]
        )

        assert result is True
        mock_logger.info.assert_called_once_with("All scanners completed!")

    @patch(
        "automated_security_helper.plugin_modules.ash_builtin.event_handlers.scan_completion_logger.ASH_LOGGER"
    )
    def test_handle_scan_completion_logging_default_values(self, mock_logger):
        """Test logging with default values when no kwargs provided."""
        result = handle_scan_completion_logging()

        assert result is True
        mock_logger.info.assert_called_once_with("All scanners completed!")

"""Unit tests for SecurityHubReporter to increase coverage."""

from pathlib import Path
from unittest.mock import patch, MagicMock

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.plugin_modules.ash_aws_plugins.security_hub_reporter import (
    SecurityHubReporter,
    SecurityHubReporterConfig,
    SecurityHubReporterConfigOptions,
)
from automated_security_helper.config.ash_config import AshConfig

# Rebuild models to resolve forward references
AshConfig.model_rebuild()


@patch("boto3.Session")
def test_security_hub_reporter_validate_success(mock_session):
    """Test SecurityHubReporter validate method with successful validation."""
    # Mock AWS services
    mock_sts_client = MagicMock()
    mock_sts_client.get_caller_identity.return_value = {"Account": "123456789012"}

    mock_securityhub_client = MagicMock()
    mock_securityhub_client.describe_hub.return_value = {"HubArn": "test-arn"}

    mock_session_instance = MagicMock()
    mock_session_instance.client.side_effect = lambda service: {
        "sts": mock_sts_client,
        "securityhub": mock_securityhub_client,
    }[service]
    mock_session.return_value = mock_session_instance

    # Create mock context
    mock_context = PluginContext(
        source_dir=Path("/test/source"),
        output_dir=Path("/test/output"),
        work_dir=Path("/test/work"),
        config=get_default_config(),
    )

    # Create reporter with proper config
    config = SecurityHubReporterConfig(
        options=SecurityHubReporterConfigOptions(aws_region="us-east-1")
    )
    reporter = SecurityHubReporter(context=mock_context, config=config)

    # Validate
    result = reporter.validate_plugin_dependencies()

    # Verify result
    assert result is True
    assert reporter.dependencies_satisfied is True


def test_security_hub_reporter_report_error(sample_ash_model):
    """Test SecurityHubReporter report method with error."""
    # Create mock context
    mock_context = PluginContext(
        source_dir=Path("/test/source"),
        output_dir=Path("/test/output"),
        work_dir=Path("/test/work"),
        config=get_default_config(),
    )

    # Create reporter
    reporter = SecurityHubReporter(context=mock_context)
    reporter.dependencies_satisfied = True

    # Create mock model with findings
    mock_model = sample_ash_model

    # Call report
    result = reporter.report(mock_model)

    # Check that the result contains expected content
    assert "Security Hub integration in development" in result
    assert "findings_count" in result

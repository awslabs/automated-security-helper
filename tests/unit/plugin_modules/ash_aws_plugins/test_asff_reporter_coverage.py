"""Unit tests for AsffReporter to increase coverage."""

from pathlib import Path


from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.plugin_modules.ash_aws_plugins.asff_reporter import (
    AsffReporter,
    AsffReporterConfig,
)
from automated_security_helper.config.ash_config import AshConfig

# Rebuild models to resolve forward references
AshConfig.model_rebuild()


def test_asff_reporter_validate_success():
    """Test AsffReporter validate method with successful validation."""
    # Create mock context
    mock_context = PluginContext(
        source_dir=Path("/test/source"),
        output_dir=Path("/test/output"),
        work_dir=Path("/test/work"),
        config=get_default_config(),
    )

    # Create reporter
    reporter = AsffReporter(context=mock_context, config=AsffReporterConfig())

    # Validate
    result = reporter.validate()

    # Verify result
    assert result is True
    assert reporter.dependencies_satisfied is True


def test_asff_reporter_report_error(sample_ash_model):
    """Test AsffReporter report method with error."""
    # Create mock context
    mock_context = PluginContext(
        source_dir=Path("/test/source"),
        output_dir=Path("/test/output"),
        work_dir=Path("/test/work"),
        config=get_default_config(),
    )

    # Create reporter
    reporter = AsffReporter(context=mock_context)
    reporter.dependencies_satisfied = True

    # Create mock model with findings
    mock_model = sample_ash_model

    # Call report
    result = reporter.report(mock_model)

    assert "report_id: ASH-" in result

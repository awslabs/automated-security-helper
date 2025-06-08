"""Unit tests for the ASFF reporter plugin."""

from unittest.mock import MagicMock
import yaml

from automated_security_helper.plugin_modules.ash_aws_plugins.asff_reporter import (
    AsffReporter,
    AsffReporterConfig,
    AsffReporterConfigOptions,
)
from automated_security_helper.config.ash_config import AshConfig

# Rebuild models to resolve forward references
AshConfig.model_rebuild()


def test_asff_reporter_config_options_validation():
    """Test validation of AWS account ID and region in config options."""
    # Valid options
    valid_options = AsffReporterConfigOptions(aws_region="us-west-2")
    assert valid_options.aws_region == "us-west-2"

    # Test with default values (None)
    default_options = AsffReporterConfigOptions()
    assert default_options.aws_account_id is None
    assert default_options.aws_region is None


def test_asff_reporter_config_defaults():
    """Test default values for ASFF reporter config."""
    config = AsffReporterConfig()
    assert config.name == "asff"
    assert config.extension == "asff"
    assert config.enabled is True
    assert isinstance(config.options, AsffReporterConfigOptions)


# Rebuild models to resolve forward references
AshConfig.model_rebuild()


def test_asff_reporter_model_post_init():
    """Test model_post_init creates default config if none provided."""
    # Create reporter with context
    from automated_security_helper.base.plugin_context import PluginContext

    from pathlib import Path

    context = PluginContext(
        source_dir=Path("/tmp/source"),
        output_dir=Path("/tmp/output"),
        work_dir=Path("/tmp/work"),
    )
    reporter = AsffReporter(context=context)

    # Call model_post_init
    reporter.model_post_init(context)

    # Verify config was created
    assert reporter.config is not None
    assert isinstance(reporter.config, AsffReporterConfig)


def test_asff_reporter_report():
    """Test report method formats model as YAML."""
    # Create reporter with context
    from automated_security_helper.base.plugin_context import PluginContext

    from pathlib import Path

    context = PluginContext(
        source_dir=Path("/tmp/source"),
        output_dir=Path("/tmp/output"),
        work_dir=Path("/tmp/work"),
    )
    reporter = AsffReporter(context=context)

    # Create mock model
    model = MagicMock()
    model.model_dump.return_value = {"test": "data"}

    # Call report method
    result = reporter.report(model)

    # Verify model was dumped with correct parameters
    model.model_dump.assert_called_once_with(
        by_alias=True, exclude_unset=True, exclude_none=True
    )

    # Verify result is YAML
    assert result == yaml.dump({"test": "data"}, indent=2)

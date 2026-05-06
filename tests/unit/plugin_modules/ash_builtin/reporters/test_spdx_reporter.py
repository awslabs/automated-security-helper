"""Tests for SpdxReporter plugin."""

from unittest.mock import MagicMock, patch

import pytest
import yaml

from automated_security_helper.plugin_modules.ash_builtin.reporters.spdx_reporter import (
    SpdxReporter,
    SPDXReporterConfig,
)


@pytest.fixture
def spdx_reporter(test_plugin_context):
    """Create an SpdxReporter instance."""
    return SpdxReporter(context=test_plugin_context)


class TestSPDXReporterConfig:
    """Tests for SPDXReporterConfig defaults."""

    def test_default_config_values(self):
        """Config has correct defaults."""
        config = SPDXReporterConfig()
        assert config.name == "spdx"
        assert config.extension == "spdx.json"
        assert config.enabled is False


class TestSpdxReporter:
    """Tests for SpdxReporter."""

    def test_model_post_init_sets_default_config(self, test_plugin_context):
        """If config is None, model_post_init sets a default SPDXReporterConfig."""
        reporter = SpdxReporter(config=None, context=test_plugin_context)
        assert reporter.config is not None
        assert isinstance(reporter.config, SPDXReporterConfig)

    def test_report_returns_yaml_string(self, spdx_reporter):
        """report() returns a valid YAML string from a simple model dump."""
        model = MagicMock()
        model.model_dump.return_value = {"key": "value", "nested": {"a": 1}}

        result = spdx_reporter.report(model)

        assert isinstance(result, str)
        parsed = yaml.safe_load(result)
        assert isinstance(parsed, dict)
        assert parsed["key"] == "value"

    def test_report_logs_warning(self, spdx_reporter, sample_ash_model):
        """report() emits a warning that it is a stub."""
        with patch(
            "automated_security_helper.plugin_modules.ash_builtin.reporters.spdx_reporter.ASH_LOGGER"
        ) as mock_logger:
            spdx_reporter.report(sample_ash_model)
            mock_logger.warning.assert_called_once()
            assert "stub" in mock_logger.warning.call_args[0][0]

    def test_report_uses_by_alias(self, spdx_reporter):
        """report() calls model_dump with by_alias=True."""
        model = MagicMock()
        model.model_dump.return_value = {"key": "value"}

        spdx_reporter.report(model)

        model.model_dump.assert_called_once_with(by_alias=True)

"""Extended tests for base/plugin_base.py — covers PluginBase methods."""

from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from automated_security_helper.base.plugin_base import PluginBase
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME


@pytest.fixture
def plugin_context(tmp_path):
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    work_dir = output_dir / ASH_WORK_DIR_NAME
    work_dir.mkdir()

    return PluginContext(
        source_dir=source_dir,
        output_dir=output_dir,
        work_dir=work_dir,
        config=AshConfig(project_name="test"),
    )


class ConcretePlugin(PluginBase):
    """Minimal concrete implementation for testing."""

    def validate_plugin_dependencies(self) -> bool:
        return True


class TestPluginBaseInit:
    """Tests for PluginBase initialization."""

    def test_basic_init(self, plugin_context):
        plugin = ConcretePlugin(context=plugin_context)
        assert plugin.context == plugin_context

    def test_init_with_config(self, plugin_context):
        from automated_security_helper.base.plugin_config import PluginConfigBase
        config = MagicMock(spec=PluginConfigBase)
        config.name = "test"
        plugin = ConcretePlugin(context=plugin_context, config=config)
        assert plugin.config is not None


class TestPluginBaseMethods:
    """Tests for PluginBase methods."""

    def test_validate_plugin_dependencies(self, plugin_context):
        plugin = ConcretePlugin(context=plugin_context)
        assert plugin.validate_plugin_dependencies() is True

    def test_get_installation_commands(self, plugin_context):
        plugin = ConcretePlugin(context=plugin_context)
        # Default implementation should return empty list or appropriate commands
        commands = plugin.get_installation_commands("linux", "amd64")
        assert isinstance(commands, list)

    def test_is_python_only_default(self, plugin_context):
        plugin = ConcretePlugin(context=plugin_context)
        # Default implementation
        result = plugin.is_python_only()
        assert isinstance(result, bool)

    def test_plugin_has_context(self, plugin_context):
        plugin = ConcretePlugin(context=plugin_context)
        assert plugin.context.source_dir == plugin_context.source_dir
        assert plugin.context.output_dir == plugin_context.output_dir

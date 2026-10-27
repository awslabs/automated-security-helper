"""Extended tests for base/plugin_base.py — covers PluginBase methods."""

from unittest.mock import MagicMock
import pytest

from automated_security_helper.base.plugin_base import PluginBase
from automated_security_helper.base.plugin_config import PluginConfigBase
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


def _hook_raises(self):
    raise RuntimeError("the plugin's values could not be read")


class TestValuesHookGuardedAtTheModelSites:
    """The model's own sites read the values hook guarded.

    ``_values_to_redact`` is an overridable hook, and every other sink in
    the diff reads it through ``guarded_values_read``. The three bare sites
    were ``__repr_str__``, the after-validator
    ``_give_its_section_the_environment_values`` and ``__setattr__``: a
    raising hook there failed building the plugin, raised on every
    ``plugin.config = ...`` assignment, and made ``repr(plugin)`` raise,
    which hides the original error the show_debug_locals traceback printer
    was showing."""

    def test_a_raising_hook_does_not_fail_building_the_plugin(
        self, plugin_context, monkeypatch
    ):
        monkeypatch.setattr(ConcretePlugin, "_values_to_redact", _hook_raises)

        plugin = ConcretePlugin(context=plugin_context)

        assert plugin.context is plugin_context

    def test_a_raising_hook_does_not_fail_an_assignment(
        self, plugin_context, monkeypatch
    ):
        plugin = ConcretePlugin(context=plugin_context)
        monkeypatch.setattr(ConcretePlugin, "_values_to_redact", _hook_raises)

        plugin.config = plugin.config
        plugin.context = plugin_context

        assert plugin.context is plugin_context

    def test_a_raising_hook_gives_a_placeholder_repr_with_no_values(
        self, tmp_path, monkeypatch
    ):
        """The placeholder carries NO field values: a value the hook would
        have hidden (a path in the plugin's context) must not print."""
        from automated_security_helper.core.constants import ASH_WORK_DIR_NAME

        source_dir = tmp_path / "ENVCANARY-f5-source"
        source_dir.mkdir()
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        (output_dir / ASH_WORK_DIR_NAME).mkdir()
        context = PluginContext(
            source_dir=source_dir,
            output_dir=output_dir,
            work_dir=output_dir / ASH_WORK_DIR_NAME,
            config=AshConfig(project_name="test"),
        )
        plugin = ConcretePlugin(context=context)
        monkeypatch.setattr(ConcretePlugin, "_values_to_redact", _hook_raises)

        text = repr(plugin)

        assert "values hook raised RuntimeError" in text, text
        assert "ENVCANARY-f5-source" not in text, text

    def test_an_unusable_hook_answer_gives_the_placeholder_repr_too(
        self, plugin_context, monkeypatch
    ):
        """None or a number is the same broken answer as a raise
        (guarded_values_read's rule): the conservative arm, never a repr
        with the values in clear."""
        monkeypatch.setattr(ConcretePlugin, "_values_to_redact", lambda self: None)
        plugin = ConcretePlugin(context=plugin_context)

        text = repr(plugin)

        assert "values hook returned an unusable answer" in text, text

    def test_repr_still_redacts_the_hooks_values(self, tmp_path, monkeypatch):
        """The control: a working hook's values are still hidden from the
        repr, and the repr still shows the model's fields."""
        from automated_security_helper.core.constants import ASH_WORK_DIR_NAME

        source_dir = tmp_path / "ENVCANARY-f5-kept"
        source_dir.mkdir()
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        (output_dir / ASH_WORK_DIR_NAME).mkdir()
        context = PluginContext(
            source_dir=source_dir,
            output_dir=output_dir,
            work_dir=output_dir / ASH_WORK_DIR_NAME,
            config=AshConfig(project_name="test"),
        )
        plugin = ConcretePlugin(context=context)
        monkeypatch.setattr(
            ConcretePlugin,
            "_values_to_redact",
            lambda self: (source_dir.as_posix(),),
        )

        text = repr(plugin)

        assert "context=" in text, text
        assert "ENVCANARY-f5-kept" not in text, text


def _hook_answers_nothing(self):
    return None


class TestSectionRedactedWhenTheValuesReadFails:
    """The plugin's own section prints itself from the values it carries.

    ``repr(plugin)`` has a value-free note to fall back to when the values
    hook fails; the section has none, so a skipped carry left
    ``repr(plugin.config)`` showing a value the configuration read from the
    environment. The section is given the configuration's own values when
    the hook's read fails, since the failure cannot take those away."""

    CANARY = "ENVCANARY-section-9c41e7d2b0"

    def _context_reading_the_canary(self, tmp_path):
        source_dir = tmp_path / "source"
        source_dir.mkdir()
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        work_dir = output_dir / ASH_WORK_DIR_NAME
        work_dir.mkdir()
        context = PluginContext(
            source_dir=source_dir,
            output_dir=output_dir,
            work_dir=work_dir,
            config=AshConfig(project_name="test"),
        )
        context.config._environment_values = [self.CANARY]
        return context

    @pytest.mark.parametrize(
        "failing_hook", [_hook_raises, _hook_answers_nothing], ids=["raises", "none"]
    )
    def test_a_failed_read_at_construction_still_redacts_the_section(
        self, tmp_path, monkeypatch, failing_hook
    ):
        context = self._context_reading_the_canary(tmp_path)
        # The control: a section nothing has given values to shows the value
        # in its name field, so the assertion below measures the carry.
        assert self.CANARY in repr(PluginConfigBase(name=self.CANARY))
        monkeypatch.setattr(ConcretePlugin, "_values_to_redact", failing_hook)

        plugin = ConcretePlugin(
            context=context, config=PluginConfigBase(name=self.CANARY)
        )

        section_text = repr(plugin.config)
        assert "name=" in section_text, section_text
        assert self.CANARY not in section_text, section_text

    def test_the_plugin_repr_keeps_its_note_beside_the_redacted_section(
        self, tmp_path, monkeypatch
    ):
        context = self._context_reading_the_canary(tmp_path)
        monkeypatch.setattr(ConcretePlugin, "_values_to_redact", _hook_raises)

        plugin = ConcretePlugin(
            context=context, config=PluginConfigBase(name=self.CANARY)
        )

        assert "values hook raised RuntimeError" in repr(plugin)
        assert self.CANARY not in repr(plugin)
        assert self.CANARY not in repr(plugin.config)

    def test_a_failed_read_at_assignment_still_redacts_the_new_section(
        self, tmp_path, monkeypatch
    ):
        context = self._context_reading_the_canary(tmp_path)
        plugin = ConcretePlugin(context=context)
        section = PluginConfigBase(name=self.CANARY)
        assert self.CANARY in repr(section)
        monkeypatch.setattr(ConcretePlugin, "_values_to_redact", _hook_raises)

        plugin.config = section

        section_text = repr(plugin.config)
        assert "name=" in section_text, section_text
        assert self.CANARY not in section_text, section_text


class _RaisesWhileDrained:
    """An iterable that gives one value and then raises. The values normalizer
    (``redacted_model.environment_strings``) catches a TypeError from
    ``tuple(values)`` and nothing else, so this is the read that fails twice:
    once inside the base values hook, and again in any fallback that reads the
    configuration's values the same way."""

    def __iter__(self):
        yield "ENVCANARY-drained-4e1a07c9"
        raise RuntimeError("the environment values could not be read")


class TestSectionFallbackRead:
    """The section's fallback read of the configuration's values is guarded.

    ``_values_for_its_section`` takes the configuration's own values exactly
    when the values hook failed, and the base hook reads those same values
    without a guard, so a configuration whose values cannot be read fails the
    hook and the fallback together. The fallback raising out of the
    after-validator and ``__setattr__`` would break what the guard around the
    hook promises: building a plugin and assigning ``config`` or ``context``
    never raise because of the values read."""

    @staticmethod
    def _context_whose_values_cannot_be_read(tmp_path):
        # Its own subdirectory: the plugin_context fixture owns tmp_path's
        # "source" and "output".
        source_dir = tmp_path / "unreadable-values" / "source"
        source_dir.mkdir(parents=True)
        output_dir = tmp_path / "unreadable-values" / "output"
        output_dir.mkdir()
        work_dir = output_dir / ASH_WORK_DIR_NAME
        work_dir.mkdir()
        context = PluginContext(
            source_dir=source_dir,
            output_dir=output_dir,
            work_dir=work_dir,
            config=AshConfig(project_name="test"),
        )
        # Past AshConfig.__setattr__, which drains a value it is given at
        # once: the read has to fail later, at the plugin, as a live
        # iterable's does.
        context.config.__pydantic_private__["_environment_values"] = (
            _RaisesWhileDrained()
        )
        return context

    def test_a_failed_fallback_read_does_not_fail_building_the_plugin(
        self, tmp_path, monkeypatch
    ):
        context = self._context_whose_values_cannot_be_read(tmp_path)
        monkeypatch.setattr(ConcretePlugin, "_values_to_redact", _hook_raises)

        plugin = ConcretePlugin(context=context)

        assert plugin.context is context
        assert "values hook raised RuntimeError" in repr(plugin)

    def test_a_failed_fallback_read_does_not_fail_an_assignment(
        self, plugin_context, tmp_path, monkeypatch
    ):
        context = self._context_whose_values_cannot_be_read(tmp_path)
        plugin = ConcretePlugin(context=plugin_context)
        monkeypatch.setattr(ConcretePlugin, "_values_to_redact", _hook_raises)

        plugin.context = context
        plugin.config = plugin.config

        assert plugin.context is context

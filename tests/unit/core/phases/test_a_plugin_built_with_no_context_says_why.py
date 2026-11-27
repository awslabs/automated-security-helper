"""A plugin built with no context fails with a reason, at the validator that raises it.

``PluginBase.setup_paths`` is a pydantic after-validator that raises ``ScannerError``
when no context was given. ``ScannerError`` subclasses ``Exception`` only, so pydantic
lets it out of the validator unwrapped (a ``ValueError`` or an ``AssertionError``
would be wrapped in a ``ValidationError``, which carries no reason). The reason it
carries is ``no_plugin_context`` with the code's default sentence, which is fit to
show. No other test builds a plugin through the validator, so a change to the raise
(a wrapped error, a reason left out) was not seen.
"""

from __future__ import annotations

import pytest

from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.core.exceptions import (
    DEFAULT_SENTENCES,
    ReasonCode,
    ScannerError,
    reason_of,
)
from automated_security_helper.utils.short_reason import is_short_reason

pytestmark = pytest.mark.unit


class _Config(ScannerPluginConfigBase):
    name: str = "no-context"


class _Plugin(ScannerPluginBase):
    def validate_plugin_dependencies(self) -> bool:
        return True

    def _execute_scan(self, target, target_type, global_ignore_paths):
        raise NotImplementedError("never scanned")


class TestAPluginBuiltWithNoContext:
    def test_the_error_is_a_scanner_error_not_a_wrapped_validation_error(self):
        with pytest.raises(ScannerError) as raised:
            _Plugin(config=_Config(), context=None)

        assert type(raised.value) is ScannerError

    def test_it_carries_the_no_plugin_context_reason_with_a_short_sentence(self):
        with pytest.raises(ScannerError) as raised:
            _Plugin(config=_Config(), context=None)

        reason = reason_of(raised.value)

        assert reason is not None, "the error carries no reason"
        assert reason.code == ReasonCode.NO_PLUGIN_CONTEXT
        assert reason.sentence == DEFAULT_SENTENCES[ReasonCode.NO_PLUGIN_CONTEXT]
        assert is_short_reason(reason.sentence), reason.sentence

    def test_its_text_names_the_class_and_the_reason_holds_no_class_name(self):
        with pytest.raises(ScannerError) as raised:
            _Plugin(config=_Config(), context=None)

        assert "_Plugin" in str(raised.value)
        assert "_Plugin" not in reason_of(raised.value).sentence

    def test_control_a_plugin_built_with_a_context_is_built(self, tmp_path):
        from automated_security_helper.base.plugin_context import PluginContext
        from automated_security_helper.config.ash_config import AshConfig

        AshConfig.model_rebuild()
        context = PluginContext(
            source_dir=tmp_path,
            output_dir=tmp_path / "out",
            work_dir=tmp_path / "work",
            config=AshConfig(project_name="with-context"),
        )

        plugin = _Plugin(config=_Config(), context=context)

        assert plugin.context is context

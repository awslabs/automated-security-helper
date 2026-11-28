"""The validator that refuses a plugin with no context records why.

``PluginBase.setup_paths`` is a pydantic after-validator that raises ``ScannerError``
when no context was given. ``ScannerError`` subclasses ``Exception`` only, so a
pydantic validator lets it out unwrapped (a ``ValueError`` or an ``AssertionError``
would be wrapped in a ``ValidationError``, which carries no reason). The reason it
carries is ``no_plugin_context`` with the code's default sentence, which is fit to
show. No test read the reason at this site: the lint reads the construction, and the
scenario cases of ``test_scanner_own_failures_name_a_reason`` reach the other
``no_plugin_context`` raise sites.

The validator is called on a stand-in with no context, since a scanner built through
its constructor raises earlier, in ``ScannerPluginBase.model_post_init``, from a file
whose raise sites record no reason yet (the lint's pending list).
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from automated_security_helper.base.plugin_base import PluginBase
from automated_security_helper.core.exceptions import (
    DEFAULT_SENTENCES,
    ReasonCode,
    ScannerError,
    reason_of,
)
from automated_security_helper.utils.short_reason import is_short_reason

pytestmark = pytest.mark.unit


class _NoContext(SimpleNamespace):
    """The stand-in's class name is what the error's text names."""


def _refusal() -> ScannerError:
    with pytest.raises(ScannerError) as raised:
        PluginBase.setup_paths(_NoContext(context=None))
    return raised.value


class TestTheValidatorThatRefusesAPluginWithNoContext:
    def test_it_raises_a_scanner_error_not_a_wrapped_one(self):
        assert type(_refusal()) is ScannerError

    def test_it_carries_the_no_plugin_context_reason_with_a_short_sentence(self):
        reason = reason_of(_refusal())

        assert reason is not None, "the error carries no reason"
        assert reason.code == ReasonCode.NO_PLUGIN_CONTEXT
        assert reason.sentence == DEFAULT_SENTENCES[ReasonCode.NO_PLUGIN_CONTEXT]
        assert is_short_reason(reason.sentence), reason.sentence

    def test_its_text_names_the_class_and_the_reason_holds_no_class_name(self):
        error = _refusal()

        assert "_NoContext" in str(error)
        assert "_NoContext" not in reason_of(error).sentence

    def test_control_a_context_lets_the_validator_return_the_plugin(self):
        plugin = _NoContext(context=object())

        assert PluginBase.setup_paths(plugin) is plugin

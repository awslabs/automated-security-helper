# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The offline resolve explainer hides a value that ends uv's whole text.

The explainer strips uv's stderr before the one redaction. A whole-text
strip removes a trailing whitespace-class character, and an env-read value
can END in one (a form feed, a line feed) while sitting at the very end of
the resolver's text: the stripped text then holds the value minus its last
character, no whole spelling matches, and the fragment goes into
``errors`` -- the reports -- and the ERROR log. The strip belongs AFTER
the redaction, where there is no value left for it to respell.
"""

from __future__ import annotations

from typing import List, Optional, Tuple

import pytest

from automated_security_helper.base.uv_tool_mixin import UVToolMixin

pytestmark = pytest.mark.unit

#: The value's visible core: this spelling surviving anywhere is the leak.
_CORE = "ops-canary-vx52"

_ENDINGS = [
    pytest.param("\x0c", id="form-feed"),
    pytest.param("\n", id="line-feed"),
]


class _OfflinePlugin(UVToolMixin):
    """The attributes and hooks the explainer reads, nothing else."""

    def __init__(self, values: Tuple[str, ...]):
        self.command = "faketool"
        self.use_uv_tool = True
        self.errors: List[str] = []
        self._values = values
        self.log_lines: List[str] = []

    def _plugin_log(self, message, **kwargs):
        self.log_lines.append(str(message))

    def _is_offline_mode(self) -> bool:
        return True

    def _values_to_redact(self) -> Tuple[str, ...]:
        return self._values

    def _uv_from_spec(self) -> Optional[str]:
        return "faketool==1.0"

    def _uv_run_inputs_for_records(self) -> Tuple[str, ...]:
        return ("faketool==1.0",)


def _resolver_text(tail: str) -> str:
    return (
        "error: No solution found when resolving dependencies:\n"
        f"  Because faketool depends on {tail}"
    )


@pytest.mark.parametrize("ending", _ENDINGS)
def test_the_explainer_hides_a_value_ending_the_text(ending):
    value = _CORE + ending
    plugin = _OfflinePlugin((value,))
    plugin._explain_offline_resolve_failure(
        {"returncode": 1, "stderr": _resolver_text(value)}, None
    )
    assert plugin.errors, "the explainer did not run"
    # The carrier first: a message built with the quoted text discarded
    # would pass the leak assertion with nothing shown at all.
    assert "uv said:" in plugin.errors[0]
    assert "depends on" in plugin.errors[0]
    assert _CORE not in plugin.errors[0], (
        "uv's text ends in the value, and the message printed it minus its "
        "last character"
    )
    assert _CORE not in "".join(plugin.log_lines)


def test_a_value_inside_the_text_stays_hidden():
    """The control: mid-text, no whole-text strip reaches the value."""
    value = _CORE + "\x0c"
    plugin = _OfflinePlugin((value,))
    plugin._explain_offline_resolve_failure(
        {"returncode": 1, "stderr": _resolver_text(value) + " and you require it"},
        None,
    )
    assert plugin.errors
    assert "and you require it" in plugin.errors[0]
    assert _CORE not in plugin.errors[0]

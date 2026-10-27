# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A multi-word value wrapped under a continuation glyph is still hidden.

The uv text layer normalizes a value's whitespace respelling back to the
value's own spelling before matching: uv wraps a clause at a space with an
indented continuation. But a wrapped NON-LAST cause of an error chain is
continued under a drawn column -- an indented U+2502 (or its ASCII bar
fallback) between the line break and the clause's next word -- so the text
holds "wordA(newline)  (glyph)   wordB". The separator then contains a
non-whitespace character, the whitespace-only normalization cannot see the
respelling, and the value prints in two halves around the glyph.

The cells plant a two-word value wrapped under each glyph and read the one
shown layer directly and through two of its routes (the dry-run cause and
the offline explainer); the control wraps at plain whitespace, which the
normalization already covers.
"""

from __future__ import annotations

import subprocess
from typing import List, Optional, Tuple

import pytest

from automated_security_helper.base.uv_tool_mixin import UVToolMixin
from automated_security_helper.utils import pre_installed_tool
from automated_security_helper.utils.uv_tool_runner import shown_uv_output

#: The halves: either spelling surviving anywhere is the leak.
_HALF_A = "ops-canary-ab12"
_HALF_B = "ops-canary-cd34"
_VALUE = f"{_HALF_A} {_HALF_B}"

_GLYPHS = [
    pytest.param("│", id="box-drawing-bar"),
    pytest.param("|", id="ascii-bar"),
]


def _wrapped(glyph: str) -> str:
    """The value as a wrapped non-last cause continues it: the second word
    under an indented column glyph."""
    return f"{_HALF_A}\n  {glyph}   {_HALF_B}"


def _chain_text(tail: str) -> str:
    return (
        "error: No solution found when resolving dependencies:\n"
        f"  Because faketool depends on {tail} and you require faketool"
    )


@pytest.mark.parametrize("glyph", _GLYPHS)
def test_the_shown_layer_hides_a_value_wrapped_under_the_glyph(glyph):
    shown = shown_uv_output(
        _chain_text(_wrapped(glyph)), (_VALUE,), tool_name="faketool", limit=None
    )
    assert "depends on" in shown
    assert _HALF_A not in shown and _HALF_B not in shown, (
        "the wrap's continuation glyph sits inside the value's respelling, "
        f"and the halves printed around it: {shown!r}"
    )


def test_a_plain_wrap_stays_hidden():
    """The control: a space respelled as a line break plus indent only."""
    shown = shown_uv_output(
        _chain_text(f"{_HALF_A}\n    {_HALF_B}"),
        (_VALUE,),
        tool_name="faketool",
        limit=None,
    )
    assert "depends on" in shown
    assert _HALF_A not in shown and _HALF_B not in shown


@pytest.mark.parametrize("glyph", _GLYPHS)
def test_the_cause_hides_a_value_wrapped_under_the_glyph(monkeypatch, glyph):
    completed = subprocess.CompletedProcess(
        args=["irrelevant"],
        returncode=1,
        stdout="",
        stderr=_chain_text(_wrapped(glyph)),
    )
    monkeypatch.setattr(pre_installed_tool, "_run", lambda command, timeout: completed)
    verdict = pre_installed_tool._judge(
        "/fake/copy",
        "faketool",
        [],
        None,
        "faketool",
        "/fake/uv",
        "/fake/python",
        None,
        "its environment (/fake/python)",
        values=(_VALUE,),
    )
    assert verdict.status == "unsatisfied"
    assert "depends on" in verdict.detail
    assert _HALF_A not in verdict.detail and _HALF_B not in verdict.detail


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


@pytest.mark.parametrize("glyph", _GLYPHS)
def test_the_explainer_hides_a_value_wrapped_under_the_glyph(glyph):
    plugin = _OfflinePlugin((_VALUE,))
    plugin._explain_offline_resolve_failure(
        {"returncode": 1, "stderr": _chain_text(_wrapped(glyph))}, None
    )
    assert plugin.errors, "the explainer did not run"
    assert "uv said:" in plugin.errors[0]
    assert _HALF_A not in plugin.errors[0] and _HALF_B not in plugin.errors[0]
    assert _HALF_A not in "".join(plugin.log_lines)

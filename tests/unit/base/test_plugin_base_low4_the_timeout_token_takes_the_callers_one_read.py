# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``_timeout_limit_token`` can take the caller's one guarded read of the values hook.

A timeout message prints its limit through ``_timeout_limit_token`` and redacts the
text with the plugin's values. The token read the hook itself, guarded, and a
caller then read it again for the redaction, unguarded: a hook that raised cost the
timeout its message although the token had fallen back correctly, and two reads of
a hook can disagree. The caller's own guarded read can now be passed in, and the
hook is then not read again.
"""

from __future__ import annotations

from typing import Any, List, Tuple

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.utils.error_text import timeout_limit_token

pytestmark = pytest.mark.unit

PluginContext.model_rebuild()
AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()

WITHOUT_A_NUMBER = "the configured scan_timeout"


class _Config(ScannerPluginConfigBase):
    name: str = "timeout-token"


def _scanner(tmp_path, answers: Any) -> Tuple[ScannerPluginBase, List[bool]]:
    """A scanner whose values hook answers ``answers`` (raising when it is an
    exception), and the list each read of the hook is counted in."""
    source = tmp_path / "source"
    source.mkdir()
    output = tmp_path / "output"
    output.mkdir()
    context = PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=tmp_path / "work",
        config=AshConfig(project_name="timeout-token"),
    )
    reads: List[bool] = []
    armed = {"yes": False}

    class _Scanner(ScannerPluginBase):
        def validate_plugin_dependencies(self) -> bool:
            return True

        def _execute_scan(self, target, target_type, global_ignore_paths):
            raise NotImplementedError("the token is all this test asks for")

        def _values_to_redact(self):
            # Quiet while the plugin is built: only the reads after are counted.
            if not armed["yes"]:
                return ()
            reads.append(True)
            if isinstance(answers, BaseException):
                raise answers
            return answers

    scanner = _Scanner(config=_Config(), context=context)
    armed["yes"] = True
    return scanner, reads


def test_without_values_the_hook_is_read_once_and_a_raise_gives_the_option_name(
    tmp_path,
):
    scanner, reads = _scanner(tmp_path, RuntimeError("the hook broke"))

    assert scanner._timeout_limit_token(60) == WITHOUT_A_NUMBER
    assert reads == [True]


def test_without_values_a_working_hook_gives_the_numbered_token(tmp_path):
    scanner, reads = _scanner(tmp_path, ())

    assert scanner._timeout_limit_token(60) == timeout_limit_token(60, ())
    assert reads == [True]


def test_with_the_callers_values_the_hook_is_not_read_at_all(tmp_path):
    scanner, reads = _scanner(tmp_path, RuntimeError("the hook broke"))

    assert scanner._timeout_limit_token(60, ()) == timeout_limit_token(60, ())
    assert reads == []


def test_the_callers_values_decide_the_token(tmp_path):
    scanner, reads = _scanner(tmp_path, ())

    typed_by_a_value = scanner._timeout_limit_token(60, ("60",))

    assert typed_by_a_value == timeout_limit_token(60, ("60",))
    assert typed_by_a_value == WITHOUT_A_NUMBER
    assert scanner._timeout_limit_token(60, ("something else",)) == (
        timeout_limit_token(60, ("something else",))
    )
    assert reads == []

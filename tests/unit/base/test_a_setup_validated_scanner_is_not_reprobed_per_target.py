# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scanner the setup phase validated is not re-probed per target.

The scan phase's setup validates each selected scanner once, then ``_pre_scan``
validated again per target -- after ``start_time``, so the re-validation's
probes landed inside the scanner's measured duration, and for a tool verified
on PATH the re-run discarded the verified route. The satisfied verdict is now
memoized per instance (``validate_plugin_dependencies_once``) and ``_pre_scan``
reads it; a False verdict is deliberately NOT memoized, so a tool that is
genuinely missing still fails per target, loudly, as before.
"""

from __future__ import annotations

from typing import ClassVar, Literal

import pytest

from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.core.enums import OfflineStrategy, ScannerToolType

pytestmark = pytest.mark.unit


class _CountingConfig(ScannerPluginConfigBase):
    name: Literal["counting"] = "counting"


def _counting_scanner(plugin_context, verdicts):
    """A scanner whose validate pops its answers from ``verdicts`` (a list)."""

    calls = []

    class CountingScanner(ScannerPluginBase):
        offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED

        def model_post_init(self, context):
            self.command = "counting-tool"
            self.tool_type = ScannerToolType.SAST
            super().model_post_init(context)

        def validate_plugin_dependencies(self) -> bool:
            calls.append(1)
            return verdicts[min(len(calls), len(verdicts)) - 1]

        def _execute_scan(self, target, target_type, global_ignore_paths):
            raise NotImplementedError

    scanner = CountingScanner(config=_CountingConfig(), context=plugin_context)
    return scanner, calls


def test_a_satisfied_validation_answers_every_later_check(plugin_context):
    scanner, calls = _counting_scanner(plugin_context, [True])

    assert scanner.validate_plugin_dependencies_once() is True
    assert scanner.dependencies_satisfied is True
    assert calls == [1]

    # The setup phase already validated; the per-target check re-runs nothing.
    assert scanner.validate_plugin_dependencies_once() is True
    assert calls == [1]
    assert scanner.dependencies_satisfied is True


def test_pre_scan_honors_the_setup_validation(plugin_context, tmp_path):
    scanner, calls = _counting_scanner(plugin_context, [True])
    assert scanner.validate_plugin_dependencies_once() is True

    target = tmp_path / "target"
    target.mkdir()
    assert scanner._pre_scan(target, target_type="source") is True
    assert scanner._pre_scan(target, target_type="converted") is True
    # One validation for the whole run: setup's.
    assert calls == [1]


def test_a_failed_validation_is_still_probed_per_target(plugin_context, tmp_path):
    scanner, calls = _counting_scanner(plugin_context, [False, False])
    assert scanner.validate_plugin_dependencies_once() is False
    assert scanner.dependencies_satisfied is False

    target = tmp_path / "target"
    target.mkdir()
    # The invalid tool still fails loudly, per target: nothing was memoized.
    assert scanner._pre_scan(target, target_type="source") is False
    assert calls == [1, 1]


def test_a_transient_setup_failure_gets_its_per_target_retry(plugin_context, tmp_path):
    scanner, calls = _counting_scanner(plugin_context, [False, True])
    assert scanner.validate_plugin_dependencies_once() is False

    target = tmp_path / "target"
    target.mkdir()
    # The second validation answers True (the transient healed) and from then
    # on is memoized like a setup-satisfied one.
    assert scanner._pre_scan(target, target_type="source") is True
    assert scanner._pre_scan(target, target_type="converted") is True
    assert calls == [1, 1]

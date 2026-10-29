# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Offline opengrep in patterns mode needs no rule cache.

Patterns mode replaces every ``--config`` with ``--pattern`` entries, so the scan
reads no rules. Offline mode still validated the rule cache first and, finding none,
recorded the missing-cache reason and declined the scanner as MISSING for rules it
would never have read. The cache check is skipped when patterns are configured; a
rules scan offline still needs the cache.

No opengrep runs here: the unit conftest's tool guard answers the version probe as a
host without opengrep would.
"""

from __future__ import annotations

import pytest

from automated_security_helper.plugin_modules.ash_builtin.scanners.opengrep_scanner import (
    OpengrepScanner,
    OpengrepScannerConfig,
    OpengrepScannerConfigOptions,
)

pytestmark = pytest.mark.unit


def test_offline_patterns_mode_does_not_need_the_rule_cache(
    test_plugin_context, monkeypatch
):
    """Fails at the base: with no OPENGREP_RULES_CACHE_DIR the scanner recorded the
    missing-cache reason and the dependency check answered False."""
    monkeypatch.delenv("OPENGREP_RULES_CACHE_DIR", raising=False)

    scanner = OpengrepScanner(
        context=test_plugin_context,
        config=OpengrepScannerConfig(
            options=OpengrepScannerConfigOptions(offline=True, patterns=["eval($X)"])
        ),
    )

    assert scanner.dependency_unavailable_reason is None
    pairs = [(arg.key, arg.value) for arg in scanner.args.extra_args]
    assert ("--pattern", "eval($X)") in pairs, pairs
    assert not any(key == "--config" for key, _ in pairs), pairs


def test_offline_rules_mode_still_needs_the_rule_cache(
    test_plugin_context, monkeypatch
):
    """The control: no patterns, no cache, the scanner declines as before."""
    monkeypatch.delenv("OPENGREP_RULES_CACHE_DIR", raising=False)

    scanner = OpengrepScanner(
        context=test_plugin_context,
        config=OpengrepScannerConfig(
            options=OpengrepScannerConfigOptions(offline=True)
        ),
    )

    assert "OPENGREP_RULES_CACHE_DIR" in (scanner.dependency_unavailable_reason or "")
    assert scanner.validate_plugin_dependencies() is False

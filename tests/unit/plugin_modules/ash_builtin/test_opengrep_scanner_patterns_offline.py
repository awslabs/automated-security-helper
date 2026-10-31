# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Offline opengrep: patterns mode is refused before the rule cache is checked.

A configuration that sets ``patterns`` is refused while the scanner is built, with
a message naming the language option opengrep needs for a ``--pattern`` search
(``--lang``), which no option of this scanner supplies, and the rule-file shape
(``options.config``) that carries several patterns. Offline, the refusal comes
before the rule-cache check, so the operator reads why patterns mode cannot run
and not a missing-cache reason for rules the scan would never have read. A rules
scan offline still needs the cache.

No opengrep runs here: the unit conftest's tool guard answers the version probe as a
host without opengrep would.
"""

from __future__ import annotations

import pytest

from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules.ash_builtin.scanners.opengrep_scanner import (
    OpengrepScanner,
    OpengrepScannerConfig,
    OpengrepScannerConfigOptions,
    patterns_mode_refusal,
)

pytestmark = pytest.mark.unit


def test_offline_patterns_mode_is_refused_before_the_cache_check(
    test_plugin_context, monkeypatch
):
    """Red at the base: with no OPENGREP_RULES_CACHE_DIR the scanner was built with
    one ``--pattern`` per entry and no ``--config``, and nothing was raised."""
    monkeypatch.delenv("OPENGREP_RULES_CACHE_DIR", raising=False)

    with pytest.raises(ScannerError) as refused:
        OpengrepScanner(
            context=test_plugin_context,
            config=OpengrepScannerConfig(
                options=OpengrepScannerConfigOptions(
                    offline=True, patterns=["eval($X)"]
                )
            ),
        )

    message = str(refused.value)
    assert message == patterns_mode_refusal(["eval($X)"])
    assert "--lang" in message
    # The refusal, not the missing-cache reason, is what the operator reads.
    assert "OPENGREP_RULES_CACHE_DIR" not in message


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

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Which ``--config-overrides`` entries the detect-secrets confinement replays.

``confine_detect_secrets_settings`` keeps a verification filter, a ``file://``
entry or a baseline when the trusted base with the operator's overrides replayed
names it. The apply folds any spelling of the declared ``detect-secrets`` section
onto that section (``DetectSecrets``, ``detectsecrets``, ``Detect-Secrets``), so
an override written that way reaches the resolved config; the replay has to read
the same spellings, or what the operator asked for is dropped as untrusted.
"""

from __future__ import annotations

import pytest

from automated_security_helper.config.secret_verification_trust import (
    _detect_secrets_overrides,
)

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    "spelling",
    [
        "detect-secrets",
        "detect_secrets",
        "DetectSecrets",
        "detectsecrets",
        "Detect-Secrets",
    ],
)
def test_a_spelling_the_apply_folds_onto_the_section_is_replayed(spelling):
    override = f"scanners.{spelling}.options.baseline_file=/ops/.secrets.baseline"
    assert _detect_secrets_overrides([override]) == [override]


def test_the_whole_scanners_segment_is_replayed_and_another_scanner_is_not():
    assert _detect_secrets_overrides(["scanners={}"]) == ["scanners={}"]
    assert _detect_secrets_overrides(["scanners.bandit.options.config_file=x"]) == []
    assert _detect_secrets_overrides(["reporters.sarif.enabled=false"]) == []

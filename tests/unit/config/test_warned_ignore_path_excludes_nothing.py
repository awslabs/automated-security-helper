# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An ignore path kept by warn mode excludes no files.

Warn mode keeps an entry with an unknown key (``fail_on_unknown_keys: false``)
instead of refusing the config. For an ignore path the stake is highest: a
kept ``{path: src/, expiraton: ...}`` applied anyway would be a PERMANENT
exclusion, the very defect the refusal was added to stop. Every live consumer
of ignore-path entries filters through ``active_ignore_paths`` (the
orchestrator and both converters compose it under
``ignore_paths_that_skip_scanning``; bandit, checkov, syft, npm-audit and the
SARIF drop step call it directly), and that filter drops ``has_unknown_keys``
entries, which this test pins.
"""

import pytest

from automated_security_helper.models.core import (
    IgnorePathWithReason,
    ignore_paths_that_skip_scanning,
)
from automated_security_helper.utils.suppression_matcher import active_ignore_paths
from automated_security_helper.utils.unknown_keys import WARN_UNKNOWN_KEYS

pytestmark = pytest.mark.unit


def _warned_entry():
    warnings: list = []
    entry = IgnorePathWithReason.model_validate(
        {"path": "src/", "reason": "r", "expiraton": "2025-01-01"},
        context={WARN_UNKNOWN_KEYS: warnings},
    )
    assert warnings, "warn mode must have recorded the unknown key"
    assert entry.has_unknown_keys
    return entry


def test_active_ignore_paths_drops_a_warned_entry():
    control = IgnorePathWithReason.model_validate(
        {"path": "build/", "reason": "generated"}
    )
    active = active_ignore_paths([_warned_entry(), control])
    assert active == [control]


def test_the_orchestrators_composition_excludes_nothing_for_it():
    # The exact composition the orchestrator hands the scanners and the
    # converters use: a warned entry must not survive it.
    control = IgnorePathWithReason.model_validate(
        {"path": "build/", "reason": "generated"}
    )
    handed_to_scanners = ignore_paths_that_skip_scanning(
        active_ignore_paths([_warned_entry(), control]),
        ignore_suppressions=False,
    )
    assert handed_to_scanners == [control]

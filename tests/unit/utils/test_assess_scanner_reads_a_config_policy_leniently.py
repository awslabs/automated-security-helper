# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``assess_scanner`` never raises, whatever text the config gave its policy.

The docstring promises it; the first line used to build the policy with
``StalenessPolicy(policy)``, outside every ``try``, so raw config text in the wrong
case (``"FAIL"``) raised ``ValueError`` before any database was looked at.
"""

from __future__ import annotations

import pytest

from automated_security_helper.utils.content_databases import StalenessPolicy
from automated_security_helper.utils.content_db_staleness import assess_scanner

pytestmark = pytest.mark.unit


class _ScannerWithNoDatabases:
    config = None

    def content_databases_in_use(self):
        return []


@pytest.mark.parametrize(
    "policy",
    ["FAIL", "Warn", " fail".strip(), "bogus", "", None, 3, StalenessPolicy.FAIL],
)
def test_a_policy_in_any_text_does_not_raise(policy):
    assert assess_scanner(_ScannerWithNoDatabases(), None, policy) == []

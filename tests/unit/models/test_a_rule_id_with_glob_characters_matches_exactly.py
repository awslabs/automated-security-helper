# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A suppression whose ``rule_id`` is a finding's exact rule id matches it.

``AshSuppression.matches`` compared rule ids through ``fnmatch`` alone, which
reads ``[`` as a character class. cdk-nag's granular ids hold brackets
(``AwsSolutions-IAM5[Resource::*]``), so a suppression the TUI saved for such a
finding never matched the finding it was saved for. The finding's exact id
(case-insensitive) matches first; the glob is tried after it.
"""

from __future__ import annotations

import pytest

from automated_security_helper.models.core import AshSuppression
from automated_security_helper.models.flat_vulnerability import FlatVulnerability

pytestmark = pytest.mark.unit

GRANULAR = "AwsSolutions-IAM5[Resource::*]"


def _finding(rule_id: str) -> FlatVulnerability:
    return FlatVulnerability(
        id="f1",
        title="t",
        description="d",
        severity="HIGH",
        scanner="cdk-nag",
        scanner_type="IAC",
        rule_id=rule_id,
        file_path="stack.template.json",
    )


def test_an_exact_rule_id_holding_glob_characters_matches():
    suppression = AshSuppression(path="**", reason="r", rule_id=GRANULAR)

    assert suppression.matches(_finding(GRANULAR)) is True


def test_the_exact_match_is_case_insensitive():
    suppression = AshSuppression(path="**", reason="r", rule_id=GRANULAR.lower())

    assert suppression.matches(_finding(GRANULAR)) is True


def test_a_glob_rule_id_still_matches_by_pattern():
    suppression = AshSuppression(path="**", reason="r", rule_id="AwsSolutions-IAM*")

    assert suppression.matches(_finding(GRANULAR)) is True
    assert suppression.matches(_finding("AwsSolutions-S3-1")) is False

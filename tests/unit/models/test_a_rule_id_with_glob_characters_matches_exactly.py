# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A suppression whose ``rule_id`` is a finding's exact rule id matches it.

``AshSuppression.matches`` compared rule ids through ``fnmatch`` alone, which
reads ``[`` as a character class. cdk-nag's granular ids hold brackets
(``AwsSolutions-IAM5[Resource::*]``), so a suppression written with the id as
the finding shows it never matched the finding it was written for. The finding's
exact id (case-insensitive) matches first; the glob is tried after it.

The form the inspect TUI saves escapes the brackets and the star as character
classes (``AwsSolutions-IAM5[[]Resource::[*]]``); that is a glob, and it matches
by the glob branch. The raw form is both an exact id and a glob, so a raw
``CKV[1]`` also matches the finding ``CKV1`` (the class ``[1]`` is the digit):
the exact-first rule adds a match, it removes none.
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


def test_the_escaped_form_the_tui_saves_matches_the_granular_id():
    """Brackets and the star each written as a one-character class."""
    escaped = "AwsSolutions-IAM5[[]Resource::[*]]"
    suppression = AshSuppression(path="**", reason="r", rule_id=escaped)

    assert suppression.matches(_finding(GRANULAR)) is True
    # It is a glob, not the literal id: it does not match another resource.
    assert suppression.matches(_finding("AwsSolutions-IAM5[Other::*]")) is False


def test_a_raw_id_with_brackets_matches_itself_and_its_glob_twin():
    """The raw id is an exact match first, and as a glob it also reads ``[1]``
    as the digit class, so it matches ``CKV1`` too. Pinned on purpose: the
    exact-first rule adds a match and takes none away."""
    suppression = AshSuppression(path="**", reason="r", rule_id="CKV[1]")

    assert suppression.matches(_finding("CKV[1]")) is True
    assert suppression.matches(_finding("CKV1")) is True
    assert suppression.matches(_finding("CKV2")) is False


def test_a_glob_rule_id_still_matches_by_pattern():
    suppression = AshSuppression(path="**", reason="r", rule_id="AwsSolutions-IAM*")

    assert suppression.matches(_finding(GRANULAR)) is True
    assert suppression.matches(_finding("AwsSolutions-S3-1")) is False

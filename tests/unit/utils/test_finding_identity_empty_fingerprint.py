# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An empty fingerprint value identifies nothing.

``result_fingerprints`` dropped only the ``"requires login"`` placeholder, so a
result whose fingerprint value was ``""`` was keyed by its scanner, rule and file
alone: a later, different finding of the same rule in the same file, with the same
empty value, computed the same key and took its id.
"""

from __future__ import annotations

import pytest

from automated_security_helper.schemas.sarif_schema_model import Message, Result
from automated_security_helper.utils.finding_identity import (
    finding_identity,
    identity_key,
    result_fingerprints,
)

pytestmark = pytest.mark.unit


def _result(**fingerprints) -> Result:
    return Result(
        ruleId="r",
        message=Message(text="finding"),
        fingerprints=fingerprints,
    )


def test_an_empty_fingerprint_value_is_dropped():
    assert result_fingerprints(_result(**{"matchBasedId/v1": ""})) == ()
    assert result_fingerprints(_result(**{"matchBasedId/v1": "   "})) == ()


def test_a_real_value_beside_an_empty_one_is_kept():
    assert result_fingerprints(_result(a="", b="x")) == (
        ("fingerprints", (("b", "x"),)),
    )


def test_two_findings_with_only_empty_fingerprints_are_keyed_by_their_lines():
    """Both carried the empty value, so both were keyed by scanner, rule and file
    and got one id."""
    first = finding_identity(
        scanner="semgrep",
        rule_id="r",
        file_path="src/a.py",
        line_start=3,
        line_end=3,
        fingerprints=result_fingerprints(_result(**{"matchBasedId/v1": ""})),
    )
    second = finding_identity(
        scanner="semgrep",
        rule_id="r",
        file_path="src/a.py",
        line_start=40,
        line_end=40,
        fingerprints=result_fingerprints(_result(**{"matchBasedId/v1": ""})),
    )

    assert first.fingerprints == () and second.fingerprints == ()
    assert identity_key(first) != identity_key(second)
    assert identity_key(first)["startLine"] == 3
    assert identity_key(second)["startLine"] == 40

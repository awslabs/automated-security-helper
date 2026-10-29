# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A secret finding's fallback snippet is masked whole.

``FlatVulnerability`` takes ``code_snippet`` from the location's snippets, then
from ``result.properties.snippet``, then from a fenced block in the message.
``secret_masking`` rewrites the region and contextRegion snippets by location
and masks a secret finding's own snippets whole, but it never visits the two
fallback slots, so a secret finding whose only snippet sat there reached the
HTML, Markdown and Text reports in clear. The fallback of a secret finding is
now the masker's own placeholder; any other finding's fallback gets the
message's masking.
"""

from __future__ import annotations

import pytest

from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.schemas.sarif_schema_model import (
    Message,
    Message1,
    PropertyBag,
    Result,
)
from automated_security_helper.utils.secret_masking import MASKED_LINE

pytestmark = pytest.mark.unit

PLANTED = "hunter2-planted-secret-value"


def _result(rule_id: str, text: str, properties: dict | None = None) -> Result:
    kwargs: dict = {
        "ruleId": rule_id,
        "level": "error",
        "message": Message(root=Message1(text=text)),
    }
    if properties is not None:
        kwargs["properties"] = PropertyBag(**properties)
    return Result(**kwargs)


def test_a_secret_findings_properties_snippet_is_the_placeholder():
    result = _result(
        "B105",
        "Possible hardcoded password: 'x'",
        {"snippet": f"password = '{PLANTED}'"},
    )

    flat = FlatVulnerability.from_sarif_result(result, "bandit", "SAST")

    assert flat.code_snippet == MASKED_LINE
    assert PLANTED not in (flat.code_snippet or "")


def test_a_secret_findings_fenced_message_snippet_is_the_placeholder():
    result = _result(
        "generic.secrets.gitleaks.token",
        f"Token found\n```\ntoken = '{PLANTED}'\n```",
    )

    flat = FlatVulnerability.from_sarif_result(result, "semgrep", "SAST")

    assert flat.code_snippet == MASKED_LINE


def test_another_findings_properties_snippet_is_kept():
    result = _result("B602", "subprocess call", {"snippet": "subprocess.call(cmd)"})

    flat = FlatVulnerability.from_sarif_result(result, "bandit", "SAST")

    assert flat.code_snippet == "subprocess.call(cmd)"

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A denied leaf counts as unchanged only when it holds the trusted JSON value.

``config_document_denials`` does not refuse a leaf whose value equals what the
trusted config has at the same place. It compared the two with Python's ``==``,
under which ``True == 1`` and ``False == 0``, so a document that wrote a number
where the trusted config has true or false was let through at a denied path,
although the two are different JSON values. The module compares JSON values as
JSON elsewhere (``_same_json_value``).
"""

from __future__ import annotations

from typing import Any, Dict, List

import pytest

from automated_security_helper.config.ash_config import (
    AshConfig,
    RuntimeOverridesConfig,
)
from automated_security_helper.config.runtime_patch import config_document_denials

pytestmark = pytest.mark.unit


def _denied_keys(document: Dict[str, Any], base: AshConfig) -> List[str]:
    allowlist = RuntimeOverridesConfig(
        enabled=True,
        allowed_paths=["/project_name"],
        denied_paths=["/fail_on_findings"],
    )
    return [
        denial.key
        for denial in config_document_denials(
            document, allowlist=allowlist, config=base
        )
    ]


@pytest.mark.parametrize(
    "trusted, written", [(True, 1), (False, 0)], ids=["true-as-1", "false-as-0"]
)
def test_a_number_where_the_trusted_value_is_true_or_false_is_refused(
    trusted: bool, written: int
) -> None:
    base = AshConfig(fail_on_findings=trusted)
    assert _denied_keys({"fail_on_findings": written}, base) == ["fail_on_findings"]


@pytest.mark.parametrize("trusted", [True, False])
def test_the_trusted_value_itself_is_still_not_refused(trusted: bool) -> None:
    """The control: the same JSON value changes nothing."""
    base = AshConfig(fail_on_findings=trusted)
    assert _denied_keys({"fail_on_findings": trusted}, base) == []

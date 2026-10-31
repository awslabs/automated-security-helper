# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A suppression with a blank ``rule_id`` is refused with what to write.

An omitted ``rule_id`` matches every rule in the suppression's path, as the
suppressions guide says. A blank one was accepted and read the same way (an
empty string is false in ``matches``), so a rule id left empty by mistake
silently covered every rule in its path, and a whitespace-only one matched
nothing at all. Both are refused, as the blank package fields are.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from automated_security_helper.models.core import AshSuppression

pytestmark = pytest.mark.unit


@pytest.mark.parametrize("blank", ["", "   "])
def test_a_blank_rule_id_is_refused(blank):
    with pytest.raises(ValidationError, match="rule_id must be omitted"):
        AshSuppression(path="app.py", reason="r", rule_id=blank)


def test_an_omitted_rule_id_is_still_accepted():
    suppression = AshSuppression(path="app.py", reason="r")

    assert suppression.rule_id is None
    assert suppression.id == "app.py|*|*|*"

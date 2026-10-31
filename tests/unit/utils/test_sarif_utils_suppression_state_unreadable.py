# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A suppression whose state cannot be read is in effect.

``suppressions_in_effect`` leaves out a suppression whose ``state`` is
``rejected`` or ``underReview``. A stand-in whose ``state`` read raises has no
known inactive state, so it counts as in effect and its other fields are still
read by the consumers (the OCSF reporter's status detail among them); a raise out
of the helper dropped the whole result's suppression reading instead.
"""

import pytest

from automated_security_helper.schemas.sarif_schema_model import Kind1
from automated_security_helper.utils.sarif_utils import (
    is_result_suppressed,
    suppressions_in_effect,
)

pytestmark = pytest.mark.unit


def _raiser(error):
    def _get(self):
        raise error

    return property(_get)


def _stub(**values):
    namespace = {"kind": None, "state": None, "justification": None}
    namespace.update(values)
    return type("SuppressionStub", (), namespace)()


def test_a_suppression_whose_state_read_raises_is_in_effect():
    suppression = _stub(
        kind=Kind1.external,
        state=_raiser(RuntimeError("state unreadable")),
        justification="a reason",
    )

    assert suppressions_in_effect([suppression]) == [suppression]
    assert is_result_suppressed(type("R", (), {"suppressions": [suppression]})())


def test_a_readable_inactive_state_is_still_left_out():
    rejected = _stub(kind=Kind1.external, state="rejected")
    unreadable = _stub(kind=Kind1.external, state=_raiser(RuntimeError("no")))

    assert suppressions_in_effect([rejected, unreadable]) == [unreadable]
